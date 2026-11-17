//! Per-server and per-user traffic reporting (`kinveil traffic`).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Result, bail};
use time::{Date, OffsetDateTime};

use crate::deploy::traffic::{
    ProtoBytes, ServerTrafficStatus, format_utc_date, parse_utc_date, query_remote_traffic,
};
use crate::state::{Server, VpnProtocol};
use crate::validate::validate_state;

use super::load_locked_state;
use super::secrets::SecretReader;

pub(crate) fn format_bytes(bytes: u128) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut unit_idx = 0usize;
    let mut val = bytes as f64;
    while val >= 1024.0 && unit_idx + 1 < UNITS.len() {
        val /= 1024.0;
        unit_idx += 1;
    }
    format!("{val:.2} {}", UNITS[unit_idx])
}

struct UserTrafficRow {
    uid: u32,
    up: u128,
    down: u128,
    total: u128,
    by_protocol: BTreeMap<VpnProtocol, ProtoBytes>,
}

pub(crate) fn resolve_date_range(from: Option<&str>, to: Option<&str>) -> Result<(Date, Date)> {
    let today = OffsetDateTime::now_utc().date();
    let to_date = match to {
        Some(raw) => parse_utc_date(raw, "--to")?,
        None => today,
    };
    let from_date = match from {
        Some(raw) => parse_utc_date(raw, "--from")?,
        None => Date::from_calendar_date(to_date.year(), to_date.month(), 1)?,
    };
    if from_date > to_date {
        bail!(
            "--from date ({}) must be <= --to date ({})",
            format_utc_date(from_date),
            format_utc_date(to_date)
        );
    }
    Ok((from_date, to_date))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_traffic(
    state_path: &Path,
    from: Option<String>,
    to: Option<String>,
    server: Option<String>,
    user: Option<String>,
    by_protocol: bool,
    secrets: &mut SecretReader,
) -> Result<()> {
    let (from_date, to_date) = resolve_date_range(from.as_deref(), to.as_deref())?;
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    validate_state(&state)?;

    let filter_uid = match user {
        Some(ref name) => Some(state.user(name)?.uid),
        None => None,
    };

    let targets: Vec<&Server> = if let Some(ref id) = server {
        let srv = state.server(id)?;
        if !srv.enabled {
            bail!("server '{id}' is disabled");
        }
        let eff = srv.effective_config(&state.settings, state.is_subscription_server(&srv.id));
        if !eff.has_traffic {
            bail!(
                "traffic accounting is not enabled on server '{id}'; run `kinveil server update {id} --traffic` and `kinveil deploy`"
            );
        }
        vec![srv]
    } else {
        let selected: Vec<&Server> = state
            .servers
            .iter()
            .filter(|s| {
                s.enabled
                    && s.effective_config(&state.settings, state.is_subscription_server(&s.id))
                        .has_traffic
            })
            .collect();
        if selected.is_empty() {
            bail!(
                "no enabled servers have traffic accounting enabled; run `kinveil server update <id> --traffic` and `kinveil deploy`"
            );
        }
        selected
    };

    let uid_lookup: HashMap<u32, (&str, bool)> = state
        .users
        .iter()
        .map(|(name, u)| (u.uid, (name.as_str(), u.enabled)))
        .collect();

    let reports = query_remote_traffic(&targets, from_date, to_date);
    let from_s = format_utc_date(from_date);
    let to_s = format_utc_date(to_date);
    let mut any_failed = false;

    for (idx, (srv, report)) in targets.iter().zip(reports.iter()).enumerate() {
        if idx > 0 {
            println!();
        }
        println!(
            "Server {} ({}) [{from_s} .. {to_s} UTC]:",
            srv.id, srv.label
        );
        match &report.status {
            ServerTrafficStatus::Undeployed => {
                println!(
                    "  [UNDEPLOYED] Traffic accounting is enabled in state.enc, but not yet deployed on '{}'. Run `kinveil deploy --server {}`.",
                    srv.id, srv.id
                );
                any_failed = true;
            }
            ServerTrafficStatus::Failed(err) => {
                println!("  [ERROR] {err}");
                any_failed = true;
            }
            ServerTrafficStatus::Ok {
                days_found,
                nic_observed,
                nic_rx,
                nic_tx,
                users,
            } => {
                if *nic_observed {
                    let nic_total = nic_rx.saturating_add(*nic_tx);
                    println!(
                        "  Public NIC:  tx={}  rx={}  rx+tx={}  (days={})",
                        format_bytes(*nic_tx),
                        format_bytes(*nic_rx),
                        format_bytes(nic_total),
                        days_found
                    );
                } else {
                    println!("  Public NIC:  unavailable  (days={days_found})");
                }

                let mut vpn_up = 0u128;
                let mut vpn_down = 0u128;
                let mut rows_by_uid: BTreeMap<u32, BTreeMap<VpnProtocol, ProtoBytes>> =
                    BTreeMap::new();

                for u in state.users.values().filter(|u| u.enabled) {
                    rows_by_uid.entry(u.uid).or_default();
                }
                for (&uid, protos) in users {
                    let entry = rows_by_uid.entry(uid).or_default();
                    for (&proto, pb) in protos {
                        vpn_up = vpn_up.saturating_add(pb.up);
                        vpn_down = vpn_down.saturating_add(pb.down);
                        entry
                            .entry(proto)
                            .or_default()
                            .add_assign_saturating(pb.up, pb.down);
                    }
                }

                let vpn_total = vpn_up.saturating_add(vpn_down);
                println!(
                    "  VPN total:   up={}  down={}  total={}",
                    format_bytes(vpn_up),
                    format_bytes(vpn_down),
                    format_bytes(vpn_total)
                );

                let mut rows: Vec<UserTrafficRow> = rows_by_uid
                    .into_iter()
                    .filter(|(uid, _)| filter_uid.is_none_or(|only| *uid == only))
                    .map(|(uid, by_proto)| {
                        let mut up = 0u128;
                        let mut down = 0u128;
                        for pb in by_proto.values() {
                            up = up.saturating_add(pb.up);
                            down = down.saturating_add(pb.down);
                        }
                        UserTrafficRow {
                            uid,
                            up,
                            down,
                            total: up.saturating_add(down),
                            by_protocol: by_proto,
                        }
                    })
                    .collect();

                rows.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.uid.cmp(&b.uid)));

                println!("  Users ({}):", rows.len());
                if rows.is_empty() {
                    println!("    (none)");
                } else {
                    for (rank, row) in rows.iter().enumerate() {
                        let label = match uid_lookup.get(&row.uid) {
                            Some((name, true)) => format!("{name} (uid={})", row.uid),
                            Some((name, false)) => format!("{name} (uid={}, disabled)", row.uid),
                            None => format!("<removed> (uid={})", row.uid),
                        };
                        let pct = if vpn_total > 0 {
                            (row.total as f64) * 100.0 / (vpn_total as f64)
                        } else {
                            0.0
                        };
                        println!(
                            "    {:>2}. {:<28}  up={:<10}  down={:<10}  total={:<10}  ({pct:.1}%)",
                            rank + 1,
                            label,
                            format_bytes(row.up),
                            format_bytes(row.down),
                            format_bytes(row.total),
                        );
                        if by_protocol {
                            for (proto, pb) in &row.by_protocol {
                                let p_tot = pb.total();
                                if p_tot > 0 {
                                    println!(
                                        "        {:<14}  up={:<10}  down={:<10}  total={}",
                                        proto.as_str(),
                                        format_bytes(pb.up),
                                        format_bytes(pb.down),
                                        format_bytes(p_tot),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if any_failed {
        bail!("traffic query failed on one or more servers");
    }
    Ok(())
}
