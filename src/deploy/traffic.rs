use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use time::{Date, Month};

use crate::deploy::remote::remote_bash_stdin_cmd;
use crate::deploy::ssh::run_ssh;
use crate::state::{Server, VpnProtocol};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtoBytes {
    pub up: u128,
    pub down: u128,
}

impl ProtoBytes {
    pub fn total(&self) -> u128 {
        self.up.saturating_add(self.down)
    }

    pub fn add_assign_saturating(&mut self, up: u128, down: u128) {
        self.up = self.up.saturating_add(up);
        self.down = self.down.saturating_add(down);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerTrafficStatus {
    Ok {
        days_found: usize,
        nic_observed: bool,
        nic_rx: u128,
        nic_tx: u128,
        users: BTreeMap<u32, BTreeMap<VpnProtocol, ProtoBytes>>,
    },
    Undeployed,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTrafficReport {
    pub server_id: String,
    pub status: ServerTrafficStatus,
}

pub fn format_utc_date(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

pub fn parse_utc_date(raw: &str, flag: &str) -> Result<Date> {
    let trimmed = raw.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        bail!("invalid {flag} date '{raw}' (expected YYYY-MM-DD)");
    }
    let year: i32 = trimmed[..4]
        .parse()
        .map_err(|_| anyhow!("invalid {flag} year in '{raw}'"))?;
    let month_num: u8 = trimmed[5..7]
        .parse()
        .map_err(|_| anyhow!("invalid {flag} month in '{raw}'"))?;
    let day: u8 = trimmed[8..10]
        .parse()
        .map_err(|_| anyhow!("invalid {flag} day in '{raw}'"))?;
    let month = Month::try_from(month_num)
        .map_err(|_| anyhow!("invalid {flag} month '{month_num}' in '{raw}'"))?;
    Date::from_calendar_date(year, month, day)
        .map_err(|e| anyhow!("invalid {flag} date '{raw}': {e}"))
}

pub fn build_traffic_probe_script(from: Date, to: Date) -> String {
    let from_s = format_utc_date(from);
    let to_s = format_utc_date(to);
    format!(
        "set -euo pipefail\n\
         SNAP=/usr/local/lib/kinveil/traffic/snapshot-traffic.sh\n\
         DATA=/var/lib/kinveil/traffic\n\
         if [ ! -x \"$SNAP\" ]; then\n\
             echo \"STATUS undeployed\"\n\
             exit 0\n\
         fi\n\
         \"$SNAP\"\n\
         echo \"STATUS ok\"\n\
         if [ -d \"$DATA\" ]; then\n\
             for f in \"$DATA\"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].tsv; do\n\
                 [ -f \"$f\" ] || continue\n\
                 day=\"${{f##*/}}\"\n\
                 day=\"${{day%.tsv}}\"\n\
                 if [[ \"$day\" < \"{from_s}\" ]] || [[ \"$day\" > \"{to_s}\" ]]; then\n\
                     continue\n\
                 fi\n\
                 while IFS= read -r line; do\n\
                     [ -n \"$line\" ] || continue\n\
                     printf 'DAY\\t%s\\t%s\\n' \"$day\" \"$line\"\n\
                 done < \"$f\"\n\
             done\n\
         fi\n"
    )
}

pub fn parse_traffic_probe_output(
    server_id: &str,
    stdout: &str,
    from: Date,
    to: Date,
) -> ServerTrafficReport {
    let make_err = |msg: String| ServerTrafficReport {
        server_id: server_id.to_owned(),
        status: ServerTrafficStatus::Failed(msg),
    };

    let mut seen_status: Option<&str> = None;
    let mut days_seen = BTreeSet::new();
    let mut nic_observed = false;
    let mut nic_rx = 0u128;
    let mut nic_tx = 0u128;
    let mut users: BTreeMap<u32, BTreeMap<VpnProtocol, ProtoBytes>> = BTreeMap::new();

    for raw in stdout.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line == "STATUS undeployed" {
            return ServerTrafficReport {
                server_id: server_id.to_owned(),
                status: ServerTrafficStatus::Undeployed,
            };
        }
        if line == "STATUS ok" {
            seen_status = Some("ok");
            continue;
        }
        let Some(rest) = line.strip_prefix("DAY\t") else {
            return make_err(format!("unexpected traffic probe line: {line}"));
        };
        let mut fields = rest.split('\t');
        let Some(day_str) = fields.next() else {
            return make_err("malformed DAY traffic line (missing date)".to_owned());
        };
        let date = match parse_utc_date(day_str, "remote day") {
            Ok(d) => d,
            Err(e) => return make_err(e.to_string()),
        };
        if date < from || date > to {
            return make_err(format!(
                "remote traffic probe returned out-of-range day '{day_str}'"
            ));
        }
        days_seen.insert(day_str.to_owned());
        let Some(kind) = fields.next() else {
            return make_err(format!("malformed DAY record on '{day_str}'"));
        };
        match kind {
            "nic" => {
                let (Some(rx_s), Some(tx_s), None) = (fields.next(), fields.next(), fields.next())
                else {
                    return make_err(format!("malformed nic record on '{day_str}'"));
                };
                let (Ok(rx), Ok(tx)) = (rx_s.parse::<u128>(), tx_s.parse::<u128>()) else {
                    return make_err(format!("invalid nic byte counts on '{day_str}'"));
                };
                nic_observed = true;
                nic_rx = nic_rx.saturating_add(rx);
                nic_tx = nic_tx.saturating_add(tx);
            }
            "uid" => {
                let (Some(uid_s), Some(proto_s), Some(up_s), Some(down_s), None) = (
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                ) else {
                    return make_err(format!("malformed uid record on '{day_str}'"));
                };
                let Ok(uid) = uid_s.parse::<u32>() else {
                    return make_err(format!("invalid uid '{uid_s}' on '{day_str}'"));
                };
                let Some(proto) = VpnProtocol::parse(proto_s) else {
                    return make_err(format!("unknown protocol '{proto_s}' on '{day_str}'"));
                };
                let (Ok(up), Ok(down)) = (up_s.parse::<u128>(), down_s.parse::<u128>()) else {
                    return make_err(format!("invalid byte counts on '{day_str}'"));
                };
                users
                    .entry(uid)
                    .or_default()
                    .entry(proto)
                    .or_default()
                    .add_assign_saturating(up, down);
            }
            other => {
                return make_err(format!(
                    "unknown traffic record type '{other}' on '{day_str}'"
                ));
            }
        }
    }

    if seen_status.is_none() {
        return make_err("empty or incomplete traffic probe output".to_owned());
    }

    ServerTrafficReport {
        server_id: server_id.to_owned(),
        status: ServerTrafficStatus::Ok {
            days_found: days_seen.len(),
            nic_observed,
            nic_rx,
            nic_tx,
            users,
        },
    }
}

pub fn query_remote_traffic(servers: &[&Server], from: Date, to: Date) -> Vec<ServerTrafficReport> {
    let script = build_traffic_probe_script(from, to);
    std::thread::scope(|scope| {
        let handles: Vec<_> = servers
            .iter()
            .map(|server| {
                let server = *server;
                let script = &script;
                scope.spawn(move || {
                    let remote_cmd = remote_bash_stdin_cmd(&server.admin_ssh.user);
                    match run_ssh(&server.admin_ssh, remote_cmd, Some(script.as_bytes())) {
                        Ok(out) => parse_traffic_probe_output(&server.id, &out.stdout, from, to),
                        Err(e) => ServerTrafficReport {
                            server_id: server.id.clone(),
                            status: ServerTrafficStatus::Failed(format!("SSH query failed: {e}")),
                        },
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("traffic query worker thread panicked"))
            .collect()
    })
}
