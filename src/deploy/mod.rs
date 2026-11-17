pub mod artifacts;
pub mod cloudflare;
pub mod lists;
pub mod remote;
pub mod ssh;
pub mod traffic;
pub mod verify;

use std::time::Duration;

use anyhow::{Context as _, Result, bail};

use crate::deploy::artifacts::{
    RuntimeArtifacts, has_prebuilt_awg_source, inspect_artifact_status, prepare_artifacts,
};
use crate::deploy::cloudflare::sync_subscription_dns;
use crate::deploy::lists::resolve_firewall_lists;
use crate::deploy::remote::{
    BundleOptions, build_disabled_server_bundle, build_server_bundle, remote_retire_caddy_cmd,
    remote_stage_and_exec_cmd,
};
use crate::deploy::ssh::run_ssh;
use crate::deploy::verify::verify_https_subscriptions;
use crate::render::ResolvedFirewallLists;
use crate::state::{AdminSsh, Server, State};
use crate::validate::validate_for_deploy;

#[derive(Debug, Clone, Copy)]
struct RemotePreflight {
    need_xray_bin: bool,
    need_geodata: bool,
    need_awg: bool,
    has_managed_sub: bool,
}

fn check_remote_state(admin: &AdminSsh, artifacts: &RuntimeArtifacts) -> RemotePreflight {
    let cmd = "sh -c 'for p in /usr/local/lib/kinveil/xray/xray /usr/local/lib/kinveil/awg/amneziawg-go; do [ -x \"$p\" ] && sha256sum \"$p\" || true; done; for p in /usr/local/lib/kinveil/xray/geoip.dat /usr/local/lib/kinveil/xray/geosite.dat; do [ -f \"$p\" ] && sha256sum \"$p\" || true; done; [ -f /etc/kinveil/.managed-sub ] && echo MANAGED_SUB || true'";
    let Ok(out) = run_ssh(admin, cmd, None) else {
        return RemotePreflight {
            need_xray_bin: true,
            need_geodata: true,
            need_awg: true,
            has_managed_sub: true,
        };
    };
    let mut need_xray_bin = true;
    let mut have_geoip = false;
    let mut have_geosite = false;
    let mut need_awg = true;
    let mut has_managed_sub = false;
    for line in out.stdout.lines() {
        let trimmed = line.trim();
        if trimmed == "MANAGED_SUB" {
            has_managed_sub = true;
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let (Some(hash), Some(path)) = (parts.next(), parts.next()) else {
            continue;
        };
        if path == "/usr/local/lib/kinveil/xray/xray"
            && hash.eq_ignore_ascii_case(&artifacts.xray_sha256)
        {
            need_xray_bin = false;
        } else if path == "/usr/local/lib/kinveil/xray/geoip.dat"
            && hash.eq_ignore_ascii_case(&artifacts.geoip_sha256)
        {
            have_geoip = true;
        } else if path == "/usr/local/lib/kinveil/xray/geosite.dat"
            && hash.eq_ignore_ascii_case(&artifacts.geosite_sha256)
        {
            have_geosite = true;
        } else if path == "/usr/local/lib/kinveil/awg/amneziawg-go"
            && hash.eq_ignore_ascii_case(&artifacts.awg_sha256)
        {
            need_awg = false;
        }
    }
    RemotePreflight {
        need_xray_bin,
        need_geodata: !(have_geoip && have_geosite),
        need_awg,
        has_managed_sub,
    }
}

fn deploy_bundles_parallel<'a>(bundles: &'a [(&'a Server, Vec<u8>)]) -> Vec<(&'a str, Result<()>)> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = bundles
            .iter()
            .map(|(server, bundle)| {
                let server = *server;
                let bundle = bundle.as_slice();
                scope.spawn(move || {
                    let cmd = remote_stage_and_exec_cmd(&server.admin_ssh.user);
                    let res = run_ssh(&server.admin_ssh, &cmd, Some(bundle)).map(|_| ());
                    (server.id.as_str(), res)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("deploy worker thread panicked"))
            .collect()
    })
}

#[derive(Debug, Clone)]
pub struct DeployOptions {
    pub dry_run: bool,
    pub server_filter: Option<String>,
    pub skip_dns: bool,
    pub takeover: bool,
}

pub fn run_deploy(state: &State, opts: &DeployOptions) -> Result<()> {
    validate_for_deploy(state).context("validation failed")?;

    if let Some(id) = &opts.server_filter
        && !state.servers.iter().any(|s| s.id == *id)
    {
        bail!("unknown server id '{id}'");
    }

    let enabled_users = state.users.values().filter(|u| u.enabled).count();
    let sub_server = state
        .active_subscription_server()
        .expect("validate_for_deploy guarantees active subscription server");
    let sub_in_scope = opts
        .server_filter
        .as_deref()
        .is_none_or(|only| only == sub_server.id);
    let need_xray = state.servers.iter().any(|s| {
        opts.server_filter
            .as_deref()
            .is_none_or(|only| s.id == only)
            && s.enabled
            && s.effective_config(&state.settings, false).has_xray
    });
    let need_any_vpn = state.servers.iter().any(|s| {
        opts.server_filter
            .as_deref()
            .is_none_or(|only| s.id == only)
            && s.enabled
            && s.effective_config(&state.settings, false)
                .has_any_vpn_protocol
    });
    let need_xray_geodata = need_xray && state.settings.firewall.needs_xray_geodata();
    let need_country_geoip = need_any_vpn && state.settings.firewall.needs_country_geoip();
    let need_geodata_any = need_xray_geodata || need_country_geoip;
    let need_awg = state.servers.iter().any(|s| {
        opts.server_filter
            .as_deref()
            .is_none_or(|only| s.id == only)
            && s.enabled
            && s.effective_config(&state.settings, false).has_amneziawg
    });

    if opts.dry_run {
        let art = inspect_artifact_status(
            &state.settings.artifacts,
            need_xray_geodata,
            need_country_geoip,
        )?;
        println!("DRY RUN — no remote SSH, DNS, or HTTP calls will be made.");
        println!("State revision: {} ({})", state.revision, state.updated_at);
        println!("Enabled users: {enabled_users}");
        if state.settings.artifacts.has_overrides() {
            println!("Artifact overrides: configured in [artifacts]");
        }
        println!(
            "Artifact xray: {} ({})",
            if !need_xray {
                "not required"
            } else if art.xray_cached {
                "cached"
            } else {
                "needs download"
            },
            art.xray_path.display()
        );
        if need_geodata_any {
            let label = match (need_country_geoip, need_xray_geodata) {
                (true, true) | (false, true) => "geoip.dat + geosite.dat",
                (true, false) => "geoip.dat",
                (false, false) => unreachable!(),
            };
            println!(
                "Artifact geodata: {} ({label})",
                if art.geodata_cached {
                    "cached"
                } else {
                    "needs download"
                }
            );
        }
        if need_any_vpn
            && (state.settings.firewall.has_dynamic_ip_lists()
                || !state.settings.firewall.xray.block_domain_lists.is_empty())
        {
            println!(
                "Firewall blocklists: countries=[{}], ip_lists={}, domain_lists={}, auto_update={}",
                state.settings.firewall.block_countries.join(","),
                state.settings.firewall.block_ip_lists.len(),
                state.settings.firewall.xray.block_domain_lists.len(),
                if state.settings.firewall.auto_update_active() {
                    format!("{}h", state.settings.firewall.auto_update.interval_hours)
                } else {
                    "disabled".to_owned()
                }
            );
        }
        println!(
            "Artifact amneziawg-go: {} ({})",
            if !need_awg {
                "not required"
            } else if art.awg_cached {
                "cached"
            } else if has_prebuilt_awg_source(&state.settings.artifacts) {
                "needs download"
            } else {
                "needs local Go build"
            },
            art.awg_path.display()
        );
        for s in &state.servers {
            if let Some(only) = &opts.server_filter
                && s.id != *only
            {
                continue;
            }
            let is_sub = state.is_subscription_server(&s.id);
            let roles = s.roles_list(is_sub);
            if s.enabled {
                let ports = s.summary_ports(&state.settings, is_sub);
                let sni_note = s
                    .summary_sni(&state.settings)
                    .map(|sni| format!(" sni={sni}"))
                    .unwrap_or_default();
                let traffic_note = if s.effective_config(&state.settings, is_sub).has_traffic {
                    " traffic=on"
                } else {
                    ""
                };
                println!(
                    "  [DEPLOY] {} ({}, {}) roles=[{}] ports=[{}]{}{} ssh={}:{}",
                    s.id,
                    s.label,
                    s.public_ipv4,
                    roles.join(","),
                    ports,
                    sni_note,
                    traffic_note,
                    s.admin_ssh.host,
                    s.admin_ssh.port.get()
                );
            } else {
                println!(
                    "  [RETIRE] {} ({}, {}) enabled=false -> stop VPN/sub units if reachable",
                    s.id, s.label, s.public_ipv4
                );
            }
        }
        match (&state.subscription.cloudflare, opts.skip_dns, sub_in_scope) {
            (Some(_), false, true) => println!(
                "  [DNS] Cloudflare sync {} -> A={}{}",
                state.subscription.domain,
                sub_server.public_ipv4,
                sub_server
                    .public_ipv6
                    .map(|v6| format!(" AAAA={v6}"))
                    .unwrap_or_else(|| " AAAA=<delete if present>".to_owned())
            ),
            (Some(_), false, false) => {
                println!("  [DNS] skipped (--server filter excluded subscription host)")
            }
            (Some(_), true, _) => println!("  [DNS] skipped (--skip-dns)"),
            (None, _, _) => println!("  [DNS] not configured in state (skipped)"),
        }
        return Ok(());
    }

    let artifacts = prepare_artifacts(
        need_xray,
        need_xray_geodata,
        need_country_geoip,
        need_awg,
        &state.settings.artifacts,
    )?;
    let fw_lists = if need_any_vpn {
        resolve_firewall_lists(&state.settings.firewall, &artifacts.geoip_bytes)?
    } else {
        ResolvedFirewallLists::default()
    };

    let in_scope_servers: Vec<&Server> = state
        .servers
        .iter()
        .filter(|s| {
            opts.server_filter
                .as_deref()
                .is_none_or(|only| s.id == only)
        })
        .collect();
    let enabled_servers: Vec<&Server> = in_scope_servers
        .iter()
        .copied()
        .filter(|s| s.enabled)
        .collect();

    let preflights: Vec<RemotePreflight> = std::thread::scope(|scope| {
        let handles: Vec<_> = enabled_servers
            .iter()
            .map(|server| {
                let server = *server;
                let artifacts = &artifacts;
                scope.spawn(move || {
                    let is_sub = state.is_subscription_server(&server.id);
                    let eff = server.effective_config(&state.settings, is_sub);
                    if eff.has_xray || eff.has_amneziawg || !is_sub {
                        check_remote_state(&server.admin_ssh, artifacts)
                    } else {
                        RemotePreflight {
                            need_xray_bin: false,
                            need_geodata: false,
                            need_awg: false,
                            has_managed_sub: false,
                        }
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("preflight worker thread panicked"))
            .collect()
    });

    let mut non_sub_bundles = Vec::new();
    let mut sub_bundles = Vec::new();
    let mut disabled_bundles = Vec::new();
    let mut non_sub_servers_for_deferred_caddy_check = Vec::new();

    for (server, preflight) in enabled_servers.iter().zip(preflights.iter()) {
        let server = *server;
        let is_sub = state.is_subscription_server(&server.id);
        let eff = server.effective_config(&state.settings, is_sub);
        let defer_caddy = eff.should_defer_caddy_retire();
        let bundle = build_server_bundle(
            state,
            server,
            &artifacts,
            &fw_lists,
            BundleOptions {
                defer_caddy_retire: defer_caddy,
                include_xray_bin: eff.has_xray && preflight.need_xray_bin,
                include_geodata: eff.has_xray && need_xray_geodata && preflight.need_geodata,
                include_awg_bin: eff.has_amneziawg && preflight.need_awg,
                allow_takeover: opts.takeover,
            },
        )
        .with_context(|| format!("failed building deploy bundle for {}", server.id))?;
        if !is_sub {
            if defer_caddy && preflight.has_managed_sub {
                non_sub_servers_for_deferred_caddy_check.push(server);
            }
            non_sub_bundles.push((server, bundle));
        } else {
            sub_bundles.push((server, bundle));
        }
    }

    for server in in_scope_servers.iter().copied().filter(|s| !s.enabled) {
        let bundle = build_disabled_server_bundle(state, server)
            .with_context(|| format!("failed building deploy bundle for {}", server.id))?;
        disabled_bundles.push((server, bundle));
    }

    let mut deploy_errors: Vec<String> = Vec::new();
    let mut server_results: Vec<(String, String)> = Vec::new();

    // 1. Converge non-subscription exit nodes before updating DNS or publishing subscriptions.
    for (server_id, res) in deploy_bundles_parallel(&non_sub_bundles) {
        match res {
            Ok(()) => server_results.push((server_id.to_owned(), "OK".to_owned())),
            Err(e) => {
                let msg = format!("{server_id}: {e}");
                server_results.push((server_id.to_owned(), format!("FAILED ({e})")));
                deploy_errors.push(msg);
            }
        }
    }

    // 2. Sync Cloudflare DNS before starting/reloading Caddy on the subscription host
    //    so its initial ACME challenge sees up-to-date records immediately.
    let mut dns_ok = true;
    let dns_summary = if !sub_in_scope {
        "SKIPPED (--server filter excluded subscription host)".to_owned()
    } else if opts.skip_dns {
        "SKIPPED (--skip-dns)".to_owned()
    } else if state.subscription.cloudflare.is_some() {
        match sync_subscription_dns(&state.subscription, sub_server) {
            Ok((s, _changed)) => format!("OK ({s})"),
            Err(e) => {
                dns_ok = false;
                deploy_errors.push(format!("cloudflare DNS: {e}"));
                format!("FAILED ({e})")
            }
        }
    } else {
        "SKIPPED (not configured)".to_owned()
    };

    // 3. Deploy the subscription host now that VPN nodes and DNS are converged.
    for (server_id, res) in deploy_bundles_parallel(&sub_bundles) {
        match res {
            Ok(()) => server_results.push((server_id.to_owned(), "OK".to_owned())),
            Err(e) => {
                let msg = format!("{server_id}: {e}");
                server_results.push((server_id.to_owned(), format!("FAILED ({e})")));
                deploy_errors.push(msg);
            }
        }
    }

    let mut https_ok = true;
    let https_summary = if !sub_in_scope {
        "SKIPPED (--server filter excluded subscription host)".to_owned()
    } else {
        match verify_https_subscriptions(state, Duration::from_secs(90)) {
            Ok(n) => format!("OK ({n} enabled subscription(s) verified)"),
            Err(e) => {
                https_ok = false;
                deploy_errors.push(format!("https verify: {e}"));
                format!("FAILED ({e})")
            }
        }
    };

    if sub_in_scope && dns_ok && https_ok {
        let retire_targets: Vec<&Server> = non_sub_servers_for_deferred_caddy_check
            .into_iter()
            .filter(|server| {
                server_results
                    .iter()
                    .any(|(id, st)| id == &server.id && st == "OK")
            })
            .collect();
        let retire_results: Vec<(&str, Result<()>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = retire_targets
                .iter()
                .map(|server| {
                    let server = *server;
                    scope.spawn(move || {
                        let cmd = remote_retire_caddy_cmd(&server.admin_ssh.user);
                        let res = run_ssh(&server.admin_ssh, &cmd, None).map(|_| ());
                        (server.id.as_str(), res)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("caddy retire worker thread panicked"))
                .collect()
        });
        for (server_id, res) in retire_results {
            if let Err(e) = res {
                deploy_errors.push(format!("retire caddy on {server_id}: {e}"));
            }
        }
    } else if sub_in_scope {
        eprintln!(
            "WARNING: aborting retiring Caddy/disabled-server cleanup because DNS or HTTPS verification failed!"
        );
    }

    if (sub_in_scope && dns_ok && https_ok) || opts.server_filter.is_some() {
        for (server_id, res) in deploy_bundles_parallel(&disabled_bundles) {
            match res {
                Ok(()) => {
                    server_results.push((server_id.to_owned(), "STOPPED (disabled)".to_owned()))
                }
                Err(e) => {
                    eprintln!(
                        "Warning: could not reach disabled server {server_id} over SSH ({e}); skipping remote stop"
                    );
                    server_results
                        .push((server_id.to_owned(), format!("UNREACHABLE/DISABLED ({e})")));
                }
            }
        }
    }

    println!("Deploy summary:");
    for (id, status) in &server_results {
        println!("  server {id}: {status}");
    }
    println!("  DNS:   {dns_summary}");
    println!("  HTTPS: {https_summary}");

    if !deploy_errors.is_empty() {
        bail!("deploy completed with errors: {}", deploy_errors.join("; "));
    }
    Ok(())
}
