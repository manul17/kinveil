pub mod artifacts;
pub mod cloudflare;
pub mod remote;
pub mod ssh;
pub mod verify;

use std::time::Duration;

use anyhow::{Context as _, Result, bail};

use crate::deploy::artifacts::{
    has_prebuilt_awg_source, inspect_artifact_status, prepare_artifacts,
};
use crate::deploy::cloudflare::sync_subscription_dns;
use crate::deploy::remote::{
    build_disabled_server_bundle, build_server_bundle, remote_retire_caddy_cmd,
    remote_stage_and_exec_cmd,
};
use crate::deploy::ssh::run_ssh;
use crate::deploy::verify::verify_https_subscriptions;
use crate::state::{AdminSsh, State};
use crate::validate::validate_for_deploy;

fn check_remote_binaries(admin: &AdminSsh, xray_sha256: &str, awg_sha256: &str) -> (bool, bool) {
    let cmd = "sh -c 'for p in /usr/local/lib/kinveil/xray/xray /usr/local/lib/kinveil/awg/amneziawg-go; do [ -x \"$p\" ] && sha256sum \"$p\" || true; done'";
    let Ok(out) = run_ssh(admin, cmd, None) else {
        return (true, true);
    };
    let mut need_xray = true;
    let mut need_awg = true;
    for line in out.stdout.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(path)) = (parts.next(), parts.next()) else {
            continue;
        };
        if path == "/usr/local/lib/kinveil/xray/xray" && hash.eq_ignore_ascii_case(xray_sha256) {
            need_xray = false;
        } else if path == "/usr/local/lib/kinveil/awg/amneziawg-go"
            && hash.eq_ignore_ascii_case(awg_sha256)
        {
            need_awg = false;
        }
    }
    (need_xray, need_awg)
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
            && s.has_xray(&state.settings)
    });
    let need_awg = state.servers.iter().any(|s| {
        opts.server_filter
            .as_deref()
            .is_none_or(|only| s.id == only)
            && s.enabled
            && s.has_amneziawg(&state.settings)
    });

    if opts.dry_run {
        let art = inspect_artifact_status(&state.settings.artifacts)?;
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
                println!(
                    "  [DEPLOY] {} ({}, {}) roles=[{}] ports=[{}]{} ssh={}:{}",
                    s.id,
                    s.label,
                    s.public_ipv4,
                    roles.join(","),
                    ports,
                    sni_note,
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

    let artifacts = prepare_artifacts(need_xray, need_awg, &state.settings.artifacts)?;

    let mut non_sub_bundles = Vec::new();
    let mut sub_bundles = Vec::new();
    let mut disabled_bundles = Vec::new();
    let mut non_sub_servers_for_deferred_caddy_check = Vec::new();

    for server in &state.servers {
        if let Some(only) = &opts.server_filter
            && server.id != *only
        {
            continue;
        }
        if server.enabled {
            let defer_caddy = !state.is_subscription_server(&server.id);
            let srv_need_xray = server.has_xray(&state.settings);
            let srv_need_awg = server.has_amneziawg(&state.settings);
            let (include_xray, include_awg) = if srv_need_xray || srv_need_awg {
                let (miss_xray, miss_awg) = check_remote_binaries(
                    &server.admin_ssh,
                    &artifacts.xray_sha256,
                    &artifacts.awg_sha256,
                );
                (srv_need_xray && miss_xray, srv_need_awg && miss_awg)
            } else {
                (false, false)
            };
            let bundle = build_server_bundle(
                state,
                server,
                &artifacts,
                defer_caddy,
                include_xray,
                include_awg,
                opts.takeover,
            )
            .with_context(|| format!("failed building deploy bundle for {}", server.id))?;
            if defer_caddy {
                non_sub_servers_for_deferred_caddy_check.push(server);
                non_sub_bundles.push((server, bundle));
            } else {
                sub_bundles.push((server, bundle));
            }
        } else {
            let bundle = build_disabled_server_bundle(state, server)
                .with_context(|| format!("failed building deploy bundle for {}", server.id))?;
            disabled_bundles.push((server, bundle));
        }
    }

    let mut deploy_errors: Vec<String> = Vec::new();
    let mut server_results: Vec<(String, String)> = Vec::new();

    // 1. Converge non-subscription exit nodes before updating DNS or publishing subscriptions.
    for (server, bundle) in &non_sub_bundles {
        let cmd = remote_stage_and_exec_cmd(&server.admin_ssh.user);
        match run_ssh(&server.admin_ssh, &cmd, Some(bundle)) {
            Ok(_) => server_results.push((server.id.clone(), "OK".to_owned())),
            Err(e) => {
                let msg = format!("{}: {e}", server.id);
                server_results.push((server.id.clone(), format!("FAILED ({e})")));
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
    for (server, bundle) in &sub_bundles {
        let cmd = remote_stage_and_exec_cmd(&server.admin_ssh.user);
        match run_ssh(&server.admin_ssh, &cmd, Some(bundle)) {
            Ok(_) => server_results.push((server.id.clone(), "OK".to_owned())),
            Err(e) => {
                let msg = format!("{}: {e}", server.id);
                server_results.push((server.id.clone(), format!("FAILED ({e})")));
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
        for server in non_sub_servers_for_deferred_caddy_check {
            if server_results
                .iter()
                .any(|(id, st)| *id == server.id && st == "OK")
            {
                let cmd = remote_retire_caddy_cmd(&server.admin_ssh.user);
                if let Err(e) = run_ssh(&server.admin_ssh, &cmd, None) {
                    deploy_errors.push(format!("retire caddy on {}: {e}", server.id));
                }
            }
        }
    } else if sub_in_scope {
        eprintln!(
            "WARNING: aborting retiring Caddy/disabled-server cleanup because DNS or HTTPS verification failed!"
        );
    }

    if (sub_in_scope && dns_ok && https_ok) || opts.server_filter.is_some() {
        for (server, bundle) in &disabled_bundles {
            let cmd = remote_stage_and_exec_cmd(&server.admin_ssh.user);
            match run_ssh(&server.admin_ssh, &cmd, Some(bundle)) {
                Ok(_) => server_results.push((server.id.clone(), "STOPPED (disabled)".to_owned())),
                Err(e) => {
                    eprintln!(
                        "Warning: could not reach disabled server {} over SSH ({e}); skipping remote stop",
                        server.id
                    );
                    server_results.push((server.id.clone(), format!("UNREACHABLE/DISABLED ({e})")));
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
