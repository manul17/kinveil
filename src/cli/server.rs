//! Server inventory, SSH host-key resolution, role/protocol, and rotation handlers.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use ssh_key::{HashAlg, PublicKey};
use time::format_description::well_known::Rfc3339;

use super::args::{ServerCommand, ServerUpdateArgs};
use super::secrets::{SecretReader, confirm_destructive, prompt_yes_no};
use super::{
    MutationMessage, dedup_strings, load_locked_state, mutate_state_and_report,
    parse_non_zero_port, parse_opt_non_zero_port, parse_optional_note, print_servers_section,
};
use crate::crypto::{
    generate_awg_obfuscation, generate_hysteria_self_signed_cert, generate_salamander_password,
    generate_x25519_awg_keypair, generate_x25519_reality_keypair, generate_xhttp_path,
    parse_hysteria_cert_info, random_hex,
};
use crate::deploy::remote::remote_wipe_cmd;
use crate::deploy::ssh::{lookup_known_hosts_key, run_ssh};
use crate::state::{
    AdminSsh, Server, ServerRole, ServerSshForwarding, ServerVpn, VpnProtocol, now_utc_seconds,
};
use crate::store::commit_state_mutation;
use crate::validate::{
    validate_hostname, validate_server_id, validate_ssh_host, validate_ssh_identity_file,
    validate_ssh_user, validate_target_host_port,
};

fn dedup_nonempty<T: Copy + PartialEq>(items: Vec<T>, label: &str) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    if out.is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(out)
}

fn apply_vpn_protocols(vpn: &mut ServerVpn, protocols: &[VpnProtocol]) {
    vpn.protocols = Some(protocols.iter().copied().collect());
}

fn normalize_sni(raw: String) -> Result<String> {
    let clean = raw.trim().to_ascii_lowercase();
    validate_hostname(&clean, "--vless-sni")?;
    Ok(clean)
}

fn normalize_target(raw: String) -> Result<String> {
    let clean = raw.trim().to_ascii_lowercase();
    validate_target_host_port(&clean, "--vless-target")?;
    Ok(clean)
}

fn normalize_xhttp_host(raw: String) -> Result<String> {
    let clean = raw.trim().to_ascii_lowercase();
    validate_hostname(&clean, "--vless-xhttp-host")?;
    Ok(clean)
}

fn parse_optional_ssh_key(raw: Option<String>, field: &str) -> Result<Option<String>> {
    match raw {
        Some(path) => {
            let trimmed = path.trim();
            validate_ssh_identity_file(trimmed, field)?;
            Ok(Some(trimmed.to_owned()))
        }
        None => Ok(None),
    }
}

fn slugify_server_id(label: &str) -> Result<String> {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
        if out.len() == 64 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        bail!("cannot derive valid server id from label '{label}'; pass --id explicitly");
    }
    validate_server_id(&out)?;
    Ok(out)
}

fn keyscan_and_confirm(host: &str, port: u16) -> Result<String> {
    let port_str = port.to_string();
    let out = Command::new("ssh-keyscan")
        .args([
            "-t",
            "ed25519,ecdsa,rsa",
            "-p",
            &port_str,
            "-T",
            "5",
            "--",
            host,
        ])
        .output()
        .context("failed to run ssh-keyscan")?;
    if !out.status.success() {
        bail!(
            "ssh-keyscan failed for {host}:{port}: {}; pass --ssh-host-key explicitly",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut ed25519_key: Option<(String, PublicKey)> = None;
    let mut fallback_key: Option<(String, PublicKey)> = None;
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _host_field = parts.next();
        let Some(ktype) = parts.next() else {
            continue;
        };
        let Some(kb64) = parts.next() else {
            continue;
        };
        let candidate = format!("{ktype} {kb64}");
        if let Ok(parsed) = PublicKey::from_openssh(&candidate) {
            if ktype == "ssh-ed25519" {
                ed25519_key = Some((candidate, parsed));
                break;
            } else if fallback_key.is_none() {
                fallback_key = Some((candidate, parsed));
            }
        }
    }
    let Some((key_str, parsed)) = ed25519_key.or(fallback_key) else {
        bail!(
            "ssh-keyscan returned no valid OpenSSH host key for {host}:{port}; pass --ssh-host-key explicitly"
        );
    };
    let fp = parsed.fingerprint(HashAlg::Sha256);
    eprintln!("Scanned SSH host key for {host}:{port}:");
    eprintln!("  Type:        {}", parsed.algorithm());
    eprintln!("  Fingerprint: {fp}");
    eprintln!("  Verify on the VPS with: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub");
    if !prompt_yes_no("Trust and pin this SSH host key?")? {
        bail!("SSH host key confirmation declined (or non-interactive TTY; pass --ssh-host-key)");
    }
    Ok(key_str)
}

fn resolve_server_host_key(explicit: Option<String>, host: &str, port: u16) -> Result<String> {
    if let Some(raw) = explicit {
        let trimmed = raw.trim();
        PublicKey::from_openssh(trimmed)
            .map_err(|_| anyhow!("invalid --ssh-host-key OpenSSH public key"))?;
        return Ok(trimmed.to_owned());
    }
    if let Some(home) = std::env::var_os("HOME") {
        let kh_path = PathBuf::from(home).join(".ssh").join("known_hosts");
        if let Some(found) = lookup_known_hosts_key(&kh_path, host, port)? {
            let fp = PublicKey::from_openssh(&found)
                .map(|pk| pk.fingerprint(HashAlg::Sha256).to_string())
                .unwrap_or_else(|_| "<unknown>".to_owned());
            eprintln!("Using pinned host key from {} ({fp})", kh_path.display());
            return Ok(found);
        }
    }
    keyscan_and_confirm(host, port)
}

fn format_ssh_fingerprint(openssh_pub: &str) -> String {
    match PublicKey::from_openssh(openssh_pub.trim()) {
        Ok(pk) => format!("{} {}", pk.algorithm(), pk.fingerprint(HashAlg::Sha256)),
        Err(_) => "<invalid>".to_owned(),
    }
}

fn print_server_details(state: &crate::state::State, srv: &Server) -> Result<()> {
    let is_sub = state.is_subscription_server(&srv.id);
    let eff = srv.effective_config(&state.settings, is_sub);
    let created = srv
        .created_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| srv.created_at.to_string());
    let roles = srv.roles_list(is_sub);

    println!("Server: {} ({})", srv.id, srv.label);
    println!(
        "  Status:      {}",
        if srv.enabled { "enabled" } else { "disabled" }
    );
    println!("  Created at:  {created}");
    if let Some(ref note) = srv.note {
        println!("  Note:        {note}");
    }
    println!("  Public IPv4: {}", srv.public_ipv4);
    println!(
        "  Public IPv6: {}",
        srv.public_ipv6
            .map_or_else(|| "-".to_owned(), |v6| v6.to_string())
    );
    println!("  Roles:       [{}]", roles.join(","));
    let key_suffix = srv
        .admin_ssh
        .identity_file
        .as_deref()
        .map(|k| format!(" key={k}"))
        .unwrap_or_default();
    println!(
        "  Admin SSH:   {}@{}:{}{key_suffix}",
        srv.admin_ssh.user, srv.admin_ssh.host, srv.admin_ssh.port
    );
    println!(
        "  SSH host fp: {}",
        format_ssh_fingerprint(&srv.admin_ssh.host_public_key)
    );

    if let Some(vpn) = &srv.vpn {
        println!(
            "  VPN role:    {}",
            if vpn.enabled { "enabled" } else { "disabled" }
        );
        let active_protos: Vec<&str> = [
            eff.has_vless_stream.then_some("vless-stream"),
            eff.has_vless_packet.then_some("vless-packet"),
            eff.has_hysteria2.then_some("hysteria2"),
            eff.has_amneziawg.then_some("amneziawg"),
            eff.has_ssh_forwarding.then_some("ssh-forwarding"),
        ]
        .into_iter()
        .flatten()
        .collect();
        println!(
            "  Protocols:   [{}] ({})",
            active_protos.join(","),
            eff.protocols_source.as_str()
        );

        let port_src = |ovr: Option<std::num::NonZeroU16>| -> &'static str {
            if ovr.is_some() { "server" } else { "config" }
        };
        println!(
            "  Ports:       vless={}/tcp ({}), hysteria2={}/udp ({}), amneziawg={}/udp ({}), ssh-forwarding={}/tcp ({})",
            eff.vless_port,
            port_src(vpn.vless.port),
            eff.hysteria2_port,
            port_src(vpn.hysteria2.port),
            eff.amneziawg_port,
            port_src(vpn.amneziawg.port),
            eff.ssh_forwarding_port,
            port_src(vpn.ssh_forwarding.port),
        );

        let sni_disp = eff.vless_sni.as_ref().map_or_else(
            || "(unset)".to_owned(),
            |(v, s)| format!("{v} ({})", s.as_str()),
        );
        let target_disp = eff.vless_target.as_ref().map_or_else(
            || "(unset)".to_owned(),
            |(v, s)| format!("{v} ({})", s.as_str()),
        );
        let host_disp = eff.vless_xhttp_host.as_ref().map_or_else(
            || "(none)".to_owned(),
            |(v, s)| format!("{v} ({})", s.as_str()),
        );
        let path_disp = eff.vless_xhttp_path.as_ref().map_or_else(
            || vpn.vless.xhttp_path.clone(),
            |(v, s)| format!("{v} ({})", s.as_str()),
        );
        println!(
            "  VLESS:       {} (sni={sni_disp}, target={target_disp}, xhttp_host={host_disp}, path={path_disp}, short_id={}, pbk={})",
            if eff.has_vless { "active" } else { "inactive" },
            vpn.vless.short_id,
            vpn.vless.public_key()?
        );

        let cert = parse_hysteria_cert_info(&vpn.hysteria2.cert_pem)?;
        println!(
            "  Hysteria2:   {} (cert_sha256={}, spki_sha256={}, valid={}..{})",
            if eff.has_hysteria2 {
                "active"
            } else {
                "inactive"
            },
            cert.pins.cert_sha256_hex,
            cert.pins.spki_sha256_b64,
            cert.not_before.date(),
            cert.not_after.date()
        );

        let obf = eff
            .awg_obfuscation
            .as_ref()
            .unwrap_or(&vpn.amneziawg.obfuscation);
        let awg_cidr = state.settings.awg_server_interface_cidr()?;
        let extra_i: String = [
            ("i2", &obf.i2),
            ("i3", &obf.i3),
            ("i4", &obf.i4),
            ("i5", &obf.i5),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.as_ref().map(|s| format!(" {k}={s:?}")))
        .collect();
        println!(
            "  AmneziaWG:   {} (cidr={awg_cidr}, pbk={}, jc={}, jmin={}, jmax={}, s1..s4={},{},{},{}, i1={:?}{extra_i})",
            if eff.has_amneziawg {
                "active"
            } else {
                "inactive"
            },
            vpn.amneziawg.public_key()?,
            obf.jc,
            obf.jmin,
            obf.jmax,
            obf.s1,
            obf.s2,
            obf.s3,
            obf.s4,
            obf.i1,
        );

        let ssh_host_pub = vpn.ssh_forwarding.host_public_key()?;
        println!(
            "  SSH fwd:     {} ({})",
            if eff.has_ssh_forwarding {
                "active"
            } else {
                "inactive"
            },
            format_ssh_fingerprint(&ssh_host_pub)
        );
        if eff.has_traffic {
            println!(
                "  Traffic:     enabled (retention={}d)",
                state.settings.traffic.retention_days,
            );
        } else {
            println!("  Traffic:     disabled");
        }
    }
    Ok(())
}

pub(super) fn cmd_server(
    state_path: &Path,
    action: ServerCommand,
    secrets: &mut SecretReader,
) -> Result<()> {
    match action {
        ServerCommand::List => {
            let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
            println!("Servers ({}):", state.servers.len());
            print_servers_section(&state, "  ");
        }
        ServerCommand::Show { id } => {
            let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
            let srv = state.server(&id)?;
            print_server_details(&state, srv)?;
        }
        ServerCommand::Add(boxed_args) => {
            let args = *boxed_args;
            let (server_id, id_derived) = match args.id {
                Some(id) => {
                    validate_server_id(&id)?;
                    (id, false)
                }
                None => (slugify_server_id(&args.label)?, true),
            };
            let ip: Ipv4Addr = args
                .ipv4
                .parse()
                .map_err(|_| anyhow!("invalid IPv4 address '{}'", args.ipv4))?;
            let ipv6: Option<Ipv6Addr> = args
                .ipv6
                .as_deref()
                .map(|v6| {
                    v6.parse::<Ipv6Addr>()
                        .map_err(|_| anyhow!("invalid IPv6 address '{v6}'"))
                })
                .transpose()?;
            let roles = dedup_nonempty(args.roles, "server roles")?;
            let wants_vpn = roles.contains(&ServerRole::Vpn);
            let vless_port = parse_opt_non_zero_port(args.vless_port, "--vless-port")?;
            let hysteria2_port = parse_opt_non_zero_port(args.hysteria2_port, "--hysteria2-port")?;
            let amneziawg_port = parse_opt_non_zero_port(args.amneziawg_port, "--amneziawg-port")?;
            let ssh_forwarding_port =
                parse_opt_non_zero_port(args.ssh_forwarding_port, "--ssh-forwarding-port")?;
            if !wants_vpn
                && (args.vless_sni.is_some()
                    || args.vless_target.is_some()
                    || args.vless_xhttp_host.is_some()
                    || !args.protocols.is_empty()
                    || vless_port.is_some()
                    || hysteria2_port.is_some()
                    || amneziawg_port.is_some()
                    || ssh_forwarding_port.is_some()
                    || args.traffic)
            {
                bail!(
                    "--vless-sni, --vless-target, --vless-xhttp-host, --protocols, --*-port, and --traffic require the 'vpn' role"
                );
            }
            let sni = args.vless_sni.map(normalize_sni).transpose()?;
            let target = args.vless_target.map(normalize_target).transpose()?;
            let xhttp_host = args
                .vless_xhttp_host
                .map(normalize_xhttp_host)
                .transpose()?;
            let protocols = if args.protocols.is_empty() {
                None
            } else {
                Some(dedup_nonempty(args.protocols, "--protocols")?)
            };
            let ssh_port = parse_non_zero_port(args.ssh_port, "--ssh-port")?;
            let ssh_host = args.ssh_host.unwrap_or_else(|| ip.to_string());
            validate_ssh_host(&ssh_host, "--ssh-host")?;
            validate_ssh_user(&args.ssh_user, "--ssh-user")?;
            let ssh_key = parse_optional_ssh_key(args.ssh_key, "--ssh-key")?;
            let note = parse_optional_note(args.note, "--note")?;

            let (_lock, pass, mut state) = load_locked_state(state_path, secrets)?;
            if state.servers.iter().any(|s| s.id == server_id) {
                if id_derived {
                    bail!(
                        "server id '{server_id}' (derived from --label '{}') already exists; pass --id explicitly",
                        args.label
                    );
                }
                bail!("server id '{server_id}' already exists");
            }
            if roles.contains(&ServerRole::Subscription)
                && let Some(existing) = &state.subscription.server_id
            {
                bail!(
                    "subscription role is already assigned to server '{existing}'; move it with `kinveil server update`"
                );
            }
            if wants_vpn {
                let vless_wanted = protocols
                    .as_ref()
                    .map_or(state.settings.vless.enabled, |p| {
                        p.contains(&VpnProtocol::Vless)
                    });
                let vless_active =
                    vless_wanted && (state.settings.vless.stream || state.settings.vless.packet);
                if vless_active && sni.is_none() && state.settings.vless.sni.is_none() {
                    bail!(
                        "--vless-sni <camouflage-domain> is required when VLESS is enabled on a server (or set [vless].sni in `kinveil config`, or exclude `vless` via `--protocols`)"
                    );
                }
            }

            let host_public_key =
                resolve_server_host_key(args.ssh_host_key, &ssh_host, ssh_port.get())?;

            let vpn = if wants_vpn {
                let mut generated = ServerVpn::generate(&server_id, ip, sni, target, xhttp_host)?;
                generated.traffic = args.traffic;
                generated.vless.port = vless_port;
                generated.hysteria2.port = hysteria2_port;
                generated.amneziawg.port = amneziawg_port;
                generated.ssh_forwarding.port = ssh_forwarding_port;
                if let Some(ref protos) = protocols {
                    apply_vpn_protocols(&mut generated, protos);
                }
                Some(generated)
            } else {
                None
            };

            let auto_assigned_sub =
                state.servers.is_empty() && state.subscription.server_id.is_none();
            if roles.contains(&ServerRole::Subscription) || auto_assigned_sub {
                state.subscription.server_id = Some(server_id.clone());
            }
            let old_revision = state.revision;
            state.servers.push(Server {
                id: server_id.clone(),
                label: args.label,
                enabled: !args.disabled,
                created_at: now_utc_seconds(),
                note,
                public_ipv4: ip,
                public_ipv6: ipv6,
                admin_ssh: AdminSsh {
                    host: ssh_host,
                    port: ssh_port,
                    user: args.ssh_user,
                    identity_file: ssh_key,
                    host_public_key,
                },
                vpn,
            });
            let new_rev = commit_state_mutation(state_path, &mut state, &pass, old_revision)?;
            if auto_assigned_sub && !roles.contains(&ServerRole::Subscription) {
                println!(
                    "Added server '{server_id}' (revision={new_rev}, auto-assigned subscription role)."
                );
            } else {
                println!("Added server '{server_id}' (revision={new_rev}).");
            }
        }
        ServerCommand::Update(boxed_args) => {
            let args: ServerUpdateArgs = *boxed_args;
            if args.rename.is_none()
                && args.roles.is_none()
                && args.protocols.is_none()
                && !args.clear_protocols
                && args.vless_sni.is_none()
                && !args.clear_vless_sni
                && args.vless_target.is_none()
                && !args.clear_vless_target
                && args.vless_xhttp_host.is_none()
                && !args.clear_vless_xhttp_host
                && args.vless_port.is_none()
                && !args.clear_vless_port
                && args.hysteria2_port.is_none()
                && !args.clear_hysteria2_port
                && args.amneziawg_port.is_none()
                && !args.clear_amneziawg_port
                && args.ssh_forwarding_port.is_none()
                && !args.clear_ssh_forwarding_port
                && !args.clear_ports
                && args.label.is_none()
                && args.ipv4.is_none()
                && args.ipv6.is_none()
                && !args.clear_ipv6
                && args.note.is_none()
                && !args.clear_note
                && args.ssh_host.is_none()
                && args.ssh_port.is_none()
                && args.ssh_user.is_none()
                && args.ssh_key.is_none()
                && !args.clear_ssh_key
                && args.ssh_host_key.is_none()
                && !args.traffic
                && !args.no_traffic
            {
                bail!(
                    "specify at least one update flag (--rename, --roles, --protocols/--clear-protocols, --vless-sni/--clear-vless-sni, --vless-target/--clear-vless-target, --vless-xhttp-host/--clear-vless-xhttp-host, --*-port/--clear-*-port, --clear-ports, --traffic/--no-traffic, --label, --ipv4, --ipv6/--clear-ipv6, --note/--clear-note, or --ssh-*)"
                );
            }

            let rename_id = args
                .rename
                .map(|raw| {
                    validate_server_id(&raw)?;
                    Ok::<_, anyhow::Error>(raw)
                })
                .transpose()?;
            let parsed_roles = args
                .roles
                .map(|r| dedup_nonempty(r, "--roles"))
                .transpose()?;
            let parsed_protocols = args
                .protocols
                .map(|p| dedup_nonempty(p, "--protocols"))
                .transpose()?;
            let mut clean_sni = args.vless_sni.map(normalize_sni).transpose()?;
            let mut clean_target = args.vless_target.map(normalize_target).transpose()?;
            let mut clean_xhttp_host = args
                .vless_xhttp_host
                .map(normalize_xhttp_host)
                .transpose()?;
            let vless_port = parse_opt_non_zero_port(args.vless_port, "--vless-port")?;
            let hysteria2_port = parse_opt_non_zero_port(args.hysteria2_port, "--hysteria2-port")?;
            let amneziawg_port = parse_opt_non_zero_port(args.amneziawg_port, "--amneziawg-port")?;
            let ssh_forwarding_port =
                parse_opt_non_zero_port(args.ssh_forwarding_port, "--ssh-forwarding-port")?;
            let traffic_edit = if args.traffic {
                Some(true)
            } else if args.no_traffic {
                Some(false)
            } else {
                None
            };

            let ipv4: Option<Ipv4Addr> = args
                .ipv4
                .as_deref()
                .map(|v4| {
                    v4.parse::<Ipv4Addr>()
                        .map_err(|_| anyhow!("invalid IPv4 address '{v4}'"))
                })
                .transpose()?;
            let ipv6: Option<Ipv6Addr> = args
                .ipv6
                .as_deref()
                .map(|v6| {
                    v6.parse::<Ipv6Addr>()
                        .map_err(|_| anyhow!("invalid IPv6 address '{v6}'"))
                })
                .transpose()?;
            let clean_note = parse_optional_note(args.note, "--note")?;
            let clean_ssh_key = parse_optional_ssh_key(args.ssh_key, "--ssh-key")?;
            let ssh_port = parse_opt_non_zero_port(args.ssh_port, "--ssh-port")?;
            if let Some(ref host) = args.ssh_host {
                validate_ssh_host(host, "--ssh-host")?;
            }
            if let Some(ref user) = args.ssh_user {
                validate_ssh_user(user, "--ssh-user")?;
            }

            let (_lock, pass, mut state) = load_locked_state(state_path, secrets)?;
            if let Some(ref new_id) = rename_id
                && new_id != &args.id
                && state.servers.iter().any(|s| s.id == *new_id)
            {
                bail!("server id '{new_id}' already exists");
            }
            let (
                target_ssh_host,
                target_ssh_port,
                host_or_port_changed,
                existing_host_key,
                ipv4_changed,
            ) = {
                let srv = state.server(&args.id)?;
                let ipv4_changed = ipv4.is_some_and(|ip| ip != srv.public_ipv4);
                let target_ssh_host = if let Some(ref explicit_host) = args.ssh_host {
                    explicit_host.clone()
                } else if let Some(new_ip4) = ipv4
                    && srv.admin_ssh.host == srv.public_ipv4.to_string()
                {
                    new_ip4.to_string()
                } else {
                    srv.admin_ssh.host.clone()
                };
                let target_ssh_port = ssh_port.unwrap_or(srv.admin_ssh.port);
                let host_or_port_changed =
                    target_ssh_host != srv.admin_ssh.host || target_ssh_port != srv.admin_ssh.port;
                (
                    target_ssh_host,
                    target_ssh_port,
                    host_or_port_changed,
                    srv.admin_ssh.host_public_key.clone(),
                    ipv4_changed,
                )
            };
            let new_host_key = if args.ssh_host_key.is_some() || host_or_port_changed {
                resolve_server_host_key(args.ssh_host_key, &target_ssh_host, target_ssh_port.get())?
            } else {
                existing_host_key
            };

            let old_revision = state.revision;
            let default_cfg_vless_sni = state.settings.vless.sni.clone();
            let cfg_vless_enabled = state.settings.vless.enabled;
            let cfg_vless_modes = state.settings.vless.stream || state.settings.vless.packet;
            let was_sub = state.is_subscription_server(&args.id);
            let final_id = rename_id.clone().unwrap_or_else(|| args.id.clone());
            {
                let sub_wanted = parsed_roles
                    .as_ref()
                    .map(|r| r.contains(&ServerRole::Subscription));

                let srv = state.server_mut(&args.id)?;
                if rename_id.is_some() {
                    srv.id = final_id.clone();
                }
                if let Some(label) = args.label {
                    srv.label = label;
                }
                if let Some(new_ip4) = ipv4 {
                    srv.public_ipv4 = new_ip4;
                    if ipv4_changed && let Some(ref mut vpn) = srv.vpn {
                        let (cert_pem, key_pem) = generate_hysteria_self_signed_cert(new_ip4)?;
                        vpn.hysteria2.cert_pem = cert_pem;
                        vpn.hysteria2.key_pem = key_pem;
                    }
                }
                if args.clear_ipv6 {
                    srv.public_ipv6 = None;
                } else if let Some(ip6) = ipv6 {
                    srv.public_ipv6 = Some(ip6);
                }
                if args.clear_note {
                    srv.note = None;
                } else if let Some(new_note) = clean_note {
                    srv.note = Some(new_note);
                }
                srv.admin_ssh.host = target_ssh_host;
                srv.admin_ssh.port = target_ssh_port;
                if let Some(user) = args.ssh_user {
                    srv.admin_ssh.user = user;
                }
                if args.clear_ssh_key {
                    srv.admin_ssh.identity_file = None;
                } else if let Some(key_path) = clean_ssh_key {
                    srv.admin_ssh.identity_file = Some(key_path);
                }
                srv.admin_ssh.host_public_key = new_host_key;

                let has_vpn_edits = clean_sni.is_some()
                    || args.clear_vless_sni
                    || clean_target.is_some()
                    || args.clear_vless_target
                    || clean_xhttp_host.is_some()
                    || args.clear_vless_xhttp_host
                    || parsed_protocols.is_some()
                    || args.clear_protocols
                    || traffic_edit.is_some();
                let has_port_edits = args.clear_ports
                    || args.clear_vless_port
                    || vless_port.is_some()
                    || args.clear_hysteria2_port
                    || hysteria2_port.is_some()
                    || args.clear_amneziawg_port
                    || amneziawg_port.is_some()
                    || args.clear_ssh_forwarding_port
                    || ssh_forwarding_port.is_some();

                let mut vpn_just_generated = false;
                if let Some(ref new_roles) = parsed_roles {
                    let wants_vpn = new_roles.contains(&ServerRole::Vpn);
                    if wants_vpn {
                        match &mut srv.vpn {
                            Some(v) => v.enabled = true,
                            None => {
                                let vless_wanted = parsed_protocols
                                    .as_ref()
                                    .map_or(cfg_vless_enabled, |p| p.contains(&VpnProtocol::Vless));
                                let vless_active = vless_wanted && cfg_vless_modes;
                                if vless_active
                                    && clean_sni.is_none()
                                    && default_cfg_vless_sni.is_none()
                                {
                                    bail!(
                                        "--vless-sni <camouflage-domain> is required when adding VLESS to '{final_id}' (or set [vless].sni in `kinveil config`, or exclude `vless` via `--protocols`)"
                                    );
                                }
                                let mut generated = ServerVpn::generate(
                                    &final_id,
                                    srv.public_ipv4,
                                    clean_sni.take(),
                                    clean_target.take(),
                                    clean_xhttp_host.take(),
                                )?;
                                if let Some(ref protos) = parsed_protocols {
                                    apply_vpn_protocols(&mut generated, protos);
                                }
                                if let Some(tr) = traffic_edit {
                                    generated.traffic = tr;
                                }
                                srv.vpn = Some(generated);
                                vpn_just_generated = true;
                            }
                        }
                    } else {
                        if has_vpn_edits || has_port_edits {
                            bail!(
                                "--vless-sni, --clear-vless-sni, --vless-target, --clear-vless-target, --vless-xhttp-host, --clear-vless-xhttp-host, --*-port, --clear-*-port, --clear-ports, --traffic/--no-traffic, and --protocols/--clear-protocols require the 'vpn' role"
                            );
                        }
                        if let Some(v) = &mut srv.vpn {
                            v.enabled = false;
                        }
                    }
                }

                if !vpn_just_generated && has_vpn_edits {
                    let vpn = srv.vpn.as_mut().filter(|v| v.enabled).ok_or_else(|| {
                        anyhow!(
                            "server '{final_id}' does not have the 'vpn' role; enable it with `kinveil server update {final_id} --roles vpn,...`"
                        )
                    })?;
                    if args.clear_vless_sni {
                        let sni_changed = vpn.vless.sni.is_some();
                        vpn.vless.sni = None;
                        if let Some(explicit_target) = clean_target.take() {
                            vpn.vless.target = Some(explicit_target);
                        } else if sni_changed || args.clear_vless_target {
                            vpn.vless.target = None;
                        }
                        if let Some(explicit_host) = clean_xhttp_host.take() {
                            vpn.vless.xhttp_host = Some(explicit_host);
                        } else if sni_changed || args.clear_vless_xhttp_host {
                            vpn.vless.xhttp_host = None;
                        }
                    } else if let Some(new_sni) = clean_sni {
                        let sni_changed = vpn.vless.sni.as_deref() != Some(new_sni.as_str());
                        vpn.vless.sni = Some(new_sni);
                        if let Some(explicit_target) = clean_target.take() {
                            vpn.vless.target = Some(explicit_target);
                        } else if sni_changed || args.clear_vless_target {
                            vpn.vless.target = None;
                        }
                        if let Some(explicit_host) = clean_xhttp_host.take() {
                            vpn.vless.xhttp_host = Some(explicit_host);
                        } else if sni_changed || args.clear_vless_xhttp_host {
                            vpn.vless.xhttp_host = None;
                        }
                    }
                    if args.clear_vless_target {
                        vpn.vless.target = None;
                    } else if let Some(explicit_target) = clean_target {
                        vpn.vless.target = Some(explicit_target);
                    }
                    if args.clear_vless_xhttp_host {
                        vpn.vless.xhttp_host = None;
                    } else if let Some(explicit_host) = clean_xhttp_host {
                        vpn.vless.xhttp_host = Some(explicit_host);
                    }
                    if args.clear_protocols {
                        vpn.protocols = None;
                    } else if let Some(ref protos) = parsed_protocols {
                        apply_vpn_protocols(vpn, protos);
                    }
                    if let Some(tr) = traffic_edit {
                        vpn.traffic = tr;
                    }
                }

                if has_port_edits {
                    let vpn = srv.vpn.as_mut().filter(|v| v.enabled).ok_or_else(|| {
                        anyhow!(
                            "server '{final_id}' does not have the 'vpn' role; enable it with `kinveil server update {final_id} --roles vpn,...`"
                        )
                    })?;
                    if args.clear_ports {
                        vpn.vless.port = None;
                        vpn.hysteria2.port = None;
                        vpn.amneziawg.port = None;
                        vpn.ssh_forwarding.port = None;
                    }
                    if args.clear_vless_port {
                        vpn.vless.port = None;
                    } else if let Some(p) = vless_port {
                        vpn.vless.port = Some(p);
                    }
                    if args.clear_hysteria2_port {
                        vpn.hysteria2.port = None;
                    } else if let Some(p) = hysteria2_port {
                        vpn.hysteria2.port = Some(p);
                    }
                    if args.clear_amneziawg_port {
                        vpn.amneziawg.port = None;
                    } else if let Some(p) = amneziawg_port {
                        vpn.amneziawg.port = Some(p);
                    }
                    if args.clear_ssh_forwarding_port {
                        vpn.ssh_forwarding.port = None;
                    } else if let Some(p) = ssh_forwarding_port {
                        vpn.ssh_forwarding.port = Some(p);
                    }
                }

                if let Some(wants_sub) = sub_wanted {
                    if wants_sub {
                        state.subscription.server_id = Some(final_id.clone());
                    } else if was_sub {
                        state.subscription.server_id = None;
                    }
                } else if was_sub {
                    state.subscription.server_id = Some(final_id.clone());
                }
            }
            let new_rev = commit_state_mutation(state_path, &mut state, &pass, old_revision)?;
            if final_id != args.id {
                println!(
                    "Updated server '{}' -> '{}' (revision={new_rev}). Run `kinveil deploy` to apply changes.",
                    args.id, final_id
                );
            } else {
                println!(
                    "Updated server '{}' (revision={new_rev}). Run `kinveil deploy` to apply changes.",
                    args.id
                );
            }
        }
        ServerCommand::Rotate {
            id,
            all,
            vless,
            hysteria2,
            amneziawg,
            ssh_forwarding,
        } => {
            if !all && !vless && !hysteria2 && !amneziawg && !ssh_forwarding {
                bail!(
                    "specify at least one rotation scope (--all, --vless, --hysteria2, --amneziawg, or --ssh-forwarding)"
                );
            }
            mutate_state_and_report(state_path, secrets, move |state| {
                let path_overridden = state.settings.vless.xhttp.path.is_some();
                let obf_overridden = state.settings.amneziawg.obfuscation.has_overrides();
                let srv = state.server_mut(&id)?;
                let ipv4 = srv.public_ipv4;
                let vpn = srv.vpn.as_mut().filter(|v| v.enabled).ok_or_else(|| {
                    anyhow!(
                        "server '{id}' does not have the 'vpn' role; enable it with `kinveil server update {id} --roles vpn,...`"
                    )
                })?;

                let mut rotated = Vec::new();
                if vless || all {
                    let (priv_key, _) = generate_x25519_reality_keypair();
                    vpn.vless.private_key = priv_key;
                    vpn.vless.short_id = random_hex(4);
                    vpn.vless.xhttp_path = generate_xhttp_path();
                    rotated.push("vless");
                }
                if hysteria2 || all {
                    let (cert_pem, key_pem) = generate_hysteria_self_signed_cert(ipv4)?;
                    vpn.hysteria2.salamander_password = generate_salamander_password(24);
                    vpn.hysteria2.cert_pem = cert_pem;
                    vpn.hysteria2.key_pem = key_pem;
                    rotated.push("hysteria2");
                }
                if amneziawg || all {
                    let (priv_key, _) = generate_x25519_awg_keypair();
                    vpn.amneziawg.private_key = priv_key;
                    vpn.amneziawg.obfuscation = generate_awg_obfuscation();
                    rotated.push("amneziawg");
                }
                if ssh_forwarding || all {
                    vpn.ssh_forwarding.host_private_key =
                        ServerSshForwarding::generate(&id)?.host_private_key;
                    rotated.push("ssh-forwarding");
                }
                let mut note = String::from(
                    " Run `kinveil deploy` so servers and subscriptions reflect the rotated keys.",
                );
                if (vless || all) && path_overridden {
                    note.push_str(" Note: [vless.xhttp].path in config.toml currently overrides per-server XHTTP path.");
                }
                if (amneziawg || all) && obf_overridden {
                    note.push_str(" Note: [amneziawg.obfuscation] overrides in config.toml currently mask rotated fields.");
                }
                Ok(MutationMessage::with_note(
                    format!("Rotated [{}] on server '{id}'", rotated.join(",")),
                    note,
                ))
            })?;
        }
        ServerCommand::Enable { ids } => {
            let ids = dedup_strings(ids);
            mutate_state_and_report(state_path, secrets, move |state| {
                for id in &ids {
                    let _ = state.server(id)?;
                }
                for id in &ids {
                    state.server_mut(id)?.enabled = true;
                }
                let action = if ids.len() == 1 {
                    format!("Enabled server '{}'", ids[0])
                } else {
                    format!("Enabled {} servers ({})", ids.len(), ids.join(", "))
                };
                Ok(MutationMessage::with_note(
                    action,
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        ServerCommand::Disable { ids } => {
            let ids = dedup_strings(ids);
            mutate_state_and_report(state_path, secrets, move |state| {
                for id in &ids {
                    let _ = state.server(id)?;
                }
                for id in &ids {
                    state.server_mut(id)?.enabled = false;
                }
                let action = if ids.len() == 1 {
                    format!("Disabled server '{}'", ids[0])
                } else {
                    format!("Disabled {} servers ({})", ids.len(), ids.join(", "))
                };
                Ok(MutationMessage::with_note(
                    action,
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        ServerCommand::Remove { ids, wipe, yes } => {
            let ids = dedup_strings(ids);
            let prompt = if ids.len() == 1 {
                let id = &ids[0];
                if wipe {
                    format!(
                        "SSH into server '{id}' to wipe managed services and permanently remove it from state?"
                    )
                } else {
                    format!("Permanently remove server '{id}' from state?")
                }
            } else {
                let joined = ids.join(", ");
                if wipe {
                    format!(
                        "SSH into servers [{joined}] to wipe managed services and permanently remove them from state?"
                    )
                } else {
                    format!(
                        "Permanently remove {} servers [{joined}] from state?",
                        ids.len()
                    )
                }
            };
            confirm_destructive(&prompt, yes)?;

            let (_lock, pass, mut state) = load_locked_state(state_path, secrets)?;
            for id in &ids {
                if !state.servers.iter().any(|s| s.id == *id) {
                    bail!("unknown server '{id}'");
                }
            }
            if wipe {
                for id in &ids {
                    let srv = state.server(id)?;
                    let cmd = remote_wipe_cmd(&srv.admin_ssh.user, srv.admin_ssh.port.get());
                    let out = run_ssh(&srv.admin_ssh, &cmd, None)
                        .with_context(|| format!("failed wiping server '{id}' before removal"))?;
                    if !out.stdout.trim().is_empty() {
                        println!("{}", out.stdout.trim());
                    }
                }
            }
            let old_revision = state.revision;
            let remove_set: HashSet<&str> = ids.iter().map(String::as_str).collect();
            state
                .servers
                .retain(|s| !remove_set.contains(s.id.as_str()));
            if let Some(ref sub_id) = state.subscription.server_id
                && remove_set.contains(sub_id.as_str())
            {
                state.subscription.server_id = None;
            }
            let new_rev = commit_state_mutation(state_path, &mut state, &pass, old_revision)?;
            if ids.len() == 1 {
                println!("Removed server '{}' (revision={new_rev}).", ids[0]);
            } else {
                println!(
                    "Removed {} servers ({}) (revision={new_rev}).",
                    ids.len(),
                    ids.join(", ")
                );
            }
        }
    }
    Ok(())
}
