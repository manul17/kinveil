//! Server inventory, SSH host-key resolution, role/protocol, and rotation handlers.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use ssh_key::{HashAlg, PublicKey};

use super::args::{ServerCommand, ServerUpdateArgs};
use super::secrets::{SecretReader, confirm_destructive, prompt_yes_no};
use super::{
    MutationMessage, load_locked_state, mutate_state_and_report, parse_non_zero_port,
    parse_note_update, parse_opt_non_zero_port, parse_optional_note, print_servers_section,
};
use crate::crypto::{
    generate_awg_obfuscation, generate_hysteria_self_signed_cert, generate_salamander_password,
    generate_x25519_awg_keypair, generate_x25519_reality_keypair, generate_xhttp_path, random_hex,
};
use crate::deploy::remote::remote_wipe_cmd;
use crate::deploy::ssh::{lookup_known_hosts_key, run_ssh};
use crate::state::{
    AdminSsh, Server, ServerPortOverrides, ServerRole, ServerSshForwarding, ServerVpn, VpnProtocol,
    now_utc_seconds,
};
use crate::store::commit_state_mutation;
use crate::validate::{
    validate_hostname, validate_server_id, validate_ssh_host, validate_ssh_user,
    validate_target_host_port,
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
    vpn.vless.enabled = protocols.contains(&VpnProtocol::Vless);
    vpn.hysteria2.enabled = protocols.contains(&VpnProtocol::Hysteria2);
    vpn.amneziawg.enabled = protocols.contains(&VpnProtocol::AmneziaWg);
    vpn.ssh_forwarding.enabled = protocols.contains(&VpnProtocol::SshForwarding);
}

fn normalize_sni(raw: String) -> Result<String> {
    let clean = raw.trim().to_ascii_lowercase();
    validate_hostname(&clean, "--sni")?;
    Ok(clean)
}

fn normalize_target(raw: String) -> Result<String> {
    let clean = raw.trim().to_ascii_lowercase();
    validate_target_host_port(&clean, "--target")?;
    Ok(clean)
}

fn normalize_xhttp_host_update(raw: String) -> Result<Option<String>> {
    let clean = raw.trim().to_ascii_lowercase();
    if clean.is_empty() {
        Ok(None)
    } else {
        validate_hostname(&clean, "--xhttp-host")?;
        Ok(Some(clean))
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
            if !wants_vpn {
                if args.sni.is_some()
                    || args.target.is_some()
                    || args.xhttp_host.is_some()
                    || !args.protocols.is_empty()
                {
                    bail!("--sni, --target, --xhttp-host, and --protocols require the 'vpn' role");
                }
            } else if args.sni.is_none() {
                bail!("--sni <camouflage-domain> is required when adding a server with role 'vpn'");
            }
            let protocols = if args.protocols.is_empty() {
                None
            } else {
                Some(dedup_nonempty(args.protocols, "--protocols")?)
            };
            let ssh_port = parse_non_zero_port(args.ssh_port, "--ssh-port")?;
            let ports = ServerPortOverrides {
                vless: parse_opt_non_zero_port(args.vless_port, "--vless-port")?,
                hysteria2: parse_opt_non_zero_port(args.hysteria2_port, "--hysteria2-port")?,
                amneziawg: parse_opt_non_zero_port(args.amneziawg_port, "--amneziawg-port")?,
                ssh_forwarding: parse_opt_non_zero_port(
                    args.ssh_forwarding_port,
                    "--ssh-forwarding-port",
                )?,
            };
            let ssh_host = args.ssh_host.unwrap_or_else(|| ip.to_string());
            validate_ssh_host(&ssh_host, "--ssh-host")?;
            validate_ssh_user(&args.ssh_user, "--ssh-user")?;
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
            let host_public_key =
                resolve_server_host_key(args.ssh_host_key, &ssh_host, ssh_port.get())?;

            let vpn = if wants_vpn {
                let mut generated = ServerVpn::generate(
                    &server_id,
                    ip,
                    args.sni.as_deref().unwrap_or(""),
                    args.target,
                    args.xhttp_host,
                )?;
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
                arch: args.arch,
                created_at: now_utc_seconds(),
                note,
                public_ipv4: ip,
                public_ipv6: ipv6,
                admin_ssh: AdminSsh {
                    host: ssh_host,
                    port: ssh_port,
                    user: args.ssh_user,
                    host_public_key,
                },
                ports,
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
            if args.roles.is_none()
                && args.protocols.is_none()
                && args.sni.is_none()
                && args.target.is_none()
                && args.xhttp_host.is_none()
                && args.vless_port.is_none()
                && args.hysteria2_port.is_none()
                && args.amneziawg_port.is_none()
                && args.ssh_forwarding_port.is_none()
                && !args.clear_ports
                && args.label.is_none()
                && args.ipv4.is_none()
                && args.ipv6.is_none()
                && !args.clear_ipv6
                && args.arch.is_none()
                && args.note.is_none()
                && args.ssh_host.is_none()
                && args.ssh_port.is_none()
                && args.ssh_user.is_none()
                && args.ssh_host_key.is_none()
            {
                bail!(
                    "specify at least one update flag (--roles, --protocols, --sni, --target, --xhttp-host, --*-port, --clear-ports, --label, --ipv4, --ipv6, --clear-ipv6, --arch, --note, or --ssh-*)"
                );
            }

            let parsed_roles = args
                .roles
                .map(|r| dedup_nonempty(r, "--roles"))
                .transpose()?;
            let parsed_protocols = args
                .protocols
                .map(|p| dedup_nonempty(p, "--protocols"))
                .transpose()?;
            let mut clean_sni = args.sni.map(normalize_sni).transpose()?;
            let mut clean_target = args.target.map(normalize_target).transpose()?;
            let mut clean_xhttp_host = args
                .xhttp_host
                .map(normalize_xhttp_host_update)
                .transpose()?;
            let vless_port = parse_opt_non_zero_port(args.vless_port, "--vless-port")?;
            let hysteria2_port = parse_opt_non_zero_port(args.hysteria2_port, "--hysteria2-port")?;
            let amneziawg_port = parse_opt_non_zero_port(args.amneziawg_port, "--amneziawg-port")?;
            let ssh_forwarding_port =
                parse_opt_non_zero_port(args.ssh_forwarding_port, "--ssh-forwarding-port")?;

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
            let note_update = parse_note_update(args.note, "--note")?;
            let ssh_port = parse_opt_non_zero_port(args.ssh_port, "--ssh-port")?;
            if let Some(ref host) = args.ssh_host {
                validate_ssh_host(host, "--ssh-host")?;
            }
            if let Some(ref user) = args.ssh_user {
                validate_ssh_user(user, "--ssh-user")?;
            }

            let (_lock, pass, mut state) = load_locked_state(state_path, secrets)?;
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
            {
                let sub_wanted = parsed_roles
                    .as_ref()
                    .map(|r| r.contains(&ServerRole::Subscription));

                let srv = state.server_mut(&args.id)?;
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
                if let Some(arch) = args.arch {
                    srv.arch = arch;
                }
                if let Some(new_note) = note_update {
                    srv.note = new_note;
                }
                srv.admin_ssh.host = target_ssh_host;
                srv.admin_ssh.port = target_ssh_port;
                if let Some(user) = args.ssh_user {
                    srv.admin_ssh.user = user;
                }
                srv.admin_ssh.host_public_key = new_host_key;

                if args.clear_ports {
                    srv.ports = ServerPortOverrides::default();
                }
                if let Some(p) = vless_port {
                    srv.ports.vless = Some(p);
                }
                if let Some(p) = hysteria2_port {
                    srv.ports.hysteria2 = Some(p);
                }
                if let Some(p) = amneziawg_port {
                    srv.ports.amneziawg = Some(p);
                }
                if let Some(p) = ssh_forwarding_port {
                    srv.ports.ssh_forwarding = Some(p);
                }

                let mut vpn_just_generated = false;
                if let Some(ref new_roles) = parsed_roles {
                    let wants_vpn = new_roles.contains(&ServerRole::Vpn);
                    if wants_vpn {
                        match &mut srv.vpn {
                            Some(v) => v.enabled = true,
                            None => {
                                let sni_val = clean_sni.take().ok_or_else(|| {
                                    anyhow!(
                                        "--sni <camouflage-domain> is required when newly adding the 'vpn' role to '{}'",
                                        args.id
                                    )
                                })?;
                                let mut generated = ServerVpn::generate(
                                    &args.id,
                                    srv.public_ipv4,
                                    &sni_val,
                                    clean_target.take(),
                                    clean_xhttp_host.take().flatten(),
                                )?;
                                if let Some(ref protos) = parsed_protocols {
                                    apply_vpn_protocols(&mut generated, protos);
                                }
                                srv.vpn = Some(generated);
                                vpn_just_generated = true;
                            }
                        }
                    } else {
                        if clean_sni.is_some()
                            || clean_target.is_some()
                            || clean_xhttp_host.is_some()
                            || parsed_protocols.is_some()
                        {
                            bail!(
                                "--sni, --target, --xhttp-host, and --protocols require the 'vpn' role"
                            );
                        }
                        if let Some(v) = &mut srv.vpn {
                            v.enabled = false;
                        }
                    }
                }

                if !vpn_just_generated
                    && (clean_sni.is_some()
                        || clean_target.is_some()
                        || clean_xhttp_host.is_some()
                        || parsed_protocols.is_some())
                {
                    let vpn = srv.vpn.as_mut().filter(|v| v.enabled).ok_or_else(|| {
                        anyhow!(
                            "server '{}' does not have the 'vpn' role; enable it with `kinveil server update {} --roles vpn,...`",
                            args.id,
                            args.id
                        )
                    })?;
                    if let Some(new_sni) = clean_sni {
                        let sni_changed = new_sni != vpn.vless.server_name;
                        vpn.vless.server_name = new_sni.clone();
                        if let Some(explicit_target) = clean_target.take() {
                            vpn.vless.target = explicit_target;
                        } else if sni_changed {
                            vpn.vless.target = format!("{new_sni}:443");
                        }
                        if let Some(explicit_host) = clean_xhttp_host.take() {
                            vpn.vless.xhttp_host = explicit_host;
                        } else if sni_changed {
                            vpn.vless.xhttp_host = None;
                        }
                    }
                    if let Some(explicit_target) = clean_target {
                        vpn.vless.target = explicit_target;
                    }
                    if let Some(explicit_host) = clean_xhttp_host {
                        vpn.vless.xhttp_host = explicit_host;
                    }
                    if let Some(ref protos) = parsed_protocols {
                        apply_vpn_protocols(vpn, protos);
                    }
                }

                if let Some(wants_sub) = sub_wanted {
                    if wants_sub {
                        state.subscription.server_id = Some(args.id.clone());
                    } else if state.is_subscription_server(&args.id) {
                        state.subscription.server_id = None;
                    }
                }
            }
            let new_rev = commit_state_mutation(state_path, &mut state, &pass, old_revision)?;
            println!(
                "Updated server '{}' (revision={new_rev}). Run `kinveil deploy` to apply changes.",
                args.id
            );
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
                let srv = state.server_mut(&id)?;
                let ipv4 = srv.public_ipv4;
                let vpn = srv.vpn.as_mut().ok_or_else(|| {
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
                    let existing_enabled = vpn.ssh_forwarding.enabled;
                    let mut next = ServerSshForwarding::generate(&id)?;
                    next.enabled = existing_enabled;
                    vpn.ssh_forwarding = next;
                    rotated.push("ssh-forwarding");
                }
                Ok(MutationMessage::with_note(
                    format!("Rotated [{}] on server '{id}'", rotated.join(",")),
                    " Run `kinveil deploy` so servers and subscriptions reflect the rotated keys.",
                ))
            })?;
        }
        ServerCommand::Enable { id } => {
            mutate_state_and_report(state_path, secrets, move |state| {
                let srv = state.server_mut(&id)?;
                srv.enabled = true;
                Ok(MutationMessage::with_note(
                    format!("Enabled server '{id}'"),
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        ServerCommand::Disable { id } => {
            mutate_state_and_report(state_path, secrets, move |state| {
                let srv = state.server_mut(&id)?;
                srv.enabled = false;
                Ok(MutationMessage::with_note(
                    format!("Disabled server '{id}'"),
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        ServerCommand::Remove { id, wipe, yes } => {
            let prompt = if wipe {
                format!(
                    "SSH into server '{id}' to wipe managed services and permanently remove it from state?"
                )
            } else {
                format!("Permanently remove server '{id}' from state?")
            };
            confirm_destructive(&prompt, yes)?;

            let (_lock, pass, mut state) = load_locked_state(state_path, secrets)?;
            let idx = state
                .servers
                .iter()
                .position(|s| s.id == id)
                .ok_or_else(|| anyhow!("unknown server '{id}'"))?;
            if wipe {
                let srv = &state.servers[idx];
                let cmd = remote_wipe_cmd(&srv.admin_ssh.user, srv.admin_ssh.port.get());
                let out = run_ssh(&srv.admin_ssh, &cmd, None)
                    .with_context(|| format!("failed wiping server '{id}' before removal"))?;
                if !out.stdout.trim().is_empty() {
                    println!("{}", out.stdout.trim());
                }
            }
            let old_revision = state.revision;
            state.servers.remove(idx);
            if state.is_subscription_server(&id) {
                state.subscription.server_id = None;
            }
            let new_rev = commit_state_mutation(state_path, &mut state, &pass, old_revision)?;
            println!("Removed server '{id}' (revision={new_rev}).");
        }
    }
    Ok(())
}
