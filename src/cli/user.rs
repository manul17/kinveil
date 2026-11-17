//! User credential, metadata, export, and client share handlers (`kinveil user ...`).

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use qrcode::QrCode;
use qrcode::render::unicode;
use time::format_description::well_known::Rfc3339;

use super::args::{ExportFormat, UserCommand};
use super::secrets::{SecretReader, confirm_destructive};
use super::{
    MutationMessage, dedup_strings, load_locked_state, mutate_state_and_report,
    parse_optional_note, print_users_section,
};
use crate::crypto::{
    generate_awg_psk, generate_openssh_ed25519, generate_salamander_password, generate_spider_x,
    generate_token, generate_uuid_v4, generate_x25519_awg_keypair,
};
use crate::deploy::ssh::format_known_hosts_entry;
use crate::render::amneziawg::render_client_ini;
use crate::render::subscriptions::{
    SubVariant, render_subscription_body, render_subscription_lines_for_server,
};
use crate::state::{
    SecretString, State, User, UserAmneziaWg, UserHysteria2, UserSshForwarding, UserVless,
};
use crate::validate::{validate_for_deploy, validate_user_name};

fn render_qr_unicode(url: &str) -> Result<String> {
    let code = QrCode::new(url.as_bytes()).context("failed to encode subscription URL as QR")?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build())
}

fn load_user_share_info(
    state_path: &Path,
    name: &str,
    secrets: &mut SecretReader,
) -> Result<(String, bool)> {
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    let user = state.user(name)?;
    if !user.enabled {
        eprintln!("Warning: user '{name}' is currently disabled.");
    }
    if let Err(e) = validate_for_deploy(&state) {
        eprintln!(
            "Warning: vault is not yet deploy-ready ({e}); run `kinveil deploy` before clients connect."
        );
    }
    let has_ssh_fwd = state.servers.iter().any(|s| {
        s.enabled
            && s.effective_config(&state.settings, false)
                .has_ssh_forwarding
    });
    Ok((state.user_subscription_url(user), has_ssh_fwd))
}

fn print_user_details(state: &State, name: &str, user: &User) -> Result<()> {
    let created = user
        .created_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| user.created_at.to_string());
    let awg_cidr = state.settings.awg_user_cidr(user.uid)?;
    let awg_pub = user.amneziawg_public_key()?;
    let ssh_pub = user.ssh_public_key()?;

    println!("User: {name}");
    println!("  UID:           {}", user.uid);
    println!(
        "  Status:        {}",
        if user.enabled { "enabled" } else { "disabled" }
    );
    println!("  Created at:    {created}");
    if let Some(ref note) = user.note {
        println!("  Note:          {note}");
    }
    println!("  Sub token:     <redacted>");
    println!("  VLESS spider:  {}", user.vless.spider_x);
    println!("  AmneziaWG IP:  {awg_cidr}");
    println!("  AmneziaWG pbk: {awg_pub}");
    println!("  SSH user:      {}", user.ssh_username());
    println!("  SSH pubkey:    {ssh_pub}");
    Ok(())
}

pub(super) fn cmd_user(
    state_path: &Path,
    action: UserCommand,
    secrets: &mut SecretReader,
) -> Result<()> {
    match action {
        UserCommand::List => {
            let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
            let enabled_users = state.users.values().filter(|u| u.enabled).count();
            println!("Users ({}, {} enabled):", state.users.len(), enabled_users);
            print_users_section(&state, "  ");
        }
        UserCommand::Show { name } => {
            let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
            let user = state.user(&name)?;
            print_user_details(&state, &name, user)?;
        }
        UserCommand::Add {
            names,
            note,
            disabled,
        } => {
            let mut seen = HashSet::new();
            for name in &names {
                validate_user_name(name)?;
                if !seen.insert(name.as_str()) {
                    bail!("duplicate user name '{name}' in arguments");
                }
            }
            let clean_note = parse_optional_note(note, "--note")?;
            mutate_state_and_report(state_path, secrets, move |state| {
                for name in &names {
                    if state.users.contains_key(name) {
                        bail!("user '{name}' already exists");
                    }
                }
                let mut added = Vec::with_capacity(names.len());
                for name in names {
                    let uid = state.next_uid;
                    state.next_uid = uid
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("UID space exhausted"))?;
                    let mut user = User::generate(uid)?;
                    user.enabled = !disabled;
                    user.note.clone_from(&clean_note);
                    state.users.insert(name.clone(), user);
                    added.push((name, uid));
                }
                if added.len() == 1 {
                    let (name, uid) = &added[0];
                    Ok(MutationMessage::with_note(
                        format!("Added user '{name}' [uid={uid}]"),
                        format!(
                            " Run `kinveil deploy` to apply on servers, then `kinveil user share {name}`."
                        ),
                    ))
                } else {
                    let summary = added
                        .iter()
                        .map(|(name, uid)| format!("{name} [uid={uid}]"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    Ok(MutationMessage::with_note(
                        format!("Added {} users ({summary})", added.len()),
                        " Run `kinveil deploy` to apply on servers, then `kinveil user share <name>`.",
                    ))
                }
            })?;
        }
        UserCommand::Update {
            name,
            rename,
            note,
            clear_note,
        } => {
            if rename.is_none() && note.is_none() && !clear_note {
                bail!("specify --rename, --note, or --clear-note to update");
            }
            if let Some(ref new_name) = rename {
                validate_user_name(new_name)?;
            }
            let clean_note = parse_optional_note(note, "--note")?;
            mutate_state_and_report(state_path, secrets, move |state| {
                if !state.users.contains_key(&name) {
                    bail!("user {name:?} not found");
                }
                if let Some(ref new_name) = rename
                    && new_name != &name
                    && state.users.contains_key(new_name)
                {
                    bail!("user '{new_name}' already exists");
                }

                let mut user = state
                    .users
                    .remove(&name)
                    .ok_or_else(|| anyhow!("user {name:?} not found"))?;
                if clear_note {
                    user.note = None;
                } else if let Some(new_note) = clean_note {
                    user.note = Some(new_note);
                }
                let target_name = rename.unwrap_or_else(|| name.clone());
                state.users.insert(target_name.clone(), user);

                let msg = if target_name != name {
                    format!("Updated user '{name}' -> '{target_name}'")
                } else {
                    format!("Updated user '{name}'")
                };
                Ok(MutationMessage::plain(msg))
            })?;
        }
        UserCommand::Enable { names } => {
            let names = dedup_strings(names);
            mutate_state_and_report(state_path, secrets, move |state| {
                for name in &names {
                    let _ = state.user(name)?;
                }
                for name in &names {
                    state.user_mut(name)?.enabled = true;
                }
                let action = if names.len() == 1 {
                    format!("Enabled user '{}'", names[0])
                } else {
                    format!("Enabled {} users ({})", names.len(), names.join(", "))
                };
                Ok(MutationMessage::with_note(
                    action,
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        UserCommand::Disable { names } => {
            let names = dedup_strings(names);
            mutate_state_and_report(state_path, secrets, move |state| {
                for name in &names {
                    let _ = state.user(name)?;
                }
                for name in &names {
                    state.user_mut(name)?.enabled = false;
                }
                let action = if names.len() == 1 {
                    format!("Disabled user '{}'", names[0])
                } else {
                    format!("Disabled {} users ({})", names.len(), names.join(", "))
                };
                Ok(MutationMessage::with_note(
                    action,
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        UserCommand::Rotate {
            name,
            all,
            vless,
            hysteria2,
            amneziawg,
            ssh_forwarding,
            rotate_url,
        } => {
            if !all && !vless && !hysteria2 && !amneziawg && !ssh_forwarding && !rotate_url {
                bail!(
                    "specify at least one rotation scope (--all, --vless, --hysteria2, --amneziawg, --ssh-forwarding, or --rotate-url)"
                );
            }
            mutate_state_and_report(state_path, secrets, move |state| {
                let user = state.user_mut(&name)?;
                let mut rotated = Vec::new();
                if vless || all {
                    user.vless = UserVless {
                        uuid: generate_uuid_v4(),
                        spider_x: generate_spider_x(),
                    };
                    rotated.push("vless");
                }
                if hysteria2 || all {
                    user.hysteria2 = UserHysteria2 {
                        auth: generate_salamander_password(24),
                    };
                    rotated.push("hysteria2");
                }
                if amneziawg || all {
                    let (awg_priv, _) = generate_x25519_awg_keypair();
                    user.amneziawg = UserAmneziaWg {
                        private_key: awg_priv,
                        preshared_key: generate_awg_psk(),
                    };
                    rotated.push("amneziawg");
                }
                if ssh_forwarding || all {
                    let (ssh_priv, _) = generate_openssh_ed25519(&user.ssh_username())?;
                    user.ssh_forwarding = UserSshForwarding {
                        private_key: ssh_priv,
                    };
                    rotated.push("ssh-forwarding");
                }
                if rotate_url {
                    user.subscription_token = SecretString::new(generate_token(24));
                    rotated.push("subscription-url");
                }

                let scope_str = rotated.join(",");
                if rotate_url {
                    Ok(MutationMessage::with_note(
                        format!("Rotated [{scope_str}] for '{name}'"),
                        format!(
                            "\nWarning: subscription URL changed; resend the new URL (`kinveil user share {name}`) to {name} to re-import, and run `kinveil deploy`."
                        ),
                    ))
                } else {
                    Ok(MutationMessage::with_note(
                        format!("Rotated [{scope_str}] for '{name}'"),
                        " Run `kinveil deploy` so servers accept the rotated credentials.",
                    ))
                }
            })?;
        }
        UserCommand::Remove { names, yes } => {
            let names = dedup_strings(names);
            let prompt = if names.len() == 1 {
                format!("Permanently remove user '{}' from state?", names[0])
            } else {
                format!(
                    "Permanently remove {} users [{}] from state?",
                    names.len(),
                    names.join(", ")
                )
            };
            confirm_destructive(&prompt, yes)?;
            mutate_state_and_report(state_path, secrets, move |state| {
                for name in &names {
                    let _ = state.user(name)?;
                }
                for name in &names {
                    state.users.remove(name);
                }
                let action = if names.len() == 1 {
                    format!("Removed user '{}'", names[0])
                } else {
                    format!("Removed {} users ({})", names.len(), names.join(", "))
                };
                Ok(MutationMessage::with_note(
                    action,
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        UserCommand::Share { name, url_only } => {
            let (url, has_ssh_fwd) = load_user_share_info(state_path, &name, secrets)?;
            if url_only {
                println!("{url}");
                return Ok(());
            }
            let qr = render_qr_unicode(&url)?;
            println!("Kinveil setup for {name}:");
            println!();
            println!("Subscription URL:\n  {url}");
            println!();
            println!("{qr}");
            println!();
            println!("Happ (iOS / Android / Windows / macOS):");
            println!("  1. Install Happ, tap '+' -> Add from URL (or scan the QR code above).");
            println!("  2. Paste the URL above; Happ imports and refreshes all protocols.");
            println!();
            println!("Throne (Windows / macOS / Linux):");
            println!(
                "  1. Open Profiles -> New profile -> Type: Subscription, paste the URL above, and update."
            );
            if has_ssh_fwd {
                println!(
                    "  2. Note: SSH forwarding is active (included automatically via Throne User-Agent or '?ssh=1')."
                );
            }
            println!();
            println!("Tips:");
            println!(
                "  - Try `<Country> VLESS-Stream` first (switch to `VLESS-Packet`, `Hysteria2`, or `AmneziaWG` if blocked)."
            );
            println!("  - Avoid Karing 1.2.25 (X25519MLKEM768 handshake bug); use Happ or Throne.");
            println!(
                "  - Use `amneziawg` on at most 1 device at a time (`vless-*` and `hysteria2` allow multiple devices)."
            );
            println!(
                "  - Treat this subscription URL/QR code like a password and do not share it publicly."
            );
        }
        UserCommand::Export {
            name,
            format,
            server,
        } => {
            let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
            let user = state.user(&name)?;
            match format {
                ExportFormat::Urls => {
                    let lines = render_subscription_lines_for_server(
                        &state,
                        &name,
                        user,
                        SubVariant::Throne,
                        server.as_deref(),
                    )?;
                    for line in lines {
                        println!("{line}");
                    }
                }
                ExportFormat::Happ => {
                    if server.is_some() {
                        bail!("--server cannot be used with --format happ");
                    }
                    let body = render_subscription_body(&state, &name, user, SubVariant::Happ)?;
                    if !body.is_empty() {
                        println!("{body}");
                    }
                }
                ExportFormat::Throne => {
                    if server.is_some() {
                        bail!("--server cannot be used with --format throne");
                    }
                    let body = render_subscription_body(&state, &name, user, SubVariant::Throne)?;
                    println!("{body}");
                }
                ExportFormat::Amneziawg => {
                    let srv = match server {
                        Some(id) => {
                            let s = state.server(&id)?;
                            if !s.enabled {
                                bail!("server '{id}' is disabled");
                            }
                            if !s.effective_config(&state.settings, false).has_amneziawg {
                                bail!("server '{id}' does not have AmneziaWG active");
                            }
                            s
                        }
                        None => state
                            .servers
                            .iter()
                            .find(|s| {
                                s.enabled
                                    && s.effective_config(&state.settings, false).has_amneziawg
                            })
                            .ok_or_else(|| anyhow!("no enabled AmneziaWG server found in state"))?,
                    };
                    let ini = render_client_ini(&state, srv, user)?;
                    println!("{ini}");
                }
                ExportFormat::Ssh => {
                    if !user.enabled {
                        bail!("cannot export SSH forwarding credentials for disabled user {name}");
                    }
                    let srv = match server {
                        Some(id) => {
                            let s = state.server(&id)?;
                            if !s.enabled {
                                bail!("server '{id}' is disabled");
                            }
                            if !s
                                .effective_config(&state.settings, false)
                                .has_ssh_forwarding
                            {
                                bail!("server '{id}' does not have ssh-forwarding active");
                            }
                            s
                        }
                        None => state
                            .servers
                            .iter()
                            .find(|s| {
                                s.enabled
                                    && s.effective_config(&state.settings, false)
                                        .has_ssh_forwarding
                            })
                            .ok_or_else(|| {
                                anyhow!("no enabled ssh-forwarding server found in state")
                            })?,
                    };
                    let vpn = srv
                        .vpn
                        .as_ref()
                        .ok_or_else(|| anyhow!("server {} lacks vpn configuration", srv.id))?;
                    let port = srv
                        .effective_config(&state.settings, false)
                        .ssh_forwarding_port;
                    let host_pub = vpn.ssh_forwarding.host_public_key()?;
                    let kh_line =
                        format_known_hosts_entry(&srv.public_ipv4.to_string(), port, &host_pub);
                    let ssh_user = user.ssh_username();
                    let priv_key = user.ssh_forwarding.private_key.as_str().trim_end();

                    println!("# Server: {} ({})", srv.id, srv.label);
                    println!("# User:   {ssh_user}@{}:{port}", srv.public_ipv4);
                    println!();
                    println!("# 1. Save known_hosts line (chmod 0600):");
                    println!("{kh_line}");
                    println!();
                    println!("# 2. Save private key (chmod 0600):");
                    println!("{priv_key}");
                    println!();
                    println!("# 3. Connect local SOCKS5 proxy (127.0.0.1:1080):");
                    println!(
                        "ssh -N -D 1080 -i <key_file> -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<known_hosts_file> -p {port} {ssh_user}@{}",
                        srv.public_ipv4
                    );
                }
            }
        }
    }
    Ok(())
}
