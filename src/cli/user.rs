//! User credential, metadata, and client share handlers (`kinveil user ...`).

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use qrcode::QrCode;
use qrcode::render::unicode;

use super::args::UserCommand;
use super::secrets::{SecretReader, confirm_destructive};
use super::{
    MutationMessage, load_locked_state, mutate_state_and_report, parse_note_update,
    parse_optional_note, print_users_section,
};
use crate::crypto::generate_token;
use crate::render::amneziawg::render_client_ini;
use crate::state::{SecretString, State, User};
use crate::validate::{validate_for_deploy, validate_user_name};

fn user_subscription_url(state: &State, user: &User) -> String {
    format!(
        "https://{}{}{}",
        state.subscription.domain,
        state.subscription.base_path.as_str(),
        user.subscription_token.as_str()
    )
}

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
    let has_ssh_fwd = state
        .servers
        .iter()
        .any(|s| s.enabled && s.has_ssh_forwarding(&state.settings));
    Ok((user_subscription_url(&state, user), has_ssh_fwd))
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
        UserCommand::Add { names, note } => {
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
                    user.note.clone_from(&clean_note);
                    state.users.insert(name.clone(), user);
                    added.push((name, uid));
                }
                if added.len() == 1 {
                    let (name, uid) = &added[0];
                    Ok(MutationMessage::with_note(
                        format!("Added user '{name}' [uid={uid}]"),
                        format!(
                            " Run `kinveil deploy` to activate on servers, then `kinveil user share {name}`."
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
                        " Run `kinveil deploy` to activate on servers, then `kinveil user share <name>`.",
                    ))
                }
            })?;
        }
        UserCommand::Update { name, note } => {
            let Some(note_update) = parse_note_update(note, "--note")? else {
                bail!("specify --note to update");
            };
            mutate_state_and_report(state_path, secrets, move |state| {
                let user = state.user_mut(&name)?;
                user.note = note_update;
                Ok(MutationMessage::plain(format!("Updated user '{name}'")))
            })?;
        }
        UserCommand::Enable { name } => {
            mutate_state_and_report(state_path, secrets, move |state| {
                let user = state.user_mut(&name)?;
                user.enabled = true;
                Ok(MutationMessage::with_note(
                    format!("Enabled user '{name}'"),
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        UserCommand::Disable { name } => {
            mutate_state_and_report(state_path, secrets, move |state| {
                let user = state.user_mut(&name)?;
                user.enabled = false;
                Ok(MutationMessage::with_note(
                    format!("Disabled user '{name}'"),
                    " Run `kinveil deploy` to apply changes.",
                ))
            })?;
        }
        UserCommand::Rotate { name, rotate_url } => {
            mutate_state_and_report(state_path, secrets, move |state| {
                let user = state.user_mut(&name)?;
                let mut rotated = User::generate(user.uid)?;
                rotated.enabled = user.enabled;
                rotated.created_at = user.created_at;
                rotated.note.clone_from(&user.note);
                if rotate_url {
                    rotated.subscription_token = SecretString::new(generate_token(24));
                } else {
                    rotated.subscription_token = user.subscription_token.clone();
                }
                *user = rotated;
                if rotate_url {
                    Ok(MutationMessage::with_note(
                        format!("Rotated credentials and subscription token for '{name}'"),
                        format!(
                            "\nWarning: subscription URL changed; resend the new URL (`kinveil user share {name}`) to {name} to re-import, and run `kinveil deploy`."
                        ),
                    ))
                } else {
                    Ok(MutationMessage::with_note(
                        format!("Rotated credentials for '{name}'"),
                        " Run `kinveil deploy` so servers accept the rotated credentials.",
                    ))
                }
            })?;
        }
        UserCommand::Remove { name, yes } => {
            confirm_destructive(
                &format!("Permanently remove user '{name}' from state?"),
                yes,
            )?;
            mutate_state_and_report(state_path, secrets, move |state| {
                state
                    .users
                    .remove(&name)
                    .ok_or_else(|| anyhow!("unknown user '{name}'"))?;
                Ok(MutationMessage::with_note(
                    format!("Removed user '{name}'"),
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
                "  - Try `<Country> vless-stream` first (switch to `vless-packet`, `hysteria`, or `amneziawg` if blocked)."
            );
            println!("  - Avoid Karing 1.2.25 (X25519MLKEM768 handshake bug); use Happ or Throne.");
            println!(
                "  - Use `amneziawg` on at most 1 device at a time (`vless-*` and `hysteria` allow multiple devices)."
            );
            println!(
                "  - Treat this subscription URL/QR code like a password and do not share it publicly."
            );
        }
        UserCommand::AmneziawgConf { name, server } => {
            let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
            let user = state.user(&name)?;
            let srv = match server {
                Some(id) => {
                    let s = state.server(&id)?;
                    if !s.has_amneziawg(&state.settings) {
                        bail!("server '{id}' does not have AmneziaWG active");
                    }
                    s
                }
                None => state
                    .servers
                    .iter()
                    .find(|s| s.enabled && s.has_amneziawg(&state.settings))
                    .ok_or_else(|| anyhow!("no enabled AmneziaWG server found in state"))?,
            };
            let ini = render_client_ini(&state, srv, user)?;
            print!("{ini}");
        }
    }
    Ok(())
}
