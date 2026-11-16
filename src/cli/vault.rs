//! Vault lifecycle, configuration summary, backup/restore, and Cloudflare handlers.

use std::fs;
use std::io::{self, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use time::format_description::well_known::Rfc3339;

use super::args::CloudflareCommand;
use super::secrets::{SecretReader, confirm_destructive};
use super::{
    MutationMessage, load_locked_state, mutate_state_and_report, print_backup_reminder,
    print_servers_section, print_users_section,
};
use crate::crypto::generate_token;
use crate::state::{CloudflareConfig, SecretString, State, now_utc_seconds};
use crate::store::{
    acquire_state_lock, backup_existing_state, commit_state_mutation, decode_state, decrypt_bytes,
    ensure_backup_dir, max_backup_revision, read_encrypted_file, verify_private_file,
    with_state_mut, write_ciphertext_atomic, write_encrypted_atomic,
};
use crate::validate::{validate_for_deploy, validate_hostname, validate_state};

pub(super) fn cmd_init(
    state_path: &Path,
    domain: Option<String>,
    base_path: Option<String>,
    secrets: &mut SecretReader,
) -> Result<()> {
    let domain = match domain {
        Some(d) => d.trim().to_ascii_lowercase(),
        None => {
            if !io::stdin().is_terminal() {
                bail!("--domain is required when running kinveil init non-interactively");
            }
            eprint!("Subscription domain (e.g. sub.example.com): ");
            io::stderr().flush()?;
            let mut buf = String::new();
            io::stdin().read_line(&mut buf)?;
            buf.trim().to_ascii_lowercase()
        }
    };
    validate_hostname(&domain, "subscription.domain")?;

    let _lock = acquire_state_lock(state_path)?;
    if state_path.exists() {
        bail!("state file {} already exists", state_path.display());
    }

    let passphrase = secrets.prompt_new_passphrase("New state passphrase: ")?;
    let state = match base_path {
        Some(bp) => State::new_with_base_path(domain.clone(), bp)?,
        None => State::new(domain.clone())?,
    };
    validate_state(&state)?;
    write_encrypted_atomic(state_path, &state, &passphrase)?;

    println!(
        "Initialized encrypted state at {} (domain: {domain})",
        state_path.display()
    );
    print_backup_reminder(state_path);
    println!(
        "Tip: Set KINVEIL_PASSPHRASE_COMMAND (e.g. via your OS keychain or password manager) for zero-prompt CLI usage."
    );
    Ok(())
}

pub(super) fn cmd_show(state_path: &Path, secrets: &mut SecretReader) -> Result<()> {
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    let updated_at = state
        .updated_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| state.updated_at.to_string());
    let enabled_users = state.users.values().filter(|u| u.enabled).count();
    let cfg = &state.settings;
    let enabled_protocols: Vec<&str> = [
        (cfg.vless.enabled && cfg.vless.stream).then_some("vless-stream"),
        (cfg.vless.enabled && cfg.vless.packet).then_some("vless-packet"),
        cfg.hysteria2.enabled.then_some("hysteria2"),
        cfg.amneziawg.enabled.then_some("amneziawg"),
        cfg.ssh_forwarding.enabled.then_some("ssh-forwarding"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let deploy_status = match validate_for_deploy(&state) {
        Ok(()) => "ready".to_owned(),
        Err(e) => format!("not ready ({e})"),
    };

    println!("Kinveil state: {}", state_path.display());
    println!("  Revision:            {}", state.revision);
    println!("  Updated at:          {updated_at}");
    println!("  Deploy status:       {deploy_status}");
    println!(
        "  Subscription domain: {} (interval={}h, base_path=<redacted>)",
        state.subscription.domain, cfg.subscription.update_interval_hours
    );
    match &state.subscription.cloudflare {
        Some(cf) => println!(
            "  Cloudflare DNS:      configured (zone={}, ttl={}, api_token=<redacted>)",
            cf.zone_id, cf.ttl
        ),
        None => println!("  Cloudflare DNS:      not configured"),
    }
    println!(
        "  Settings defaults:   vless={}/tcp, hysteria2={}/udp, amneziawg={}/udp, ssh-forwarding={}/tcp, subnet={}, mtu={}, protocols=[{}]",
        cfg.vless.port,
        cfg.hysteria2.port,
        cfg.amneziawg.port,
        cfg.ssh_forwarding.port,
        cfg.amneziawg.subnet,
        cfg.amneziawg.mtu,
        enabled_protocols.join(","),
    );
    println!(
        "  Firewall:            block_private_networks={}, block_bittorrent={}",
        cfg.firewall.block_private_networks, cfg.firewall.block_bittorrent,
    );
    if cfg.artifacts.has_overrides() {
        let mut items = Vec::new();
        if let Some(url) = &cfg.artifacts.xray_zip_url {
            items.push(format!("xray={url}"));
        }
        if let Some(url) = &cfg.artifacts.amneziawg_url {
            items.push(format!("amneziawg={url}"));
        }
        println!("  Artifact overrides:  {}", items.join(", "));
    }

    println!("  Servers ({}):", state.servers.len());
    print_servers_section(&state, "    ");

    println!(
        "  Users ({}, {} enabled):",
        state.users.len(),
        enabled_users
    );
    print_users_section(&state, "    ");

    Ok(())
}

pub(super) fn cmd_validate(state_path: &Path, secrets: &mut SecretReader) -> Result<()> {
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    validate_state(&state)?;
    let deploy_note = match validate_for_deploy(&state) {
        Ok(()) => "ready".to_owned(),
        Err(e) => format!("not yet ready ({e})"),
    };
    println!(
        "Validation OK: revision={}, users={}, servers={}, deploy={}",
        state.revision,
        state.users.len(),
        state.servers.len(),
        deploy_note
    );
    Ok(())
}

pub(super) fn cmd_set_domain(
    state_path: &Path,
    domain: String,
    rotate_base_path: bool,
    secrets: &mut SecretReader,
) -> Result<()> {
    let clean_domain = domain.trim().to_ascii_lowercase();
    validate_hostname(&clean_domain, "subscription.domain")?;
    mutate_state_and_report(state_path, secrets, move |state| {
        state.subscription.domain = clean_domain.clone();
        if rotate_base_path {
            state.subscription.base_path = SecretString::new(format!("/{}/", generate_token(16)));
        }
        let note = if rotate_base_path {
            "\nWarning: subscription base path rotated; point DNS to the subscription host, run `kinveil deploy`, and re-share links (`kinveil user share <name>`)."
        } else {
            " Point DNS to the subscription host and run `kinveil deploy` (clients must re-import links with the new domain)."
        };
        Ok(MutationMessage::with_note(
            format!("Updated subscription domain to '{clean_domain}'"),
            note,
        ))
    })
}

pub(super) fn cmd_cloudflare(
    state_path: &Path,
    action: CloudflareCommand,
    secrets: &mut SecretReader,
) -> Result<()> {
    match action {
        CloudflareCommand::Set { zone_id, ttl } => {
            let passphrase = secrets.prompt_passphrase("State passphrase: ")?;
            let api_token = secrets.prompt_one("Cloudflare API token: ")?;
            let (rev, ()) = with_state_mut(state_path, &passphrase, move |state| {
                state.subscription.cloudflare = Some(CloudflareConfig {
                    zone_id,
                    api_token: SecretString::new(api_token.trim()),
                    ttl,
                });
                Ok(())
            })?;
            println!("Saved Cloudflare DNS config in state (revision={rev}).");
        }
        CloudflareCommand::Clear => {
            mutate_state_and_report(state_path, secrets, |state| {
                state.subscription.cloudflare = None;
                Ok(MutationMessage::plain(
                    "Cleared Cloudflare DNS config from state",
                ))
            })?;
        }
    }
    Ok(())
}

pub(super) fn cmd_passwd(state_path: &Path, secrets: &mut SecretReader) -> Result<()> {
    let _lock = acquire_state_lock(state_path)?;
    let current_pass = secrets.prompt_passphrase("Current state passphrase: ")?;
    let mut state = read_encrypted_file(state_path, &current_pass)?;
    validate_state(&state)?;
    let new_pass = secrets.prompt_new_passphrase("New state passphrase: ")?;
    let old_revision = state.revision;
    let new_rev = commit_state_mutation(state_path, &mut state, &new_pass, old_revision)?;
    println!(
        "Updated state passphrase (revision={new_rev}). Note: rolling backups in backups/ remain encrypted with their original passphrases."
    );
    print_backup_reminder(state_path);
    Ok(())
}

pub(super) fn cmd_backup(
    state_path: &Path,
    dest: PathBuf,
    secrets: &mut SecretReader,
) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(&dest) {
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to write backup through symlink {}",
                dest.display()
            );
        }
        if meta.is_dir() {
            bail!(
                "backup destination {} is a directory; provide a file path",
                dest.display()
            );
        }
    }
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    validate_state(&state)?;
    let raw = fs::read(state_path)
        .with_context(|| format!("reading encrypted state {}", state_path.display()))?;
    write_ciphertext_atomic(&dest, &raw)?;
    println!(
        "Verified and wrote encrypted backup (revision={}) to {}.",
        state.revision,
        dest.display()
    );
    Ok(())
}

pub(super) fn cmd_restore(
    state_path: &Path,
    src: PathBuf,
    yes: bool,
    secrets: &mut SecretReader,
) -> Result<()> {
    let meta = fs::symlink_metadata(&src)
        .with_context(|| format!("inspecting backup file {}", src.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!(
            "backup source {} must be a regular non-symlink file",
            src.display()
        );
    }
    let raw = fs::read(&src).with_context(|| format!("reading backup {}", src.display()))?;
    let passphrase = secrets.prompt_passphrase("Backup passphrase: ")?;
    let plaintext = decrypt_bytes(&raw, &passphrase)?;
    let mut state = decode_state(&plaintext)?;
    validate_state(&state)?;

    if fs::symlink_metadata(state_path).is_ok() {
        confirm_destructive(
            &format!(
                "Restore backup {} over existing vault {}?",
                src.display(),
                state_path.display()
            ),
            yes,
        )?;
    }

    let _lock = acquire_state_lock(state_path)?;
    let mut floor = max_backup_revision(state_path)?;
    if fs::symlink_metadata(state_path).is_ok() {
        match read_encrypted_file(state_path, &passphrase) {
            Ok(existing) => {
                floor = floor.max(existing.revision);
                backup_existing_state(state_path, existing.revision)?;
            }
            Err(_) => {
                verify_private_file(state_path)?;
                let old_raw = fs::read(state_path)
                    .with_context(|| format!("reading existing {}", state_path.display()))?;
                let backup_dir = ensure_backup_dir(state_path)?;
                let rescue = backup_dir.join(format!(
                    "state.pre-restore-{}.enc",
                    now_utc_seconds().unix_timestamp()
                ));
                write_ciphertext_atomic(&rescue, &old_raw)?;
            }
        }
    }
    if state.revision <= floor {
        state.revision = floor.saturating_add(1);
    }
    state.updated_at = now_utc_seconds();
    write_encrypted_atomic(state_path, &state, &passphrase)?;
    println!(
        "Restored state (revision={}) from {}.",
        state.revision,
        src.display()
    );
    Ok(())
}
