//! CLI subcommand dispatch and shared workflow helpers.

pub mod args;
mod config;
mod debug;
mod secrets;
mod server;
mod subscription;
mod traffic;
mod user;
mod vault;

use std::collections::HashSet;
use std::io;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use clap::CommandFactory as _;
use zeroize::Zeroizing;

pub use args::Cli;
use args::{Commands, DebugCommand};
use config::cmd_config;
use debug::cmd_debug_render;
use secrets::{SecretReader, confirm_destructive};
use server::cmd_server;
use subscription::cmd_subscription;
use traffic::cmd_traffic;
use user::cmd_user;
use vault::{cmd_backup, cmd_init, cmd_passwd, cmd_restore, cmd_show, cmd_validate};

use crate::deploy::verify::{check_external, check_remote_ssh};
use crate::deploy::{DeployOptions, run_deploy};
use crate::state::State;
use crate::store::{
    StateLock, acquire_state_lock, commit_state_mutation, default_state_path, read_encrypted_file,
};
use crate::validate::{validate_note, validate_state};

fn resolve_state_path(cli: &Cli) -> Result<PathBuf> {
    match &cli.state {
        Some(p) => Ok(p.clone()),
        None => default_state_path(),
    }
}

pub(crate) fn load_locked_state(
    state_path: &Path,
    secrets: &mut SecretReader,
) -> Result<(StateLock, Zeroizing<String>, State)> {
    let lock = acquire_state_lock(state_path)?;
    let (passphrase, source) = secrets.prompt_passphrase_with_source("State passphrase: ")?;
    let state = read_encrypted_file(state_path, &passphrase)
        .with_context(|| format!("passphrase supplied via {}", source.as_str()))?;
    Ok((lock, passphrase, state))
}

pub(crate) fn print_backup_reminder(state_path: &Path) {
    println!(
        "Reminder: Back up updated encrypted state at {}",
        state_path.display()
    );
}

pub(crate) struct MutationMessage {
    action: String,
    follow_up: Option<String>,
}

impl MutationMessage {
    pub(crate) fn plain(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            follow_up: None,
        }
    }

    pub(crate) fn with_note(action: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            follow_up: Some(note.into()),
        }
    }
}

pub(crate) fn mutate_state_and_report<F>(
    state_path: &Path,
    secrets: &mut SecretReader,
    f: F,
) -> Result<()>
where
    F: FnOnce(&mut State) -> Result<MutationMessage>,
{
    let (_lock, passphrase, mut state) = load_locked_state(state_path, secrets)?;
    let old_revision = state.revision;
    let msg = f(&mut state)?;
    let rev = commit_state_mutation(state_path, &mut state, &passphrase, old_revision)?;
    if let Some(note) = msg.follow_up {
        println!("{} (revision={rev}).{note}", msg.action);
    } else {
        println!("{} (revision={rev}).", msg.action);
    }
    Ok(())
}

pub(crate) fn dedup_strings(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

pub(crate) fn parse_non_zero_port(port: u16, flag: &str) -> Result<NonZeroU16> {
    NonZeroU16::new(port).ok_or_else(|| anyhow!("{flag} must be a valid TCP/UDP port (1..=65535)"))
}

pub(crate) fn parse_opt_non_zero_port(port: Option<u16>, flag: &str) -> Result<Option<NonZeroU16>> {
    port.map(|p| parse_non_zero_port(p, flag)).transpose()
}

pub(crate) fn parse_optional_note(note: Option<String>, field: &str) -> Result<Option<String>> {
    match note {
        Some(raw) => {
            validate_note(&raw, field)?;
            Ok(Some(raw.trim().to_owned()))
        }
        None => Ok(None),
    }
}

pub(crate) fn print_servers_section(state: &State, indent: &str) {
    for s in &state.servers {
        let is_sub = state.is_subscription_server(&s.id);
        let roles = s.roles_list(is_sub);
        let ports = s.summary_ports(&state.settings, is_sub);
        let v6_str = s
            .public_ipv6
            .map_or_else(|| "-".to_owned(), |v6| v6.to_string());
        let sni_suffix = s
            .summary_sni(&state.settings)
            .map(|sni| format!(" sni={sni}"))
            .unwrap_or_default();
        let traffic_suffix = if s.effective_config(&state.settings, is_sub).has_traffic {
            " traffic=on"
        } else {
            ""
        };
        let note_suffix = match &s.note {
            Some(note) => format!(" note={note:?}"),
            None => String::new(),
        };
        println!(
            "{indent}- {} ({}) [{}] ipv4={} ipv6={} ssh={}@{}:{} roles=[{}] ports=[{}]{sni_suffix}{traffic_suffix}{note_suffix}",
            s.id,
            s.label,
            if s.enabled { "enabled" } else { "disabled" },
            s.public_ipv4,
            v6_str,
            s.admin_ssh.user,
            s.admin_ssh.host,
            s.admin_ssh.port,
            roles.join(","),
            ports
        );
    }
}

pub(crate) fn print_users_section(state: &State, indent: &str) {
    for (name, u) in state.users_by_uid() {
        let created = u.created_at.date();
        let awg_ip = state
            .settings
            .awg_user_cidr(u.uid)
            .map(|cidr| cidr.strip_suffix("/32").unwrap_or(&cidr).to_owned())
            .unwrap_or_else(|_| "-".to_owned());
        let note_suffix = match &u.note {
            Some(note) => format!(" note={note:?}"),
            None => String::new(),
        };
        println!(
            "{indent}- uid={} name={} [{}] awg={awg_ip} created={created}{note_suffix}",
            u.uid,
            name,
            if u.enabled { "enabled" } else { "disabled" },
        );
    }
}

fn cmd_deploy(
    state_path: &Path,
    dry_run: bool,
    server: Option<String>,
    skip_dns: bool,
    takeover: bool,
    yes: bool,
    secrets: &mut SecretReader,
) -> Result<()> {
    if takeover && !dry_run {
        confirm_destructive(
            "Allow --takeover on remote host(s) (replaces /etc/nftables.conf and disables ufw)?",
            yes,
        )?;
    }
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    run_deploy(
        &state,
        &DeployOptions {
            dry_run,
            server_filter: server,
            skip_dns,
            takeover,
        },
    )
}

fn cmd_check(
    state_path: &Path,
    server: Option<String>,
    ssh: bool,
    secrets: &mut SecretReader,
) -> Result<()> {
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    validate_state(&state)?;
    if let Some(id) = &server
        && !state.servers.iter().any(|s| s.id == *id)
    {
        bail!("unknown server id '{id}'");
    }
    if ssh {
        println!(
            "Check scope: TCP + HTTPS external probes + SSH remote checks (systemd, nftables, UDP sockets, REALITY TLS 1.3 + H2)"
        );
    } else {
        println!(
            "Check scope: TCP + HTTPS external probes (UDP services untested; pass --ssh for remote systemd, UDP socket, and REALITY checks)"
        );
    }
    let mut rows = check_external(&state, server.as_deref())?;
    if ssh {
        rows.extend(check_remote_ssh(&state, server.as_deref())?);
    }
    let mut any_failed = false;
    for row in &rows {
        let marker = if row.ok { "OK" } else { "FAIL" };
        println!("  [{marker}] {}: {}", row.target, row.detail);
        if !row.ok {
            any_failed = true;
        }
    }
    if any_failed {
        bail!("one or more health checks failed");
    }
    Ok(())
}

pub fn run_cli(cli: Cli) -> Result<()> {
    if let Commands::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        clap_complete::generate(shell, &mut cmd, "kinveil", &mut io::stdout());
        return Ok(());
    }

    let state_path = resolve_state_path(&cli)?;
    let mut secrets = SecretReader::from_env()?;

    match cli.command {
        Commands::Init { domain, base_path } => {
            cmd_init(&state_path, domain, base_path, &mut secrets)
        }
        Commands::Show => cmd_show(&state_path, &mut secrets),
        Commands::Validate => cmd_validate(&state_path, &mut secrets),
        Commands::Config {
            print,
            file,
            reset,
            yes,
        } => cmd_config(&state_path, print, file, reset, yes, &mut secrets),
        Commands::Subscription { action } => cmd_subscription(&state_path, action, &mut secrets),
        Commands::User { action } => cmd_user(&state_path, action, &mut secrets),
        Commands::Server { action } => cmd_server(&state_path, action, &mut secrets),
        Commands::Deploy {
            dry_run,
            server,
            skip_dns,
            takeover,
            yes,
        } => cmd_deploy(
            &state_path,
            dry_run,
            server,
            skip_dns,
            takeover,
            yes,
            &mut secrets,
        ),
        Commands::Check { server, ssh } => cmd_check(&state_path, server, ssh, &mut secrets),
        Commands::Traffic {
            from,
            to,
            server,
            user,
            by_protocol,
        } => cmd_traffic(
            &state_path,
            from,
            to,
            server,
            user,
            by_protocol,
            &mut secrets,
        ),
        Commands::Passwd => cmd_passwd(&state_path, &mut secrets),
        Commands::Backup { path } => cmd_backup(&state_path, path, &mut secrets),
        Commands::Restore { path, yes } => cmd_restore(&state_path, path, yes, &mut secrets),
        Commands::Debug { action } => match action {
            DebugCommand::Render {
                dir,
                allow_non_tmpfs,
            } => cmd_debug_render(&state_path, &dir, allow_non_tmpfs, &mut secrets),
        },
        Commands::Completions { .. } => unreachable!(),
    }
}
