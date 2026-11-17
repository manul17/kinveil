//! Subscription domain, secret path, and Cloudflare DNS handlers (`kinveil subscription ...`).

use std::path::Path;

use anyhow::{Result, anyhow, bail};

use super::args::{CloudflareCommand, SubscriptionCommand};
use super::secrets::SecretReader;
use super::{MutationMessage, load_locked_state, mutate_state_and_report};
use crate::crypto::generate_token;
use crate::render::caddy::{
    DEFAULT_PROFILE_TITLE, compile_subscription_routing, format_routing_summary,
};
use crate::state::{CloudflareConfig, SecretString};
use crate::store::commit_state_mutation;
use crate::validate::{validate_base_path, validate_cloudflare_zone_and_ttl, validate_hostname};

pub(super) fn cmd_subscription(
    state_path: &Path,
    action: SubscriptionCommand,
    secrets: &mut SecretReader,
) -> Result<()> {
    match action {
        SubscriptionCommand::Show { routing } => {
            let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
            let sub = &state.subscription;
            let cfg = &state.settings.subscription;
            let host = match &sub.server_id {
                Some(id) => match state.server(id) {
                    Ok(srv) if srv.enabled => format!("{id} ({}, {})", srv.label, srv.public_ipv4),
                    Ok(srv) => format!("{id} ({}, disabled)", srv.label),
                    Err(_) => format!("{id} (unknown)"),
                },
                None => "(none assigned)".to_owned(),
            };
            let title = cfg.profile_title.as_deref().map_or_else(
                || format!("{DEFAULT_PROFILE_TITLE} (default)"),
                str::to_owned,
            );
            let routing_summary = format_routing_summary(&cfg.routing);
            println!("Subscription configuration:");
            println!("  Domain:          {}", sub.domain);
            println!("  Update interval: {}h", cfg.update_interval_hours);
            println!("  Host server:     {host}");
            println!("  Base path:       <redacted>");
            println!("  Profile title:   {title}");
            println!("  Client routing:  {routing_summary}");
            match &sub.cloudflare {
                Some(cf) => println!(
                    "  Cloudflare DNS:  configured (zone={}, ttl={}, api_token=<redacted>)",
                    cf.zone_id, cf.ttl
                ),
                None => println!("  Cloudflare DNS:  not configured"),
            }
            if routing {
                let compiled = compile_subscription_routing(&cfg.routing)?;
                println!(
                    "  Happ link:       {}",
                    compiled.happ_header.as_deref().unwrap_or("(none)")
                );
                println!(
                    "  Throne link:     {}",
                    compiled.throne_header.as_deref().unwrap_or("(none)")
                );
            }
        }
        SubscriptionCommand::SetDomain {
            domain,
            rotate_path,
        } => {
            let clean_domain = domain.trim().to_ascii_lowercase();
            validate_hostname(&clean_domain, "subscription.domain")?;
            mutate_state_and_report(state_path, secrets, move |state| {
                state.subscription.domain = clean_domain.clone();
                if rotate_path {
                    state.subscription.base_path =
                        SecretString::new(format!("/{}/", generate_token(16)));
                }
                let note = if rotate_path {
                    "\nWarning: subscription base path rotated; point DNS to the subscription host, run `kinveil deploy`, and re-share links (`kinveil user share <name>`)."
                } else {
                    " Point DNS to the subscription host and run `kinveil deploy` (clients must re-import links with the new domain)."
                };
                Ok(MutationMessage::with_note(
                    format!("Updated subscription domain to '{clean_domain}'"),
                    note,
                ))
            })?;
        }
        SubscriptionCommand::SetPath { path, rotate } => {
            let explicit_path = match (path, rotate) {
                (Some(raw), false) => {
                    let clean = raw.trim().to_owned();
                    validate_base_path(&clean)?;
                    Some(clean)
                }
                (None, true) => None,
                _ => bail!("specify either --path <path> or --rotate"),
            };
            mutate_state_and_report(state_path, secrets, move |state| {
                let next_path = match explicit_path {
                    Some(p) => p,
                    None => format!("/{}/", generate_token(16)),
                };
                state.subscription.base_path = SecretString::new(next_path);
                Ok(MutationMessage::with_note(
                    "Updated subscription URL base path",
                    "\nWarning: subscription URLs changed; run `kinveil deploy` and re-share links (`kinveil user share <name>`).",
                ))
            })?;
        }
        SubscriptionCommand::Cloudflare { action } => match action {
            CloudflareCommand::Set { zone_id, ttl } => {
                let clean_zone_id = zone_id.trim().to_owned();
                validate_cloudflare_zone_and_ttl(&clean_zone_id, ttl)?;
                let (_lock, pass, mut state) = load_locked_state(state_path, secrets)?;
                let api_token = secrets.prompt_one("Cloudflare API token: ")?;
                let old_revision = state.revision;
                state.subscription.cloudflare = Some(CloudflareConfig {
                    zone_id: clean_zone_id,
                    api_token: SecretString::new(api_token.trim()),
                    ttl,
                });
                let rev = commit_state_mutation(state_path, &mut state, &pass, old_revision)?;
                println!("Saved Cloudflare DNS config in state (revision={rev}).");
            }
            CloudflareCommand::Update { zone_id, ttl } => {
                if zone_id.is_none() && ttl.is_none() {
                    bail!("specify --zone-id and/or --ttl to update");
                }
                mutate_state_and_report(state_path, secrets, move |state| {
                    let cf = state.subscription.cloudflare.as_mut().ok_or_else(|| {
                        anyhow!(
                            "Cloudflare DNS is not configured; run `kinveil subscription cloudflare set --zone-id <id>` first"
                        )
                    })?;
                    if let Some(z) = zone_id {
                        cf.zone_id = z.trim().to_owned();
                    }
                    if let Some(t) = ttl {
                        cf.ttl = t;
                    }
                    Ok(MutationMessage::plain("Updated Cloudflare DNS config"))
                })?;
            }
            CloudflareCommand::Clear => {
                mutate_state_and_report(state_path, secrets, |state| {
                    state.subscription.cloudflare = None;
                    Ok(MutationMessage::plain(
                        "Cleared Cloudflare DNS config from state",
                    ))
                })?;
            }
        },
    }
    Ok(())
}
