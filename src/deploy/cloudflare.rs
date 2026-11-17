use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use ureq::Agent;

use crate::state::{CloudflareConfig, Server, SubscriptionConfig};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

fn cf_agent() -> Agent {
    Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into()
}

#[derive(Debug, Deserialize)]
struct CfListResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: Vec<CfDnsRecord>,
}

#[derive(Debug, Deserialize)]
struct CfSingleResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    code: u64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CfDnsRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    proxied: bool,
    ttl: u32,
}

#[derive(Serialize)]
struct UpsertRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    proxied: bool,
}

fn format_cf_errors(errors: &[CfError]) -> String {
    if errors.is_empty() {
        "unknown Cloudflare API error".to_owned()
    } else {
        errors
            .iter()
            .map(|e| format!("{}: {}", e.code, e.message))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn cf_get_records(agent: &Agent, cf: &CloudflareConfig, domain: &str) -> Result<Vec<CfDnsRecord>> {
    let url = format!("{CF_API_BASE}/zones/{}/dns_records", cf.zone_id);
    let auth = format!("Bearer {}", cf.api_token.as_str());
    let mut resp = agent
        .get(&url)
        .header("Authorization", &auth)
        .query("name", domain)
        .query("per_page", "100")
        .call()
        .context("Cloudflare DNS list request failed")?;
    let raw = resp
        .body_mut()
        .read_to_string()
        .context("failed reading Cloudflare DNS list response")?;
    let body: CfListResponse =
        serde_json::from_str(&raw).context("failed parsing Cloudflare DNS list JSON")?;
    if !body.success {
        bail!(
            "Cloudflare DNS list error: {}",
            format_cf_errors(&body.errors)
        );
    }
    Ok(body.result)
}

fn cf_create_record(
    agent: &Agent,
    cf: &CloudflareConfig,
    record_type: &str,
    domain: &str,
    content: &str,
) -> Result<()> {
    let url = format!("{CF_API_BASE}/zones/{}/dns_records", cf.zone_id);
    let auth = format!("Bearer {}", cf.api_token.as_str());
    let payload = UpsertRecord {
        record_type,
        name: domain,
        content,
        ttl: cf.ttl,
        proxied: false,
    };
    let json_bytes = serde_json::to_vec(&payload)?;
    let mut resp = agent
        .post(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .send(&json_bytes)
        .with_context(|| format!("Cloudflare DNS create {record_type} request failed"))?;
    let raw = resp
        .body_mut()
        .read_to_string()
        .context("failed reading Cloudflare create response")?;
    let body: CfSingleResponse =
        serde_json::from_str(&raw).context("failed parsing Cloudflare create response JSON")?;
    if !body.success {
        bail!(
            "Cloudflare DNS create {record_type} failed: {}",
            format_cf_errors(&body.errors)
        );
    }
    Ok(())
}

fn cf_patch_record(
    agent: &Agent,
    cf: &CloudflareConfig,
    record_id: &str,
    record_type: &str,
    domain: &str,
    content: &str,
) -> Result<()> {
    let url = format!("{CF_API_BASE}/zones/{}/dns_records/{record_id}", cf.zone_id);
    let auth = format!("Bearer {}", cf.api_token.as_str());
    let payload = UpsertRecord {
        record_type,
        name: domain,
        content,
        ttl: cf.ttl,
        proxied: false,
    };
    let json_bytes = serde_json::to_vec(&payload)?;
    let mut resp = agent
        .patch(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .send(&json_bytes)
        .with_context(|| format!("Cloudflare DNS patch {record_type} request failed"))?;
    let raw = resp
        .body_mut()
        .read_to_string()
        .context("failed reading Cloudflare patch response")?;
    let body: CfSingleResponse =
        serde_json::from_str(&raw).context("failed parsing Cloudflare patch response JSON")?;
    if !body.success {
        bail!(
            "Cloudflare DNS patch {record_type} failed: {}",
            format_cf_errors(&body.errors)
        );
    }
    Ok(())
}

fn cf_delete_record(
    agent: &Agent,
    cf: &CloudflareConfig,
    record_id: &str,
    record_type: &str,
) -> Result<()> {
    let url = format!("{CF_API_BASE}/zones/{}/dns_records/{record_id}", cf.zone_id);
    let auth = format!("Bearer {}", cf.api_token.as_str());
    let mut resp = agent
        .delete(&url)
        .header("Authorization", &auth)
        .call()
        .with_context(|| format!("Cloudflare DNS delete {record_type} request failed"))?;
    let raw = resp
        .body_mut()
        .read_to_string()
        .context("failed reading Cloudflare delete response")?;
    let body: CfSingleResponse =
        serde_json::from_str(&raw).context("failed parsing Cloudflare delete response JSON")?;
    if !body.success {
        bail!(
            "Cloudflare DNS delete {record_type} failed: {}",
            format_cf_errors(&body.errors)
        );
    }
    Ok(())
}

fn sync_single_rr(
    agent: &Agent,
    cf: &CloudflareConfig,
    domain: &str,
    record_type: &str,
    desired_content: Option<&str>,
    existing: &[&CfDnsRecord],
) -> Result<(String, bool)> {
    match desired_content {
        None => {
            if existing.is_empty() {
                return Ok((format!("{record_type}: absent (ok)"), false));
            }
            for rec in existing {
                cf_delete_record(agent, cf, &rec.id, record_type)?;
            }
            Ok((
                format!("{record_type}: deleted {} stale record(s)", existing.len()),
                true,
            ))
        }
        Some(target) => {
            if existing.is_empty() {
                cf_create_record(agent, cf, record_type, domain, target)?;
                return Ok((format!("{record_type}: created -> {target}"), true));
            }
            let first = existing[0];
            let mut changed = false;
            let mut summary = if first.content == target && !first.proxied && first.ttl == cf.ttl {
                format!("{record_type}: unchanged ({target})")
            } else {
                cf_patch_record(agent, cf, &first.id, record_type, domain, target)?;
                changed = true;
                format!("{record_type}: updated -> {target}")
            };
            if existing.len() > 1 {
                for extra in &existing[1..] {
                    cf_delete_record(agent, cf, &extra.id, record_type)?;
                }
                changed = true;
                summary.push_str(&format!(" (removed {} duplicate(s))", existing.len() - 1));
            }
            Ok((summary, changed))
        }
    }
}

pub fn sync_subscription_dns(
    sub: &SubscriptionConfig,
    sub_server: &Server,
) -> Result<(String, bool)> {
    let cf = sub
        .cloudflare
        .as_ref()
        .ok_or_else(|| anyhow!("Cloudflare configuration missing"))?;
    let agent = cf_agent();
    let records = cf_get_records(&agent, cf, &sub.domain)?;
    let a_records: Vec<&CfDnsRecord> = records.iter().filter(|r| r.record_type == "A").collect();
    let aaaa_records: Vec<&CfDnsRecord> =
        records.iter().filter(|r| r.record_type == "AAAA").collect();

    let v4 = sub_server.public_ipv4.to_string();
    let v6 = sub_server.public_ipv6.map(|ip| ip.to_string());
    let (a_status, a_changed) =
        sync_single_rr(&agent, cf, &sub.domain, "A", Some(v4.as_str()), &a_records)?;
    let (aaaa_status, aaaa_changed) = sync_single_rr(
        &agent,
        cf,
        &sub.domain,
        "AAAA",
        v6.as_deref(),
        &aaaa_records,
    )?;
    Ok((
        format!("{a_status}, {aaaa_status}"),
        a_changed || aaaa_changed,
    ))
}
