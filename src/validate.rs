//! Static configuration and invariant validation for encrypted vault state.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, anyhow, bail};
use ssh_key::PublicKey;

use crate::crypto::{decode_32byte_b64, parse_and_verify_hysteria_cert, verify_x25519_pair};
use crate::render::ResolvedFirewallLists;
use crate::render::amneziawg::{render_apply_script, render_server_uapi};
use crate::render::caddy::{compile_subscription_routing, render_caddyfile};
use crate::render::firewall::{render_nftables, render_nftables_for_host, render_sysctl};
use crate::render::ssh_forwarding::{render_authorized_keys, render_sshd_config};
use crate::render::subscriptions::{SubVariant, render_subscription_body};
use crate::render::traffic::{
    render_traffic_config_env, render_traffic_flush_service, render_traffic_service,
    render_traffic_timer, render_traffic_users_conf,
};
use crate::render::xray::render_xray_config;
use crate::state::{AwgObfuscation, IntOrRange, SCHEMA_VERSION, Server, State, parse_range_u32};

fn validate_domain_labels(host: &str, allow_single_label: bool, field: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || (!allow_single_label && !host.contains('.'))
    {
        bail!("{field} must be a valid DNS hostname");
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("{field} contains an invalid DNS label");
        }
    }
    Ok(())
}

/// Validates a DNS hostname (`subscription.domain`).
pub fn validate_hostname(host: &str, field: &str) -> Result<()> {
    validate_domain_labels(host, false, field)
}

/// Validates an admin SSH target hostname or IP without permitting option injection.
pub fn validate_ssh_host(host: &str, field: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 || host.starts_with('-') {
        bail!("{field} must be a valid hostname or IP address without leading '-' or whitespace");
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("{field} must be a valid hostname or IP address without leading '-' or whitespace");
    }
    Ok(())
}

/// Validates an admin SSH username without permitting option injection.
pub fn validate_ssh_user(user: &str, field: &str) -> Result<()> {
    if user.is_empty()
        || user.len() > 64
        || user.starts_with('-')
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("{field} must be a valid POSIX username [A-Za-z0-9._-] without leading '-'");
    }
    Ok(())
}

/// Validates an optional OpenSSH identity file path without permitting option injection.
pub fn validate_ssh_identity_file(path: &str, field: &str) -> Result<()> {
    if path.trim().is_empty()
        || path.len() > 1024
        || path.starts_with('-')
        || path.chars().any(char::is_control)
    {
        bail!(
            "{field} must be a non-empty file path (<= 1024 chars) without leading '-' or control characters"
        );
    }
    Ok(())
}

/// Validates a user map key (`[A-Za-z0-9._-]`).
pub fn validate_user_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("invalid user name {name:?} (expected 1..=64 [A-Za-z0-9._-])");
    }
    Ok(())
}

/// Validates a server identifier (`[a-z0-9_-]`).
pub fn validate_server_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        bail!("server id must use lowercase ASCII [a-z0-9_-]");
    }
    Ok(())
}

/// Validates the secret subscription path prefix (`/token/`).
pub fn validate_base_path(bp: &str) -> Result<()> {
    if bp.len() < 10
        || !bp.starts_with('/')
        || !bp.ends_with('/')
        || bp.contains("//")
        || bp.contains("..")
        || !bp
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_'))
    {
        bail!(
            "subscription.base_path must start and end with '/', have at least 8 inner characters, and use only [A-Za-z0-9/_-]"
        );
    }
    Ok(())
}

/// Validates an optional client subscription profile title (`1..=64` printable UTF-8 chars).
pub fn validate_profile_title(title: &str) -> Result<()> {
    if title.trim().is_empty() || title.chars().count() > 64 {
        bail!("subscription.profile_title must be 1..=64 characters");
    }
    if title.chars().any(char::is_control) {
        bail!("subscription.profile_title must not contain control characters");
    }
    Ok(())
}

fn validate_deep_link(link: &str, prefix: &str, field: &str) -> Result<()> {
    if !link.starts_with(prefix) || link.len() <= prefix.len() {
        bail!("{field} must start with '{prefix}'");
    }
    if !link
        .bytes()
        .all(|b| (0x21..=0x7E).contains(&b) && !matches!(b, b'"' | b'\\' | b'{' | b'}'))
    {
        bail!(
            "{field} must contain only non-whitespace printable ASCII without quotes, backslashes, or braces"
        );
    }
    Ok(())
}

/// Validates an optional `happ://routing/...` deep link.
pub fn validate_happ_link(link: &str) -> Result<()> {
    validate_deep_link(link, "happ://routing/", "subscription.routing.happ_link")
}

/// Validates an optional `throne://route/...` deep link.
pub fn validate_throne_link(link: &str) -> Result<()> {
    validate_deep_link(link, "throne://route/", "subscription.routing.throne_link")
}

/// Normalizes and validates an ISO 3166-1 alpha-2 country code.
pub fn normalize_country_code(raw: &str, field: &str) -> Result<String> {
    let clean = raw.trim().to_ascii_lowercase();
    if clean.len() != 2
        || !clean.bytes().all(|b| b.is_ascii_lowercase())
        || matches!(clean.as_str(), "xx" | "zz")
    {
        bail!("{field} entry {raw:?} must be a 2-letter ISO 3166-1 alpha-2 country code");
    }
    Ok(clean)
}

/// Validates a domain selector (`domain:tld`, `full:host`, `geosite:name`, `keyword:`, `regexp:`, or hostname).
pub fn validate_domain_selector(raw: &str, field: &str) -> Result<()> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\'))
    {
        bail!("{field} entry {raw:?} contains invalid characters or is empty");
    }
    if let Some((prefix, rest)) = trimmed.split_once(':') {
        let p_lower = prefix.to_ascii_lowercase();
        match p_lower.as_str() {
            "geosite" => {
                if rest.is_empty()
                    || !rest.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-')
                    })
                {
                    bail!("{field} geosite selector {raw:?} is invalid");
                }
            }
            "domain" => {
                let host = rest.strip_prefix('.').unwrap_or(rest);
                validate_domain_labels(host, true, field)?;
            }
            "full" => {
                validate_domain_labels(rest, false, field)?;
            }
            "keyword" | "regexp" => {
                if rest.is_empty() {
                    bail!("{field} selector {raw:?} must have a non-empty pattern");
                }
            }
            _ => bail!("{field} entry {raw:?} uses an unsupported selector prefix"),
        }
    } else {
        validate_hostname(trimmed, field)?;
    }
    Ok(())
}

/// Parses an IP address or CIDR literal and canonicalizes host bits via `trunc()`.
pub fn parse_cidr_or_ip(raw: &str, field: &str) -> Result<ipnet::IpNet> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("{field} entry {raw:?} is empty or contains invalid characters");
    }
    if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
        return Ok(net.trunc());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ipnet::IpNet::from(ip));
    }
    bail!("{field} entry {raw:?} must be an IP address or CIDR")
}

/// Validates a URL path (`2..=128` chars starting with '/', no whitespace, '?', '#', or control chars).
fn validate_url_path(path: &str, field: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() < 2
        || path.len() > 128
        || path
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '?' | '#') || c.is_control())
    {
        bail!(
            "{field} must be a 2..=128 character URL path starting with '/' without whitespace, '?', or '#'"
        );
    }
    Ok(())
}

/// Validates an IP selector (`geoip:<cc|private>`, IP address, or CIDR).
fn validate_ip_selector(raw: &str, field: &str) -> Result<()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("{field} entry {raw:?} is empty or contains invalid characters");
    }
    if trimmed
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("geoip:"))
    {
        let rest = &trimmed[6..];
        if rest.is_empty()
            || !rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            bail!("{field} geoip selector {raw:?} is invalid");
        }
        return Ok(());
    }
    if trimmed.parse::<IpAddr>().is_ok() || trimmed.parse::<ipnet::IpNet>().is_ok() {
        return Ok(());
    }
    bail!("{field} entry {raw:?} must be an IP address, CIDR, or geoip:<code|private>")
}

fn validate_global_dns_ip(ip: IpAddr, field: &str) -> Result<()> {
    let disallowed = match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4_dial(v4),
        IpAddr::V6(v6) => is_disallowed_ipv6_dial(v6),
    };
    if disallowed {
        bail!("{field} must not target loopback, private, link-local, or reserved IP {ip}");
    }
    Ok(())
}

fn validate_xray_dns_server(entry: &str, blocked_cidrs: &[ipnet::IpNet]) -> Result<()> {
    let trimmed = entry.trim();
    if let Some(rest) = trimmed.strip_prefix("https+local://") {
        let as_https = format!("https://{rest}");
        let host = parse_http_url_host(&as_https, "dns.xray_servers", true)?;
        if let Ok(ip) = host.parse::<IpAddr>()
            && blocked_cidrs.iter().any(|net| net.contains(&ip))
        {
            bail!("dns.xray_servers resolver {ip} is blocked by firewall.block_cidrs");
        }
        return Ok(());
    }
    let ip: IpAddr = trimmed.parse().map_err(|_| {
        anyhow!("dns.xray_servers entry {entry:?} must be an 'https+local://' DoH URL or global IP address")
    })?;
    validate_global_dns_ip(ip, "dns.xray_servers")?;
    if blocked_cidrs.iter().any(|net| net.contains(&ip)) {
        bail!("dns.xray_servers resolver {ip} is blocked by firewall.block_cidrs");
    }
    Ok(())
}

/// Validates an optional human-readable note on a user or server (`1..=256` non-control chars).
pub fn validate_note(note: &str, field: &str) -> Result<()> {
    if note.trim().is_empty() || note.chars().count() > 256 {
        bail!("{field} must be 1..=256 characters when set");
    }
    if note.chars().any(char::is_control) {
        bail!("{field} must not contain control characters");
    }
    Ok(())
}

fn is_disallowed_ipv4_dial(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || o[0] == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || o[0] >= 240
}

fn is_disallowed_ipv6_dial(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_disallowed_ipv4_dial(v4);
    }
    let seg0 = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (seg0 & 0xFE00) == 0xFC00
        || (seg0 & 0xFFC0) == 0xFE80
}

fn validate_non_local_dial_host(host: &str, field: &str) -> Result<()> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        bail!("{field} dial host must not be empty");
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        bail!("{field} must not target localhost");
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        let disallowed = match ip {
            IpAddr::V4(v4) => is_disallowed_ipv4_dial(v4),
            IpAddr::V6(v6) => is_disallowed_ipv6_dial(v6),
        };
        if disallowed {
            bail!("{field} must not target loopback, private, link-local, or reserved IP {ip}");
        }
    }
    Ok(())
}

fn parse_http_url_host<'a>(url: &'a str, field: &str, require_https: bool) -> Result<&'a str> {
    let rest = if require_https {
        url.strip_prefix("https://")
            .ok_or_else(|| anyhow!("{field} must start with https://"))?
    } else {
        url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .ok_or_else(|| anyhow!("{field} must start with http:// or https://"))?
    };
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("{field} must not contain whitespace or control characters");
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        bail!("{field} must specify a valid host without embedded credentials");
    }
    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((ip_str, tail)) = after_bracket.split_once(']') else {
            bail!("{field} has malformed bracketed IPv6 host");
        };
        ip_str
            .parse::<Ipv6Addr>()
            .map_err(|_| anyhow!("{field} has invalid bracketed IPv6 host"))?;
        if !tail.is_empty() {
            let port_str = tail
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("{field} has invalid IPv6 host:port"))?;
            let port: u16 = port_str
                .parse()
                .map_err(|_| anyhow!("{field} has invalid port"))?;
            if port == 0 {
                bail!("{field} port must be >= 1");
            }
        }
        ip_str
    } else if let Some((h, port_str)) = authority.rsplit_once(':') {
        if h.contains(':') || h.contains('[') || h.contains(']') {
            bail!("{field} IPv6 addresses must be bracketed as [ipv6]:port");
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow!("{field} has invalid port"))?;
        if port == 0 {
            bail!("{field} port must be >= 1");
        }
        validate_ssh_host(h, field)?;
        h
    } else {
        if authority.contains(':') || authority.contains('[') || authority.contains(']') {
            bail!("{field} IPv6 addresses must be bracketed as [ipv6]");
        }
        validate_ssh_host(authority, field)?;
        authority
    };
    validate_non_local_dial_host(host, field)?;
    Ok(host)
}

fn validate_http_url(url: &str, field: &str, require_https: bool) -> Result<()> {
    let _ = parse_http_url_host(url, field, require_https)?;
    Ok(())
}

fn validate_country_url_template(tpl: &str, field: &str) -> Result<()> {
    if !tpl.contains("{cc}") {
        bail!("{field} must contain the '{{cc}}' country-code placeholder");
    }
    let sample = tpl.replace("{cc}", "de");
    validate_http_url(&sample, field, true)
}

fn validate_artifact_pair(
    url: Option<&str>,
    sha256: Option<&str>,
    url_field: &str,
    sha_field: &str,
) -> Result<()> {
    match (url, sha256) {
        (None, None) => Ok(()),
        (Some(u), Some(digest)) => {
            validate_http_url(u, url_field, true)?;
            let clean = digest.trim();
            if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("{sha_field} must be a 64-character hexadecimal SHA-256 digest");
            }
            Ok(())
        }
        _ => bail!("{url_field} and {sha_field} must both be set together"),
    }
}

fn is_valid_uuid(uuid: &str) -> bool {
    let parts: Vec<&str> = uuid.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens)
        .all(|(p, len)| p.len() == len && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_valid_short_id(sid: &str) -> bool {
    !sid.is_empty()
        && sid.len() <= 16
        && sid.len().is_multiple_of(2)
        && sid.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_target_host<'a>(target: &'a str, field: &str) -> Result<&'a str> {
    let (host, port_str) = if let Some(rest) = target.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once("]:") else {
            bail!("{field} must be in host:port or [ipv6]:port format");
        };
        host.parse::<Ipv6Addr>()
            .map_err(|_| anyhow!("{field} has an invalid bracketed IPv6 host"))?;
        (host, tail)
    } else {
        let Some((host, p)) = target.rsplit_once(':') else {
            bail!("{field} must be in host:port format");
        };
        if host.contains(':') || host.contains('[') || host.contains(']') {
            bail!("{field} IPv6 addresses must be bracketed as [ipv6]:port");
        }
        validate_ssh_host(host, field)?;
        (host, p)
    };
    validate_non_local_dial_host(host, field)?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("{field} has an invalid port"))?;
    if port == 0 {
        bail!("{field} port must be >= 1");
    }
    Ok(host)
}

pub(crate) fn validate_target_host_port(target: &str, field: &str) -> Result<()> {
    let _ = parse_target_host(target, field)?;
    Ok(())
}

fn validate_awg_header_ranges(ranges: &[(&str, &IntOrRange)], scope: &str) -> Result<()> {
    let mut header_ranges = Vec::with_capacity(ranges.len());
    for &(name, val) in ranges {
        let field = format!("{scope}.{name}");
        let (lo, hi) = val.bounds(&field)?;
        if lo == 0 {
            bail!("{scope}.{name} must be >= 1");
        }
        header_ranges.push((lo, hi));
    }
    for i in 0..header_ranges.len() {
        for j in (i + 1)..header_ranges.len() {
            let (a_lo, a_hi) = header_ranges[i];
            let (b_lo, b_hi) = header_ranges[j];
            if a_lo <= b_hi && b_lo <= a_hi {
                bail!("{scope}: amneziawg h1..h4 values/ranges must not overlap");
            }
        }
    }
    Ok(())
}

fn validate_awg_cps_line(val: &str, scope: &str, name: &str) -> Result<()> {
    if val.trim().is_empty() || val.chars().any(char::is_control) {
        bail!(
            "{scope}: amneziawg {name} must be a non-empty single line without control characters"
        );
    }
    Ok(())
}

fn validate_awg_obfuscation(obf: &AwgObfuscation, server_id: &str) -> Result<()> {
    let scope = format!("server.{server_id}.amneziawg");
    if obf.jc == 0 || obf.jc > 128 {
        bail!("server {server_id}: amneziawg jc must be in 1..=128");
    }
    if obf.jmin == 0 || obf.jmin > obf.jmax || obf.jmax > 1280 {
        bail!("server {server_id}: amneziawg jmin/jmax must satisfy 1 <= jmin <= jmax <= 1280");
    }
    for (name, val) in [
        ("s1", obf.s1),
        ("s2", obf.s2),
        ("s3", obf.s3),
        ("s4", obf.s4),
    ] {
        if !(12..=1024).contains(&val) {
            bail!(
                "server {server_id}: amneziawg {name} must be in 12..=1024 for header protection nonce"
            );
        }
    }
    // 148 + S1 != 92 + S2 prevents padded handshake init and response packet lengths colliding.
    if u32::from(obf.s1) + 148 == u32::from(obf.s2) + 92 {
        bail!(
            "server {server_id}: amneziawg handshake init and response lengths collide (148 + s1 == 92 + s2)"
        );
    }

    validate_awg_header_ranges(
        &[
            ("h1", &obf.h1),
            ("h2", &obf.h2),
            ("h3", &obf.h3),
            ("h4", &obf.h4),
        ],
        &scope,
    )?;

    validate_awg_cps_line(&obf.i1, &format!("server {server_id}"), "i1")?;
    for (name, opt) in [
        ("i2", &obf.i2),
        ("i3", &obf.i3),
        ("i4", &obf.i4),
        ("i5", &obf.i5),
    ] {
        if let Some(val) = opt {
            validate_awg_cps_line(val, &format!("server {server_id}"), name)?;
        }
    }
    decode_32byte_b64(obf.header_protection_key.as_str())?;
    obf.content_padding_addition
        .validate(&format!("{scope}.content_padding_addition"))?;
    Ok(())
}

fn validate_vless_sni_value(state: &State, sni: &str, field: &str) -> Result<()> {
    validate_hostname(sni, field)?;
    if sni.trim().eq_ignore_ascii_case(&state.subscription.domain) {
        bail!(
            "{field} ({sni}) must not match subscription.domain ({}); REALITY must masquerade as an unrelated external site",
            state.subscription.domain
        );
    }
    Ok(())
}

fn validate_vless_target_value(state: &State, target: &str, field: &str) -> Result<()> {
    let target_host = parse_target_host(target, field)?;
    if target_host.eq_ignore_ascii_case(&state.subscription.domain) {
        bail!(
            "{field} ({target}) must not point at subscription.domain ({})",
            state.subscription.domain
        );
    }
    if let Ok(target_ip) = target_host.parse::<IpAddr>() {
        if state.servers.iter().any(|s| {
            IpAddr::V4(s.public_ipv4) == target_ip
                || s.public_ipv6.map(IpAddr::V6) == Some(target_ip)
        }) {
            bail!("{field} ({target}) must not point at a managed server IP ({target_ip})");
        }
        for raw_cidr in &state.settings.firewall.block_cidrs {
            let net = parse_cidr_or_ip(raw_cidr, "firewall.block_cidrs")?;
            if net.contains(&target_ip) {
                bail!(
                    "{field} ({target}) target IP {target_ip} is blocked by firewall.block_cidrs"
                );
            }
        }
    }
    Ok(())
}

fn validate_vless_xhttp_host_value(state: &State, host: &str, field: &str) -> Result<()> {
    validate_hostname(host, field)?;
    if host.trim().eq_ignore_ascii_case(&state.subscription.domain) {
        bail!(
            "{field} ({host}) must not match subscription.domain ({})",
            state.subscription.domain
        );
    }
    Ok(())
}

fn validate_settings(state: &State) -> Result<()> {
    let settings = &state.settings;
    let awg_subnet = settings.validated_awg_subnet()?;

    let fw = &settings.firewall;
    for cc in &fw.block_countries {
        normalize_country_code(cc, "firewall.block_countries")?;
    }
    let mut blocked_cidrs = Vec::with_capacity(fw.block_cidrs.len());
    for cidr in &fw.block_cidrs {
        blocked_cidrs.push(parse_cidr_or_ip(cidr, "firewall.block_cidrs")?);
    }
    let (blocked_egress_v4, _) = crate::render::firewall::static_egress_cidrs(fw)?;
    for url in &fw.block_ip_lists {
        validate_http_url(url, "firewall.block_ip_lists", true)?;
    }
    if fw.auto_update.interval_hours == 0 {
        bail!("firewall.auto_update.interval_hours must be >= 1");
    }
    validate_country_url_template(
        &fw.auto_update.ipv4_country_url,
        "firewall.auto_update.ipv4_country_url",
    )?;
    validate_country_url_template(
        &fw.auto_update.ipv6_country_url,
        "firewall.auto_update.ipv6_country_url",
    )?;
    for domain in &fw.xray.block_domains {
        validate_domain_selector(domain, "firewall.xray.block_domains")?;
    }
    for url in &fw.xray.block_domain_lists {
        validate_http_url(url, "firewall.xray.block_domain_lists", true)?;
    }

    if !(1..=8).contains(&settings.dns.xray_servers.len()) {
        bail!("dns.xray_servers must contain 1 to 8 resolvers");
    }
    for entry in &settings.dns.xray_servers {
        validate_xray_dns_server(entry, &blocked_cidrs)?;
    }
    if settings.dns.amneziawg_servers.is_empty() || settings.dns.amneziawg_servers.len() > 4 {
        bail!("dns.amneziawg_servers must contain 1 to 4 IPv4 addresses");
    }
    for &dns in &settings.dns.amneziawg_servers {
        if dns.is_unspecified()
            || dns.is_loopback()
            || dns.is_link_local()
            || dns.is_multicast()
            || dns.is_broadcast()
        {
            bail!("dns.amneziawg_servers contains invalid DNS address {dns}");
        }
        if awg_subnet.contains(&dns) {
            bail!(
                "dns.amneziawg_servers address {dns} must not fall inside amneziawg.subnet ({awg_subnet})"
            );
        }
        if blocked_egress_v4.iter().any(|net| net.contains(&dns)) {
            bail!(
                "dns.amneziawg_servers address {dns} is blocked by firewall rules (private networks or firewall.block_cidrs)"
            );
        }
    }

    if settings.subscription.update_interval_hours == 0 {
        bail!("subscription.update_interval_hours must be >= 1");
    }
    if let Some(title) = &settings.subscription.profile_title {
        validate_profile_title(title)?;
    }

    let routing = &settings.subscription.routing;
    for cc in &routing.bypass_countries {
        normalize_country_code(cc, "subscription.routing.bypass_countries")?;
    }
    for cc in &routing.block_countries {
        normalize_country_code(cc, "subscription.routing.block_countries")?;
    }
    for domain in &routing.direct_domains {
        validate_domain_selector(domain, "subscription.routing.direct_domains")?;
    }
    for domain in &routing.proxy_domains {
        validate_domain_selector(domain, "subscription.routing.proxy_domains")?;
    }
    for domain in &routing.block_domains {
        validate_domain_selector(domain, "subscription.routing.block_domains")?;
    }
    for ip in &routing.direct_ips {
        validate_ip_selector(ip, "subscription.routing.direct_ips")?;
    }
    for ip in &routing.proxy_ips {
        validate_ip_selector(ip, "subscription.routing.proxy_ips")?;
    }
    for ip in &routing.block_ips {
        validate_ip_selector(ip, "subscription.routing.block_ips")?;
    }
    validate_http_url(
        &routing.domestic_doh,
        "subscription.routing.domestic_doh",
        true,
    )?;
    validate_global_dns_ip(
        routing.domestic_dns_ip,
        "subscription.routing.domestic_dns_ip",
    )?;
    validate_http_url(&routing.remote_doh, "subscription.routing.remote_doh", true)?;
    validate_global_dns_ip(routing.remote_dns_ip, "subscription.routing.remote_dns_ip")?;
    if let Some(link) = &routing.happ_link {
        validate_happ_link(link)?;
    }
    if let Some(link) = &routing.throne_link {
        validate_throne_link(link)?;
    }
    let _ = compile_subscription_routing(routing)?;

    if settings.sysctl.udp_rmem_default == 0
        || settings.sysctl.udp_wmem_default == 0
        || settings.sysctl.udp_rmem_max < settings.sysctl.udp_rmem_default
        || settings.sysctl.udp_wmem_max < settings.sysctl.udp_wmem_default
    {
        bail!("sysctl buffer limits are inconsistent or zero");
    }

    let vless = &settings.vless;
    if vless.enabled && !vless.stream && !vless.packet {
        bail!("vless.stream or vless.packet must be true when vless.enabled is true");
    }
    if let Some(sni) = &vless.sni {
        validate_vless_sni_value(state, sni, "vless.sni")?;
    }
    if let Some(target) = &vless.target {
        validate_vless_target_value(state, target, "vless.target")?;
    }
    if let Some(host) = &vless.xhttp_host {
        validate_vless_xhttp_host_value(state, host, "vless.xhttp_host")?;
    }
    const SUPPORTED_FINGERPRINTS: &[&str] = &[
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
    ];
    if !SUPPORTED_FINGERPRINTS.contains(&vless.fingerprint.as_str()) {
        bail!(
            "vless.fingerprint {:?} is invalid (expected one of: {})",
            vless.fingerprint,
            SUPPORTED_FINGERPRINTS.join(", ")
        );
    }
    if let Some(ref xhttp_path) = vless.xhttp.path {
        validate_url_path(xhttp_path, "vless.xhttp.path")?;
    }
    parse_range_u32(&vless.xhttp.padding_bytes, "vless.xhttp.padding_bytes")?;
    if vless.xhttp.sc_max_buffered_posts == 0 {
        bail!("vless.xhttp.sc_max_buffered_posts must be >= 1");
    }
    vless.xmux.validate()?;

    let h2 = &settings.hysteria2;
    if h2.alpn.is_empty() || h2.alpn.iter().any(|a| a.trim().is_empty()) {
        bail!("hysteria2.alpn must contain at least one non-empty ALPN token");
    }
    validate_http_url(&h2.masquerade_url, "hysteria2.masquerade_url", false)?;
    if h2.udp_idle_timeout_secs < 5 {
        bail!("hysteria2.udp_idle_timeout_secs must be >= 5");
    }

    let awg = &settings.amneziawg;
    if awg.mtu < 1280 || awg.mtu > 1500 {
        bail!("amneziawg.mtu must be in 1280..=1500");
    }
    awg.rekey_after_time
        .validate("amneziawg.rekey_after_time")?;
    awg.rekey_timeout.validate("amneziawg.rekey_timeout")?;
    awg.reject_after_time
        .validate("amneziawg.reject_after_time")?;
    awg.keepalive_timeout
        .validate("amneziawg.keepalive_timeout")?;
    awg.max_handshake_attempts
        .validate("amneziawg.max_handshake_attempts")?;
    let obf = &awg.obfuscation;
    if let Some(jc) = obf.jc
        && (jc == 0 || jc > 128)
    {
        bail!("amneziawg.obfuscation.jc must be in 1..=128");
    }
    if let Some(jmin) = obf.jmin
        && (jmin == 0 || jmin > 1280)
    {
        bail!("amneziawg.obfuscation.jmin must be in 1..=1280");
    }
    if let Some(jmax) = obf.jmax
        && (jmax == 0 || jmax > 1280)
    {
        bail!("amneziawg.obfuscation.jmax must be in 1..=1280");
    }
    if let (Some(jmin), Some(jmax)) = (obf.jmin, obf.jmax)
        && jmin > jmax
    {
        bail!("amneziawg.obfuscation.jmin ({jmin}) must be <= amneziawg.obfuscation.jmax ({jmax})");
    }
    for (name, opt) in [
        ("s1", obf.s1),
        ("s2", obf.s2),
        ("s3", obf.s3),
        ("s4", obf.s4),
    ] {
        if let Some(val) = opt
            && !(12..=1024).contains(&val)
        {
            bail!("amneziawg.obfuscation.{name} must be in 12..=1024 for header protection nonce");
        }
    }
    if let (Some(s1), Some(s2)) = (obf.s1, obf.s2)
        && u32::from(s1) + 148 == u32::from(s2) + 92
    {
        bail!(
            "amneziawg.obfuscation handshake init and response lengths collide (148 + s1 == 92 + s2)"
        );
    }
    let set_headers: Vec<(&str, &IntOrRange)> = [
        ("h1", obf.h1.as_ref()),
        ("h2", obf.h2.as_ref()),
        ("h3", obf.h3.as_ref()),
        ("h4", obf.h4.as_ref()),
    ]
    .into_iter()
    .filter_map(|(name, opt)| opt.map(|v| (name, v)))
    .collect();
    if !set_headers.is_empty() {
        validate_awg_header_ranges(&set_headers, "amneziawg.obfuscation")?;
    }
    for (name, opt) in [
        ("i1", &obf.i1),
        ("i2", &obf.i2),
        ("i3", &obf.i3),
        ("i4", &obf.i4),
        ("i5", &obf.i5),
    ] {
        if let Some(val) = opt {
            validate_awg_cps_line(val, "amneziawg.obfuscation", name)?;
        }
    }
    if let Some(ref cpa) = obf.content_padding_addition {
        cpa.validate("amneziawg.obfuscation.content_padding_addition")?;
    }

    if !(1..=3650).contains(&settings.traffic.retention_days) {
        bail!("traffic.retention_days must be in 1..=3650");
    }

    validate_artifact_pair(
        settings.artifacts.xray_zip_url.as_deref(),
        settings.artifacts.xray_zip_sha256.as_deref(),
        "artifacts.xray_zip_url",
        "artifacts.xray_zip_sha256",
    )?;
    validate_artifact_pair(
        settings.artifacts.geoip_url.as_deref(),
        settings.artifacts.geoip_sha256.as_deref(),
        "artifacts.geoip_url",
        "artifacts.geoip_sha256",
    )?;
    validate_artifact_pair(
        settings.artifacts.geosite_url.as_deref(),
        settings.artifacts.geosite_sha256.as_deref(),
        "artifacts.geosite_url",
        "artifacts.geosite_sha256",
    )?;
    validate_artifact_pair(
        settings.artifacts.amneziawg_url.as_deref(),
        settings.artifacts.amneziawg_sha256.as_deref(),
        "artifacts.amneziawg_url",
        "artifacts.amneziawg_sha256",
    )?;
    Ok(())
}

fn validate_server(
    state: &State,
    server: &Server,
    vless_pubs: &mut HashSet<String>,
    awg_pubs: &mut HashSet<String>,
    ssh_pubs: &mut HashSet<String>,
) -> Result<()> {
    validate_server_id(&server.id)?;
    if server.label.trim().is_empty() || server.label.chars().any(|c| c.is_control() || c == '#') {
        bail!(
            "server {}: label must not be empty or contain # or control characters",
            server.id
        );
    }
    if let Some(note) = &server.note {
        validate_note(note, &format!("server.{}.note", server.id))?;
    }

    if server.public_ipv4.is_unspecified()
        || server.public_ipv4.is_loopback()
        || server.public_ipv4.is_link_local()
        || server.public_ipv4.is_multicast()
        || server.public_ipv4.is_broadcast()
    {
        bail!(
            "server {}: invalid public_ipv4 {}",
            server.id,
            server.public_ipv4
        );
    }
    if let Some(ip6) = server.public_ipv6
        && (ip6.is_unspecified()
            || ip6.is_loopback()
            || ip6.is_multicast()
            || ip6.to_ipv4_mapped().is_some()
            || (ip6.segments()[0] & 0xFFC0) == 0xFE80)
    {
        bail!("server {}: invalid public_ipv6 {ip6}", server.id);
    }

    validate_ssh_host(
        &server.admin_ssh.host,
        &format!("server.{}.admin_ssh.host", server.id),
    )?;
    validate_ssh_user(
        &server.admin_ssh.user,
        &format!("server.{}.admin_ssh.user", server.id),
    )?;
    if let Some(identity_file) = &server.admin_ssh.identity_file {
        validate_ssh_identity_file(
            identity_file,
            &format!("server.{}.admin_ssh.identity_file", server.id),
        )?;
    }
    PublicKey::from_openssh(server.admin_ssh.host_public_key.trim())
        .map_err(|_| anyhow!("server {}: invalid admin_ssh.host_public_key", server.id))?;

    let is_sub = state.is_subscription_server(&server.id);
    let eff = server.effective_config(&state.settings, is_sub);
    if server.enabled
        && !eff.has_vless
        && !eff.has_hysteria2
        && !eff.has_amneziawg
        && !eff.is_subscription
        && !eff.has_ssh_forwarding
    {
        bail!(
            "enabled server {}: must have at least one active service (vpn protocol or subscription)",
            server.id
        );
    }

    // Active TCP & UDP port collision checks within a single server.
    let mut tcp_ports = HashSet::new();
    tcp_ports.insert(server.admin_ssh.port.get());
    if eff.has_vless && !tcp_ports.insert(eff.vless_port) {
        bail!(
            "server {}: VLESS TCP port {} collides with another service",
            server.id,
            eff.vless_port
        );
    }
    if eff.is_subscription && (!tcp_ports.insert(80) || !tcp_ports.insert(443)) {
        bail!(
            "server {}: subscription HTTP/HTTPS ports 80/443 collide with another service",
            server.id
        );
    }
    if eff.has_ssh_forwarding && !tcp_ports.insert(eff.ssh_forwarding_port) {
        bail!(
            "server {}: SSH forwarding TCP port {} collides with another service",
            server.id,
            eff.ssh_forwarding_port
        );
    }

    if eff.has_hysteria2 && eff.has_amneziawg && eff.hysteria2_port == eff.amneziawg_port {
        bail!(
            "server {}: UDP ports hysteria2 ({}) and amneziawg ({}) must be distinct",
            server.id,
            eff.hysteria2_port,
            eff.amneziawg_port
        );
    }

    if let Some(vpn) = &server.vpn {
        if let Some(ref protos) = vpn.protocols
            && protos.is_empty()
        {
            bail!(
                "server {}: vpn.protocols must not be empty when set",
                server.id
            );
        }
        if eff.vless_wanted && !state.settings.vless.stream && !state.settings.vless.packet {
            bail!(
                "server {}: VLESS is enabled via server protocols override, so vless.stream or vless.packet must be true in config.toml",
                server.id
            );
        }
        let vr = &vpn.vless;
        if let Some(sni) = &vr.sni {
            validate_vless_sni_value(state, sni, &format!("server.{}.vpn.vless.sni", server.id))?;
        }
        if let Some(target) = &vr.target {
            validate_vless_target_value(
                state,
                target,
                &format!("server.{}.vpn.vless.target", server.id),
            )?;
        }
        if let Some(xhttp_host) = &vr.xhttp_host {
            validate_vless_xhttp_host_value(
                state,
                xhttp_host,
                &format!("server.{}.vpn.vless.xhttp_host", server.id),
            )?;
        }
        if eff.has_vless {
            let Some((eff_sni, _)) = &eff.vless_sni else {
                bail!(
                    "server {}: VLESS is enabled but neither server.vpn.vless.sni nor [vless].sni is configured",
                    server.id
                );
            };
            validate_vless_sni_value(
                state,
                eff_sni,
                &format!("server.{}.effective.vless.sni", server.id),
            )?;
            let Some((eff_target, _)) = &eff.vless_target else {
                bail!(
                    "server {}: VLESS is enabled but effective target could not be resolved",
                    server.id
                );
            };
            validate_vless_target_value(
                state,
                eff_target,
                &format!("server.{}.effective.vless.target", server.id),
            )?;
            if let Some((eff_host, _)) = &eff.vless_xhttp_host {
                validate_vless_xhttp_host_value(
                    state,
                    eff_host,
                    &format!("server.{}.effective.vless.xhttp_host", server.id),
                )?;
            }
        }
        validate_url_path(
            &vr.xhttp_path,
            &format!("server.{}.vpn.vless.xhttp_path", server.id),
        )?;
        let vr_pub = vr
            .public_key()
            .map_err(|_| anyhow!("server {}: invalid REALITY X25519 private key", server.id))?;
        verify_x25519_pair(vr.private_key.as_str(), &vr_pub).map_err(|_| {
            anyhow!(
                "server {}: REALITY X25519 keypair derivation failed",
                server.id
            )
        })?;
        if !vless_pubs.insert(vr_pub) {
            bail!("server {}: duplicate REALITY public key", server.id);
        }
        if !is_valid_short_id(&vr.short_id) {
            bail!("server {}: invalid REALITY short_id", server.id);
        }

        let h2 = &vpn.hysteria2;
        if h2.salamander_password.len() < 8 || h2.salamander_password.chars().any(char::is_control)
        {
            bail!(
                "server {}: Hysteria2 salamander_password is too short or invalid",
                server.id
            );
        }
        parse_and_verify_hysteria_cert(
            &h2.cert_pem,
            h2.key_pem.as_str(),
            &server.public_ipv4.to_string(),
        )
        .map_err(|e| anyhow!("server {}: {e}", server.id))?;

        let awg = &vpn.amneziawg;
        let awg_pub = awg.public_key().map_err(|_| {
            anyhow!(
                "server {}: invalid AmneziaWG server X25519 private key",
                server.id
            )
        })?;
        verify_x25519_pair(awg.private_key.as_str(), &awg_pub).map_err(|_| {
            anyhow!(
                "server {}: AmneziaWG server X25519 keypair derivation failed",
                server.id
            )
        })?;
        if !awg_pubs.insert(awg_pub) {
            bail!("server {}: duplicate AmneziaWG public key", server.id);
        }
        validate_awg_obfuscation(&awg.obfuscation, &server.id)?;
        if let Some(ref merged_obf) = eff.awg_obfuscation {
            validate_awg_obfuscation(merged_obf, &server.id)?;
        }

        let host_pub = vpn.ssh_forwarding.host_public_key().map_err(|e| {
            anyhow!(
                "server {}: invalid ssh_forwarding host private key: {e}",
                server.id
            )
        })?;
        if !ssh_pubs.insert(host_pub.trim().to_owned()) {
            bail!(
                "server {}: duplicate ssh_forwarding host public key",
                server.id
            );
        }
    }

    Ok(())
}

/// Validates Cloudflare DNS zone ID format and record TTL bounds.
pub fn validate_cloudflare_zone_and_ttl(zone_id: &str, ttl: u32) -> Result<()> {
    if zone_id.is_empty()
        || zone_id.len() > 64
        || !zone_id.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        bail!("subscription.cloudflare.zone_id is invalid");
    }
    if ttl != 1 && !(60..=86400).contains(&ttl) {
        bail!("subscription.cloudflare.ttl must be 1 (auto) or 60..=86400");
    }
    Ok(())
}

/// Validates schema invariants, key derivation, TLS certificates, ports, and trial config renders.
pub fn validate_state(state: &State) -> Result<()> {
    if state.schema_version != SCHEMA_VERSION {
        bail!("unsupported schema_version {}", state.schema_version);
    }
    if state.revision < 1 {
        bail!("state revision must be >= 1");
    }

    validate_settings(state)?;

    validate_hostname(&state.subscription.domain, "subscription.domain")?;
    validate_base_path(state.subscription.base_path.as_str())?;
    if let Some(sub_id) = &state.subscription.server_id
        && !state.servers.iter().any(|s| s.id == *sub_id)
    {
        bail!("subscription.server_id references unknown server {sub_id:?}");
    }
    if let Some(cf) = &state.subscription.cloudflare {
        validate_cloudflare_zone_and_ttl(&cf.zone_id, cf.ttl)?;
        if cf.api_token.trim().is_empty() || cf.api_token.chars().any(char::is_whitespace) {
            bail!("subscription.cloudflare.api_token is invalid");
        }
    }

    let mut max_uid = 0u32;
    let mut uids = HashSet::new();
    let mut tokens = HashSet::new();
    let mut uuids = HashSet::new();
    let mut hyst_auths = HashSet::new();
    let mut awg_pubs = HashSet::new();
    let mut ssh_pubs = HashSet::new();

    for (name, user) in &state.users {
        validate_user_name(name)?;
        if let Some(note) = &user.note {
            validate_note(note, &format!("users.{name}.note"))?;
        }
        if user.uid == 0 || !uids.insert(user.uid) {
            bail!("duplicate or zero user uid {}", user.uid);
        }
        max_uid = max_uid.max(user.uid);
        let _ = state.settings.awg_user_cidr(user.uid)?;

        let tok = user.subscription_token.as_str();
        if !(16..=128).contains(&tok.len())
            || !tok
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || !tokens.insert(tok)
        {
            bail!(
                "invalid or duplicate subscription_token for uid {}",
                user.uid
            );
        }

        if !is_valid_uuid(user.vless.uuid.as_str())
            || !uuids.insert(user.vless.uuid.to_ascii_lowercase())
        {
            bail!("invalid or duplicate VLESS UUID for uid {}", user.uid);
        }
        validate_url_path(
            &user.vless.spider_x,
            &format!("users.{name}.vless.spider_x"),
        )?;

        let auth = user.hysteria2.auth.as_str();
        if auth.len() < 8
            || auth.chars().any(|c| c.is_whitespace() || c.is_control())
            || !hyst_auths.insert(auth)
        {
            bail!(
                "invalid or duplicate Hysteria2 auth credential for uid {}",
                user.uid
            );
        }

        let awg_pub = user
            .amneziawg_public_key()
            .map_err(|_| anyhow!("invalid AmneziaWG X25519 private key for uid {}", user.uid))?;
        if !awg_pubs.insert(awg_pub) {
            bail!("duplicate AmneziaWG public key for uid {}", user.uid);
        }
        let awg_psk = decode_32byte_b64(user.amneziawg.preshared_key.as_str()).map_err(|_| {
            anyhow!(
                "invalid AmneziaWG pre-shared key for uid {} (expected 32-byte base64)",
                user.uid
            )
        })?;
        if awg_psk.iter().all(|&b| b == 0) {
            bail!(
                "AmneziaWG pre-shared key for uid {} must not be all zeros",
                user.uid
            );
        }

        let ssh_pub = user
            .ssh_public_key()
            .map_err(|e| anyhow!("invalid SSH Ed25519 private key for uid {}: {e}", user.uid))?;
        if !ssh_pubs.insert(ssh_pub) {
            bail!("duplicate SSH public key for uid {}", user.uid);
        }
    }

    if state.next_uid == 0 || state.next_uid <= max_uid {
        bail!(
            "next_uid ({}) must be >= 1 and > max existing uid ({max_uid})",
            state.next_uid
        );
    }

    let mut server_ids = HashSet::new();
    let mut server_labels = HashSet::new();
    let mut server_ips = HashSet::new();
    let mut server_ipv6s = HashSet::new();
    let mut srv_vless_pubs = HashSet::new();
    let mut srv_awg_pubs = HashSet::new();
    let mut srv_ssh_pubs = HashSet::new();

    for server in &state.servers {
        if !server_ids.insert(server.id.as_str()) {
            bail!("duplicate server id {}", server.id);
        }
        if !server_labels.insert(server.label.as_str()) {
            bail!("duplicate server label for server {}", server.id);
        }
        if !server_ips.insert(server.public_ipv4) {
            bail!("duplicate server public_ipv4 for server {}", server.id);
        }
        if let Some(ip6) = server.public_ipv6
            && !server_ipv6s.insert(ip6)
        {
            bail!("duplicate server public_ipv6 for server {}", server.id);
        }
        validate_server(
            state,
            server,
            &mut srv_vless_pubs,
            &mut srv_awg_pubs,
            &mut srv_ssh_pubs,
        )?;
    }

    // Trial-render all active server configurations and subscriptions in memory.
    let empty_lists = ResolvedFirewallLists::default();
    let enabled_user_count = state.enabled_users_by_uid().len();
    let sample_uids: Vec<u32> = if enabled_user_count == 0 {
        vec![1001]
    } else {
        (0..enabled_user_count).map(|i| 1001 + i as u32).collect()
    };
    let sample_dns = ["1.1.1.1".parse::<IpAddr>().expect("valid static IP")];
    let mut has_enabled_vpn_protocol = false;
    for server in state.servers.iter().filter(|s| s.enabled) {
        let is_sub = state.is_subscription_server(&server.id);
        let eff = server.effective_config(&state.settings, is_sub);
        if eff.has_xray {
            has_enabled_vpn_protocol = true;
            let _ = render_xray_config(state, server, &empty_lists)?;
        }
        if eff.has_amneziawg {
            has_enabled_vpn_protocol = true;
            let _ = render_server_uapi(state, server)?;
            let _ = render_apply_script(state)?;
        }
        let _ = render_sysctl(state, server);
        if eff.is_subscription {
            let _ = render_caddyfile(state)?;
        }
        if eff.has_ssh_forwarding {
            has_enabled_vpn_protocol = true;
            let _ = render_sshd_config(state, server)?;
            let _ = render_authorized_keys(state)?;
        }
        if eff.has_traffic {
            let _ = render_traffic_config_env(state.settings.traffic.retention_days);
            let _ = render_traffic_users_conf(state)?;
            let _ = render_traffic_service();
            let _ = render_traffic_timer();
            let _ = render_traffic_flush_service(eff.has_xray);
        }
        let _ = render_nftables(
            state,
            server,
            Some(999),
            &sample_uids,
            &sample_dns,
            &empty_lists,
        )?;
        let _ = render_nftables_for_host(state, server)?;
    }

    if has_enabled_vpn_protocol {
        for (name, user) in state.enabled_users_by_uid() {
            let _ = render_subscription_body(state, name, user, SubVariant::Happ)?;
            let _ = render_subscription_body(state, name, user, SubVariant::Throne)?;
        }
    }

    Ok(())
}

/// Validates that `state` is ready for production deployment.
pub fn validate_for_deploy(state: &State) -> Result<()> {
    validate_state(state)?;
    if !state.users.values().any(|u| u.enabled) {
        bail!("cannot deploy with zero enabled users");
    }
    if !state.servers.iter().any(|s| {
        s.enabled
            && s.effective_config(&state.settings, false)
                .has_any_vpn_protocol
    }) {
        bail!("cannot deploy without at least one enabled 'vpn' server with active protocols");
    }
    if state.active_subscription_server().is_none() {
        bail!("deployment requires an enabled subscription host server (subscription.server_id)");
    }
    Ok(())
}
