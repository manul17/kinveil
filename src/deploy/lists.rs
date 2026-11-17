use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use ureq::Agent;

use crate::render::ResolvedFirewallLists;
use crate::render::xray::normalize_xray_domain_selector;
use crate::state::FirewallSettings;
use crate::validate::{normalize_country_code, parse_cidr_or_ip, validate_domain_selector};

const MAX_LIST_BYTES: u64 = 32 * 1024 * 1024;

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let Some(&b) = buf.get(*pos) else {
            bail!("unexpected EOF reading protobuf varint");
        };
        *pos += 1;
        if shift >= 64 || (shift == 63 && b > 1) {
            bail!("protobuf varint overflow");
        }
        val |= u64::from(b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            return Ok(val);
        }
        shift += 7;
    }
}

fn read_len_delimited<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len_u64 = read_varint(buf, pos)?;
    let len = usize::try_from(len_u64).map_err(|_| anyhow!("protobuf field length overflow"))?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow!("protobuf slice offset overflow"))?;
    let Some(slice) = buf.get(*pos..end) else {
        bail!("truncated protobuf length-delimited field");
    };
    *pos = end;
    Ok(slice)
}

fn skip_field(buf: &[u8], pos: &mut usize, wire_type: u64) -> Result<()> {
    match wire_type {
        0 => {
            let _ = read_varint(buf, pos)?;
        }
        1 => {
            let end = pos
                .checked_add(8)
                .ok_or_else(|| anyhow!("protobuf 64-bit offset overflow"))?;
            if end > buf.len() {
                bail!("truncated protobuf 64-bit field");
            }
            *pos = end;
        }
        2 => {
            let _ = read_len_delimited(buf, pos)?;
        }
        5 => {
            let end = pos
                .checked_add(4)
                .ok_or_else(|| anyhow!("protobuf 32-bit offset overflow"))?;
            if end > buf.len() {
                bail!("truncated protobuf 32-bit field");
            }
            *pos = end;
        }
        other => bail!("unsupported protobuf wire type {other}"),
    }
    Ok(())
}

fn decode_cidr_message(buf: &[u8]) -> Result<IpNet> {
    let mut pos = 0usize;
    let mut ip_bytes: &[u8] = &[];
    let mut prefix: u32 = 0;

    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_num, wire_type) {
            (1, 2) => ip_bytes = read_len_delimited(buf, &mut pos)?,
            (2, 0) => {
                let raw = read_varint(buf, &mut pos)?;
                prefix = u32::try_from(raw).unwrap_or(u32::MAX);
            }
            _ => skip_field(buf, &mut pos, wire_type)?,
        }
    }

    match ip_bytes.len() {
        4 => {
            let octets: [u8; 4] = ip_bytes.try_into().expect("4 bytes");
            let p = u8::try_from(prefix)
                .map_err(|_| anyhow!("invalid IPv4 prefix length {prefix} in geoip.dat"))?;
            let net = Ipv4Net::new(Ipv4Addr::from(octets), p)
                .with_context(|| format!("invalid IPv4 CIDR prefix /{p} in geoip.dat"))?;
            Ok(IpNet::V4(net.trunc()))
        }
        16 => {
            let octets: [u8; 16] = ip_bytes.try_into().expect("16 bytes");
            let p = u8::try_from(prefix)
                .map_err(|_| anyhow!("invalid IPv6 prefix length {prefix} in geoip.dat"))?;
            let net = Ipv6Net::new(Ipv6Addr::from(octets), p)
                .with_context(|| format!("invalid IPv6 CIDR prefix /{p} in geoip.dat"))?;
            Ok(IpNet::V6(net.trunc()))
        }
        len => bail!("invalid CIDR ip byte length {len} in geoip.dat"),
    }
}

/// Map of normalized lowercase ISO country codes to extracted `(IPv4, IPv6)` CIDR lists.
pub type CountryCidrMap = BTreeMap<String, (Vec<Ipv4Net>, Vec<Ipv6Net>)>;

/// Extracts IPv4 and IPv6 CIDRs for the requested ISO country codes from an Xray/V2Ray `geoip.dat`
/// Protobuf blob (`GeoIPList` -> `GeoIP` -> `CIDR`), ignoring inverse-match entries.
pub fn extract_geoip_country_cidrs(
    geoip_bytes: &[u8],
    countries: &[String],
) -> Result<CountryCidrMap> {
    let wanted: HashSet<String> = countries
        .iter()
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    let mut out: CountryCidrMap = BTreeMap::new();
    if wanted.is_empty() || geoip_bytes.is_empty() {
        return Ok(out);
    }

    let mut pos = 0usize;
    while pos < geoip_bytes.len() {
        let tag = read_varint(geoip_bytes, &mut pos)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        if field_num != 1 || wire_type != 2 {
            skip_field(geoip_bytes, &mut pos, wire_type)?;
            continue;
        }
        let geoip_msg = read_len_delimited(geoip_bytes, &mut pos)?;
        let mut sub_pos = 0usize;
        let mut country_code = String::new();
        let mut inverse_match = false;
        let mut raw_cidrs: Vec<&[u8]> = Vec::new();

        while sub_pos < geoip_msg.len() {
            let sub_tag = read_varint(geoip_msg, &mut sub_pos)?;
            let sub_field = sub_tag >> 3;
            let sub_wire = sub_tag & 0x07;
            match (sub_field, sub_wire) {
                (1, 2) => {
                    let bytes = read_len_delimited(geoip_msg, &mut sub_pos)?;
                    let s = std::str::from_utf8(bytes)
                        .context("invalid UTF-8 country_code in geoip.dat")?;
                    country_code = s.trim().to_ascii_lowercase();
                }
                (2, 2) => {
                    raw_cidrs.push(read_len_delimited(geoip_msg, &mut sub_pos)?);
                }
                (3, 0) => {
                    inverse_match = read_varint(geoip_msg, &mut sub_pos)? != 0;
                }
                _ => skip_field(geoip_msg, &mut sub_pos, sub_wire)?,
            }
        }

        if inverse_match || !wanted.contains(&country_code) {
            continue;
        }

        let entry = out.entry(country_code).or_default();
        for raw_cidr in raw_cidrs {
            match decode_cidr_message(raw_cidr)? {
                IpNet::V4(net) => entry.0.push(net),
                IpNet::V6(net) => entry.1.push(net),
            }
        }
    }

    Ok(out)
}

/// Parses plain-text IP/CIDR list text (`#` and `;` comments allowed), truncating host bits.
pub fn parse_ip_list_text(text: &str, source: &str) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>)> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for raw_line in text.lines() {
        let no_hash = raw_line.split('#').next().unwrap_or("");
        let no_semi = no_hash.split(';').next().unwrap_or("");
        let trimmed = no_semi.trim();
        if trimmed.is_empty() {
            continue;
        }
        match parse_cidr_or_ip(trimmed, source)? {
            IpNet::V4(net) => v4.push(net),
            IpNet::V6(net) => v6.push(net),
        }
    }
    Ok((v4, v6))
}

/// Parses plain-text domain list text (`#` comments allowed; leading `.` normalized to `domain:`).
pub fn parse_domain_list_text(text: &str, source: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw_line in text.lines() {
        let trimmed = raw_line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidate = if let Some(rest) = trimmed.strip_prefix('.') {
            Cow::Owned(format!("domain:{rest}"))
        } else {
            Cow::Borrowed(trimmed)
        };
        validate_domain_selector(&candidate, source)?;
        let norm = normalize_xray_domain_selector(&candidate);
        if seen.insert(norm.clone()) {
            out.push(norm);
        }
    }
    Ok(out)
}

fn build_list_agent(https_only: bool) -> Agent {
    Agent::config_builder()
        .https_only(https_only)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into()
}

fn fetch_list_text(agent: &Agent, url: &str, label: &str) -> Result<String> {
    let mut resp = agent
        .get(url)
        .call()
        .with_context(|| format!("failed downloading {label} from {url}"))?;
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(MAX_LIST_BYTES)
        .read_to_vec()
        .with_context(|| format!("failed reading {label} body from {url}"))?;
    String::from_utf8(bytes).with_context(|| format!("{label} from {url} is not valid UTF-8"))
}

pub fn resolve_firewall_lists_inner(
    fw: &FirewallSettings,
    geoip_bytes: &[u8],
    https_only: bool,
) -> Result<ResolvedFirewallLists> {
    let mut countries = Vec::new();
    for raw_cc in &fw.block_countries {
        let cc = normalize_country_code(raw_cc, "firewall.block_countries")?;
        if !countries.contains(&cc) {
            countries.push(cc);
        }
    }

    let mut extra_ipv4 = Vec::new();
    let mut extra_ipv6 = Vec::new();
    let mut extra_xray_domains = Vec::new();
    let mut missing_geoip_countries = Vec::new();
    let mut seen_domains = HashSet::new();

    let need_http = !fw.block_ip_lists.is_empty() || !fw.xray.block_domain_lists.is_empty();
    let mut agent_opt: Option<Agent> = need_http.then(|| build_list_agent(https_only));

    if !countries.is_empty() {
        let geo_map = extract_geoip_country_cidrs(geoip_bytes, &countries)?;
        for cc in &countries {
            if let Some((v4, v6)) = geo_map.get(cc)
                && (!v4.is_empty() || !v6.is_empty())
            {
                extra_ipv4.extend_from_slice(v4);
                extra_ipv6.extend_from_slice(v6);
            } else {
                if !geoip_bytes.is_empty() {
                    missing_geoip_countries.push(cc.clone());
                }
                let agent = agent_opt.get_or_insert_with(|| build_list_agent(https_only));
                let v4_url = fw.auto_update.ipv4_country_url.replace("{cc}", cc);
                let v6_url = fw.auto_update.ipv6_country_url.replace("{cc}", cc);
                let v4_text = fetch_list_text(agent, &v4_url, &format!("IPv4 list for '{cc}'"))?;
                let v6_text = fetch_list_text(agent, &v6_url, &format!("IPv6 list for '{cc}'"))?;
                let (v4, v6_from_v4) = parse_ip_list_text(&v4_text, &v4_url)?;
                let (v4_from_v6, v6) = parse_ip_list_text(&v6_text, &v6_url)?;
                if v4.is_empty() && v6_from_v4.is_empty() && v4_from_v6.is_empty() && v6.is_empty()
                {
                    bail!("country fallback lists for '{cc}' yielded zero CIDR entries");
                }
                extra_ipv4.extend(v4);
                extra_ipv4.extend(v4_from_v6);
                extra_ipv6.extend(v6_from_v4);
                extra_ipv6.extend(v6);
            }
        }
    }

    let mut seen_ip_urls = HashSet::new();
    for raw_url in &fw.block_ip_lists {
        let url = raw_url.trim();
        if !seen_ip_urls.insert(url.to_owned()) {
            continue;
        }
        let agent = agent_opt.get_or_insert_with(|| build_list_agent(https_only));
        let text = fetch_list_text(agent, url, "firewall.block_ip_lists")?;
        let (v4, v6) = parse_ip_list_text(&text, "firewall.block_ip_lists")?;
        if v4.is_empty() && v6.is_empty() {
            bail!("firewall.block_ip_lists URL {url} yielded zero CIDR entries");
        }
        extra_ipv4.extend(v4);
        extra_ipv6.extend(v6);
    }

    let mut seen_domain_urls = HashSet::new();
    for raw_url in &fw.xray.block_domain_lists {
        let url = raw_url.trim();
        if !seen_domain_urls.insert(url.to_owned()) {
            continue;
        }
        let agent = agent_opt.get_or_insert_with(|| build_list_agent(https_only));
        let text = fetch_list_text(agent, url, "firewall.xray.block_domain_lists")?;
        let domains = parse_domain_list_text(&text, "firewall.xray.block_domain_lists")?;
        if domains.is_empty() {
            bail!("firewall.xray.block_domain_lists URL {url} yielded zero domain entries");
        }
        for d in domains {
            if seen_domains.insert(d.clone()) {
                extra_xray_domains.push(d);
            }
        }
    }

    Ok(ResolvedFirewallLists {
        extra_ipv4: Ipv4Net::aggregate(&extra_ipv4),
        extra_ipv6: Ipv6Net::aggregate(&extra_ipv6),
        extra_xray_domains,
        missing_geoip_countries,
    })
}

pub fn resolve_firewall_lists(
    fw: &FirewallSettings,
    geoip_bytes: &[u8],
) -> Result<ResolvedFirewallLists> {
    resolve_firewall_lists_inner(fw, geoip_bytes, true)
}
