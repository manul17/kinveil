use std::net::IpAddr;

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde_json::{Map, Value, json};

use crate::render::push_unique;
use crate::render::xray::{normalize_ip_selector, normalize_xray_domain_selector};
use crate::state::{State, SubscriptionRoutingSettings};
use crate::validate::{
    normalize_country_code, validate_happ_link, validate_profile_title, validate_throne_link,
};

pub const DEFAULT_PROFILE_TITLE: &str = "Kinveil";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompiledRouting {
    pub happ_header: Option<String>,
    pub happ_json: Option<String>,
    pub throne_header: Option<String>,
    pub throne_json: Option<String>,
}

pub fn format_routing_summary(routing: &SubscriptionRoutingSettings) -> String {
    if !routing.is_active() {
        return "disabled".to_owned();
    }
    let mut parts = Vec::new();
    if !routing.bypass_countries.is_empty() {
        let codes: Vec<String> = routing
            .bypass_countries
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .collect();
        parts.push(format!("bypass_countries=[{}]", codes.join(",")));
    }
    if !routing.block_countries.is_empty() {
        let codes: Vec<String> = routing
            .block_countries
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .collect();
        parts.push(format!("block_countries=[{}]", codes.join(",")));
    }
    for (label, count) in [
        ("direct_domains", routing.direct_domains.len()),
        ("direct_ips", routing.direct_ips.len()),
        ("proxy_domains", routing.proxy_domains.len()),
        ("proxy_ips", routing.proxy_ips.len()),
        ("block_domains", routing.block_domains.len()),
        ("block_ips", routing.block_ips.len()),
    ] {
        if count > 0 {
            parts.push(format!("{label}={count}"));
        }
    }
    if routing.has_compiled_rules() {
        parts.push(format!("domestic_doh={}", routing.domestic_doh));
        parts.push(format!("remote_doh={}", routing.remote_doh));
    }
    if routing.happ_link.is_some() {
        parts.push("happ_link=override".to_owned());
    }
    if routing.throne_link.is_some() {
        parts.push("throne_link=override".to_owned());
    }
    parts.join(", ")
}

fn build_happ_compiled(
    name: &str,
    bypass_countries: &[String],
    block_countries: &[String],
    routing: &SubscriptionRoutingSettings,
) -> Result<(String, String)> {
    let mut direct_sites = vec!["geosite:private".to_owned()];
    for cc in bypass_countries {
        push_unique(&mut direct_sites, format!("domain:{cc}"));
    }
    for d in &routing.direct_domains {
        push_unique(&mut direct_sites, normalize_xray_domain_selector(d));
    }

    let mut direct_ips = vec!["geoip:private".to_owned()];
    for cc in bypass_countries {
        push_unique(&mut direct_ips, format!("geoip:{cc}"));
    }
    for ip in &routing.direct_ips {
        push_unique(&mut direct_ips, normalize_ip_selector(ip));
    }

    let mut proxy_sites = Vec::new();
    for d in &routing.proxy_domains {
        push_unique(&mut proxy_sites, normalize_xray_domain_selector(d));
    }
    let mut proxy_ips = Vec::new();
    for ip in &routing.proxy_ips {
        push_unique(&mut proxy_ips, normalize_ip_selector(ip));
    }

    let mut block_sites = Vec::new();
    for cc in block_countries {
        push_unique(&mut block_sites, format!("domain:{cc}"));
    }
    for d in &routing.block_domains {
        push_unique(&mut block_sites, normalize_xray_domain_selector(d));
    }
    let mut block_ips = Vec::new();
    for cc in block_countries {
        push_unique(&mut block_ips, format!("geoip:{cc}"));
    }
    for ip in &routing.block_ips {
        push_unique(&mut block_ips, normalize_ip_selector(ip));
    }

    let obj = json!({
        "Name": name,
        "GlobalProxy": "true",
        "RouteOrder": "block-proxy-direct",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": routing.remote_doh,
        "RemoteDNSIP": routing.remote_dns_ip.to_string(),
        "DomesticDNSType": "DoH",
        "DomesticDNSDomain": routing.domestic_doh,
        "DomesticDNSIP": routing.domestic_dns_ip.to_string(),
        "DnsHosts": json!({}),
        "DirectSites": direct_sites,
        "DirectIp": direct_ips,
        "ProxySites": proxy_sites,
        "ProxyIp": proxy_ips,
        "BlockSites": block_sites,
        "BlockIp": block_ips,
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false",
    });
    let compact = serde_json::to_string(&obj)?;
    let pretty = serde_json::to_string_pretty(&obj)?;
    let link = format!(
        "happ://routing/onadd/{}",
        STANDARD.encode(compact.as_bytes())
    );
    validate_happ_link(&link)?;
    Ok((link, pretty))
}

fn build_throne_rule(
    name: &str,
    action: &str,
    outbound: Option<&str>,
    countries: &[String],
    domains: &[String],
    ips: &[String],
) -> Option<Value> {
    let mut rule_set = Vec::new();
    let mut exact_domain = Vec::new();
    let mut domain_suffix = Vec::new();
    let mut domain_keyword = Vec::new();
    let mut domain_regex = Vec::new();
    let mut ip_cidr = Vec::new();
    let mut ip_is_private = false;

    for cc in countries {
        push_unique(&mut rule_set, format!("geoip-{cc}"));
        push_unique(&mut domain_suffix, cc.clone());
    }

    for raw in domains {
        let trimmed = raw.trim();
        if let Some((prefix, rest)) = trimmed.split_once(':') {
            match prefix.to_ascii_lowercase().as_str() {
                "geosite" => {
                    push_unique(
                        &mut rule_set,
                        format!("geosite-{}", rest.to_ascii_lowercase()),
                    );
                }
                "domain" => {
                    let clean = rest.strip_prefix('.').unwrap_or(rest).to_ascii_lowercase();
                    push_unique(&mut domain_suffix, clean);
                }
                "full" => {
                    push_unique(&mut exact_domain, rest.to_ascii_lowercase());
                }
                "keyword" => {
                    push_unique(&mut domain_keyword, rest.to_ascii_lowercase());
                }
                "regexp" => {
                    push_unique(&mut domain_regex, rest.to_owned());
                }
                _ => {}
            }
        } else {
            push_unique(&mut domain_suffix, trimmed.to_ascii_lowercase());
        }
    }

    for raw in ips {
        let trimmed = raw.trim();
        if trimmed
            .get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case("geoip:"))
        {
            let tag = trimmed[6..].to_ascii_lowercase();
            if tag == "private" {
                ip_is_private = true;
            } else {
                push_unique(&mut rule_set, format!("geoip-{tag}"));
            }
        } else if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
            push_unique(&mut ip_cidr, net.to_string());
        } else if let Ok(addr) = trimmed.parse::<IpAddr>() {
            let cidr = match addr {
                IpAddr::V4(v4) => format!("{v4}/32"),
                IpAddr::V6(v6) => format!("{v6}/128"),
            };
            push_unique(&mut ip_cidr, cidr);
        }
    }

    let any_match = ip_is_private
        || !rule_set.is_empty()
        || !exact_domain.is_empty()
        || !domain_suffix.is_empty()
        || !domain_keyword.is_empty()
        || !domain_regex.is_empty()
        || !ip_cidr.is_empty();
    if !any_match {
        return None;
    }

    let mut map = Map::new();
    map.insert("action".to_owned(), Value::String(action.to_owned()));
    if !exact_domain.is_empty() {
        map.insert("domain".to_owned(), json!(exact_domain));
    }
    if !domain_keyword.is_empty() {
        map.insert("domain_keyword".to_owned(), json!(domain_keyword));
    }
    if !domain_regex.is_empty() {
        map.insert("domain_regex".to_owned(), json!(domain_regex));
    }
    if !domain_suffix.is_empty() {
        map.insert("domain_suffix".to_owned(), json!(domain_suffix));
    }
    if !ip_cidr.is_empty() {
        map.insert("ip_cidr".to_owned(), json!(ip_cidr));
    }
    if ip_is_private {
        map.insert("ip_is_private".to_owned(), Value::Bool(true));
    }
    map.insert("name".to_owned(), Value::String(name.to_owned()));
    if let Some(ob) = outbound {
        map.insert("outbound".to_owned(), Value::String(ob.to_owned()));
    }
    if !rule_set.is_empty() {
        map.insert("rule_set".to_owned(), json!(rule_set));
    }
    map.insert("type".to_owned(), Value::String("custom".to_owned()));
    Some(Value::Object(map))
}

fn build_throne_compiled(
    name: &str,
    bypass_countries: &[String],
    block_countries: &[String],
    routing: &SubscriptionRoutingSettings,
) -> Result<(String, String)> {
    let mut rules = vec![
        json!({
            "action": "hijack-dns",
            "name": "Hijack DNS",
            "protocol": "dns",
            "type": "custom"
        }),
        json!({
            "action": "route",
            "ip_is_private": true,
            "name": "Private IPs Direct",
            "outbound": "direct",
            "type": "custom"
        }),
    ];
    if let Some(block_rule) = build_throne_rule(
        "Block Rules",
        "reject",
        None,
        block_countries,
        &routing.block_domains,
        &routing.block_ips,
    ) {
        rules.push(block_rule);
    }
    if let Some(proxy_rule) = build_throne_rule(
        "Proxy Rules",
        "route",
        Some("proxy"),
        &[],
        &routing.proxy_domains,
        &routing.proxy_ips,
    ) {
        rules.push(proxy_rule);
    }
    if let Some(direct_rule) = build_throne_rule(
        "Direct Rules",
        "route",
        Some("direct"),
        bypass_countries,
        &routing.direct_domains,
        &routing.direct_ips,
    ) {
        rules.push(direct_rule);
    }

    let obj = json!({
        "default_outbound": "proxy",
        "kind": "throne-route-profile",
        "name": name,
        "rules": rules,
        "v": 1,
    });
    let compact = serde_json::to_string(&obj)?;
    let pretty = serde_json::to_string_pretty(&obj)?;
    let link = format!(
        "throne://route/{}",
        STANDARD_NO_PAD.encode(compact.as_bytes())
    );
    validate_throne_link(&link)?;
    Ok((link, pretty))
}

pub fn compile_subscription_routing(
    routing: &SubscriptionRoutingSettings,
) -> Result<CompiledRouting> {
    let mut bypass_countries = Vec::new();
    for raw_cc in &routing.bypass_countries {
        let cc = normalize_country_code(raw_cc, "subscription.routing.bypass_countries")?;
        push_unique(&mut bypass_countries, cc);
    }
    let mut block_countries = Vec::new();
    for raw_cc in &routing.block_countries {
        let cc = normalize_country_code(raw_cc, "subscription.routing.block_countries")?;
        if bypass_countries.contains(&cc) {
            bail!(
                "country code '{cc}' cannot appear in both subscription.routing.bypass_countries and subscription.routing.block_countries"
            );
        }
        push_unique(&mut block_countries, cc);
    }

    let mut out = CompiledRouting::default();
    if routing.has_compiled_rules() {
        let name = match (bypass_countries.len(), block_countries.len()) {
            (1, 0) => format!("Bypass {}", bypass_countries[0].to_ascii_uppercase()),
            (0, 1) => format!("Block {}", block_countries[0].to_ascii_uppercase()),
            _ => "Split Tunnel".to_owned(),
        };
        let (happ_link, happ_json) =
            build_happ_compiled(&name, &bypass_countries, &block_countries, routing)?;
        let (throne_link, throne_json) =
            build_throne_compiled(&name, &bypass_countries, &block_countries, routing)?;
        out.happ_header = Some(happ_link);
        out.happ_json = Some(happ_json);
        out.throne_header = Some(throne_link);
        out.throne_json = Some(throne_json);
    }

    if let Some(ref h) = routing.happ_link {
        validate_happ_link(h)?;
        out.happ_header = Some(h.clone());
        out.happ_json = None;
        if !routing.has_compiled_rules() && routing.throne_link.is_none() {
            out.throne_header = Some(h.clone());
        }
    }
    if let Some(ref t) = routing.throne_link {
        validate_throne_link(t)?;
        out.throne_header = Some(t.clone());
        out.throne_json = None;
    }

    Ok(out)
}

fn escape_re2(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn format_handle_block(matcher: Option<&str>, target: &str, routing: Option<&str>) -> String {
    let open = match matcher {
        Some(m) => format!("        handle {m} {{\n"),
        None => "        handle {\n".to_owned(),
    };
    let routing_stmt = match routing {
        Some(r) => format!("            header routing \"{r}\"\n"),
        None => String::new(),
    };
    format!(
        "{open}{routing_stmt}            rewrite * /{{re.sub.1}}/{target}\n            file_server\n        }}"
    )
}

pub fn render_caddyfile(state: &State) -> Result<String> {
    let sub = &state.subscription;
    let sub_settings = &state.settings.subscription;
    if sub.domain.is_empty() || !sub.base_path.starts_with('/') || !sub.base_path.ends_with('/') {
        bail!("invalid subscription domain or base_path");
    }
    let escaped_prefix = escape_re2(sub.base_path.as_str());
    let title = sub_settings
        .profile_title
        .as_deref()
        .unwrap_or(DEFAULT_PROFILE_TITLE);
    validate_profile_title(title)?;
    let profile_title_b64 = STANDARD.encode(title.as_bytes());
    let compiled = compile_subscription_routing(&sub_settings.routing)?;

    let (shared_routing_line, tail_handlers) = if compiled.happ_header == compiled.throne_header {
        let shared = match &compiled.happ_header {
            Some(r) => format!("\n            routing \"{r}\""),
            None => String::new(),
        };
        let handles = [
            "        handle @throne {",
            "            rewrite * /{re.sub.1}/throne",
            "            file_server",
            "        }",
            "        handle @throne_query {",
            "            rewrite * /{re.sub.1}/throne",
            "            file_server",
            "        }",
            "        rewrite * /{re.sub.1}/happ",
            "        file_server",
        ]
        .join("\n");
        (shared, handles)
    } else {
        let h_throne =
            format_handle_block(Some("@throne"), "throne", compiled.throne_header.as_deref());
        let h_query = format_handle_block(
            Some("@throne_query"),
            "throne",
            compiled.throne_header.as_deref(),
        );
        let h_happ = format_handle_block(None, "happ", compiled.happ_header.as_deref());
        (String::new(), format!("{h_throne}\n{h_query}\n{h_happ}"))
    };

    Ok(format!(
        r#"{{
    admin off
    servers {{
        protocols h1 h2
    }}
}}

{domain} {{
    log {{
        output discard
    }}

    @sub_path path_regexp sub ^{prefix}([A-Za-z0-9_-]+)$
    handle @sub_path {{
        root * /var/lib/kinveil/sub
        header {{
            Cache-Control "private, no-store"
            Vary "User-Agent"
            Profile-Title "base64:{profile_title_b64}"
            Profile-Update-Interval "{hours}"
            Content-Type "text/plain; charset=utf-8"{shared_routing_line}
        }}
        @throne {{
            header_regexp User-Agent (?i)^throne/
        }}
        @throne_query {{
            query ssh=1
        }}
{tail_handlers}
    }}

    handle {{
        respond 404
    }}
}}
"#,
        domain = sub.domain,
        prefix = escaped_prefix,
        profile_title_b64 = profile_title_b64,
        hours = sub_settings.update_interval_hours,
        shared_routing_line = shared_routing_line,
        tail_handlers = tail_handlers,
    ))
}
