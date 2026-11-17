use anyhow::{Result, bail};
use serde_json::json;

use crate::render::{
    ALWAYS_BLOCKED_IPV4_CIDRS, ALWAYS_BLOCKED_IPV6_CIDRS, PRIVATE_IPV4_CIDRS, PRIVATE_IPV6_CIDRS,
    ResolvedFirewallLists, push_unique,
};
use crate::state::{Server, State};
use crate::validate::{normalize_country_code, parse_cidr_or_ip};

pub(crate) fn normalize_xray_domain_selector(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some((prefix, rest)) = trimmed.split_once(':') {
        let p_lower = prefix.to_ascii_lowercase();
        if p_lower == "regexp" {
            format!("regexp:{rest}")
        } else {
            let rest_clean = if p_lower == "domain" {
                rest.strip_prefix('.').unwrap_or(rest)
            } else {
                rest
            };
            format!("{p_lower}:{}", rest_clean.to_ascii_lowercase())
        }
    } else {
        format!("domain:{}", trimmed.to_ascii_lowercase())
    }
}

pub(crate) fn normalize_ip_selector(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("geoip:"))
    {
        format!("geoip:{}", trimmed[6..].to_ascii_lowercase())
    } else {
        trimmed.to_owned()
    }
}

pub fn render_xray_config(
    state: &State,
    server: &Server,
    lists: &ResolvedFirewallLists,
) -> Result<String> {
    let vpn = server
        .vpn
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn configuration", server.id))?;
    let eff = server.effective_config(&state.settings, state.is_subscription_server(&server.id));
    if !eff.has_vless && !eff.has_hysteria2 {
        bail!("server {} has no active Xray protocols enabled", server.id);
    }

    let vless_cfg = &state.settings.vless;
    let hyst_cfg = &state.settings.hysteria2;

    let mut inbounds = Vec::new();
    if eff.has_vless {
        let (sni, _) = eff
            .vless_sni
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server {} lacks effective VLESS SNI", server.id))?;
        let (target, _) = eff
            .vless_target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server {} lacks effective VLESS target", server.id))?;
        let (xhttp_path, _) = eff.vless_xhttp_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!("server {} lacks effective VLESS XHTTP path", server.id)
        })?;
        let vless_clients: Vec<serde_json::Value> = state
            .enabled_users_by_uid()
            .into_iter()
            .map(|(_name, p)| {
                json!({
                    "id": p.vless.uuid.as_str(),
                    "email": format!("uid-{}:vless", p.uid)
                })
            })
            .collect();
        let xhttp_mode = match (eff.has_vless_stream, eff.has_vless_packet) {
            (true, true) => "auto",
            (true, false) => "stream-up",
            (false, true) => "packet-up",
            (false, false) => unreachable!("checked eff.has_vless"),
        };

        let mut xhttp_settings = serde_json::Map::new();
        xhttp_settings.insert("mode".to_owned(), json!(xhttp_mode));
        xhttp_settings.insert("path".to_owned(), json!(xhttp_path));
        if let Some((host, _)) = &eff.vless_xhttp_host
            && !host.is_empty()
        {
            xhttp_settings.insert("host".to_owned(), json!(host));
        }
        xhttp_settings.insert(
            "scMaxBufferedPosts".to_owned(),
            json!(vless_cfg.xhttp.sc_max_buffered_posts),
        );
        xhttp_settings.insert(
            "xPaddingBytes".to_owned(),
            json!(vless_cfg.xhttp.padding_bytes),
        );

        inbounds.push(json!({
            "tag": "vless-reality",
            "listen": "::",
            "port": eff.vless_port,
            "protocol": "vless",
            "settings": {
                "clients": vless_clients,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": serde_json::Value::Object(xhttp_settings),
                "realitySettings": {
                    "show": false,
                    "target": target,
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": vpn.vless.private_key,
                    "shortIds": [vpn.vless.short_id]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": true
            }
        }));
    }

    if eff.has_hysteria2 {
        let hyst_clients: Vec<serde_json::Value> = state
            .enabled_users_by_uid()
            .into_iter()
            .map(|(_name, p)| {
                json!({
                    "auth": p.hysteria2.auth.as_str(),
                    "email": format!("uid-{}:hysteria2", p.uid)
                })
            })
            .collect();

        inbounds.push(json!({
            "tag": "hysteria2",
            "listen": "::",
            "port": eff.hysteria2_port,
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "clients": hyst_clients
            },
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "tlsSettings": {
                    "alpn": hyst_cfg.alpn,
                    "certificates": [{
                        "certificateFile": "/etc/kinveil/tls/hysteria.crt",
                        "keyFile": "/etc/kinveil/tls/hysteria.key"
                    }]
                },
                "hysteriaSettings": {
                    "version": 2,
                    "udpIdleTimeout": hyst_cfg.udp_idle_timeout_secs,
                    "masquerade": {
                        "type": "proxy",
                        "url": hyst_cfg.masquerade_url,
                        "rewriteHost": true
                    }
                },
                "finalmask": {
                    "udp": [{
                        "type": "salamander",
                        "settings": {
                            "password": vpn.hysteria2.salamander_password
                        }
                    }]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls", "quic"],
                "routeOnly": true
            }
        }));
    }

    let mut rules = Vec::new();
    let fw = &state.settings.firewall;
    if fw.xray.block_bittorrent {
        rules.push(json!({
            "type": "field",
            "protocol": ["bittorrent"],
            "outboundTag": "block"
        }));
    }
    // On a single-VPS setup, let connected VPN clients refresh their HTTPS subscription.
    // Match both subscription domain (Pass 1 before domain block rules) and host IP (Pass 2).
    if state.is_subscription_server(&server.id) {
        rules.push(json!({
            "type": "field",
            "domain": [format!("full:{}", state.subscription.domain)],
            "network": "tcp",
            "port": "80,443",
            "outboundTag": "direct"
        }));
        let mut sub_ips = vec![format!("{}/32", server.public_ipv4)];
        if let Some(ipv6) = server.public_ipv6 {
            sub_ips.push(format!("{ipv6}/128"));
        }
        rules.push(json!({
            "type": "field",
            "ip": sub_ips,
            "network": "tcp",
            "port": "80,443",
            "outboundTag": "direct"
        }));
    }

    let mut countries = Vec::new();
    for raw_cc in &fw.block_countries {
        push_unique(
            &mut countries,
            normalize_country_code(raw_cc, "firewall.block_countries")?,
        );
    }

    let mut domains = Vec::new();
    for cc in &countries {
        push_unique(&mut domains, format!("domain:{cc}"));
    }
    for d in &fw.xray.block_domains {
        push_unique(&mut domains, normalize_xray_domain_selector(d));
    }
    for d in &lists.extra_xray_domains {
        push_unique(&mut domains, d.clone());
    }
    if !domains.is_empty() {
        rules.push(json!({
            "type": "field",
            "domain": domains,
            "outboundTag": "block"
        }));
    }

    let mut custom_blocked_ips = Vec::new();
    for cc in &countries {
        if !lists.missing_geoip_countries.contains(cc) {
            push_unique(&mut custom_blocked_ips, format!("geoip:{cc}"));
        }
    }
    for raw_cidr in &fw.block_cidrs {
        let net = parse_cidr_or_ip(raw_cidr, "firewall.block_cidrs")?;
        push_unique(&mut custom_blocked_ips, net.to_string());
    }
    if !custom_blocked_ips.is_empty() {
        rules.push(json!({
            "type": "field",
            "ip": custom_blocked_ips,
            "outboundTag": "block"
        }));
    }

    let mut blocked_ips: Vec<String> = Vec::new();
    if fw.block_private_networks {
        blocked_ips.extend(PRIVATE_IPV4_CIDRS.iter().copied().map(str::to_owned));
        blocked_ips.push(format!("{}/32", server.public_ipv4));
        blocked_ips.extend(PRIVATE_IPV6_CIDRS.iter().copied().map(str::to_owned));
    } else {
        // Always prevent Xray from dialing loopback, link-local, IMDS, or host public IPs over lo.
        // Go/Xray normalizes IPv4-mapped IPv6 addresses to IPv4 before checking IPv4 CIDRs,
        // and rejects `::ffff:0:0/96` as an invalid >32-bit mask.
        blocked_ips.extend(ALWAYS_BLOCKED_IPV4_CIDRS.iter().copied().map(str::to_owned));
        blocked_ips.push(format!("{}/32", server.public_ipv4));
        blocked_ips.extend(ALWAYS_BLOCKED_IPV6_CIDRS.iter().copied().map(str::to_owned));
    }
    if let Some(ipv6) = server.public_ipv6 {
        blocked_ips.push(format!("{ipv6}/128"));
    }
    rules.push(json!({
        "type": "field",
        "ip": blocked_ips,
        "outboundTag": "block"
    }));

    let mut doc = serde_json::Map::new();
    if eff.has_traffic {
        doc.insert(
            "api".to_owned(),
            json!({
                "tag": "api",
                "listen": "/run/kinveil-xray/api.sock",
                "services": ["StatsService"]
            }),
        );
    }
    doc.insert(
        "dns".to_owned(),
        json!({
            "servers": state.settings.dns.xray_servers
        }),
    );
    doc.insert("inbounds".to_owned(), json!(inbounds));
    doc.insert(
        "log".to_owned(),
        json!({
            "access": "none",
            "loglevel": "warning"
        }),
    );
    doc.insert(
        "outbounds".to_owned(),
        json!([
            {
                "tag": "direct",
                "protocol": "freedom",
                "streamSettings": {
                    "sockopt": {
                        "domainStrategy": "UseIP"
                    }
                }
            },
            { "tag": "block", "protocol": "blackhole" }
        ]),
    );
    if eff.has_traffic {
        doc.insert(
            "policy".to_owned(),
            json!({
                "levels": {
                    "0": {
                        "statsUserUplink": true,
                        "statsUserDownlink": true
                    }
                }
            }),
        );
    }
    doc.insert(
        "routing".to_owned(),
        json!({
            "domainStrategy": "IPIfNonMatch",
            "rules": rules
        }),
    );
    if eff.has_traffic {
        doc.insert("stats".to_owned(), json!({}));
    }

    let mut rendered = serde_json::to_string_pretty(&serde_json::Value::Object(doc))?;
    rendered.push('\n');
    Ok(rendered)
}

pub fn render_systemd_unit(has_traffic: bool) -> String {
    let traffic_lines = if has_traffic {
        "RuntimeDirectory=kinveil-xray\nRuntimeDirectoryMode=0700\nExecStartPre=/usr/bin/rm -f /run/kinveil-xray/api.sock /run/kinveil-xray/api.sock.lock\n"
    } else {
        ""
    };
    format!(
        r#"[Unit]
Description=Kinveil Xray-core service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=kinveil
Group=kinveil
{traffic_lines}AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/lib/kinveil/xray/xray run -config /etc/kinveil/xray.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
"#
    )
}
