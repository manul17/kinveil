use anyhow::{Result, bail};
use serde_json::json;

use crate::render::{
    ALWAYS_BLOCKED_IPV4_CIDRS, ALWAYS_BLOCKED_IPV6_CIDRS, PRIVATE_IPV4_CIDRS, PRIVATE_IPV6_CIDRS,
};
use crate::state::{Server, State};

pub fn render_xray_config(state: &State, server: &Server) -> Result<String> {
    let vpn = server
        .vpn
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn configuration", server.id))?;
    let has_vless_stream = server.has_vless_stream(&state.settings);
    let has_vless_packet = server.has_vless_packet(&state.settings);
    let has_vless = has_vless_stream || has_vless_packet;
    let has_hysteria2 = server.has_hysteria2(&state.settings);
    if !has_vless && !has_hysteria2 {
        bail!("server {} has no active Xray protocols enabled", server.id);
    }

    let vless_cfg = &state.settings.vless;
    let hyst_cfg = &state.settings.hysteria2;

    let mut inbounds = Vec::new();
    if has_vless {
        let vless_clients: Vec<serde_json::Value> = state
            .enabled_users_by_uid()
            .into_iter()
            .map(|(name, p)| json!({ "id": p.vless.uuid.as_str(), "email": name }))
            .collect();
        let xhttp_mode = match (has_vless_stream, has_vless_packet) {
            (true, true) => "auto",
            (true, false) => "stream-up",
            (false, true) => "packet-up",
            (false, false) => unreachable!("checked has_vless"),
        };

        let mut xhttp_settings = serde_json::Map::new();
        xhttp_settings.insert("mode".to_owned(), json!(xhttp_mode));
        xhttp_settings.insert("path".to_owned(), json!(vpn.vless.xhttp_path));
        if let Some(host) = vpn.vless.xhttp_host.as_deref()
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
            "port": server.effective_vless_port(&state.settings),
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
                    "target": vpn.vless.target,
                    "xver": 0,
                    "serverNames": [vpn.vless.server_name],
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

    if has_hysteria2 {
        let hyst_clients: Vec<serde_json::Value> = state
            .enabled_users_by_uid()
            .into_iter()
            .map(|(name, p)| json!({ "auth": p.hysteria2.auth.as_str(), "email": name }))
            .collect();

        inbounds.push(json!({
            "tag": "hysteria2",
            "listen": "::",
            "port": server.effective_hysteria2_port(&state.settings),
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
    if state.settings.firewall.block_bittorrent {
        rules.push(json!({
            "type": "field",
            "protocol": ["bittorrent"],
            "outboundTag": "block"
        }));
    }
    // On a single-VPS setup, let connected VPN clients refresh their HTTPS subscription.
    if state.is_subscription_server(&server.id) {
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

    let mut blocked_ips: Vec<String> = Vec::new();
    if state.settings.firewall.block_private_networks {
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

    let doc = json!({
        "log": {
            "access": "none",
            "loglevel": "warning"
        },
        "inbounds": inbounds,
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": { "domainStrategy": "UseIP" }
            },
            { "tag": "block", "protocol": "blackhole" }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": rules
        }
    });

    let mut rendered = serde_json::to_string_pretty(&doc)?;
    rendered.push('\n');
    Ok(rendered)
}

pub fn render_systemd_unit() -> String {
    r#"[Unit]
Description=Kinveil Xray-core service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=kinveil
Group=kinveil
AmbientCapabilities=CAP_NET_BIND_SERVICE
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
    .to_owned()
}
