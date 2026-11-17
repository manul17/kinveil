use anyhow::{Result, bail};

use crate::crypto::base64_key_to_hex;
use crate::render::format_authority;
use crate::state::{Server, State, User};

fn check_ini_field(value: &str, name: &str) -> Result<()> {
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        bail!("invalid AmneziaWG field {name}");
    }
    Ok(())
}

/// Render the AmneziaWG 3.1 client `.conf` INI without a trailing newline so
/// base64url-encoded `vpn://` subscription links stay clean across clients.
pub fn render_client_ini(state: &State, server: &Server, user: &User) -> Result<String> {
    if !user.enabled {
        bail!("cannot render AmneziaWG config for disabled user");
    }
    let vpn = server
        .vpn
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn configuration", server.id))?;
    let awg_cfg = &state.settings.amneziawg;
    let dns_servers = &state.settings.dns.amneziawg_servers;
    if dns_servers.is_empty() {
        bail!("dns.amneziawg_servers must not be empty");
    }

    let address = state.settings.awg_user_cidr(user.uid)?;
    let eff = server.effective_config(&state.settings, false);
    let obf = eff
        .awg_obfuscation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn configuration", server.id))?;
    check_ini_field(
        user.amneziawg.private_key.as_str(),
        "user.amneziawg.private_key",
    )?;
    check_ini_field(
        user.amneziawg.preshared_key.as_str(),
        "user.amneziawg.preshared_key",
    )?;
    let server_awg_pub = vpn.amneziawg.public_key()?;
    check_ini_field(&server_awg_pub, "server.vpn.amneziawg.public_key")?;
    let h1_s = obf.h1.to_string();
    let h2_s = obf.h2.to_string();
    let h3_s = obf.h3.to_string();
    let h4_s = obf.h4.to_string();
    let cpa_s = obf.content_padding_addition.to_string();
    let rekey_after_s = awg_cfg.rekey_after_time.to_string();
    let rekey_timeout_s = awg_cfg.rekey_timeout.to_string();
    let reject_after_s = awg_cfg.reject_after_time.to_string();
    let keepalive_s = awg_cfg.keepalive_timeout.to_string();
    let max_handshake_s = awg_cfg.max_handshake_attempts.to_string();
    check_ini_field(&h1_s, "obfuscation.h1")?;
    check_ini_field(&h2_s, "obfuscation.h2")?;
    check_ini_field(&h3_s, "obfuscation.h3")?;
    check_ini_field(&h4_s, "obfuscation.h4")?;
    check_ini_field(&obf.i1, "obfuscation.i1")?;
    for (label, val) in [
        ("obfuscation.i2", &obf.i2),
        ("obfuscation.i3", &obf.i3),
        ("obfuscation.i4", &obf.i4),
        ("obfuscation.i5", &obf.i5),
    ] {
        if let Some(v) = val {
            check_ini_field(v, label)?;
        }
    }
    check_ini_field(
        obf.header_protection_key.as_str(),
        "obfuscation.header_protection_key",
    )?;
    check_ini_field(&cpa_s, "obfuscation.content_padding_addition")?;
    check_ini_field(&rekey_after_s, "rekey_after_time")?;
    check_ini_field(&rekey_timeout_s, "rekey_timeout")?;
    check_ini_field(&reject_after_s, "reject_after_time")?;
    check_ini_field(&keepalive_s, "keepalive_timeout")?;
    check_ini_field(&max_handshake_s, "max_handshake_attempts")?;

    let comment = server.label.trim();
    if comment.is_empty() || comment.contains('\n') || comment.contains('\r') {
        bail!("invalid server label for AmneziaWG comment");
    }

    let endpoint = format_authority(&server.public_ipv4.to_string(), eff.amneziawg_port);
    let dns_joined = dns_servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    let mut lines = vec![
        "[Interface]".to_owned(),
        format!("PrivateKey = {}", user.amneziawg.private_key.as_str()),
        format!("Address = {address}"),
        format!("DNS = {dns_joined}"),
        format!("MTU = {}", awg_cfg.mtu),
        format!("Jc = {}", obf.jc),
        format!("Jmin = {}", obf.jmin),
        format!("Jmax = {}", obf.jmax),
        format!("S1 = {}", obf.s1),
        format!("S2 = {}", obf.s2),
        format!("S3 = {}", obf.s3),
        format!("S4 = {}", obf.s4),
        format!("H1 = {h1_s}"),
        format!("H2 = {h2_s}"),
        format!("H3 = {h3_s}"),
        format!("H4 = {h4_s}"),
        format!("I1 = {}", obf.i1),
    ];
    for (key, val) in [
        ("I2", &obf.i2),
        ("I3", &obf.i3),
        ("I4", &obf.i4),
        ("I5", &obf.i5),
    ] {
        if let Some(v) = val {
            lines.push(format!("{key} = {v}"));
        }
    }
    lines.extend([
        format!(
            "HeaderProtectionKey = {}",
            obf.header_protection_key.as_str()
        ),
        format!("ContentPaddingAddition = {}", obf.content_padding_addition),
        format!("RekeyAfterTime = {}", awg_cfg.rekey_after_time),
        format!("RekeyTimeout = {}", awg_cfg.rekey_timeout),
        format!("RejectAfterTime = {}", awg_cfg.reject_after_time),
        format!("KeepaliveTimeout = {}", awg_cfg.keepalive_timeout),
        format!("MaxHandshakeAttempts = {}", awg_cfg.max_handshake_attempts),
        format!(
            "RandomTrailers = {}",
            if awg_cfg.random_trailers { "on" } else { "off" }
        ),
        format!(
            "DisableCookies = {}",
            if awg_cfg.disable_cookies { "on" } else { "off" }
        ),
        String::new(),
        format!("# {comment} amneziawg"),
        "[Peer]".to_owned(),
        format!("PublicKey = {server_awg_pub}"),
        format!("PresharedKey = {}", user.amneziawg.preshared_key.as_str()),
        "AllowedIPs = 0.0.0.0/0, ::/0".to_owned(),
        format!("Endpoint = {endpoint}"),
    ]);
    Ok(lines.join("\n"))
}

/// Render the AmneziaWG 3.1 server UAPI `set=1` document sent over `/var/run/amneziawg/kv0.sock`.
pub fn render_server_uapi(state: &State, server: &Server) -> Result<String> {
    let vpn = server
        .vpn
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn configuration", server.id))?;
    let awg_cfg = &state.settings.amneziawg;

    let priv_hex = base64_key_to_hex(vpn.amneziawg.private_key.as_str())?;
    let eff = server.effective_config(&state.settings, false);
    let obf = eff
        .awg_obfuscation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn configuration", server.id))?;
    let hpk_hex = base64_key_to_hex(obf.header_protection_key.as_str())?;
    let port = eff.amneziawg_port;

    // amneziawg-go UAPI parses boolean flags with Go's strconv.ParseBool ("true"/"false"),
    // unlike client .conf INI files which use "on".
    let mut lines = vec![
        "set=1".to_owned(),
        format!("private_key={priv_hex}"),
        format!("listen_port={port}"),
        format!("jc={}", obf.jc),
        format!("jmin={}", obf.jmin),
        format!("jmax={}", obf.jmax),
        format!("s1={}", obf.s1),
        format!("s2={}", obf.s2),
        format!("s3={}", obf.s3),
        format!("s4={}", obf.s4),
        format!("h1={}", obf.h1),
        format!("h2={}", obf.h2),
        format!("h3={}", obf.h3),
        format!("h4={}", obf.h4),
        format!("i1={}", obf.i1),
    ];
    for (key, val) in [
        ("i2", &obf.i2),
        ("i3", &obf.i3),
        ("i4", &obf.i4),
        ("i5", &obf.i5),
    ] {
        if let Some(v) = val {
            lines.push(format!("{key}={v}"));
        }
    }
    lines.extend([
        format!("header_protection_key={hpk_hex}"),
        format!("content_padding_addition={}", obf.content_padding_addition),
        format!("rekey_after_time={}", awg_cfg.rekey_after_time),
        format!("rekey_timeout={}", awg_cfg.rekey_timeout),
        format!("reject_after_time={}", awg_cfg.reject_after_time),
        format!("keepalive_timeout={}", awg_cfg.keepalive_timeout),
        format!("max_handshake_attempts={}", awg_cfg.max_handshake_attempts),
        format!("random_trailers={}", awg_cfg.random_trailers),
        format!("disable_cookies={}", awg_cfg.disable_cookies),
        "replace_peers=true".to_owned(),
    ]);

    for (_, user) in state.enabled_users_by_uid() {
        let peer_pub = user.amneziawg_public_key()?;
        let peer_hex = base64_key_to_hex(&peer_pub)?;
        let psk_hex = base64_key_to_hex(user.amneziawg.preshared_key.as_str())?;
        let peer_cidr = state.settings.awg_user_cidr(user.uid)?;
        lines.push(format!("public_key={peer_hex}"));
        lines.push(format!("preshared_key={psk_hex}"));
        lines.push("replace_allowed_ips=true".to_owned());
        lines.push(format!("allowed_ip={peer_cidr}"));
    }

    let mut out = lines.join("\n");
    out.push_str("\n\n");
    Ok(out)
}

pub fn render_apply_script(state: &State) -> Result<String> {
    let server_cidr = state.settings.awg_server_interface_cidr()?;
    let mtu = state.settings.amneziawg.mtu;
    let body = include_str!("../deploy/scripts/apply_uapi.sh");
    Ok(format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSERVER_CIDR=\"{server_cidr}\"\nAWG_MTU={mtu}\n\n{body}"
    ))
}

pub fn render_systemd_unit() -> String {
    r#"[Unit]
Description=Kinveil AmneziaWG 3.1 interface
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KERNELSPACE=1
RuntimeDirectory=amneziawg
RuntimeDirectoryMode=0700
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/lib/kinveil/awg/amneziawg-go -f kv0
ExecStartPost=/etc/kinveil/awg/apply-uapi.sh
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
"#
    .to_owned()
}
