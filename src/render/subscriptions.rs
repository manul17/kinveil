use std::fmt::Write as _;

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

use crate::crypto::parse_cert_pins_only;
use crate::render::amneziawg::render_client_ini;
use crate::render::format_authority;
use crate::state::{State, User};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubVariant {
    Happ,
    Throne,
}

fn quote_with_safe(input: &str, extra_safe: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || extra_safe.contains(&b)
        {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn quote_strict(input: &str) -> String {
    quote_with_safe(input, b"")
}

fn quote_slash_safe(input: &str) -> String {
    quote_with_safe(input, b"/")
}

fn encode_query(fields: &[(&str, String)], safe: &[u8]) -> String {
    let mut out = String::new();
    for (idx, (k, v)) in fields.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&quote_with_safe(k, safe));
        out.push('=');
        out.push_str(&quote_with_safe(v, safe));
    }
    out
}

fn sanitize_fragment(fragment: &str) -> Result<String> {
    if fragment.is_empty()
        || fragment.contains('\n')
        || fragment.contains('\r')
        || fragment.contains('#')
    {
        bail!("invalid subscription profile fragment");
    }
    Ok(quote_slash_safe(fragment))
}

fn render_subscription_lines(
    state: &State,
    user_name: &str,
    user: &User,
    variant: SubVariant,
) -> Result<Vec<String>> {
    render_subscription_lines_for_server(state, user_name, user, variant, None)
}

pub fn render_subscription_lines_for_server(
    state: &State,
    user_name: &str,
    user: &User,
    variant: SubVariant,
    server_filter: Option<&str>,
) -> Result<Vec<String>> {
    if !user.enabled {
        bail!("cannot render subscription for disabled user {user_name}");
    }
    if let Some(id) = server_filter {
        let srv = state.server(id)?;
        if !srv.enabled {
            bail!("server '{id}' is disabled");
        }
    }

    let mut links = Vec::new();
    let vless_cfg = &state.settings.vless;
    let hyst_cfg = &state.settings.hysteria2;
    if hyst_cfg.alpn.is_empty() {
        bail!("hysteria2.alpn must not be empty");
    }

    for server in state
        .servers
        .iter()
        .filter(|s| server_filter.is_none_or(|only| s.id == only) && s.enabled && s.has_vpn())
    {
        let vpn = server
            .vpn
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server {} missing vpn block", server.id))?;
        let eff =
            server.effective_config(&state.settings, state.is_subscription_server(&server.id));

        // 1. VLESS REALITY XHTTP links (stream-up, packet-up)
        let mut vless_modes = Vec::new();
        if eff.has_vless_stream {
            vless_modes.push("stream-up");
        }
        if eff.has_vless_packet {
            vless_modes.push("packet-up");
        }
        if !vless_modes.is_empty() {
            let vless = &vpn.vless;
            let (sni, _) = eff
                .vless_sni
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("server {} lacks effective VLESS SNI", server.id))?;
            let (xhttp_path, _) = eff.vless_xhttp_path.as_ref().ok_or_else(|| {
                anyhow::anyhow!("server {} lacks effective VLESS XHTTP path", server.id)
            })?;
            let vless_authority = format_authority(&server.public_ipv4.to_string(), eff.vless_port);
            let mlkem = if vless_cfg.support_x25519mlkem768 {
                "true"
            } else {
                "false"
            };
            let xhttp_host = eff
                .vless_xhttp_host
                .as_ref()
                .map(|(h, _)| h.as_str())
                .unwrap_or("");
            let xmux_val = vless_cfg.xmux.to_xray_json();

            for mode in vless_modes {
                let mut extra_map = Map::new();
                extra_map.insert("mode".to_owned(), Value::String(mode.to_owned()));
                extra_map.insert(
                    "xPaddingBytes".to_owned(),
                    Value::String(vless_cfg.xhttp.padding_bytes.clone()),
                );
                extra_map.insert("xmux".to_owned(), xmux_val.clone());
                let extra_json = serde_json::to_string(&Value::Object(extra_map))?;

                let fields = [
                    ("encryption", "none".to_owned()),
                    ("fp", vless_cfg.fingerprint.clone()),
                    ("host", xhttp_host.to_owned()),
                    ("path", xhttp_path.clone()),
                    ("pbk", vless.public_key()?),
                    ("security", "reality".to_owned()),
                    ("sid", vless.short_id.clone()),
                    ("sni", sni.clone()),
                    ("spx", user.vless.spider_x.clone()),
                    ("support-x25519mlkem768", mlkem.to_owned()),
                    ("type", "xhttp".to_owned()),
                    ("x_padding_bytes", vless_cfg.xhttp.padding_bytes.clone()),
                    ("mode", mode.to_owned()),
                    ("extra", extra_json),
                ];
                let mode_label = if mode == "stream-up" {
                    "VLESS-Stream"
                } else {
                    "VLESS-Packet"
                };
                let fragment = sanitize_fragment(&format!("{} {mode_label}", server.label))?;
                let query = encode_query(&fields, b"");
                links.push(format!(
                    "vless://{}@{}?{}#{}",
                    quote_strict(user.vless.uuid.as_str()),
                    vless_authority,
                    query,
                    fragment
                ));
            }
        }

        // 2. Hysteria2 link
        if eff.has_hysteria2 {
            let hyst = &vpn.hysteria2;
            let pins = parse_cert_pins_only(&hyst.cert_pem)?;
            let sni = server.public_ipv4.to_string();
            let hyst_authority =
                format_authority(&server.public_ipv4.to_string(), eff.hysteria2_port);
            let hyst_fields = [
                ("alpn", hyst_cfg.alpn.join(",")),
                ("obfs", "salamander".to_owned()),
                (
                    "obfs-password",
                    hyst.salamander_password.as_str().to_owned(),
                ),
                ("pinSHA256", pins.cert_sha256_hex),
                ("security", "tls".to_owned()),
                ("sni", sni.clone()),
                ("vcn", sni),
            ];
            let mut hyst_url = format!(
                "hysteria2://{}@{}?{}",
                quote_strict(user.hysteria2.auth.as_str()),
                hyst_authority,
                encode_query(&hyst_fields, b"")
            );
            if variant == SubVariant::Throne {
                // Throne does not validate self-signed Hysteria2 certificates from pinSHA256 alone;
                // keep &insecure=0 and the literal (+, /, =) SPKI digest paired with vcn/sni.
                let _ = write!(
                    hyst_url,
                    "&insecure=0&tls_certificate_public_key_sha256={}",
                    pins.spki_sha256_b64
                );
            }
            let hyst_fragment = sanitize_fragment(&format!("{} Hysteria2", server.label))?;
            hyst_url.push('#');
            hyst_url.push_str(&hyst_fragment);
            links.push(hyst_url);
        }

        // 3. AmneziaWG 3.1 link
        if eff.has_amneziawg {
            let ini = render_client_ini(state, server, user)?;
            links.push(format!("vpn://{}", URL_SAFE_NO_PAD.encode(ini.as_bytes())));
        }
    }

    if variant == SubVariant::Throne {
        for server in state
            .servers
            .iter()
            .filter(|s| server_filter.is_none_or(|only| s.id == only) && s.enabled)
        {
            let eff = server.effective_config(&state.settings, false);
            if !eff.has_ssh_forwarding {
                continue;
            }
            let vpn = server
                .vpn
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("server {} missing vpn block", server.id))?;
            let priv_b64 = STANDARD_NO_PAD.encode(user.ssh_forwarding.private_key.as_bytes());
            let host_pub = vpn.ssh_forwarding.host_public_key()?;
            let host_b64 = STANDARD_NO_PAD.encode(host_pub.trim().as_bytes());
            let ssh_fields = [
                ("user", user.ssh_username()),
                ("private_key", priv_b64),
                ("host_key", host_b64),
            ];
            let authority =
                format_authority(&server.public_ipv4.to_string(), eff.ssh_forwarding_port);
            let fragment = sanitize_fragment(&format!("{} SSH", server.label))?;
            links.push(format!(
                "ssh://{}?{}#{}",
                authority,
                encode_query(&ssh_fields, b"+/"),
                fragment
            ));
        }
    }

    if links.is_empty() {
        let any_ssh = state.servers.iter().any(|s| {
            server_filter.is_none_or(|only| s.id == only)
                && s.enabled
                && s.effective_config(&state.settings, false)
                    .has_ssh_forwarding
        });
        if any_ssh && variant == SubVariant::Happ {
            return Ok(Vec::new());
        }
        if let Some(id) = server_filter {
            bail!("server '{id}' has no active VPN protocols to export");
        }
        bail!("subscription rendered zero links (no enabled vpn servers)");
    }
    Ok(links)
}

pub fn render_subscription_body(
    state: &State,
    user_name: &str,
    user: &User,
    variant: SubVariant,
) -> Result<String> {
    let links = render_subscription_lines(state, user_name, user, variant)?;
    if links.is_empty() {
        return Ok(String::new());
    }
    let mut joined = links.join("\n");
    joined.push('\n');
    Ok(STANDARD.encode(joined.as_bytes()))
}
