mod common;

use std::collections::HashMap;
use std::io::{Cursor, Read as _, Write as _};
use std::net::IpAddr;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::multi_server_state;
use flate2::read::GzDecoder;
use serde_json::Value;
use tar::Archive;

use kinveil::crypto::{base64_key_to_hex, parse_cert_pins_only, sha256_hex};
use kinveil::deploy::artifacts::RuntimeArtifacts;
use kinveil::deploy::remote::{
    build_disabled_server_bundle, build_server_bundle, remote_stage_and_exec_cmd,
};
use kinveil::render::amneziawg::{render_apply_script, render_client_ini, render_server_uapi};
use kinveil::render::caddy::render_caddyfile;
use kinveil::render::firewall::{render_nftables, render_nftables_for_host, render_sysctl};
use kinveil::render::ssh_forwarding::{
    render_authorized_keys, render_systemd_unit as render_ssh_unit,
};
use kinveil::render::subscriptions::{SubVariant, render_subscription_body};
use kinveil::render::xray::render_xray_config;
use kinveil::state::parse_config_toml;
use kinveil::validate::{validate_happ_routing, validate_state};

fn unpack_tar_gz(bytes: &[u8]) -> HashMap<String, (u32, Vec<u8>)> {
    let dec = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(dec);
    let mut map = HashMap::new();
    for entry in archive.entries().unwrap() {
        let mut e = entry.unwrap();
        let path = e.path().unwrap().to_string_lossy().into_owned();
        let mode = e.header().mode().unwrap();
        let mut data = Vec::new();
        e.read_to_end(&mut data).unwrap();
        map.insert(path, (mode, data));
    }
    map
}

fn fake_artifacts() -> RuntimeArtifacts {
    let fake_xray = b"\x7fELF-fake-xray".to_vec();
    let fake_awg = b"\x7fELF-fake-awg".to_vec();
    RuntimeArtifacts {
        xray_sha256: sha256_hex(&fake_xray),
        xray_bytes: fake_xray,
        awg_sha256: sha256_hex(&fake_awg),
        awg_bytes: fake_awg,
    }
}

#[test]
fn disabled_users_and_servers_excluded_from_renders() {
    let state = multi_server_state();
    let srv1 = &state.servers[0];
    let srv2 = &state.servers[1];
    let srv3 = &state.servers[2];
    let alice = state.user("alice").unwrap();
    let bob = state.user("bob").unwrap();
    let charlie = state.user("charlie").unwrap();

    // Xray reflects port overrides, excludes disabled users, omits gRPC API/access logs,
    // blocks self public IPs without invalid ::ffff:0:0/96, and permits 80,443 direct on the subscription host.
    let xray_srv1: Value =
        serde_json::from_str(&render_xray_config(&state, srv1).unwrap()).unwrap();
    let rules_srv1 = xray_srv1["routing"]["rules"].as_array().unwrap();
    assert_eq!(rules_srv1[1]["outboundTag"], "direct");
    assert_eq!(rules_srv1[1]["port"], "80,443");
    let direct_ips_1 = rules_srv1[1]["ip"].as_array().unwrap();
    assert!(direct_ips_1.iter().any(|ip| ip == "198.51.100.10/32"));
    assert!(direct_ips_1.iter().any(|ip| ip == "2001:db8::10/128"));
    let blocked_ips_1 = rules_srv1[2]["ip"].as_array().unwrap();
    assert!(blocked_ips_1.iter().any(|ip| ip == "198.51.100.10/32"));
    assert!(blocked_ips_1.iter().any(|ip| ip == "2001:db8::10/128"));
    assert!(blocked_ips_1.iter().all(|ip| ip != "::ffff:0:0/96"));

    let xray_srv2: Value =
        serde_json::from_str(&render_xray_config(&state, srv2).unwrap()).unwrap();
    let rules_srv2 = xray_srv2["routing"]["rules"].as_array().unwrap();
    assert!(rules_srv2.iter().all(|r| r["outboundTag"] != "direct"));
    let blocked_ips_2 = rules_srv2[1]["ip"].as_array().unwrap();
    assert!(blocked_ips_2.iter().any(|ip| ip == "198.51.100.11/32"));
    assert!(blocked_ips_2.iter().all(|ip| ip != "::ffff:0:0/96"));

    let mut allow_priv_state = state.clone();
    allow_priv_state
        .set_config_toml("[firewall]\nblock_private_networks = false\n")
        .unwrap();
    let xray_allow_priv: Value = serde_json::from_str(
        &render_xray_config(&allow_priv_state, &allow_priv_state.servers[1]).unwrap(),
    )
    .unwrap();
    let blocked_allow_priv = xray_allow_priv["routing"]["rules"][1]["ip"]
        .as_array()
        .unwrap();
    assert_eq!(
        blocked_allow_priv,
        &[
            Value::from("0.0.0.0/8"),
            Value::from("100.100.100.200/32"),
            Value::from("127.0.0.0/8"),
            Value::from("169.254.0.0/16"),
            Value::from("224.0.0.0/4"),
            Value::from("240.0.0.0/4"),
            Value::from("198.51.100.11/32"),
            Value::from("::/128"),
            Value::from("::1/128"),
            Value::from("fd00:ec2::254/128"),
            Value::from("fe80::/10"),
            Value::from("ff00::/8"),
        ]
    );
    assert_eq!(xray_srv2["log"]["access"], "none");
    assert_eq!(xray_srv2["inbounds"][0]["port"], 10443);
    assert_eq!(xray_srv2["inbounds"][1]["port"], 10444);
    assert_eq!(
        xray_srv2["outbounds"][0]["settings"]["domainStrategy"],
        "UseIP"
    );
    assert!(xray_srv2.get("api").is_none());
    let vless_clients = xray_srv2["inbounds"][0]["settings"]["clients"]
        .as_array()
        .unwrap();
    assert_eq!(vless_clients.len(), 2);
    assert!(vless_clients.iter().all(|c| c["email"] != "charlie"));

    // AmneziaWG INI vs UAPI
    let ini = render_client_ini(&state, srv2, alice).unwrap();
    assert!(!ini.ends_with('\n'));
    assert!(ini.contains("RandomTrailers = on"));
    assert!(ini.contains("DisableCookies = on"));
    assert!(ini.contains("Endpoint = 198.51.100.11:51821"));
    assert!(ini.contains(&format!(
        "PresharedKey = {}",
        alice.amneziawg.preshared_key.as_str()
    )));
    assert!(ini.contains(&state.settings.awg_user_cidr(alice.uid).unwrap()));

    let uapi = render_server_uapi(&state, srv2).unwrap();
    assert!(uapi.starts_with("set=1\n"));
    assert!(uapi.ends_with("\n\n"));
    assert!(uapi.contains("listen_port=51821\n"));
    assert!(uapi.contains("random_trailers=true\n"));
    assert!(uapi.contains("disable_cookies=true\n"));
    assert!(uapi.contains(&format!(
        "preshared_key={}\n",
        base64_key_to_hex(alice.amneziawg.preshared_key.as_str()).unwrap()
    )));
    assert!(uapi.contains(&format!(
        "header_protection_key={}",
        base64_key_to_hex(
            &srv2
                .vpn
                .as_ref()
                .unwrap()
                .amneziawg
                .obfuscation
                .header_protection_key
        )
        .unwrap()
    )));
    assert!(uapi.contains(&base64_key_to_hex(&alice.amneziawg_public_key().unwrap()).unwrap()));
    assert!(uapi.contains(&base64_key_to_hex(&bob.amneziawg_public_key().unwrap()).unwrap()));
    assert!(!uapi.contains(&base64_key_to_hex(&charlie.amneziawg_public_key().unwrap()).unwrap()));

    // SSH forwarding includes enabled users (alice, bob) and excludes disabled (charlie)
    let ssh_unit = render_ssh_unit();
    assert!(
        ssh_unit.contains("ExecStartPre=/usr/bin/install -d -m 0755 -o root -g root /run/sshd")
    );
    assert!(ssh_unit.contains("ProtectSystem=strict"));
    assert!(ssh_unit.contains("ReadWritePaths=/run"));
    assert!(!ssh_unit.contains("NoNewPrivileges"));
    let auth_keys = render_authorized_keys(&state).unwrap();
    assert_eq!(auth_keys.len(), 2);
    assert_eq!(auth_keys[0].0, "vpnssh1");
    assert_eq!(auth_keys[1].0, "vpnssh2");
    assert!(auth_keys[0].1.starts_with("restrict,port-forwarding "));

    // Firewall & sysctl follow enabled roles and disabled-host retirement
    let sysctl = render_sysctl(&state, srv1);
    assert!(sysctl.contains("net.ipv4.ip_forward = 1"));
    assert!(!sysctl.contains("net.ipv6.conf.all.forwarding"));
    assert!(sysctl.contains("net.core.rmem_max = 16777216"));
    let sysctl_disabled = render_sysctl(&state, srv3);
    assert!(sysctl_disabled.contains("net.ipv4.ip_forward = 0"));

    let dns_ips: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap()];
    let nft1 = render_nftables(&state, srv1, Some(999), &[1001], &dns_ips).unwrap();
    assert!(nft1.starts_with("#!/usr/sbin/nft -f\nflush ruleset\n\ntable inet kinveil {\n"));
    assert!(nft1.contains("tcp dport 2220 accept"));
    assert!(nft1.contains("tcp dport { 80, 443 } accept"));
    assert!(nft1.contains("set vpnssh_users { type uid; elements = { 1001 }; }"));
    assert!(nft1.contains("meta skuid 999 ip daddr 198.51.100.10 tcp dport { 80, 443 } accept"));
    assert!(nft1.contains("iifname \"kv0\" oifname \"kv0\" reject"));
    assert!(
        nft1.contains("iifname \"kv0\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu")
    );
    assert!(nft1.contains("iifname \"kv0\" meta nfproto ipv6 reject"));
    assert!(nft1.contains("iifname \"kv0\" oifname != \"kv0\" ip saddr 10.8.0.0/16 masquerade"));

    let nft2 = render_nftables(&state, srv2, Some(999), &[1001], &dns_ips).unwrap();
    assert!(nft2.contains("tcp dport 10443 accept"));
    assert!(nft2.contains("udp dport 10444 accept"));
    assert!(nft2.contains("udp dport 51821 accept"));
    assert!(nft2.contains("meta skuid 999 fib daddr type local reject"));
    assert!(!nft2.contains("80, 443"));
    assert!(!nft2.contains("vpnssh_users"));

    let nft3_host = render_nftables_for_host(&state, srv3).unwrap();
    assert!(nft3_host.contains("tcp dport 2220 accept"));
    assert!(!nft3_host.contains("80, 443"));
    assert!(!nft3_host.contains("chain forward"));

    let alice_happ = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "alice", alice, SubVariant::Happ).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(!alice_happ.contains("198.51.100.12"));
    assert!(alice_happ.contains("198.51.100.10:8443"));
    assert!(alice_happ.contains("198.51.100.11:10443"));
}

#[test]
fn throne_hysteria2_spki_pin_is_unescaped_and_happ_omits_ssh() {
    let state = multi_server_state();
    let srv1 = &state.servers[0];
    let alice = state.user("alice").unwrap();
    let bob = state.user("bob").unwrap();

    let alice_happ = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "alice", alice, SubVariant::Happ).unwrap())
            .unwrap(),
    )
    .unwrap();
    let alice_throne = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "alice", alice, SubVariant::Throne).unwrap())
            .unwrap(),
    )
    .unwrap();
    let bob_throne = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "bob", bob, SubVariant::Throne).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert!(!alice_happ.contains("ssh://"));
    assert!(!alice_happ.contains("tls_certificate_public_key_sha256"));
    assert!(alice_happ.contains("#DE%20Frankfurt%20vless-stream"));
    assert!(alice_happ.contains("#DE%20Frankfurt%20vless-packet"));
    assert!(!alice_happ.contains("vless-alice"));

    let pins1 = parse_cert_pins_only(&srv1.vpn.as_ref().unwrap().hysteria2.cert_pem).unwrap();
    assert!(alice_throne.contains(&format!(
        "&insecure=0&tls_certificate_public_key_sha256={}",
        pins1.spki_sha256_b64
    )));
    assert!(alice_throne.contains("&sni=198.51.100.10&vcn=198.51.100.10&insecure=0&"));
    assert!(alice_throne.contains("ssh://198.51.100.10:2222?"));
    assert!(bob_throne.contains("#FI%20Helsinki%20vless-stream"));
    assert!(bob_throne.contains("ssh://198.51.100.10:2222?"));
    assert!(!bob_throne.contains("ssh://198.51.100.11:"));

    let vpn_line = alice_happ
        .lines()
        .find(|l| l.starts_with("vpn://"))
        .unwrap();
    let decoded_ini = String::from_utf8(URL_SAFE_NO_PAD.decode(&vpn_line[6..]).unwrap()).unwrap();
    assert!(decoded_ini.contains("[Interface]"));
}

#[test]
fn server_bundle_permissions_and_deferred_caddy_retirement() {
    let state = multi_server_state();
    let srv1 = &state.servers[0];
    let srv2 = &state.servers[1];
    let srv3 = &state.servers[2];
    let alice = state.user("alice").unwrap();
    let bob = state.user("bob").unwrap();
    let charlie = state.user("charlie").unwrap();
    let artifacts = fake_artifacts();

    let bundle1 = unpack_tar_gz(
        &build_server_bundle(&state, srv1, &artifacts, false, true, true, false).unwrap(),
    );
    assert_eq!(bundle1["install.sh"].0, 0o755);
    let install1 = String::from_utf8_lossy(&bundle1["install.sh"].1);
    assert!(install1.contains(
        "ADMIN_SSH_PORT=2220\nHAS_XRAY=1\nHAS_AWG=1\nHAS_SUB=1\nHAS_SSH=1\nCO_LOCATED_SUB_V4=\"198.51.100.10\"\nCO_LOCATED_SUB_V6=\"2001:db8::10\"\nDEFER_CADDY_RETIRE=0\nALLOW_TAKEOVER=0\n"
    ));
    assert!(install1.contains("PRIVATE_IPV4_LIST=\"0.0.0.0/8, 10.0.0.0/8,"));
    assert!(install1.contains("127.0.0.0/8"));
    assert!(install1.contains("::ffff:0:0/96"));
    assert_eq!(bundle1["files/etc/kinveil/tls/hysteria.key"].0, 0o600);
    assert_eq!(bundle1["files/etc/kinveil/awg/uapi.conf"].0, 0o600);
    assert_eq!(bundle1["files/etc/kinveil/ssh/host_ed25519"].0, 0o600);
    assert_eq!(bundle1["bin/xray"].0, 0o755);
    assert_eq!(bundle1["bin/amneziawg-go"].0, 0o755);
    assert!(bundle1.contains_key("files/etc/caddy/Caddyfile"));
    assert!(bundle1.contains_key("files/etc/sysctl.d/90-kinveil.conf"));
    assert!(bundle1.contains_key("files/etc/systemd/system/kinveil-xray.service"));
    assert!(bundle1.contains_key("files/etc/systemd/system/kinveil-awg.service"));
    assert!(bundle1.contains_key("files/etc/systemd/system/kinveil-ssh.service"));
    assert!(bundle1.contains_key("files/etc/kinveil/ssh/authorized_keys/vpnssh1"));
    assert!(bundle1.contains_key("files/etc/kinveil/ssh/authorized_keys/vpnssh2"));
    assert!(!bundle1.contains_key("files/etc/kinveil/ssh/authorized_keys/vpnssh3"));
    assert!(bundle1.contains_key(&format!("sub/{}/happ", alice.subscription_token.as_str())));
    assert!(bundle1.contains_key(&format!("sub/{}/throne", alice.subscription_token.as_str())));
    assert!(bundle1.contains_key(&format!("sub/{}/happ", bob.subscription_token.as_str())));
    assert!(!bundle1.contains_key(&format!("sub/{}/happ", charlie.subscription_token.as_str())));

    let bundle_takeover = unpack_tar_gz(
        &build_server_bundle(&state, srv1, &artifacts, false, true, true, true).unwrap(),
    );
    assert!(String::from_utf8_lossy(&bundle_takeover["install.sh"].1).contains("ALLOW_TAKEOVER=1"));

    let bundle2 = unpack_tar_gz(
        &build_server_bundle(&state, srv2, &artifacts, true, false, false, false).unwrap(),
    );
    assert!(String::from_utf8_lossy(&bundle2["install.sh"].1).contains("DEFER_CADDY_RETIRE=1"));
    assert!(!bundle2.contains_key("bin/xray"));
    assert!(!bundle2.contains_key("bin/amneziawg-go"));
    assert!(!bundle2.contains_key("files/etc/caddy/Caddyfile"));
    assert!(!bundle2.contains_key("files/etc/kinveil/ssh/sshd_config"));

    let disabled_bundle = unpack_tar_gz(&build_disabled_server_bundle(&state, srv3).unwrap());
    assert!(disabled_bundle.contains_key("install.sh"));
    assert!(
        String::from_utf8_lossy(&disabled_bundle["install.sh"].1).contains("ADMIN_SSH_PORT=2220\n")
    );
    assert!(disabled_bundle.contains_key("files/etc/nftables.conf"));

    let cmd_root = remote_stage_and_exec_cmd("root");
    let cmd_ops = remote_stage_and_exec_cmd("ops");
    assert!(cmd_root.starts_with("sh -c "));
    assert!(cmd_ops.starts_with("sudo -n sh -c "));
    assert!(cmd_root.contains("/run/kinveil-stage.XXXXXX"));
    assert!(cmd_root.contains(r#"bash "$STAGE/install.sh" "$STAGE""#));
    assert!(cmd_root.contains(r#"trap '\''rm -rf "$STAGE"'\'' EXIT"#));
    assert!(cmd_ops.contains(r#"trap '\''rm -rf "$STAGE"'\'' EXIT"#));
    for cmd in [&cmd_root, &cmd_ops] {
        let syntax_status = Command::new("sh")
            .args(["-n", "-c", cmd])
            .status()
            .expect("invoke sh -n");
        assert!(syntax_status.success(), "sh -n failed for: {cmd}");
    }
}

#[test]
fn rendered_shell_scripts_pass_syntax_checks() {
    let state = multi_server_state();
    let srv1 = &state.servers[0];
    let srv3 = &state.servers[2];
    let artifacts = fake_artifacts();

    let bundle1 = unpack_tar_gz(
        &build_server_bundle(&state, srv1, &artifacts, false, true, true, false).unwrap(),
    );
    let disabled_bundle = unpack_tar_gz(&build_disabled_server_bundle(&state, srv3).unwrap());
    let apply_sh = render_apply_script(&state).unwrap();

    assert_shell_syntax("bash", &String::from_utf8_lossy(&bundle1["install.sh"].1));
    assert_shell_syntax(
        "bash",
        &String::from_utf8_lossy(&disabled_bundle["install.sh"].1),
    );
    assert_shell_syntax("bash", &apply_sh);
    assert_shell_syntax("sh", include_str!("../src/deploy/scripts/wipe.sh"));
}

fn assert_shell_syntax(shell: &str, script: &str) {
    let mut child = Command::new(shell)
        .arg("-n")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {shell} -n: {e}"));
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())
        .expect("write script to stdin");
    let status = child.wait().expect("wait for shell syntax check");
    assert!(status.success(), "{shell} -n failed syntax check");
}

#[test]
fn caddy_profile_title_and_happ_routing_validation() {
    let mut state = multi_server_state();

    let default_caddy = render_caddyfile(&state).unwrap();
    assert!(default_caddy.contains("Profile-Title \"base64:S2ludmVpbA==\""));
    assert!(!default_caddy.contains("\n            routing "));

    state
        .set_config_toml(
            "[subscription]\nprofile_title = \"My Home Net\"\nhapp_routing = \"happ://routing/onadd/abc123\"\n",
        )
        .unwrap();
    let custom_caddy = render_caddyfile(&state).unwrap();
    assert!(custom_caddy.contains("Profile-Title \"base64:TXkgSG9tZSBOZXQ=\""));
    assert!(custom_caddy.contains("routing \"happ://routing/onadd/abc123\""));

    assert!(validate_happ_routing("happ://routing/onadd/abc123").is_ok());
    assert!(validate_happ_routing("happ://routing/bad\"quote").is_err());
    assert!(validate_happ_routing("happ://routing/bad\\slash").is_err());
    assert!(validate_happ_routing("happ://routing/bad space").is_err());
    assert!(validate_happ_routing("happ://routing/bad{brace}").is_err());
}

#[test]
fn protocol_toggles_global_and_per_server_control_renders_and_bundles() {
    let mut state = multi_server_state();
    state
        .set_config_toml("[vless]\nstream = false\n\n[amneziawg]\nenabled = false\n")
        .expect("disable vless.stream and amneziawg globally");
    validate_state(&state).expect("validate global protocol toggles");

    let srv1 = &state.servers[0];
    let alice = state.user("alice").unwrap();
    let xray: Value = serde_json::from_str(&render_xray_config(&state, srv1).unwrap()).unwrap();
    assert_eq!(
        xray["inbounds"][0]["streamSettings"]["xhttpSettings"]["mode"],
        "packet-up"
    );

    let sub = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "alice", alice, SubVariant::Happ).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(!sub.contains("vless-stream"));
    assert!(sub.contains("vless-packet"));
    assert!(sub.contains("hysteria2://"));
    assert!(!sub.contains("vpn://"));

    assert!(render_sysctl(&state, srv1).contains("net.ipv4.ip_forward = 0"));
    let bundle = unpack_tar_gz(
        &build_server_bundle(&state, srv1, &fake_artifacts(), false, true, true, false).unwrap(),
    );
    let install = String::from_utf8_lossy(&bundle["install.sh"].1);
    assert!(install.contains("HAS_XRAY=1\nHAS_AWG=0\n"));
    assert!(!bundle.contains_key("bin/amneziawg-go"));
    assert!(!bundle.contains_key("files/etc/kinveil/awg/uapi.conf"));

    // Per-server protocol toggle disabling Xray protocols leaves only AmneziaWG
    let mut awg_only = multi_server_state();
    awg_only
        .set_config_toml("")
        .expect("restore default settings");
    let vpn2 = awg_only.servers[1].vpn.as_mut().unwrap();
    vpn2.vless.enabled = false;
    vpn2.hysteria2.enabled = false;
    assert_eq!(parse_config_toml("").unwrap(), awg_only.settings);
    assert!(!awg_only.servers[1].has_xray(&awg_only.settings));
    assert!(awg_only.servers[1].has_amneziawg(&awg_only.settings));

    let nft_awg_only = render_nftables_for_host(&awg_only, &awg_only.servers[1]).unwrap();
    assert!(!nft_awg_only.contains("tcp dport 10443"));
    assert!(!nft_awg_only.contains("udp dport 10444"));
    assert!(nft_awg_only.contains("udp dport 51821 accept"));

    let awg_bundle = unpack_tar_gz(
        &build_server_bundle(
            &awg_only,
            &awg_only.servers[1],
            &fake_artifacts(),
            true,
            true,
            true,
            false,
        )
        .unwrap(),
    );
    let install_awg = String::from_utf8_lossy(&awg_bundle["install.sh"].1);
    assert!(install_awg.contains("HAS_XRAY=0\nHAS_AWG=1\n"));
    assert!(!awg_bundle.contains_key("bin/xray"));
    assert!(!awg_bundle.contains_key("files/etc/kinveil/xray.json"));
    assert!(awg_bundle.contains_key("bin/amneziawg-go"));
}
