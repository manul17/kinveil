mod common;

use std::collections::BTreeSet;
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{fake_artifacts, multi_server_state, unpack_tar_gz};
use serde_json::Value;

use kinveil::crypto::base64_key_to_hex;
use kinveil::deploy::remote::{
    BundleOptions, build_disabled_server_bundle, build_server_bundle, remote_stage_and_exec_cmd,
};
use kinveil::render::ResolvedFirewallLists;
use kinveil::render::amneziawg::{render_client_ini, render_server_uapi};
use kinveil::render::caddy::{compile_subscription_routing, render_caddyfile};
use kinveil::render::firewall::{render_nftables_for_host, render_sysctl};
use kinveil::render::ssh_forwarding::render_systemd_unit as render_ssh_unit;
use kinveil::render::subscriptions::{
    SubVariant, render_subscription_body, render_subscription_lines_for_server,
};
use kinveil::render::xray::{render_systemd_unit as render_xray_unit, render_xray_config};
use kinveil::state::{VpnProtocol, parse_config_toml};
use kinveil::validate::validate_state;

#[test]
fn disabled_users_and_servers_excluded_from_renders() {
    let state = multi_server_state();
    let srv1 = &state.servers[0];
    let srv2 = &state.servers[1];
    let srv3 = &state.servers[2];
    let alice = state.user("alice").unwrap();
    let bob = state.user("bob").unwrap();
    let charlie = state.user("charlie").unwrap();

    // Non-subscription Xray node omits subscription direct-bypass rule, excludes disabled users,
    // and respects block_private_networks = false.
    let empty_lists = ResolvedFirewallLists::default();
    let xray_srv2: Value =
        serde_json::from_str(&render_xray_config(&state, srv2, &empty_lists).unwrap()).unwrap();
    let rules_srv2 = xray_srv2["routing"]["rules"].as_array().unwrap();
    assert!(rules_srv2.iter().all(|r| r["outboundTag"] != "direct"));

    let mut allow_priv_state = state.clone();
    allow_priv_state
        .set_config_toml("[firewall]\nblock_private_networks = false\n")
        .unwrap();
    let xray_allow_priv: Value = serde_json::from_str(
        &render_xray_config(
            &allow_priv_state,
            &allow_priv_state.servers[1],
            &empty_lists,
        )
        .unwrap(),
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

    // AmneziaWG INI (no trailing newline, Endpoint uses server port override) & UAPI (trailing \n\n, excludes disabled peers).
    let ini = render_client_ini(&state, srv2, alice).unwrap();
    assert!(!ini.ends_with('\n'));
    assert!(ini.contains("Endpoint = 198.51.100.11:51821"));

    let uapi = render_server_uapi(&state, srv2).unwrap();
    assert!(uapi.starts_with("set=1\n") && uapi.ends_with("\n\n"));
    assert!(uapi.contains("listen_port=51821\n"));
    assert!(uapi.contains(&base64_key_to_hex(&alice.amneziawg_public_key().unwrap()).unwrap()));
    assert!(uapi.contains(&base64_key_to_hex(&bob.amneziawg_public_key().unwrap()).unwrap()));
    assert!(!uapi.contains(&base64_key_to_hex(&charlie.amneziawg_public_key().unwrap()).unwrap()));

    // SSH systemd hardening unit & sysctl ip_forward toggle.
    let ssh_unit = render_ssh_unit();
    assert!(
        ssh_unit.contains("ExecStartPre=/usr/bin/install -d -m 0755 -o root -g root /run/sshd")
    );
    assert!(ssh_unit.contains("ProtectSystem=strict"));
    assert!(ssh_unit.contains("ReadWritePaths=/run"));
    assert!(!ssh_unit.contains("NoNewPrivileges"));

    let sysctl = render_sysctl(&state, srv1);
    assert!(sysctl.contains("net.ipv4.ip_forward = 1"));
    assert!(!sysctl.contains("net.ipv6.conf.all.forwarding"));
    assert!(render_sysctl(&state, srv3).contains("net.ipv4.ip_forward = 0"));

    // Disabled srv3 excluded from rendered client subscriptions, and vpn:// embeds valid AWG INI.
    let alice_happ = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "alice", alice, SubVariant::Happ).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(!alice_happ.contains("198.51.100.12"));
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

    let empty_lists = ResolvedFirewallLists::default();
    let bundle1 = unpack_tar_gz(
        &build_server_bundle(
            &state,
            srv1,
            &artifacts,
            &empty_lists,
            BundleOptions {
                defer_caddy_retire: false,
                include_xray_bin: true,
                include_geodata: true,
                include_awg_bin: true,
                allow_takeover: false,
            },
        )
        .unwrap(),
    );
    assert_eq!(bundle1["install.sh"].0, 0o755);
    let install1 = String::from_utf8_lossy(&bundle1["install.sh"].1);
    assert!(install1.contains(
        "ADMIN_SSH_USER=\"root\"\nADMIN_SSH_PORT=2220\nHAS_VPN=1\nHAS_XRAY=1\nHAS_AWG=1\nHAS_SUB=1\nHAS_SSH=1\nHAS_FW_UPDATE=0\nCO_LOCATED_SUB_V4=\"198.51.100.10\"\nCO_LOCATED_SUB_V6=\"2001:db8::10\"\nDEFER_CADDY_RETIRE=0\nALLOW_TAKEOVER=0\n"
    ));
    let nft_blocked = String::from_utf8_lossy(&bundle1["files/etc/kinveil/nft-blocked.nft"].1);
    assert!(nft_blocked.contains("set egress_blocked_v4"));
    assert!(nft_blocked.contains("10.0.0.0/8"));
    assert!(nft_blocked.contains("set egress_blocked_v6"));
    assert!(nft_blocked.contains("::ffff:0.0.0.0/96"));
    assert!(!bundle1.contains_key("bin/update-firewall.sh"));
    assert_eq!(bundle1["files/etc/kinveil/tls/hysteria.key"].0, 0o600);
    assert_eq!(bundle1["files/etc/kinveil/awg/uapi.conf"].0, 0o600);
    assert_eq!(bundle1["files/etc/kinveil/ssh/host_ed25519"].0, 0o600);
    assert_eq!(bundle1["bin/xray"].0, 0o755);
    assert_eq!(bundle1["bin/geoip.dat"].0, 0o644);
    assert_eq!(bundle1["bin/geosite.dat"].0, 0o644);
    assert_eq!(bundle1["bin/amneziawg-go"].0, 0o755);
    assert!(bundle1.contains_key("files/etc/caddy/Caddyfile"));
    assert!(bundle1.contains_key("files/etc/sysctl.d/90-kinveil.conf"));
    assert!(bundle1.contains_key("files/etc/systemd/resolved.conf.d/90-kinveil.conf"));
    assert!(bundle1.contains_key("files/etc/ssh/sshd_config.d/0-00-kinveil-admin.conf"));
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
        &build_server_bundle(
            &state,
            srv1,
            &artifacts,
            &empty_lists,
            BundleOptions {
                defer_caddy_retire: false,
                include_xray_bin: true,
                include_geodata: false,
                include_awg_bin: true,
                allow_takeover: true,
            },
        )
        .unwrap(),
    );
    assert!(String::from_utf8_lossy(&bundle_takeover["install.sh"].1).contains("ALLOW_TAKEOVER=1"));
    assert!(!bundle_takeover.contains_key("bin/geoip.dat"));

    let bundle2 = unpack_tar_gz(
        &build_server_bundle(
            &state,
            srv2,
            &artifacts,
            &empty_lists,
            BundleOptions {
                defer_caddy_retire: true,
                ..BundleOptions::default()
            },
        )
        .unwrap(),
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
    assert!(
        String::from_utf8_lossy(&disabled_bundle["files/etc/sysctl.d/90-kinveil.conf"].1)
            .contains("net.ipv4.ip_forward = 0")
    );

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
fn caddy_profile_title_and_routing_compilation() {
    let mut state = multi_server_state();

    state
        .set_config_toml(
            "[subscription]\nprofile_title = \"My Home Net\"\n\n[subscription.routing]\nhapp_link = \"happ://routing/onadd/abc123\"\n",
        )
        .unwrap();
    let custom_caddy = render_caddyfile(&state).unwrap();
    assert!(custom_caddy.contains("Profile-Title \"base64:TXkgSG9tZSBOZXQ=\""));
    assert!(custom_caddy.contains("routing \"happ://routing/onadd/abc123\""));

    state
        .set_config_toml(
            "[subscription.routing]\nbypass_countries = [\"de\"]\nblock_countries = [\"fr\", \"jp\"]\ndirect_domains = [\"domain:example.de\"]\ndomestic_doh = \"https://9.9.9.9/dns-query\"\ndomestic_dns_ip = \"9.9.9.9\"\n",
        )
        .unwrap();
    let compiled = compile_subscription_routing(&state.settings.subscription.routing).unwrap();
    let happ_link = compiled.happ_header.as_deref().unwrap();
    let throne_link = compiled.throne_header.as_deref().unwrap();
    assert!(happ_link.starts_with("happ://routing/onadd/"));
    assert!(throne_link.starts_with("throne://route/"));

    let happ_json: Value = serde_json::from_str(compiled.happ_json.as_deref().unwrap()).unwrap();
    assert_eq!(happ_json["Name"], "Split Tunnel");
    assert_eq!(happ_json["DomesticDNSDomain"], "https://9.9.9.9/dns-query");
    assert_eq!(happ_json["RemoteDNSDomain"], "https://1.1.1.1/dns-query");
    assert_eq!(
        happ_json["DirectSites"],
        serde_json::json!(["geosite:private", "domain:de", "domain:example.de"])
    );
    assert_eq!(
        happ_json["DirectIp"],
        serde_json::json!(["geoip:private", "geoip:de"])
    );
    assert_eq!(
        happ_json["BlockSites"],
        serde_json::json!(["domain:fr", "domain:jp"])
    );
    assert_eq!(
        happ_json["BlockIp"],
        serde_json::json!(["geoip:fr", "geoip:jp"])
    );

    let throne_json: Value =
        serde_json::from_str(compiled.throne_json.as_deref().unwrap()).unwrap();
    assert_eq!(throne_json["kind"], "throne-route-profile");
    assert_eq!(throne_json["name"], "Split Tunnel");
    let throne_rules = throne_json["rules"].as_array().unwrap();
    assert_eq!(throne_rules[0]["action"], "hijack-dns");
    assert_eq!(throne_rules[1]["ip_is_private"], true);
    assert_eq!(throne_rules[2]["action"], "reject");
    assert_eq!(
        throne_rules[2]["rule_set"],
        serde_json::json!(["geoip-fr", "geoip-jp"])
    );
    assert_eq!(
        throne_rules[2]["domain_suffix"],
        serde_json::json!(["fr", "jp"])
    );
    assert_eq!(throne_rules[3]["outbound"], "direct");
    assert_eq!(throne_rules[3]["rule_set"], serde_json::json!(["geoip-de"]));
    assert_eq!(
        throne_rules[3]["domain_suffix"],
        serde_json::json!(["de", "example.de"])
    );

    let split_caddy = render_caddyfile(&state).unwrap();
    assert!(split_caddy.contains(&format!("header routing \"{throne_link}\"")));
    assert!(split_caddy.contains(&format!("header routing \"{happ_link}\"")));
}

#[test]
fn firewall_country_domain_ip_blocking_and_dns_settings() {
    let mut state = multi_server_state();
    state
        .set_config_toml(
            "[firewall]\nblock_countries = [\"jp\", \"de\"]\nblock_cidrs = [\"203.0.113.5/24\"]\nblock_ip_lists = [\"https://lists.example.com/ips.txt\"]\n\n[firewall.auto_update]\ninterval_hours = 12\n\n[firewall.xray]\nblock_domains = [\"full:custom.example.com\", \"geosite:category-ads\"]\nblock_domain_lists = [\"https://lists.example.com/domains.txt\"]\n\n[dns]\nxray_servers = [\"https+local://1.1.1.1/dns-query\"]\namneziawg_servers = [\"1.1.1.1\"]\n\n[vless.xhttp]\npath = \"/custom-edge\"\n\n[amneziawg]\nrandom_trailers = false\ndisable_cookies = false\n",
        )
        .unwrap();
    assert!(state.settings.firewall.needs_country_geoip());
    assert!(state.settings.firewall.needs_xray_geodata());
    assert!(state.settings.firewall.auto_update_active());
    validate_state(&state).unwrap();

    let lists = ResolvedFirewallLists {
        extra_ipv4: vec![
            "198.18.0.0/16".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ],
        extra_ipv6: vec!["2001:db8:abcd::/48".parse().unwrap()],
        extra_xray_domains: vec!["domain:bad.example".to_owned()],
        missing_geoip_countries: vec!["jp".to_owned()],
    };

    // Co-located subscription server keeps direct 80,443 bypass BEFORE firewall block rules.
    let xray_sub: Value =
        serde_json::from_str(&render_xray_config(&state, &state.servers[0], &lists).unwrap())
            .unwrap();
    assert_eq!(
        xray_sub["dns"]["servers"],
        serde_json::json!(["https+local://1.1.1.1/dns-query"])
    );
    assert_eq!(
        xray_sub["inbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
        "/custom-edge"
    );
    assert_eq!(
        xray_sub["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
        "UseIP"
    );
    let rules = xray_sub["routing"]["rules"].as_array().unwrap();
    assert_eq!(rules[1]["outboundTag"], "direct");
    assert_eq!(
        rules[1]["domain"],
        serde_json::json!(["full:sub.example.com"])
    );
    assert_eq!(rules[2]["outboundTag"], "direct");
    assert_eq!(
        rules[2]["ip"],
        serde_json::json!(["198.51.100.10/32", "2001:db8::10/128"])
    );
    assert_eq!(rules[3]["outboundTag"], "block");
    assert_eq!(
        rules[3]["domain"],
        serde_json::json!([
            "domain:jp",
            "domain:de",
            "full:custom.example.com",
            "geosite:category-ads",
            "domain:bad.example"
        ])
    );
    assert_eq!(rules[4]["outboundTag"], "block");
    assert_eq!(
        rules[4]["ip"],
        serde_json::json!(["geoip:de", "203.0.113.0/24"])
    );

    let ini = render_client_ini(&state, &state.servers[0], state.user("alice").unwrap()).unwrap();
    assert!(ini.contains("DNS = 1.1.1.1\n"));
    assert!(ini.contains("RandomTrailers = off\n"));
    assert!(ini.contains("DisableCookies = off\n"));
    let uapi = render_server_uapi(&state, &state.servers[0]).unwrap();
    assert!(uapi.contains("random_trailers=false\n"));
    assert!(uapi.contains("disable_cookies=false\n"));

    let bundle = unpack_tar_gz(
        &build_server_bundle(
            &state,
            &state.servers[0],
            &fake_artifacts(),
            &lists,
            BundleOptions::default(),
        )
        .unwrap(),
    );
    let install = String::from_utf8_lossy(&bundle["install.sh"].1);
    assert!(install.contains("HAS_VPN=1\n"));
    assert!(install.contains("HAS_FW_UPDATE=1\n"));
    assert!(bundle.contains_key("bin/update-firewall.sh"));
    assert!(bundle.contains_key("files/etc/systemd/system/kinveil-firewall-update.service"));
    let timer = String::from_utf8_lossy(
        &bundle["files/etc/systemd/system/kinveil-firewall-update.timer"].1,
    );
    assert!(timer.contains("OnActiveSec=12h"));
    assert!(timer.contains("OnUnitActiveSec=12h"));
    let urls = String::from_utf8_lossy(&bundle["files/etc/kinveil/firewall/urls.txt"].1);
    assert!(urls.contains("/country/jp/ipv4-aggregated.txt"));
    assert!(urls.contains("/country/de/ipv6-aggregated.txt"));
    assert!(urls.contains("https://lists.example.com/ips.txt"));
    let nft_blocked = String::from_utf8_lossy(&bundle["files/etc/kinveil/nft-blocked.nft"].1);
    assert!(nft_blocked.contains("203.0.113.0/24"));
    assert!(nft_blocked.contains("192.0.2.0/24"));
    assert!(nft_blocked.contains("2001:db8:abcd::/48"));
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
    let empty_lists = ResolvedFirewallLists::default();
    let xray: Value =
        serde_json::from_str(&render_xray_config(&state, srv1, &empty_lists).unwrap()).unwrap();
    assert_eq!(
        xray["inbounds"][0]["streamSettings"]["xhttpSettings"]["mode"],
        "packet-up"
    );

    let sub_with_srv2_override = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "alice", alice, SubVariant::Happ).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(!sub_with_srv2_override.contains("VLESS-Stream"));
    assert!(sub_with_srv2_override.contains("VLESS-Packet"));
    assert!(sub_with_srv2_override.contains("hysteria2://"));
    // srv2's explicit `--protocols` override retains amneziawg even when [amneziawg].enabled = false globally
    assert!(!sub_with_srv2_override.contains("DE%20Frankfurt%20amneziawg"));
    assert!(sub_with_srv2_override.contains("vpn://"));

    state.servers[1].vpn.as_mut().unwrap().protocols = None;
    let alice = state.user("alice").unwrap();
    let sub = String::from_utf8(
        STANDARD
            .decode(render_subscription_body(&state, "alice", alice, SubVariant::Happ).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(!sub.contains("vpn://"));

    let srv1 = &state.servers[0];

    assert!(render_sysctl(&state, srv1).contains("net.ipv4.ip_forward = 0"));
    let bundle = unpack_tar_gz(
        &build_server_bundle(
            &state,
            srv1,
            &fake_artifacts(),
            &empty_lists,
            BundleOptions {
                defer_caddy_retire: false,
                include_xray_bin: true,
                include_geodata: false,
                include_awg_bin: true,
                allow_takeover: false,
            },
        )
        .unwrap(),
    );
    let install = String::from_utf8_lossy(&bundle["install.sh"].1);
    assert!(install.contains("HAS_VPN=1\nHAS_XRAY=1\nHAS_AWG=0\n"));
    assert!(!bundle.contains_key("bin/amneziawg-go"));
    assert!(!bundle.contains_key("files/etc/kinveil/awg/uapi.conf"));

    // Per-server protocol toggle disabling Xray protocols leaves only AmneziaWG
    let mut awg_only = multi_server_state();
    awg_only
        .set_config_toml("")
        .expect("restore default settings");
    let vpn2 = awg_only.servers[1].vpn.as_mut().unwrap();
    vpn2.protocols = Some(BTreeSet::from([VpnProtocol::AmneziaWg]));
    assert_eq!(parse_config_toml("").unwrap(), awg_only.settings);
    let eff = awg_only.servers[1].effective_config(&awg_only.settings, false);
    assert!(!eff.has_xray);
    assert!(eff.has_amneziawg);

    let nft_awg_only = render_nftables_for_host(&awg_only, &awg_only.servers[1]).unwrap();
    assert!(!nft_awg_only.contains("tcp dport 10443"));
    assert!(!nft_awg_only.contains("udp dport 10444"));
    assert!(nft_awg_only.contains("udp dport 51821 accept"));
    assert!(nft_awg_only.contains("include \"/etc/kinveil/nft-blocked.nft\""));

    let awg_bundle = unpack_tar_gz(
        &build_server_bundle(
            &awg_only,
            &awg_only.servers[1],
            &fake_artifacts(),
            &empty_lists,
            BundleOptions {
                defer_caddy_retire: true,
                include_xray_bin: true,
                include_geodata: false,
                include_awg_bin: true,
                allow_takeover: false,
            },
        )
        .unwrap(),
    );
    let install_awg = String::from_utf8_lossy(&awg_bundle["install.sh"].1);
    assert!(install_awg.contains("HAS_VPN=1\nHAS_XRAY=0\nHAS_AWG=1\n"));
    assert!(!awg_bundle.contains_key("bin/xray"));
    assert!(!awg_bundle.contains_key("files/etc/kinveil/xray.json"));
    assert!(awg_bundle.contains_key("bin/amneziawg-go"));
    assert!(awg_bundle.contains_key("files/etc/kinveil/nft-blocked.nft"));
}

#[test]
fn config_vless_and_awg_overrides_propagate_into_renders_and_server_filter() {
    let mut state = multi_server_state();
    // Clear srv1's per-server SNI so it inherits [vless] config defaults, while srv2 keeps its override.
    state.servers[0].vpn.as_mut().unwrap().vless.sni = None;
    state.servers[0].vpn.as_mut().unwrap().vless.xhttp_host = None;
    state
        .set_config_toml(
            "[vless]\nsni = \"cfg-sni.example.com\"\ntarget = \"edge-sni.example.com:443\"\nxhttp_host = \"cdn.example.com\"\n\n[amneziawg.obfuscation]\njc = 8\ni1 = \"<b 0xdeadbeef>\"\ni2 = \"<t>\"\n\n[ssh_forwarding]\nenabled = true\n",
        )
        .unwrap();
    validate_state(&state).expect("validate overrides");

    let srv1 = &state.servers[0];
    let srv2 = &state.servers[1];
    let alice = state.user("alice").unwrap();
    let empty_lists = ResolvedFirewallLists::default();

    let xray1: Value =
        serde_json::from_str(&render_xray_config(&state, srv1, &empty_lists).unwrap()).unwrap();
    assert_eq!(
        xray1["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"][0],
        "cfg-sni.example.com"
    );
    assert_eq!(
        xray1["inbounds"][0]["streamSettings"]["realitySettings"]["target"],
        "edge-sni.example.com:443"
    );
    assert_eq!(
        xray1["inbounds"][0]["streamSettings"]["xhttpSettings"]["host"],
        "cdn.example.com"
    );

    // srv2 overrides sni -> www.apple.com, so it must NOT inherit cfg target or xhttp_host
    let xray2: Value =
        serde_json::from_str(&render_xray_config(&state, srv2, &empty_lists).unwrap()).unwrap();
    assert_eq!(
        xray2["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"][0],
        "www.apple.com"
    );
    assert_eq!(
        xray2["inbounds"][0]["streamSettings"]["realitySettings"]["target"],
        "www.apple.com:443"
    );
    assert!(
        xray2["inbounds"][0]["streamSettings"]["xhttpSettings"]
            .get("host")
            .is_none()
    );

    let ini = render_client_ini(&state, srv1, alice).unwrap();
    assert!(ini.contains("Jc = 8\n"));
    assert!(ini.contains("I1 = <b 0xdeadbeef>\n"));
    assert!(ini.contains("I2 = <t>\n"));

    let uapi = render_server_uapi(&state, srv1).unwrap();
    assert!(uapi.contains("jc=8\n"));
    assert!(uapi.contains("i1=<b 0xdeadbeef>\n"));
    assert!(uapi.contains("i2=<t>\n"));

    let srv1_links = render_subscription_lines_for_server(
        &state,
        "alice",
        alice,
        SubVariant::Throne,
        Some("srv1"),
    )
    .unwrap();
    assert!(
        srv1_links
            .iter()
            .any(|l| l.contains("198.51.100.10:8443") && l.contains("sni=cfg-sni.example.com"))
    );
    assert!(
        srv1_links
            .iter()
            .any(|l| l.contains("#DE%20Frankfurt%20Hysteria2"))
    );
    assert!(
        srv1_links
            .iter()
            .any(|l| l.contains("#DE%20Frankfurt%20SSH"))
    );
    assert!(srv1_links.iter().all(|l| !l.contains("198.51.100.11")));

    assert!(
        render_subscription_lines_for_server(
            &state,
            "alice",
            alice,
            SubVariant::Throne,
            Some("srv3")
        )
        .is_err()
    );
}

#[test]
fn traffic_accounting_toggles_and_bundle_rendering() {
    let mut state = multi_server_state();
    state.servers[0].vpn.as_mut().unwrap().traffic = true;
    validate_state(&state).expect("validate with per-server traffic enabled");

    let empty_lists = ResolvedFirewallLists::default();
    let xray_on: Value =
        serde_json::from_str(&render_xray_config(&state, &state.servers[0], &empty_lists).unwrap())
            .unwrap();
    assert_eq!(xray_on["api"]["listen"], "/run/kinveil-xray/api.sock");
    assert_eq!(
        xray_on["api"]["services"],
        serde_json::json!(["StatsService"])
    );
    assert_eq!(xray_on["policy"]["levels"]["0"]["statsUserUplink"], true);
    assert_eq!(xray_on["policy"]["levels"]["0"]["statsUserDownlink"], true);
    assert_eq!(xray_on["stats"], serde_json::json!({}));
    assert_eq!(
        xray_on["inbounds"][0]["settings"]["clients"][0]["email"],
        "uid-1:vless"
    );
    assert_eq!(
        xray_on["inbounds"][1]["settings"]["clients"][0]["email"],
        "uid-1:hysteria2"
    );

    let xray_off: Value =
        serde_json::from_str(&render_xray_config(&state, &state.servers[1], &empty_lists).unwrap())
            .unwrap();
    assert!(xray_off.get("api").is_none());
    assert!(xray_off.get("policy").is_none());
    assert!(xray_off.get("stats").is_none());
    assert_eq!(
        xray_off["inbounds"][0]["settings"]["clients"][0]["email"],
        "uid-1:vless"
    );

    let unit_on = render_xray_unit(true);
    assert!(unit_on.contains("RuntimeDirectory=kinveil-xray"));
    assert!(unit_on.contains("RuntimeDirectoryMode=0700"));
    assert!(unit_on.contains("ExecStartPre=/usr/bin/rm -f /run/kinveil-xray/api.sock"));
    let unit_off = render_xray_unit(false);
    assert!(!unit_off.contains("RuntimeDirectory"));
    assert!(!unit_off.contains("ExecStartPre"));

    let nft_on = render_nftables_for_host(&state, &state.servers[0]).unwrap();
    assert!(nft_on.contains("include \"/etc/kinveil/nft-traffic.nft\""));
    let nft_off = render_nftables_for_host(&state, &state.servers[1]).unwrap();
    assert!(!nft_off.contains("nft-traffic.nft"));

    let artifacts = fake_artifacts();
    let bundle_on = unpack_tar_gz(
        &build_server_bundle(
            &state,
            &state.servers[0],
            &artifacts,
            &empty_lists,
            BundleOptions::default(),
        )
        .unwrap(),
    );
    assert!(String::from_utf8_lossy(&bundle_on["install.sh"].1).contains("HAS_TRAFFIC=1\n"));
    assert_eq!(bundle_on["bin/snapshot-traffic.sh"].0, 0o755);
    assert_eq!(bundle_on["files/etc/kinveil/traffic/config.env"].0, 0o600);
    assert_eq!(
        String::from_utf8_lossy(&bundle_on["files/etc/kinveil/traffic/config.env"].1),
        "RETENTION_DAYS=90\n"
    );
    assert_eq!(bundle_on["files/etc/kinveil/traffic/users.conf"].0, 0o600);
    assert_eq!(
        String::from_utf8_lossy(&bundle_on["files/etc/kinveil/traffic/users.conf"].1),
        "1 10.8.0.2\n2 10.8.0.3\n"
    );
    assert_eq!(
        bundle_on["files/etc/systemd/system/kinveil-traffic.service"].0,
        0o644
    );
    assert_eq!(
        bundle_on["files/etc/systemd/system/kinveil-traffic.timer"].0,
        0o644
    );
    let flush_unit = String::from_utf8_lossy(
        &bundle_on["files/etc/systemd/system/kinveil-traffic-flush.service"].1,
    );
    assert!(flush_unit.contains("PartOf=kinveil-xray.service"));

    let bundle_off = unpack_tar_gz(
        &build_server_bundle(
            &state,
            &state.servers[1],
            &artifacts,
            &empty_lists,
            BundleOptions::default(),
        )
        .unwrap(),
    );
    assert!(String::from_utf8_lossy(&bundle_off["install.sh"].1).contains("HAS_TRAFFIC=0\n"));
    assert!(!bundle_off.contains_key("bin/snapshot-traffic.sh"));
    assert!(!bundle_off.contains_key("files/etc/kinveil/traffic/config.env"));

    // Custom [traffic].retention_days = 30 with non-Xray flush unit and opt-out server
    state
        .set_config_toml("[traffic]\nretention_days = 30\n")
        .unwrap();
    state.servers[0].vpn.as_mut().unwrap().traffic = true;
    state.servers[0].vpn.as_mut().unwrap().protocols = Some(BTreeSet::from([
        VpnProtocol::AmneziaWg,
        VpnProtocol::SshForwarding,
    ]));
    state.servers[1].vpn.as_mut().unwrap().traffic = false;
    validate_state(&state).unwrap();

    let bundle_awg_traffic = unpack_tar_gz(
        &build_server_bundle(
            &state,
            &state.servers[0],
            &artifacts,
            &empty_lists,
            BundleOptions::default(),
        )
        .unwrap(),
    );
    assert_eq!(
        String::from_utf8_lossy(&bundle_awg_traffic["files/etc/kinveil/traffic/config.env"].1),
        "RETENTION_DAYS=30\n"
    );
    let flush_no_xray = String::from_utf8_lossy(
        &bundle_awg_traffic["files/etc/systemd/system/kinveil-traffic-flush.service"].1,
    );
    assert!(!flush_no_xray.contains("kinveil-xray.service"));

    let bundle_opt_out = unpack_tar_gz(
        &build_server_bundle(
            &state,
            &state.servers[1],
            &artifacts,
            &empty_lists,
            BundleOptions::default(),
        )
        .unwrap(),
    );
    assert!(!bundle_opt_out.contains_key("bin/snapshot-traffic.sh"));
}
