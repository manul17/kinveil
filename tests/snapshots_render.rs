use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use insta::assert_snapshot;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use kinveil::render::ResolvedFirewallLists;
use kinveil::render::amneziawg::{render_apply_script, render_client_ini, render_server_uapi};
use kinveil::render::caddy::render_caddyfile;
use kinveil::render::firewall::{render_nftables, render_nftables_for_host};
use kinveil::render::ssh_forwarding::{render_authorized_keys, render_sshd_config};
use kinveil::render::subscriptions::{SubVariant, render_subscription_body};
use kinveil::render::xray::render_xray_config;
use kinveil::state::{
    AdminSsh, AwgObfuscation, IntOrRange, SecretString, Server, ServerAmneziaWg, ServerHysteria2,
    ServerSshForwarding, ServerVless, ServerVpn, State, User, UserAmneziaWg, UserHysteria2,
    UserSshForwarding, UserVless, VpnProtocol,
};
use kinveil::validate::validate_state;

const ADMIN_HOST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICrUkVEvlvVP9WAHK0OdphmI6/y1E5Vipv6n/8oVXSfj admin";

const SRV1_SSH_PRIV: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB6oRZIsU5SG+rk9argOFIepHt6cHIhjRk6uRfl/MSXJAAAAJiFrezkha3s
5AAAAAtzc2gtZWQyNTUxOQAAACB6oRZIsU5SG+rk9argOFIepHt6cHIhjRk6uRfl/MSXJA
AAAEBKog1oKNKta7NRzJb5SCI1wREBZQeqJYve5EPS2Q8cCnqhFkixTlIb6uT1quA4Uh6k
e3pwciGNGTq5F+X8xJckAAAAEGtpbnZlaWwtc3NoLXNydjEBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

const SRV2_SSH_PRIV: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDd39mVfK2AWgGBJ7doUdxPiwP7IB5hx/ndkv1P/WD+2QAAAJgc2/YFHNv2
BQAAAAtzc2gtZWQyNTUxOQAAACDd39mVfK2AWgGBJ7doUdxPiwP7IB5hx/ndkv1P/WD+2Q
AAAED0IkFcOWePVjxYBTDm+/8CLiRkZsVF/i1cjh+nRuDNhd3f2ZV8rYBaAYEnt2hR3E+L
A/sgHmHH+d2S/U/9YP7ZAAAAEGtpbnZlaWwtc3NoLXNydjIBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

const SRV1_HYST_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBYzCCAQqgAwIBAgIBATAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA0xOTguNTEu
MTAwLjEwMCAXDTI1MDEwMTAwMDAwMFoYDzIwOTkwMTAxMDAwMDAwWjAYMRYwFAYD
VQQDDA0xOTguNTEuMTAwLjEwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjaqL
hoQJ+3AXBQtcxPe0pINIvuibZ+Hc6UrhwYkSwj6Ky0i5Nmv0r/kjG42CCB70RC+Z
7V06At+6q0XIakz8c6NDMEEwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBaAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBocExjNkCjAKBggqhkjOPQQDAgNH
ADBEAiBDxhwGXmthUpMdpgQ2npJb/M1EBNPx8SQbDtJPcFcivgIgZdyn5CEFhst3
vaCHZ7YadRqblsNM1MPpzwcOxztj82I=
-----END CERTIFICATE-----
";
const SRV1_HYST_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn5IRbB1TrChojL0L
XtNSJMQJGcTf1FTMQSmG+X8B3uihRANCAASNqouGhAn7cBcFC1zE97Skg0i+6Jtn
4dzpSuHBiRLCPorLSLk2a/Sv+SMbjYIIHvREL5ntXToC37qrRchqTPxz
-----END PRIVATE KEY-----
";

const SRV2_HYST_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBZDCCAQqgAwIBAgIBAjAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA0xOTguNTEu
MTAwLjExMCAXDTI1MDEwMTAwMDAwMFoYDzIwOTkwMTAxMDAwMDAwWjAYMRYwFAYD
VQQDDA0xOTguNTEuMTAwLjExMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa9tb
frhcjmPD9G6HfxctnQZitf3kbZgBM1E5fbhcQXhwmMDEXW+ODetNWDXxKknCvx42
MiZPVqT/vYCnnrriCKNDMEEwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBaAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBocExjNkCzAKBggqhkjOPQQDAgNI
ADBFAiAoerE6hx94KzpaI4QiQGw6hfjoaLO9rYsNhRnJuhED/wIhAONYSdxNGt/R
uIgrk8mnfDfD37kWfGhiCgUblv7Y2TJ0
-----END CERTIFICATE-----
";
const SRV2_HYST_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu4cD1rAdpGllKPFQ
JfGRR2prbMN0CBV9R2u8haOPB4+hRANCAARr21t+uFyOY8P0bod/Fy2dBmK1/eRt
mAEzUTl9uFxBeHCYwMRdb44N601YNfEqScK/HjYyJk9WpP+9gKeeuuII
-----END PRIVATE KEY-----
";

const ALICE_SSH_PRIV: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAMBkncHILNUzq1evXE7Q7VZtYx855SLHtg82iYF7n3bwAAAJCu1lTVrtZU
1QAAAAtzc2gtZWQyNTUxOQAAACAMBkncHILNUzq1evXE7Q7VZtYx855SLHtg82iYF7n3bw
AAAECIqUs6PZJckMXksJ8bw4eV6h9ai4uRkRVywS75iQRKagwGSdwcgs1TOrV69cTtDtVm
1jHznlIse2DzaJgXufdvAAAAB3ZwbnNzaDEBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
";

const BOB_SSH_PRIV: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAC9nCvT+ytrGqCEVNsfOY+ozx9ZoHkjWh5yJ2YuLrroQAAAJAbLixmGy4s
ZgAAAAtzc2gtZWQyNTUxOQAAACAC9nCvT+ytrGqCEVNsfOY+ozx9ZoHkjWh5yJ2YuLrroQ
AAAEBBCbbbAj8GShICCANMB+ws9OD6dPqdSVNEYJAf5t998wL2cK9P7K2saoIRU2x85j6j
PH1mgeSNaHnInZi4uuuhAAAAB3ZwbnNzaDIBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
";

const CHARLIE_SSH_PRIV: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCGvz4Gh0LsItkVB1moriSxZ4Zcrh3J9kT6dfGrqzfoEgAAAJCM+EYAjPhG
AAAAAAtzc2gtZWQyNTUxOQAAACCGvz4Gh0LsItkVB1moriSxZ4Zcrh3J9kT6dfGrqzfoEg
AAAED59R0f8ASK1OmtlGcSytuXVoFxACk8u2qhMIgc4cuiw4a/PgaHQuwi2RUHWaiuJLFn
hlyuHcn2RPp18aurN+gSAAAAB3ZwbnNzaDMBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
";

fn fixed_obfuscation(seed: u16) -> AwgObfuscation {
    AwgObfuscation {
        jc: 4 + (seed % 3),
        jmin: 60 + seed,
        jmax: 180 + seed,
        s1: 41 + seed,
        s2: 134 + seed,
        s3: 38 + seed,
        s4: 16 + seed,
        h1: IntOrRange::Int(162_955_118 + u32::from(seed) * 1000),
        h2: IntOrRange::Int(983_515_823 + u32::from(seed) * 1000),
        h3: IntOrRange::Int(1_305_870_938 + u32::from(seed) * 1000),
        h4: IntOrRange::Int(1_813_353_860 + u32::from(seed) * 1000),
        i1: "<r 52>".to_owned(),
        i2: None,
        i3: None,
        i4: None,
        i5: None,
        header_protection_key: SecretString::new("dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMzJieXQ="),
        content_padding_addition: IntOrRange::Range("17-41".to_owned()),
    }
}

fn deterministic_state() -> State {
    let mut state = State::new_with_base_path("sub.example.com".to_owned(), "/s8k2m9x4p1q7w3z5/")
        .expect("init state");
    state
        .set_config_toml("[ssh_forwarding]\nenabled = true\n")
        .expect("enable ssh_forwarding for deterministic snapshot");
    let fixed_ts = OffsetDateTime::parse("2026-11-15T12:00:00Z", &Rfc3339).unwrap();
    state.updated_at = fixed_ts;
    state.next_uid = 4;
    state.subscription.server_id = Some("srv1".to_owned());

    state.users = BTreeMap::from([
        (
            "alice".to_owned(),
            User {
                uid: 1,
                enabled: true,
                created_at: fixed_ts,
                note: None,
                subscription_token: SecretString::new("alicetoken000001"),
                vless: UserVless {
                    uuid: SecretString::new("11111111-1111-4111-8111-111111111111"),
                    spider_x: "/a1b2c3d4e5f6a7b".to_owned(),
                },
                hysteria2: UserHysteria2 {
                    auth: SecretString::new("AliceHystAuth123456"),
                },
                amneziawg: UserAmneziaWg {
                    private_key: SecretString::new("cLIdBM6FBFlytyBicj69emtXwDtphkEK2NgWOS02IHA="),
                    preshared_key: SecretString::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
                    ),
                },
                ssh_forwarding: UserSshForwarding {
                    private_key: SecretString::new(ALICE_SSH_PRIV),
                },
            },
        ),
        (
            "bob".to_owned(),
            User {
                uid: 2,
                enabled: true,
                created_at: fixed_ts,
                note: None,
                subscription_token: SecretString::new("bobtoken00000002"),
                vless: UserVless {
                    uuid: SecretString::new("22222222-2222-4222-8222-222222222222"),
                    spider_x: "/b1b2c3d4e5f6a7b".to_owned(),
                },
                hysteria2: UserHysteria2 {
                    auth: SecretString::new("BobHystAuth12345678"),
                },
                amneziawg: UserAmneziaWg {
                    private_key: SecretString::new("wIFdFGVn3yVsZ6Yv0pEH4trIazjv4/Nzzo1ZO4zbn14="),
                    preshared_key: SecretString::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=",
                    ),
                },
                ssh_forwarding: UserSshForwarding {
                    private_key: SecretString::new(BOB_SSH_PRIV),
                },
            },
        ),
        (
            "charlie".to_owned(),
            User {
                uid: 3,
                enabled: false,
                created_at: fixed_ts,
                note: None,
                subscription_token: SecretString::new("charlietoken0003"),
                vless: UserVless {
                    uuid: SecretString::new("33333333-3333-4333-8333-333333333333"),
                    spider_x: "/c1b2c3d4e5f6a7b".to_owned(),
                },
                hysteria2: UserHysteria2 {
                    auth: SecretString::new("CharlieHystAuth1234"),
                },
                amneziawg: UserAmneziaWg {
                    private_key: SecretString::new("2HcrfOS5J1mWV6YaFiRmKEBiyIhdMu20kXwyJTYUb3g="),
                    preshared_key: SecretString::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=",
                    ),
                },
                ssh_forwarding: UserSshForwarding {
                    private_key: SecretString::new(CHARLIE_SSH_PRIV),
                },
            },
        ),
    ]);

    state.servers = vec![
        Server {
            id: "srv1".to_owned(),
            label: "DE Germany".to_owned(),
            enabled: true,
            created_at: fixed_ts,
            note: None,
            public_ipv4: Ipv4Addr::new(198, 51, 100, 10),
            public_ipv6: Some("2001:db8::10".parse::<Ipv6Addr>().unwrap()),
            admin_ssh: AdminSsh {
                host: "198.51.100.10".to_owned(),
                port: NonZeroU16::new(2220).unwrap(),
                user: "root".to_owned(),
                identity_file: None,
                host_public_key: ADMIN_HOST_PUB.to_owned(),
            },
            vpn: Some(ServerVpn {
                enabled: true,
                protocols: None,
                traffic: false,
                vless: ServerVless {
                    port: None,
                    sni: Some("www.example.com".to_owned()),
                    target: None,
                    xhttp_host: Some("www.example.com".to_owned()),
                    xhttp_path: "/x9k2m4p7q1w8".to_owned(),
                    private_key: SecretString::new("MFAVLI_V3BOtl9G5cG6JTEYODG_NW5elfnpGclrcY00"),
                    short_id: "0123456789abcdef".to_owned(),
                },
                hysteria2: ServerHysteria2 {
                    port: None,
                    salamander_password: SecretString::new("SalamanderSecret0001"),
                    cert_pem: SRV1_HYST_CERT.to_owned(),
                    key_pem: SecretString::new(SRV1_HYST_KEY),
                },
                amneziawg: ServerAmneziaWg {
                    port: None,
                    private_key: SecretString::new("sIkVu5AawQJr5ognt+FU5/A8ZMom9gyOqIJSf4TGOGc="),
                    obfuscation: fixed_obfuscation(0),
                },
                ssh_forwarding: ServerSshForwarding {
                    port: None,
                    host_private_key: SecretString::new(SRV1_SSH_PRIV),
                },
            }),
        },
        Server {
            id: "srv2".to_owned(),
            label: "FI Finland".to_owned(),
            enabled: true,
            created_at: fixed_ts,
            note: None,
            public_ipv4: Ipv4Addr::new(198, 51, 100, 11),
            public_ipv6: None,
            admin_ssh: AdminSsh {
                host: "198.51.100.11".to_owned(),
                port: NonZeroU16::new(2220).unwrap(),
                user: "root".to_owned(),
                identity_file: None,
                host_public_key: ADMIN_HOST_PUB.to_owned(),
            },
            vpn: Some(ServerVpn {
                enabled: true,
                protocols: Some(BTreeSet::from([
                    VpnProtocol::Vless,
                    VpnProtocol::Hysteria2,
                    VpnProtocol::AmneziaWg,
                ])),
                traffic: false,
                vless: ServerVless {
                    port: Some(NonZeroU16::new(10443).unwrap()),
                    sni: Some("www.example.com".to_owned()),
                    target: None,
                    xhttp_host: None,
                    xhttp_path: "/r3t6v8n1b5c0".to_owned(),
                    private_key: SecretString::new("0NMcJYxMQRofDdGRTtRY5js_I16d-N7aoGdJ1PajfG8"),
                    short_id: "fedcba9876543210".to_owned(),
                },
                hysteria2: ServerHysteria2 {
                    port: Some(NonZeroU16::new(10444).unwrap()),
                    salamander_password: SecretString::new("SalamanderSecret0002"),
                    cert_pem: SRV2_HYST_CERT.to_owned(),
                    key_pem: SecretString::new(SRV2_HYST_KEY),
                },
                amneziawg: ServerAmneziaWg {
                    port: Some(NonZeroU16::new(51821).unwrap()),
                    private_key: SecretString::new("2Gbr6WS/dDIL0UlWRPaYKV1WpCwuAdOX8zzEZ8AcwWM="),
                    obfuscation: fixed_obfuscation(1),
                },
                ssh_forwarding: ServerSshForwarding {
                    port: None,
                    host_private_key: SecretString::new(SRV2_SSH_PRIV),
                },
            }),
        },
        Server {
            id: "srv3".to_owned(),
            label: "NL Retired".to_owned(),
            enabled: false,
            created_at: fixed_ts,
            note: None,
            public_ipv4: Ipv4Addr::new(198, 51, 100, 12),
            public_ipv6: None,
            admin_ssh: AdminSsh {
                host: "198.51.100.12".to_owned(),
                port: NonZeroU16::new(2220).unwrap(),
                user: "root".to_owned(),
                identity_file: None,
                host_public_key: ADMIN_HOST_PUB.to_owned(),
            },
            vpn: None,
        },
    ];

    state
}

#[test]
fn render_snapshots() {
    let state = deterministic_state();
    validate_state(&state).expect("deterministic snapshot fixture must validate");

    let srv1 = &state.servers[0];
    let srv2 = &state.servers[1];
    let srv3 = &state.servers[2];
    let alice = state.user("alice").unwrap();

    let empty_lists = ResolvedFirewallLists::default();
    assert_snapshot!(
        "xray_srv1",
        render_xray_config(&state, srv1, &empty_lists).unwrap()
    );
    assert_snapshot!(
        "xray_srv2_overrides",
        render_xray_config(&state, srv2, &empty_lists).unwrap()
    );
    assert_snapshot!("caddyfile", render_caddyfile(&state).unwrap());

    let dns_ips: Vec<IpAddr> = vec![
        "1.1.1.1".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
    ];
    assert_snapshot!(
        "nftables_srv1_standalone",
        render_nftables(
            &state,
            srv1,
            Some(999),
            &[1001, 1002],
            &dns_ips,
            &empty_lists
        )
        .unwrap()
    );
    assert_snapshot!(
        "nftables_srv1_host",
        render_nftables_for_host(&state, srv1).unwrap()
    );
    assert_snapshot!(
        "nftables_srv2_standalone",
        render_nftables(&state, srv2, Some(999), &[1001], &dns_ips, &empty_lists).unwrap()
    );
    assert_snapshot!(
        "nftables_srv3_disabled_host",
        render_nftables_for_host(&state, srv3).unwrap()
    );

    assert_snapshot!("uapi_srv1", render_server_uapi(&state, srv1).unwrap());
    assert_snapshot!("apply_uapi_sh", render_apply_script(&state).unwrap());
    assert_snapshot!(
        "sshd_config_srv1",
        render_sshd_config(&state, srv1).unwrap()
    );
    let auth_keys = render_authorized_keys(&state)
        .unwrap()
        .into_iter()
        .map(|(u, k)| format!("{u}: {k}"))
        .collect::<Vec<_>>()
        .join("");
    assert_snapshot!("authorized_keys", auth_keys);

    assert_snapshot!(
        "awg_client_alice_srv1",
        render_client_ini(&state, srv1, alice).unwrap()
    );

    let decode_sub = |name, user, variant| {
        let b64 = render_subscription_body(&state, name, user, variant).unwrap();
        String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap()
    };
    assert_snapshot!(
        "subscription_alice_happ",
        decode_sub("alice", alice, SubVariant::Happ)
    );
    assert_snapshot!(
        "subscription_alice_throne",
        decode_sub("alice", alice, SubVariant::Throne)
    );
}
