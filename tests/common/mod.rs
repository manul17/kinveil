#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::Permissions;
use std::io::Read as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use flate2::read::GzDecoder;
use kinveil::crypto::{generate_openssh_ed25519, sha256_hex};
use kinveil::deploy::artifacts::RuntimeArtifacts;
use kinveil::state::{
    AdminSsh, CloudflareConfig, SecretString, Server, ServerVpn, State, User, VpnProtocol,
    now_utc_seconds,
};
use tar::Archive;

pub struct TempPrivateDir {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
}

impl TempPrivateDir {
    pub fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(prefix)
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .expect("create 0700 tempdir");
        let path = dir.path().to_path_buf();
        Self { _dir: dir, path }
    }
}

pub fn make_user(uid: u32, enabled: bool) -> User {
    let mut user = User::generate(uid).expect("generate user");
    user.enabled = enabled;
    user
}

pub struct ServerSpec<'a> {
    pub ipv6: Option<&'a str>,
    pub protocols: Option<&'a [VpnProtocol]>,
    pub enabled: bool,
    pub admin_ssh_port: u16,
    pub sni: &'a str,
    pub vless_port: Option<u16>,
    pub hysteria2_port: Option<u16>,
    pub amneziawg_port: Option<u16>,
}

pub fn make_server(id: &str, label: &str, ipv4: &str, spec: ServerSpec<'_>) -> Server {
    let ip: Ipv4Addr = ipv4.parse().expect("ipv4");
    let (_, host_pub) = generate_openssh_ed25519("admin").expect("admin ssh host key");
    let mut vpn = ServerVpn::generate(id, ip, Some(spec.sni.to_owned()), None, None)
        .expect("generate server vpn");
    vpn.protocols = spec
        .protocols
        .map(|list| list.iter().copied().collect::<BTreeSet<_>>());
    vpn.vless.port = spec
        .vless_port
        .map(|p| NonZeroU16::new(p).expect("non-zero"));
    vpn.hysteria2.port = spec
        .hysteria2_port
        .map(|p| NonZeroU16::new(p).expect("non-zero"));
    vpn.amneziawg.port = spec
        .amneziawg_port
        .map(|p| NonZeroU16::new(p).expect("non-zero"));

    Server {
        id: id.to_owned(),
        label: label.to_owned(),
        enabled: spec.enabled,
        created_at: now_utc_seconds(),
        note: None,
        public_ipv4: ip,
        public_ipv6: spec.ipv6.map(|s| s.parse::<Ipv6Addr>().expect("ipv6")),
        admin_ssh: AdminSsh {
            host: ipv4.to_owned(),
            port: NonZeroU16::new(spec.admin_ssh_port).expect("non-zero"),
            user: "root".to_owned(),
            identity_file: None,
            host_public_key: host_pub,
        },
        vpn: Some(vpn),
    }
}

pub fn unpack_tar_gz(bytes: &[u8]) -> HashMap<String, (u32, Vec<u8>)> {
    let dec = GzDecoder::new(std::io::Cursor::new(bytes));
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

pub fn fake_artifacts() -> RuntimeArtifacts {
    let fake_xray = b"\x7fELF-fake-xray".to_vec();
    let fake_geoip = b"fake-geoip".to_vec();
    let fake_geosite = b"fake-geosite".to_vec();
    let fake_awg = b"\x7fELF-fake-awg".to_vec();
    RuntimeArtifacts {
        xray_sha256: sha256_hex(&fake_xray),
        xray_bytes: fake_xray,
        geoip_sha256: sha256_hex(&fake_geoip),
        geoip_bytes: fake_geoip,
        geosite_sha256: sha256_hex(&fake_geosite),
        geosite_bytes: fake_geosite,
        awg_sha256: sha256_hex(&fake_awg),
        awg_bytes: fake_awg,
    }
}

pub fn valid_deployable_state() -> State {
    let mut state = State::new_with_base_path("sub.example.com".to_owned(), "/s3cr3t-base/")
        .expect("init state");
    state.subscription.server_id = Some("de1".to_owned());
    state.subscription.cloudflare = Some(CloudflareConfig {
        zone_id: "0123456789abcdef0123456789abcdef".to_owned(),
        api_token: SecretString::new("cf-test-token-value"),
        ttl: 60,
    });
    state.users = BTreeMap::from([
        ("alice".to_owned(), make_user(1, true)),
        ("bob".to_owned(), make_user(2, false)),
    ]);
    state.next_uid = 3;
    state.servers.push(make_server(
        "de1",
        "DE Germany",
        "198.51.100.10",
        ServerSpec {
            ipv6: None,
            protocols: None,
            enabled: true,
            admin_ssh_port: 22,
            sni: "www.microsoft.com",
            vless_port: None,
            hysteria2_port: None,
            amneziawg_port: None,
        },
    ));
    state.servers.push(make_server(
        "fi1",
        "FI Finland",
        "198.51.100.11",
        ServerSpec {
            ipv6: None,
            protocols: None,
            enabled: false,
            admin_ssh_port: 22,
            sni: "www.microsoft.com",
            vless_port: None,
            hysteria2_port: None,
            amneziawg_port: None,
        },
    ));
    state
}

pub fn multi_server_state() -> State {
    let mut state = State::new("sub.example.com".to_owned()).expect("init state");
    state
        .set_config_toml("[ssh_forwarding]\nenabled = true\n")
        .expect("enable ssh_forwarding for multi-server test fixture");
    state.subscription.server_id = Some("srv1".to_owned());
    state.users = BTreeMap::from([
        ("alice".to_owned(), make_user(1, true)),
        ("bob".to_owned(), make_user(2, true)),
        ("charlie".to_owned(), make_user(3, false)),
    ]);
    state.next_uid = 4;

    state.servers.push(make_server(
        "srv1",
        "DE Frankfurt",
        "198.51.100.10",
        ServerSpec {
            ipv6: Some("2001:db8::10"),
            protocols: None,
            enabled: true,
            admin_ssh_port: 2220,
            sni: "www.apple.com",
            vless_port: None,
            hysteria2_port: None,
            amneziawg_port: None,
        },
    ));

    state.servers.push(make_server(
        "srv2",
        "FI Helsinki",
        "198.51.100.11",
        ServerSpec {
            ipv6: None,
            protocols: Some(&[
                VpnProtocol::Vless,
                VpnProtocol::Hysteria2,
                VpnProtocol::AmneziaWg,
            ]),
            enabled: true,
            admin_ssh_port: 2220,
            sni: "www.apple.com",
            vless_port: Some(10443),
            hysteria2_port: Some(10444),
            amneziawg_port: Some(51821),
        },
    ));

    state.servers.push(make_server(
        "srv3",
        "NL Retired",
        "198.51.100.12",
        ServerSpec {
            ipv6: None,
            protocols: None,
            enabled: false,
            admin_ssh_port: 2220,
            sni: "www.apple.com",
            vless_port: None,
            hysteria2_port: None,
            amneziawg_port: None,
        },
    ));

    state
}
