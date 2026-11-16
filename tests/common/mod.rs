#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::{self, Permissions};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use kinveil::crypto::generate_openssh_ed25519;
use kinveil::state::{
    AdminSsh, CloudflareConfig, SecretString, Server, ServerArch, ServerPortOverrides, ServerVpn,
    State, User, now_utc_seconds,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct TempPrivateDir {
    pub path: PathBuf,
}

impl TempPrivateDir {
    pub fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("{prefix}-{}-{nanos}-{seq}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp dir");
        fs::set_permissions(&path, Permissions::from_mode(0o700)).expect("chmod 0700 temp dir");
        Self { path }
    }
}

impl Drop for TempPrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn make_user(uid: u32, enabled: bool) -> User {
    let mut user = User::generate(uid).expect("generate user");
    user.enabled = enabled;
    user
}

pub struct ServerSpec<'a> {
    pub ipv6: Option<&'a str>,
    pub has_vpn: bool,
    pub has_ssh: bool,
    pub enabled: bool,
    pub sni: &'a str,
    pub ports: ServerPortOverrides,
}

pub fn make_server(id: &str, label: &str, ipv4: &str, spec: ServerSpec<'_>) -> Server {
    let ip: Ipv4Addr = ipv4.parse().expect("ipv4");
    let (_, host_pub) = generate_openssh_ed25519("admin").expect("admin ssh host key");
    let vpn = if spec.has_vpn {
        let mut vpn =
            ServerVpn::generate(id, ip, spec.sni, None, None).expect("generate server vpn");
        vpn.ssh_forwarding.enabled = spec.has_ssh;
        Some(vpn)
    } else {
        None
    };

    Server {
        id: id.to_owned(),
        label: label.to_owned(),
        enabled: spec.enabled,
        arch: ServerArch::X86_64,
        created_at: now_utc_seconds(),
        note: None,
        public_ipv4: ip,
        public_ipv6: spec.ipv6.map(|s| s.parse::<Ipv6Addr>().expect("ipv6")),
        admin_ssh: AdminSsh {
            host: ipv4.to_owned(),
            port: NonZeroU16::new(22).expect("non-zero"),
            user: "root".to_owned(),
            host_public_key: host_pub,
        },
        ports: spec.ports,
        vpn,
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
            has_vpn: true,
            has_ssh: true,
            enabled: true,
            sni: "www.microsoft.com",
            ports: ServerPortOverrides::default(),
        },
    ));
    state.servers.push(make_server(
        "fi1",
        "FI Finland",
        "198.51.100.11",
        ServerSpec {
            ipv6: None,
            has_vpn: true,
            has_ssh: false,
            enabled: false,
            sni: "www.microsoft.com",
            ports: ServerPortOverrides::default(),
        },
    ));
    state
}

pub fn multi_server_state() -> State {
    let mut state = State::new("sub.example.com".to_owned()).expect("init state");
    state.subscription.server_id = Some("srv1".to_owned());
    state.users = BTreeMap::from([
        ("alice".to_owned(), make_user(1, true)),
        ("bob".to_owned(), make_user(2, true)),
        ("charlie".to_owned(), make_user(3, false)),
    ]);
    state.next_uid = 4;

    let mut srv1 = make_server(
        "srv1",
        "DE Frankfurt",
        "198.51.100.10",
        ServerSpec {
            ipv6: Some("2001:db8::10"),
            has_vpn: true,
            has_ssh: true,
            enabled: true,
            sni: "www.apple.com",
            ports: ServerPortOverrides::default(),
        },
    );
    srv1.admin_ssh.port = NonZeroU16::new(2220).expect("non-zero");
    state.servers.push(srv1);

    let mut srv2 = make_server(
        "srv2",
        "FI Helsinki",
        "198.51.100.11",
        ServerSpec {
            ipv6: None,
            has_vpn: true,
            has_ssh: false,
            enabled: true,
            sni: "www.apple.com",
            ports: ServerPortOverrides {
                vless: Some(NonZeroU16::new(10443).expect("non-zero")),
                hysteria2: Some(NonZeroU16::new(10444).expect("non-zero")),
                amneziawg: Some(NonZeroU16::new(51821).expect("non-zero")),
                ssh_forwarding: None,
            },
        },
    );
    srv2.admin_ssh.port = NonZeroU16::new(2220).expect("non-zero");
    state.servers.push(srv2);

    let mut srv3 = make_server(
        "srv3",
        "NL Retired",
        "198.51.100.12",
        ServerSpec {
            ipv6: None,
            has_vpn: true,
            has_ssh: false,
            enabled: false,
            sni: "www.apple.com",
            ports: ServerPortOverrides::default(),
        },
    );
    srv3.admin_ssh.port = NonZeroU16::new(2220).expect("non-zero");
    state.servers.push(srv3);

    state
}
