pub mod amneziawg;
pub mod caddy;
pub mod firewall;
pub mod ssh_forwarding;
pub mod subscriptions;
pub mod xray;

pub const PRIVATE_IPV4_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

pub const PRIVATE_IPV6_CIDRS: &[&str] = &[
    "::/128",
    "::1/128",
    "64:ff9b::/96",
    "100::/64",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

pub const ALWAYS_BLOCKED_IPV4_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "100.100.100.200/32",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

pub const ALWAYS_BLOCKED_IPV6_CIDRS: &[&str] = &[
    "::/128",
    "::1/128",
    "fd00:ec2::254/128",
    "fe80::/10",
    "ff00::/8",
];

pub fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
