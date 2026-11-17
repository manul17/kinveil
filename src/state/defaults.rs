use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;

use anyhow::Result;
use ipnet::Ipv4Net;
use serde::Deserialize;
use serde_json::Value;

use crate::state::IntOrRange;

pub const DEFAULT_CONFIG_TOML: &str = include_str!("../../config.example.toml");

pub const DEFAULT_AWG_DNS_SERVERS: [Ipv4Addr; 2] =
    [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)];
pub const DEFAULT_XRAY_DNS_SERVERS: [&str; 2] = [
    "https+local://1.1.1.1/dns-query",
    "https+local://1.0.0.1/dns-query",
];
pub const DEFAULT_DOH_URL: &str = "https://1.1.1.1/dns-query";
pub const DEFAULT_DNS_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
pub const DEFAULT_AWG_SUBNET_CIDR: &str = "10.8.0.0/16";
pub const DEFAULT_VLESS_PORT: u16 = 8443;
pub const DEFAULT_HYSTERIA2_PORT: u16 = 443;
pub const DEFAULT_MASQUERADE_URL: &str = "https://www.cloudflare.com";
pub const DEFAULT_AWG_PORT: u16 = 7443;
pub const DEFAULT_SSH_FORWARDING_PORT: u16 = 2222;
pub const DEFAULT_TRAFFIC_RETENTION_DAYS: u32 = 90;
pub const DEFAULT_UPDATE_INTERVAL_HOURS: u32 = 12;
pub const DEFAULT_FIREWALL_UPDATE_INTERVAL_HOURS: u32 = 24;
pub const DEFAULT_IPV4_COUNTRY_URL: &str =
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/{cc}/ipv4-aggregated.txt";
pub const DEFAULT_IPV6_COUNTRY_URL: &str =
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/{cc}/ipv6-aggregated.txt";

pub fn default_awg_subnet() -> Ipv4Net {
    DEFAULT_AWG_SUBNET_CIDR
        .parse()
        .expect("valid default AWG subnet")
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallAutoUpdateSettings {
    pub enabled: bool,
    pub interval_hours: u32,
    pub ipv4_country_url: String,
    pub ipv6_country_url: String,
}

impl Default for FirewallAutoUpdateSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: DEFAULT_FIREWALL_UPDATE_INTERVAL_HOURS,
            ipv4_country_url: DEFAULT_IPV4_COUNTRY_URL.to_owned(),
            ipv6_country_url: DEFAULT_IPV6_COUNTRY_URL.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallXraySettings {
    pub block_bittorrent: bool,
    pub block_domains: Vec<String>,
    pub block_domain_lists: Vec<String>,
}

impl Default for FirewallXraySettings {
    fn default() -> Self {
        Self {
            block_bittorrent: true,
            block_domains: Vec::new(),
            block_domain_lists: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallSettings {
    pub block_private_networks: bool,
    pub block_countries: Vec<String>,
    pub block_cidrs: Vec<String>,
    pub block_ip_lists: Vec<String>,
    pub auto_update: FirewallAutoUpdateSettings,
    pub xray: FirewallXraySettings,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        Self {
            block_private_networks: true,
            block_countries: Vec::new(),
            block_cidrs: Vec::new(),
            block_ip_lists: Vec::new(),
            auto_update: FirewallAutoUpdateSettings::default(),
            xray: FirewallXraySettings::default(),
        }
    }
}

impl FirewallSettings {
    pub fn has_dynamic_ip_lists(&self) -> bool {
        !self.block_countries.is_empty() || !self.block_ip_lists.is_empty()
    }

    pub fn auto_update_active(&self) -> bool {
        self.auto_update.enabled && self.has_dynamic_ip_lists()
    }

    pub fn needs_country_geoip(&self) -> bool {
        !self.block_countries.is_empty()
    }

    pub fn needs_xray_geodata(&self) -> bool {
        !self.block_countries.is_empty()
            || !self.xray.block_domain_lists.is_empty()
            || self.xray.block_domains.iter().any(|d| {
                d.trim()
                    .get(..8)
                    .is_some_and(|p| p.eq_ignore_ascii_case("geosite:"))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsSettings {
    pub xray_servers: Vec<String>,
    pub amneziawg_servers: Vec<Ipv4Addr>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            xray_servers: DEFAULT_XRAY_DNS_SERVERS
                .iter()
                .copied()
                .map(str::to_owned)
                .collect(),
            amneziawg_servers: DEFAULT_AWG_DNS_SERVERS.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubscriptionRoutingSettings {
    pub bypass_countries: Vec<String>,
    pub block_countries: Vec<String>,
    pub direct_domains: Vec<String>,
    pub direct_ips: Vec<String>,
    pub proxy_domains: Vec<String>,
    pub proxy_ips: Vec<String>,
    pub block_domains: Vec<String>,
    pub block_ips: Vec<String>,
    pub domestic_doh: String,
    pub domestic_dns_ip: IpAddr,
    pub remote_doh: String,
    pub remote_dns_ip: IpAddr,
    pub happ_link: Option<String>,
    pub throne_link: Option<String>,
}

impl Default for SubscriptionRoutingSettings {
    fn default() -> Self {
        Self {
            bypass_countries: Vec::new(),
            block_countries: Vec::new(),
            direct_domains: Vec::new(),
            direct_ips: Vec::new(),
            proxy_domains: Vec::new(),
            proxy_ips: Vec::new(),
            block_domains: Vec::new(),
            block_ips: Vec::new(),
            domestic_doh: DEFAULT_DOH_URL.to_owned(),
            domestic_dns_ip: DEFAULT_DNS_IP,
            remote_doh: DEFAULT_DOH_URL.to_owned(),
            remote_dns_ip: DEFAULT_DNS_IP,
            happ_link: None,
            throne_link: None,
        }
    }
}

impl SubscriptionRoutingSettings {
    pub fn has_compiled_rules(&self) -> bool {
        !self.bypass_countries.is_empty()
            || !self.block_countries.is_empty()
            || !self.direct_domains.is_empty()
            || !self.direct_ips.is_empty()
            || !self.proxy_domains.is_empty()
            || !self.proxy_ips.is_empty()
            || !self.block_domains.is_empty()
            || !self.block_ips.is_empty()
    }

    pub fn is_active(&self) -> bool {
        self.has_compiled_rules() || self.happ_link.is_some() || self.throne_link.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubscriptionSettings {
    pub update_interval_hours: u32,
    pub profile_title: Option<String>,
    pub routing: SubscriptionRoutingSettings,
}

impl Default for SubscriptionSettings {
    fn default() -> Self {
        Self {
            update_interval_hours: DEFAULT_UPDATE_INTERVAL_HOURS,
            profile_title: None,
            routing: SubscriptionRoutingSettings::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XhttpSettings {
    pub path: Option<String>,
    pub padding_bytes: String,
    pub sc_max_buffered_posts: u32,
}

impl Default for XhttpSettings {
    fn default() -> Self {
        Self {
            path: None,
            padding_bytes: "100-1000".to_owned(),
            sc_max_buffered_posts: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XmuxConfig {
    pub max_concurrency: IntOrRange,
    pub max_connections: IntOrRange,
    pub c_max_reuse_times: IntOrRange,
    pub h_max_request_times: IntOrRange,
    pub h_max_reusable_secs: IntOrRange,
    pub h_keep_alive_period: IntOrRange,
}

impl Default for XmuxConfig {
    fn default() -> Self {
        Self {
            max_concurrency: IntOrRange::Range("16-32".to_owned()),
            max_connections: IntOrRange::Int(0),
            c_max_reuse_times: IntOrRange::Int(0),
            h_max_request_times: IntOrRange::Range("600-900".to_owned()),
            h_max_reusable_secs: IntOrRange::Range("1800-3000".to_owned()),
            h_keep_alive_period: IntOrRange::Int(0),
        }
    }
}

impl XmuxConfig {
    pub fn to_xray_json(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (key, val) in [
            ("cMaxReuseTimes", &self.c_max_reuse_times),
            ("hKeepAlivePeriod", &self.h_keep_alive_period),
            ("hMaxRequestTimes", &self.h_max_request_times),
            ("hMaxReusableSecs", &self.h_max_reusable_secs),
            ("maxConcurrency", &self.max_concurrency),
            ("maxConnections", &self.max_connections),
        ] {
            let jv = match val {
                IntOrRange::Int(n) => Value::Number((*n).into()),
                IntOrRange::Range(s) => Value::String(s.clone()),
            };
            map.insert(key.to_owned(), jv);
        }
        Value::Object(map)
    }

    pub fn validate(&self) -> Result<()> {
        for (field, val) in [
            ("vless.xmux.max_concurrency", &self.max_concurrency),
            ("vless.xmux.max_connections", &self.max_connections),
            ("vless.xmux.c_max_reuse_times", &self.c_max_reuse_times),
            ("vless.xmux.h_max_request_times", &self.h_max_request_times),
            ("vless.xmux.h_max_reusable_secs", &self.h_max_reusable_secs),
            ("vless.xmux.h_keep_alive_period", &self.h_keep_alive_period),
        ] {
            val.validate(field)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VlessSettings {
    pub enabled: bool,
    pub port: NonZeroU16,
    pub sni: Option<String>,
    pub target: Option<String>,
    pub xhttp_host: Option<String>,
    pub stream: bool,
    pub packet: bool,
    pub fingerprint: String,
    pub support_x25519mlkem768: bool,
    pub xhttp: XhttpSettings,
    pub xmux: XmuxConfig,
}

impl Default for VlessSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: NonZeroU16::new(DEFAULT_VLESS_PORT).expect("non-zero default vless port"),
            sni: None,
            target: None,
            xhttp_host: None,
            stream: true,
            packet: true,
            fingerprint: "chrome".to_owned(),
            support_x25519mlkem768: true,
            xhttp: XhttpSettings::default(),
            xmux: XmuxConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Hysteria2Settings {
    pub enabled: bool,
    pub port: NonZeroU16,
    pub alpn: Vec<String>,
    pub masquerade_url: String,
    pub udp_idle_timeout_secs: u32,
}

impl Default for Hysteria2Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: NonZeroU16::new(DEFAULT_HYSTERIA2_PORT).expect("non-zero default hysteria2 port"),
            alpn: vec!["h3".to_owned()],
            masquerade_url: DEFAULT_MASQUERADE_URL.to_owned(),
            udp_idle_timeout_secs: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AwgObfuscationOverrides {
    pub jc: Option<u16>,
    pub jmin: Option<u16>,
    pub jmax: Option<u16>,
    pub s1: Option<u16>,
    pub s2: Option<u16>,
    pub s3: Option<u16>,
    pub s4: Option<u16>,
    pub h1: Option<IntOrRange>,
    pub h2: Option<IntOrRange>,
    pub h3: Option<IntOrRange>,
    pub h4: Option<IntOrRange>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub content_padding_addition: Option<IntOrRange>,
}

impl AwgObfuscationOverrides {
    pub fn has_overrides(&self) -> bool {
        self.jc.is_some()
            || self.jmin.is_some()
            || self.jmax.is_some()
            || self.s1.is_some()
            || self.s2.is_some()
            || self.s3.is_some()
            || self.s4.is_some()
            || self.h1.is_some()
            || self.h2.is_some()
            || self.h3.is_some()
            || self.h4.is_some()
            || self.i1.is_some()
            || self.i2.is_some()
            || self.i3.is_some()
            || self.i4.is_some()
            || self.i5.is_some()
            || self.content_padding_addition.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AmneziaWgSettings {
    pub enabled: bool,
    pub port: NonZeroU16,
    pub subnet: Ipv4Net,
    pub mtu: u16,
    pub rekey_after_time: IntOrRange,
    pub rekey_timeout: IntOrRange,
    pub reject_after_time: IntOrRange,
    pub keepalive_timeout: IntOrRange,
    pub max_handshake_attempts: IntOrRange,
    pub random_trailers: bool,
    pub disable_cookies: bool,
    pub obfuscation: AwgObfuscationOverrides,
}

impl Default for AmneziaWgSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: NonZeroU16::new(DEFAULT_AWG_PORT).expect("non-zero default amneziawg port"),
            subnet: default_awg_subnet(),
            mtu: 1360,
            rekey_after_time: IntOrRange::Range("100-118".to_owned()),
            rekey_timeout: IntOrRange::Range("5-9".to_owned()),
            reject_after_time: IntOrRange::Range("176-249".to_owned()),
            keepalive_timeout: IntOrRange::Range("9-12".to_owned()),
            max_handshake_attempts: IntOrRange::Range("16-26".to_owned()),
            random_trailers: true,
            disable_cookies: true,
            obfuscation: AwgObfuscationOverrides::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshForwardingSettings {
    pub enabled: bool,
    pub port: NonZeroU16,
}

impl Default for SshForwardingSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            port: NonZeroU16::new(DEFAULT_SSH_FORWARDING_PORT)
                .expect("non-zero default ssh forwarding port"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficSettings {
    pub retention_days: u32,
}

impl Default for TrafficSettings {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_TRAFFIC_RETENTION_DAYS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SysctlSettings {
    pub udp_rmem_max: u64,
    pub udp_wmem_max: u64,
    pub udp_rmem_default: u64,
    pub udp_wmem_default: u64,
}

impl Default for SysctlSettings {
    fn default() -> Self {
        Self {
            udp_rmem_max: 16_777_216,
            udp_wmem_max: 16_777_216,
            udp_rmem_default: 4_194_304,
            udp_wmem_default: 4_194_304,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactSettings {
    pub xray_zip_url: Option<String>,
    pub xray_zip_sha256: Option<String>,
    pub geoip_url: Option<String>,
    pub geoip_sha256: Option<String>,
    pub geosite_url: Option<String>,
    pub geosite_sha256: Option<String>,
    pub amneziawg_url: Option<String>,
    pub amneziawg_sha256: Option<String>,
}

impl ArtifactSettings {
    pub fn has_overrides(&self) -> bool {
        self.xray_zip_url.is_some()
            || self.xray_zip_sha256.is_some()
            || self.geoip_url.is_some()
            || self.geoip_sha256.is_some()
            || self.geosite_url.is_some()
            || self.geosite_sha256.is_some()
            || self.amneziawg_url.is_some()
            || self.amneziawg_sha256.is_some()
    }
}
