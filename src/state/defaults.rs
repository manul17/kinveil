use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use anyhow::Result;
use ipnet::Ipv4Net;
use serde::Deserialize;
use serde_json::Value;

use crate::state::IntOrRange;

pub const DEFAULT_CONFIG_TOML: &str = include_str!("../../config.example.toml");

pub const DEFAULT_AWG_DNS_SERVERS: [Ipv4Addr; 2] =
    [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];
pub const DEFAULT_AWG_SUBNET_CIDR: &str = "10.8.0.0/16";
pub const DEFAULT_VLESS_PORT: u16 = 8443;
pub const DEFAULT_HYSTERIA2_PORT: u16 = 9443;
pub const DEFAULT_AWG_PORT: u16 = 7443;
pub const DEFAULT_SSH_FORWARDING_PORT: u16 = 2222;
pub const DEFAULT_UPDATE_INTERVAL_HOURS: u32 = 12;

pub fn default_awg_subnet() -> Ipv4Net {
    DEFAULT_AWG_SUBNET_CIDR
        .parse()
        .expect("valid default AWG subnet")
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallSettings {
    pub block_private_networks: bool,
    pub block_bittorrent: bool,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        Self {
            block_private_networks: true,
            block_bittorrent: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubscriptionSettings {
    pub update_interval_hours: u32,
    pub profile_title: Option<String>,
    pub happ_routing: Option<String>,
}

impl Default for SubscriptionSettings {
    fn default() -> Self {
        Self {
            update_interval_hours: DEFAULT_UPDATE_INTERVAL_HOURS,
            profile_title: None,
            happ_routing: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XhttpSettings {
    pub padding_bytes: String,
    pub sc_max_buffered_posts: u32,
}

impl Default for XhttpSettings {
    fn default() -> Self {
        Self {
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
            masquerade_url: "https://www.microsoft.com".to_owned(),
            udp_idle_timeout_secs: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AmneziaWgSettings {
    pub enabled: bool,
    pub port: NonZeroU16,
    pub subnet: Ipv4Net,
    pub dns_servers: Vec<Ipv4Addr>,
    pub mtu: u16,
    pub rekey_after_time: IntOrRange,
    pub rekey_timeout: IntOrRange,
    pub reject_after_time: IntOrRange,
    pub keepalive_timeout: IntOrRange,
    pub max_handshake_attempts: IntOrRange,
}

impl Default for AmneziaWgSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: NonZeroU16::new(DEFAULT_AWG_PORT).expect("non-zero default amneziawg port"),
            subnet: default_awg_subnet(),
            dns_servers: DEFAULT_AWG_DNS_SERVERS.to_vec(),
            mtu: 1360,
            rekey_after_time: IntOrRange::Range("100-118".to_owned()),
            rekey_timeout: IntOrRange::Range("5-9".to_owned()),
            reject_after_time: IntOrRange::Range("176-249".to_owned()),
            keepalive_timeout: IntOrRange::Range("9-12".to_owned()),
            max_handshake_attempts: IntOrRange::Range("16-26".to_owned()),
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
            enabled: true,
            port: NonZeroU16::new(DEFAULT_SSH_FORWARDING_PORT)
                .expect("non-zero default ssh forwarding port"),
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
    pub amneziawg_url: Option<String>,
    pub amneziawg_sha256: Option<String>,
}

impl ArtifactSettings {
    pub fn has_custom_xray(&self) -> bool {
        self.xray_zip_url.is_some() || self.xray_zip_sha256.is_some()
    }

    pub fn has_custom_amneziawg(&self) -> bool {
        self.amneziawg_url.is_some() || self.amneziawg_sha256.is_some()
    }

    pub fn has_overrides(&self) -> bool {
        self.has_custom_xray() || self.has_custom_amneziawg()
    }
}
