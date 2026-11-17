//! Top-level encrypted vault state model, domain types, defaults, and query helpers.
//!
//! ## Schema Invariants (`schema_version = 1`)
//! - `config_toml` stores the operator's exact commented TOML verbatim and is hydrated into
//!   [`Settings`] on load via `TryFrom<RawState>` with `#[serde(deny_unknown_fields)]`.
//! - Secret fields use [`SecretString`] (`Zeroizing<String>`, redacted in `Debug`); derived
//!   public keys are omitted from JSON and recomputed from private keys on demand.
//! - User UIDs (`next_uid`) increment monotonically and never reuse deleted `vpnssh<uid>`
//!   accounts or AmneziaWG `/32` allocations.

pub mod defaults;

pub use self::defaults::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::ops::Deref;

use anyhow::{Context as _, Result, anyhow, bail};
use ipnet::Ipv4Net;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::crypto::{
    derive_ed25519_public_without_comment, derive_x25519_public_awg, derive_x25519_public_reality,
    generate_awg_obfuscation, generate_awg_psk, generate_hysteria_self_signed_cert,
    generate_openssh_ed25519, generate_salamander_password, generate_spider_x, generate_token,
    generate_uuid_v4, generate_x25519_awg_keypair, generate_x25519_reality_keypair,
    generate_xhttp_path, random_hex,
};

pub const SCHEMA_VERSION: u32 = 1;

/// UTF-8 secret value that is zeroized on drop and redacted in `Debug` output,
/// while serializing transparently as a plain JSON string inside the encrypted state.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self(Zeroizing::new(s)))
    }
}

pub fn now_utc_seconds() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0).unwrap_or(now)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntOrRange {
    Int(u32),
    Range(String),
}

impl fmt::Display for IntOrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(n) => write!(f, "{n}"),
            Self::Range(s) => f.write_str(s),
        }
    }
}

impl IntOrRange {
    pub fn validate(&self, field: &str) -> Result<()> {
        self.bounds(field).map(|_| ())
    }

    pub fn bounds(&self, field: &str) -> Result<(u32, u32)> {
        match self {
            Self::Int(n) => Ok((*n, *n)),
            Self::Range(s) => {
                if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                    let n: u32 = s
                        .parse()
                        .map_err(|_| anyhow!("{field} integer value out of range"))?;
                    return Ok((n, n));
                }
                parse_range_u32(s, field)
            }
        }
    }
}

pub fn parse_range_u32(value: &str, field: &str) -> Result<(u32, u32)> {
    let Some((lo_str, hi_str)) = value.split_once('-') else {
        bail!("{field} must be a non-negative integer range 'lo-hi'");
    };
    if lo_str.is_empty()
        || hi_str.is_empty()
        || !lo_str.bytes().all(|b| b.is_ascii_digit())
        || !hi_str.bytes().all(|b| b.is_ascii_digit())
    {
        bail!("{field} must be a non-negative integer range 'lo-hi'");
    }
    let lo: u32 = lo_str
        .parse()
        .map_err(|_| anyhow!("{field} range lower bound is out of range"))?;
    let hi: u32 = hi_str
        .parse()
        .map_err(|_| anyhow!("{field} range upper bound is out of range"))?;
    if lo > hi {
        bail!("{field} range lower bound exceeds upper bound");
    }
    Ok((lo, hi))
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub firewall: FirewallSettings,
    pub dns: DnsSettings,
    pub subscription: SubscriptionSettings,
    pub vless: VlessSettings,
    pub hysteria2: Hysteria2Settings,
    pub amneziawg: AmneziaWgSettings,
    pub ssh_forwarding: SshForwardingSettings,
    pub traffic: TrafficSettings,
    pub sysctl: SysctlSettings,
    pub artifacts: ArtifactSettings,
}

/// Parses raw TOML configuration text into [`Settings`].
pub fn parse_config_toml(raw: &str) -> Result<Settings> {
    toml::from_str::<Settings>(raw).context("parsing config.toml")
}

impl Settings {
    pub fn validated_awg_subnet(&self) -> Result<Ipv4Net> {
        let net = self.amneziawg.subnet;
        if net.prefix_len() > 30 {
            bail!("amneziawg.subnet prefix must be <= /30");
        }
        if net.addr() != net.network() {
            bail!("amneziawg.subnet must specify the network address");
        }
        Ok(net)
    }

    pub fn awg_server_interface_cidr(&self) -> Result<String> {
        let net = self.validated_awg_subnet()?;
        let server_ip = u32::from(net.network())
            .checked_add(1)
            .map(Ipv4Addr::from)
            .ok_or_else(|| anyhow!("amneziawg subnet overflow"))?;
        Ok(format!("{server_ip}/{}", net.prefix_len()))
    }

    pub fn awg_user_cidr(&self, uid: u32) -> Result<String> {
        let net = self.validated_awg_subnet()?;
        let offset = uid
            .checked_add(1)
            .ok_or_else(|| anyhow!("uid overflow for amneziawg IP"))?;
        let raw_ip = u32::from(net.network())
            .checked_add(offset)
            .ok_or_else(|| anyhow!("amneziawg subnet overflow"))?;
        let ip = Ipv4Addr::from(raw_ip);
        if !net.contains(&ip) || ip == net.network() || ip == net.broadcast() {
            bail!(
                "uid {uid} exceeds usable host capacity of subnet {}",
                self.amneziawg.subnet
            );
        }
        Ok(format!("{ip}/32"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionConfig {
    pub domain: String,
    pub base_path: SecretString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<CloudflareConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    pub zone_id: String,
    pub api_token: SecretString,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub uid: u32,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub subscription_token: SecretString,
    pub vless: UserVless,
    pub hysteria2: UserHysteria2,
    pub amneziawg: UserAmneziaWg,
    pub ssh_forwarding: UserSshForwarding,
}

impl User {
    pub fn generate(uid: u32) -> Result<Self> {
        let (awg_priv, _) = generate_x25519_awg_keypair();
        let (ssh_priv, _) = generate_openssh_ed25519(&format!("vpnssh{uid}"))?;
        Ok(Self {
            uid,
            enabled: true,
            created_at: now_utc_seconds(),
            note: None,
            subscription_token: SecretString::new(generate_token(24)),
            vless: UserVless {
                uuid: generate_uuid_v4(),
                spider_x: generate_spider_x(),
            },
            hysteria2: UserHysteria2 {
                auth: generate_salamander_password(24),
            },
            amneziawg: UserAmneziaWg {
                private_key: awg_priv,
                preshared_key: generate_awg_psk(),
            },
            ssh_forwarding: UserSshForwarding {
                private_key: ssh_priv,
            },
        })
    }

    pub fn ssh_username(&self) -> String {
        format!("vpnssh{}", self.uid)
    }

    pub fn amneziawg_public_key(&self) -> Result<String> {
        derive_x25519_public_awg(self.amneziawg.private_key.as_str())
    }

    pub fn ssh_public_key(&self) -> Result<String> {
        derive_ed25519_public_without_comment(self.ssh_forwarding.private_key.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserVless {
    pub uuid: SecretString,
    pub spider_x: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserHysteria2 {
    pub auth: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAmneziaWg {
    pub private_key: SecretString,
    pub preshared_key: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSshForwarding {
    pub private_key: SecretString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, clap::ValueEnum)]
pub enum ServerRole {
    Vpn,
    Subscription,
}

impl ServerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vpn => "vpn",
            Self::Subscription => "subscription",
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
pub enum VpnProtocol {
    #[value(name = "vless")]
    #[serde(rename = "vless")]
    Vless,
    #[value(name = "hysteria2")]
    #[serde(rename = "hysteria2")]
    Hysteria2,
    #[value(name = "amneziawg")]
    #[serde(rename = "amneziawg")]
    AmneziaWg,
    #[value(name = "ssh-forwarding")]
    #[serde(rename = "ssh-forwarding")]
    SshForwarding,
}

impl VpnProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Hysteria2 => "hysteria2",
            Self::AmneziaWg => "amneziawg",
            Self::SshForwarding => "ssh-forwarding",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "vless" => Some(Self::Vless),
            "hysteria2" => Some(Self::Hysteria2),
            "amneziawg" => Some(Self::AmneziaWg),
            "ssh-forwarding" => Some(Self::SshForwarding),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSource {
    Derived,
    Config,
    Server,
}

impl ValueSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "derived",
            Self::Config => "config",
            Self::Server => "server",
        }
    }
}

/// Resolved 2-layer (`config.toml` -> per-server overrides) configuration for one [`Server`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveServerConfig {
    pub has_vpn: bool,
    pub is_subscription: bool,
    pub protocols_source: ValueSource,
    pub vless_wanted: bool,
    pub has_vless_stream: bool,
    pub has_vless_packet: bool,
    pub has_vless: bool,
    pub has_hysteria2: bool,
    pub has_xray: bool,
    pub has_amneziawg: bool,
    pub has_ssh_forwarding: bool,
    pub has_any_vpn_protocol: bool,
    pub vless_port: u16,
    pub hysteria2_port: u16,
    pub amneziawg_port: u16,
    pub ssh_forwarding_port: u16,
    pub vless_sni: Option<(String, ValueSource)>,
    pub vless_target: Option<(String, ValueSource)>,
    pub vless_xhttp_host: Option<(String, ValueSource)>,
    pub vless_xhttp_path: Option<(String, ValueSource)>,
    pub awg_obfuscation: Option<AwgObfuscation>,
    pub has_traffic: bool,
}

impl EffectiveServerConfig {
    /// Returns true if retiring Caddy should wait until post-deploy DNS/HTTPS verification
    /// succeeds rather than stopping Caddy early during deployment.
    pub fn should_defer_caddy_retire(&self) -> bool {
        let needs_80_or_443 = (self.has_vless && matches!(self.vless_port, 80 | 443))
            || (self.has_ssh_forwarding && matches!(self.ssh_forwarding_port, 80 | 443));
        !self.is_subscription && !needs_80_or_443
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub id: String,
    pub label: String,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub public_ipv4: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ipv6: Option<Ipv6Addr>,
    pub admin_ssh: AdminSsh,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn: Option<ServerVpn>,
}

impl Server {
    /// Resolves effective protocols, ports, VLESS camouflage, and AmneziaWG obfuscation
    /// across the 2-layer hierarchy (`config.toml` -> per-server overrides).
    pub fn effective_config(
        &self,
        settings: &Settings,
        is_subscription: bool,
    ) -> EffectiveServerConfig {
        let has_vpn = self.has_vpn();
        let (protocols_override, protocols_source) =
            match self.vpn.as_ref().and_then(|v| v.protocols.as_ref()) {
                Some(set) => (Some(set), ValueSource::Server),
                None => (None, ValueSource::Config),
            };
        let proto_enabled = |proto: VpnProtocol, cfg_default: bool| -> bool {
            protocols_override.map_or(cfg_default, |set| set.contains(&proto))
        };
        let vless_wanted = has_vpn && proto_enabled(VpnProtocol::Vless, settings.vless.enabled);
        let has_vless_stream = vless_wanted && settings.vless.stream;
        let has_vless_packet = vless_wanted && settings.vless.packet;
        let has_vless = has_vless_stream || has_vless_packet;
        let has_hysteria2 =
            has_vpn && proto_enabled(VpnProtocol::Hysteria2, settings.hysteria2.enabled);
        let has_xray = has_vless || has_hysteria2;
        let has_amneziawg =
            has_vpn && proto_enabled(VpnProtocol::AmneziaWg, settings.amneziawg.enabled);
        let has_ssh_forwarding =
            has_vpn && proto_enabled(VpnProtocol::SshForwarding, settings.ssh_forwarding.enabled);
        let has_any_vpn_protocol =
            has_vless || has_hysteria2 || has_amneziawg || has_ssh_forwarding;
        let has_traffic = has_any_vpn_protocol && self.vpn.as_ref().is_some_and(|v| v.traffic);

        let vless_port = self
            .vpn
            .as_ref()
            .and_then(|v| v.vless.port)
            .unwrap_or(settings.vless.port)
            .get();
        let hysteria2_port = self
            .vpn
            .as_ref()
            .and_then(|v| v.hysteria2.port)
            .unwrap_or(settings.hysteria2.port)
            .get();
        let amneziawg_port = self
            .vpn
            .as_ref()
            .and_then(|v| v.amneziawg.port)
            .unwrap_or(settings.amneziawg.port)
            .get();
        let ssh_forwarding_port = self
            .vpn
            .as_ref()
            .and_then(|v| v.ssh_forwarding.port)
            .unwrap_or(settings.ssh_forwarding.port)
            .get();

        let (vless_sni, vless_target, vless_xhttp_host, vless_xhttp_path, awg_obfuscation) =
            match &self.vpn {
                Some(vpn) => {
                    let cfg_sni = settings
                        .vless
                        .sni
                        .as_deref()
                        .map(|s| s.trim().to_ascii_lowercase())
                        .filter(|s| !s.is_empty());
                    let cfg_target = settings
                        .vless
                        .target
                        .as_deref()
                        .map(|t| t.trim().to_ascii_lowercase())
                        .filter(|t| !t.is_empty());
                    let cfg_xhttp_host = settings
                        .vless
                        .xhttp_host
                        .as_deref()
                        .map(|h| h.trim().to_ascii_lowercase())
                        .filter(|h| !h.is_empty());

                    let (sni, target, xhttp_host) = if let Some(ref srv_sni) = vpn.vless.sni {
                        let srv_sni_clean = srv_sni.trim().to_ascii_lowercase();
                        let same_as_cfg_sni = cfg_sni.as_deref() == Some(srv_sni_clean.as_str());
                        let sni = Some((srv_sni_clean.clone(), ValueSource::Server));
                        let target = vpn
                            .vless
                            .target
                            .as_deref()
                            .map(|t| (t.trim().to_ascii_lowercase(), ValueSource::Server))
                            .or_else(|| {
                                same_as_cfg_sni
                                    .then(|| cfg_target.map(|t| (t, ValueSource::Config)))
                                    .flatten()
                            })
                            .or_else(|| {
                                Some((format!("{srv_sni_clean}:443"), ValueSource::Derived))
                            });
                        let xhttp_host = vpn
                            .vless
                            .xhttp_host
                            .as_deref()
                            .map(|h| (h.trim().to_ascii_lowercase(), ValueSource::Server))
                            .or_else(|| {
                                same_as_cfg_sni
                                    .then(|| cfg_xhttp_host.map(|h| (h, ValueSource::Config)))
                                    .flatten()
                            });
                        (sni, target, xhttp_host)
                    } else {
                        let sni = cfg_sni.map(|s| (s, ValueSource::Config));
                        let target = vpn
                            .vless
                            .target
                            .as_deref()
                            .map(|t| (t.trim().to_ascii_lowercase(), ValueSource::Server))
                            .or_else(|| cfg_target.map(|t| (t, ValueSource::Config)))
                            .or_else(|| {
                                sni.as_ref()
                                    .map(|(s, _)| (format!("{s}:443"), ValueSource::Derived))
                            });
                        let xhttp_host = vpn
                            .vless
                            .xhttp_host
                            .as_deref()
                            .map(|h| (h.trim().to_ascii_lowercase(), ValueSource::Server))
                            .or_else(|| cfg_xhttp_host.map(|h| (h, ValueSource::Config)));
                        (sni, target, xhttp_host)
                    };

                    let xhttp_path = settings
                        .vless
                        .xhttp
                        .path
                        .as_deref()
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .map(|p| (p.to_owned(), ValueSource::Config))
                        .or_else(|| Some((vpn.vless.xhttp_path.clone(), ValueSource::Server)));

                    let mut obf = vpn.amneziawg.obfuscation.clone();
                    let awg_obf = &settings.amneziawg.obfuscation;
                    if let Some(jc) = awg_obf.jc {
                        obf.jc = jc;
                    }
                    if let Some(jmin) = awg_obf.jmin {
                        obf.jmin = jmin;
                    }
                    if let Some(jmax) = awg_obf.jmax {
                        obf.jmax = jmax;
                    }
                    if let Some(s1) = awg_obf.s1 {
                        obf.s1 = s1;
                    }
                    if let Some(s2) = awg_obf.s2 {
                        obf.s2 = s2;
                    }
                    if let Some(s3) = awg_obf.s3 {
                        obf.s3 = s3;
                    }
                    if let Some(s4) = awg_obf.s4 {
                        obf.s4 = s4;
                    }
                    if let Some(ref h1) = awg_obf.h1 {
                        obf.h1 = h1.clone();
                    }
                    if let Some(ref h2) = awg_obf.h2 {
                        obf.h2 = h2.clone();
                    }
                    if let Some(ref h3) = awg_obf.h3 {
                        obf.h3 = h3.clone();
                    }
                    if let Some(ref h4) = awg_obf.h4 {
                        obf.h4 = h4.clone();
                    }
                    if let Some(ref i1) = awg_obf.i1 {
                        obf.i1 = i1.clone();
                    }
                    if let Some(ref i2) = awg_obf.i2 {
                        obf.i2 = Some(i2.clone());
                    }
                    if let Some(ref i3) = awg_obf.i3 {
                        obf.i3 = Some(i3.clone());
                    }
                    if let Some(ref i4) = awg_obf.i4 {
                        obf.i4 = Some(i4.clone());
                    }
                    if let Some(ref i5) = awg_obf.i5 {
                        obf.i5 = Some(i5.clone());
                    }
                    if let Some(ref cpa) = awg_obf.content_padding_addition {
                        obf.content_padding_addition = cpa.clone();
                    }

                    (sni, target, xhttp_host, xhttp_path, Some(obf))
                }
                None => (None, None, None, None, None),
            };

        EffectiveServerConfig {
            has_vpn,
            is_subscription,
            protocols_source,
            vless_wanted,
            has_vless_stream,
            has_vless_packet,
            has_vless,
            has_hysteria2,
            has_xray,
            has_amneziawg,
            has_ssh_forwarding,
            has_any_vpn_protocol,
            vless_port,
            hysteria2_port,
            amneziawg_port,
            ssh_forwarding_port,
            vless_sni,
            vless_target,
            vless_xhttp_host,
            vless_xhttp_path,
            awg_obfuscation,
            has_traffic,
        }
    }

    pub fn has_vpn(&self) -> bool {
        self.vpn.as_ref().is_some_and(|v| v.enabled)
    }

    pub fn roles_list(&self, is_subscription: bool) -> Vec<&'static str> {
        let mut roles = Vec::new();
        if self.has_vpn() {
            roles.push(ServerRole::Vpn.as_str());
        }
        if is_subscription {
            roles.push(ServerRole::Subscription.as_str());
        }
        roles
    }

    pub fn summary_sni(&self, settings: &Settings) -> Option<String> {
        let eff = self.effective_config(settings, false);
        if eff.has_vless {
            eff.vless_sni.map(|(sni, _)| sni)
        } else {
            None
        }
    }

    pub fn summary_ports(&self, settings: &Settings, is_subscription: bool) -> String {
        let eff = self.effective_config(settings, is_subscription);
        let mut ports = Vec::new();
        if eff.has_vless {
            ports.push(format!("vless={}/tcp", eff.vless_port));
        }
        if eff.has_hysteria2 {
            ports.push(format!("hysteria2={}/udp", eff.hysteria2_port));
        }
        if eff.has_amneziawg {
            ports.push(format!("amneziawg={}/udp", eff.amneziawg_port));
        }
        if eff.is_subscription {
            ports.push("https=80,443/tcp".to_owned());
        }
        if eff.has_ssh_forwarding {
            ports.push(format!("ssh-forwarding={}/tcp", eff.ssh_forwarding_port));
        }
        ports.join(",")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSsh {
    pub host: String,
    pub port: NonZeroU16,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    pub host_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerVpn {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<BTreeSet<VpnProtocol>>,
    pub traffic: bool,
    pub vless: ServerVless,
    pub hysteria2: ServerHysteria2,
    pub amneziawg: ServerAmneziaWg,
    pub ssh_forwarding: ServerSshForwarding,
}

impl ServerVpn {
    pub fn generate(
        server_id: &str,
        ipv4: Ipv4Addr,
        sni_opt: Option<String>,
        target_opt: Option<String>,
        xhttp_host_opt: Option<String>,
    ) -> Result<Self> {
        let sni = sni_opt
            .map(|s| {
                let clean = s.trim().to_ascii_lowercase();
                crate::validate::validate_hostname(&clean, "--vless-sni")?;
                Ok::<_, anyhow::Error>(clean)
            })
            .transpose()?;
        let target = target_opt
            .map(|t| {
                let clean = t.trim().to_ascii_lowercase();
                crate::validate::validate_target_host_port(&clean, "--vless-target")?;
                Ok::<_, anyhow::Error>(clean)
            })
            .transpose()?;
        let xhttp_host = xhttp_host_opt
            .map(|h| {
                let clean = h.trim().to_ascii_lowercase();
                crate::validate::validate_hostname(&clean, "--vless-xhttp-host")?;
                Ok::<_, anyhow::Error>(clean)
            })
            .transpose()?;
        let (vless_priv, _) = generate_x25519_reality_keypair();
        let (hyst_cert, hyst_key) = generate_hysteria_self_signed_cert(ipv4)?;
        let (awg_priv, _) = generate_x25519_awg_keypair();
        let ssh_forwarding = ServerSshForwarding::generate(server_id)?;
        Ok(Self {
            enabled: true,
            protocols: None,
            traffic: false,
            vless: ServerVless {
                port: None,
                sni,
                target,
                xhttp_host,
                xhttp_path: generate_xhttp_path(),
                private_key: vless_priv,
                short_id: random_hex(4),
            },
            hysteria2: ServerHysteria2 {
                port: None,
                salamander_password: generate_salamander_password(24),
                cert_pem: hyst_cert,
                key_pem: hyst_key,
            },
            amneziawg: ServerAmneziaWg {
                port: None,
                private_key: awg_priv,
                obfuscation: generate_awg_obfuscation(),
            },
            ssh_forwarding,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerVless {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<NonZeroU16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_host: Option<String>,
    pub xhttp_path: String,
    pub private_key: SecretString,
    pub short_id: String,
}

impl ServerVless {
    pub fn public_key(&self) -> Result<String> {
        derive_x25519_public_reality(self.private_key.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHysteria2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<NonZeroU16>,
    pub salamander_password: SecretString,
    pub cert_pem: String,
    pub key_pem: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerAmneziaWg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<NonZeroU16>,
    pub private_key: SecretString,
    pub obfuscation: AwgObfuscation,
}

impl ServerAmneziaWg {
    pub fn public_key(&self) -> Result<String> {
        derive_x25519_public_awg(self.private_key.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwgObfuscation {
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub s3: u16,
    pub s4: u16,
    pub h1: IntOrRange,
    pub h2: IntOrRange,
    pub h3: IntOrRange,
    pub h4: IntOrRange,
    pub i1: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i5: Option<String>,
    pub header_protection_key: SecretString,
    pub content_padding_addition: IntOrRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSshForwarding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<NonZeroU16>,
    pub host_private_key: SecretString,
}

impl ServerSshForwarding {
    pub fn generate(server_id: &str) -> Result<Self> {
        let (priv_key, _) =
            crate::crypto::generate_openssh_ed25519(&format!("kinveil-ssh-{server_id}"))?;
        Ok(Self {
            port: None,
            host_private_key: priv_key,
        })
    }

    pub fn host_public_key(&self) -> Result<String> {
        Ok(format!(
            "{}\n",
            derive_ed25519_public_without_comment(self.host_private_key.as_str())?
        ))
    }
}

/// Root state persisted inside the encrypted `state.enc` vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawState")]
pub struct State {
    pub schema_version: u32,
    pub revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub next_uid: u32,
    pub config_toml: String,
    #[serde(skip)]
    pub settings: Settings,
    pub subscription: SubscriptionConfig,
    pub users: BTreeMap<String, User>,
    pub servers: Vec<Server>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawState {
    schema_version: u32,
    revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    next_uid: u32,
    config_toml: String,
    subscription: SubscriptionConfig,
    users: BTreeMap<String, User>,
    servers: Vec<Server>,
}

impl TryFrom<RawState> for State {
    type Error = anyhow::Error;

    fn try_from(raw: RawState) -> Result<Self> {
        let settings = parse_config_toml(&raw.config_toml)?;
        Ok(Self {
            schema_version: raw.schema_version,
            revision: raw.revision,
            updated_at: raw.updated_at,
            next_uid: raw.next_uid,
            config_toml: raw.config_toml,
            settings,
            subscription: raw.subscription,
            users: raw.users,
            servers: raw.servers,
        })
    }
}

impl State {
    pub fn new(domain: String) -> Result<Self> {
        let base_path = format!("/{}/", generate_token(16));
        Self::new_with_base_path(domain, base_path)
    }

    pub fn new_with_base_path(domain: String, base_path: impl Into<String>) -> Result<Self> {
        let config_toml = DEFAULT_CONFIG_TOML.to_owned();
        let settings = parse_config_toml(&config_toml)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            revision: 1,
            updated_at: now_utc_seconds(),
            next_uid: 1,
            config_toml,
            settings,
            subscription: SubscriptionConfig {
                domain: domain.trim().to_ascii_lowercase(),
                base_path: SecretString::from(base_path.into()),
                server_id: None,
                cloudflare: None,
            },
            users: BTreeMap::new(),
            servers: Vec::new(),
        })
    }

    /// Parses `raw` TOML and updates both `config_toml` and hydrated `settings`.
    pub fn set_config_toml(&mut self, raw: impl Into<String>) -> Result<()> {
        let raw = raw.into();
        let settings = parse_config_toml(&raw)?;
        self.config_toml = raw;
        self.settings = settings;
        Ok(())
    }

    pub fn touch(&mut self) {
        self.revision = self.revision.saturating_add(1);
        self.updated_at = now_utc_seconds();
    }

    fn users_sorted(&self, only_enabled: bool) -> Vec<(&str, &User)> {
        let mut entries: Vec<(&str, &User)> = self
            .users
            .iter()
            .filter(|(_, user)| !only_enabled || user.enabled)
            .map(|(name, user)| (name.as_str(), user))
            .collect();
        entries
            .sort_by(|(name_a, a), (name_b, b)| a.uid.cmp(&b.uid).then_with(|| name_a.cmp(name_b)));
        entries
    }

    pub fn users_by_uid(&self) -> Vec<(&str, &User)> {
        self.users_sorted(false)
    }

    pub fn enabled_users_by_uid(&self) -> Vec<(&str, &User)> {
        self.users_sorted(true)
    }

    pub fn user(&self, name: &str) -> Result<&User> {
        self.users
            .get(name)
            .ok_or_else(|| anyhow!("user {name:?} not found"))
    }

    pub fn user_mut(&mut self, name: &str) -> Result<&mut User> {
        self.users
            .get_mut(name)
            .ok_or_else(|| anyhow!("user {name:?} not found"))
    }

    pub fn server(&self, id: &str) -> Result<&Server> {
        self.servers
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| anyhow!("server {id:?} not found"))
    }

    pub fn server_mut(&mut self, id: &str) -> Result<&mut Server> {
        self.servers
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| anyhow!("server {id:?} not found"))
    }

    pub fn is_subscription_server(&self, id: &str) -> bool {
        self.subscription.server_id.as_deref() == Some(id)
    }

    pub fn active_subscription_server(&self) -> Option<&Server> {
        let sub_id = self.subscription.server_id.as_deref()?;
        self.servers.iter().find(|s| s.id == sub_id && s.enabled)
    }

    pub fn user_subscription_url(&self, user: &User) -> String {
        format!(
            "https://{}{}{}",
            self.subscription.domain,
            self.subscription.base_path.as_str(),
            user.subscription_token.as_str()
        )
    }
}
