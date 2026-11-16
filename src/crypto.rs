use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use rand::{Rng, RngExt};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType,
};
use sha2::{Digest, Sha256};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
use x509_parser::time::ASN1Time;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::state::{AwgObfuscation, IntOrRange, SecretString};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPins {
    pub cert_sha256_hex: String,
    pub spki_sha256_b64: String,
}

pub fn random_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

pub fn generate_token(len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.random_range(0..ALPHABET.len());
        out.push(ALPHABET[idx] as char);
    }
    out
}

pub fn generate_salamander_password(len: usize) -> SecretString {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    let mut out = Zeroizing::new(String::with_capacity(len));
    for _ in 0..len {
        let idx = rng.random_range(0..ALPHABET.len());
        out.push(ALPHABET[idx] as char);
    }
    SecretString::new(out.as_str())
}

pub fn generate_uuid_v4() -> SecretString {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    SecretString::new(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

pub fn generate_spider_x() -> String {
    format!("/{}", random_hex(8))
}

pub fn generate_xhttp_path() -> String {
    format!("/api/v2/{}", random_hex(6))
}

pub fn decode_32byte_b64(encoded: &str) -> Result<[u8; 32]> {
    let raw = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| URL_SAFE.decode(encoded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| anyhow!("invalid 32-byte base64 key"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte key"))?;
    Ok(arr)
}

pub fn base64_key_to_hex(encoded: &str) -> Result<String> {
    let bytes = decode_32byte_b64(encoded)?;
    Ok(hex_encode(&bytes))
}

fn generate_x25519_raw() -> (StaticSecret, X25519PublicKey) {
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(raw.as_mut());
    // Clamp per RFC 7748 so raw bytes match standard X25519 scalar representation.
    raw[0] &= 248;
    raw[31] &= 127;
    raw[31] |= 64;
    let secret = StaticSecret::from(*raw);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

pub fn derive_x25519_public_reality(private_b64: &str) -> Result<String> {
    let priv_bytes = Zeroizing::new(decode_32byte_b64(private_b64)?);
    let secret = StaticSecret::from(*priv_bytes);
    let derived = X25519PublicKey::from(&secret);
    Ok(URL_SAFE_NO_PAD.encode(derived.as_bytes()))
}

pub fn derive_x25519_public_awg(private_b64: &str) -> Result<String> {
    let priv_bytes = Zeroizing::new(decode_32byte_b64(private_b64)?);
    let secret = StaticSecret::from(*priv_bytes);
    let derived = X25519PublicKey::from(&secret);
    Ok(STANDARD.encode(derived.as_bytes()))
}

pub fn generate_x25519_reality_keypair() -> (SecretString, String) {
    let (secret, public) = generate_x25519_raw();
    (
        SecretString::new(URL_SAFE_NO_PAD.encode(secret.to_bytes())),
        URL_SAFE_NO_PAD.encode(public.as_bytes()),
    )
}

pub fn generate_x25519_awg_keypair() -> (SecretString, String) {
    let (secret, public) = generate_x25519_raw();
    (
        SecretString::new(STANDARD.encode(secret.to_bytes())),
        STANDARD.encode(public.as_bytes()),
    )
}

pub fn generate_awg_hpk() -> SecretString {
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(raw.as_mut());
    SecretString::new(STANDARD.encode(raw.as_ref()))
}

/// Generates a 32-byte non-zero WireGuard/AmneziaWG pre-shared key encoded in standard Base64.
pub fn generate_awg_psk() -> SecretString {
    let mut raw = Zeroizing::new([0u8; 32]);
    while raw.iter().all(|&b| b == 0) {
        rand::rng().fill_bytes(raw.as_mut());
    }
    SecretString::new(STANDARD.encode(raw.as_ref()))
}

pub fn verify_x25519_pair(private_b64: &str, public_b64: &str) -> Result<()> {
    let priv_bytes = Zeroizing::new(decode_32byte_b64(private_b64)?);
    let pub_bytes = decode_32byte_b64(public_b64)?;
    let secret = StaticSecret::from(*priv_bytes);
    let derived = X25519PublicKey::from(&secret);
    if derived.as_bytes() != &pub_bytes {
        bail!("X25519 private key does not match public key");
    }
    Ok(())
}

pub fn generate_openssh_ed25519(comment: &str) -> Result<(SecretString, String)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(seed.as_mut());
    let kp = Ed25519Keypair::from_seed(&seed);
    let priv_key = PrivateKey::new(KeypairData::Ed25519(kp), comment)
        .map_err(|e| anyhow!("failed to construct Ed25519 private key: {e}"))?;
    let priv_pem = priv_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow!("failed to encode OpenSSH private key: {e}"))?;
    let pub_line = priv_key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow!("failed to encode OpenSSH public key: {e}"))?;
    Ok((SecretString::new(priv_pem.as_str()), pub_line))
}

fn parse_openssh_private_key(priv_pem: &str) -> Result<PrivateKey> {
    if let Ok(pk) = PrivateKey::from_openssh(priv_pem) {
        return Ok(pk);
    }

    // Fallback for valid OpenSSH private keys wrapped at up to 76 columns
    // (RFC 2045 base64 MIME wrapping uses 76-char lines, whereas pem-rfc7468
    // inside ssh-key::PrivateKey::from_openssh limits lines to 70 chars).
    let trimmed = priv_pem.trim_matches(|c| matches!(c, '\r' | '\n'));
    let lines: Vec<&str> = trimmed.lines().collect();
    if lines.len() < 3
        || lines[0] != "-----BEGIN OPENSSH PRIVATE KEY-----"
        || lines[lines.len() - 1] != "-----END OPENSSH PRIVATE KEY-----"
    {
        bail!("invalid OpenSSH private key PEM boundaries");
    }

    let mut joined = Zeroizing::new(String::new());
    for line in &lines[1..lines.len() - 1] {
        if line.is_empty()
            || line.len() > 76
            || !line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            bail!("invalid OpenSSH private key PEM body");
        }
        joined.push_str(line);
    }

    let der = Zeroizing::new(
        STANDARD
            .decode(joined.as_bytes())
            .map_err(|e| anyhow!("invalid OpenSSH private key base64: {e}"))?,
    );
    PrivateKey::from_bytes(&der).map_err(|e| anyhow!("invalid OpenSSH private key: {e}"))
}

fn parse_unencrypted_ed25519_private_key(priv_pem: &str) -> Result<PrivateKey> {
    let priv_key = parse_openssh_private_key(priv_pem)?;
    if priv_key.is_encrypted() {
        bail!("SSH private key must not be passphrase-encrypted inside state");
    }
    if priv_key.algorithm() != Algorithm::Ed25519 {
        bail!("SSH private key must use Ed25519 algorithm");
    }
    Ok(priv_key)
}

/// Derive `"ssh-ed25519 <base64>"` without any OpenSSH comment.
pub fn derive_ed25519_public_without_comment(priv_pem: &str) -> Result<String> {
    let priv_key = parse_unencrypted_ed25519_private_key(priv_pem)?;
    let full = priv_key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow!("failed to encode OpenSSH public key: {e}"))?;
    let mut parts = full.split_whitespace();
    let (Some(ktype), Some(kb64)) = (parts.next(), parts.next()) else {
        bail!("malformed derived OpenSSH public key");
    };
    Ok(format!("{ktype} {kb64}"))
}

pub fn verify_openssh_ed25519_pair(priv_pem: &str, pub_openssh: &str) -> Result<()> {
    let priv_key = parse_unencrypted_ed25519_private_key(priv_pem)?;
    let pub_key = PublicKey::from_openssh(pub_openssh.trim())
        .map_err(|e| anyhow!("invalid OpenSSH public key: {e}"))?;
    if pub_key.algorithm() != Algorithm::Ed25519 {
        bail!("SSH public key must use Ed25519 algorithm");
    }
    if priv_key.public_key().key_data() != pub_key.key_data() {
        bail!("SSH private key does not match public key");
    }
    Ok(())
}

pub fn generate_hysteria_self_signed_cert(ipv4: Ipv4Addr) -> Result<(String, SecretString)> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| anyhow!("failed to init cert params: {e}"))?;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(3650);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ipv4.to_string());
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(ipv4))];

    let key_pair =
        KeyPair::generate().map_err(|e| anyhow!("failed to generate TLS keypair: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("failed to self-sign Hysteria2 cert: {e}"))?;
    Ok((cert.pem(), SecretString::new(key_pair.serialize_pem())))
}

pub fn parse_cert_pins_only(cert_pem: &str) -> Result<CertPins> {
    let (rem, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|_| anyhow!("invalid Hysteria2 certificate PEM"))?;
    if pem.label != "CERTIFICATE" {
        bail!("expected CERTIFICATE PEM block");
    }
    if parse_x509_pem(rem).is_ok() {
        bail!("expected a single Hysteria2 certificate PEM block");
    }
    let cert = pem
        .parse_x509()
        .map_err(|_| anyhow!("invalid X.509 Hysteria2 certificate"))?;

    let cert_hash = Sha256::digest(&pem.contents);
    let spki_hash = Sha256::digest(cert.public_key().raw);
    Ok(CertPins {
        cert_sha256_hex: hex_encode(&cert_hash),
        spki_sha256_b64: STANDARD.encode(spki_hash),
    })
}

pub fn parse_and_verify_hysteria_cert(
    cert_pem: &str,
    key_pem: &str,
    expected_host_or_ip: &str,
) -> Result<CertPins> {
    let (rem, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|_| anyhow!("invalid Hysteria2 certificate PEM"))?;
    if pem.label != "CERTIFICATE" {
        bail!("expected CERTIFICATE PEM block");
    }
    if parse_x509_pem(rem).is_ok() {
        bail!("expected a single Hysteria2 certificate PEM block");
    }
    let cert = pem
        .parse_x509()
        .map_err(|_| anyhow!("invalid X.509 Hysteria2 certificate"))?;

    let key_pair =
        KeyPair::from_pem(key_pem).map_err(|_| anyhow!("invalid Hysteria2 private key PEM"))?;
    if key_pair.subject_public_key_info() != cert.public_key().raw {
        bail!("Hysteria2 certificate does not match private key");
    }

    let now = ASN1Time::now().to_datetime();
    let nb = cert.validity().not_before.to_datetime();
    let na = cert.validity().not_after.to_datetime();
    if now < nb || now > na {
        bail!("Hysteria2 certificate is outside its validity window");
    }

    let san = cert
        .subject_alternative_name()
        .map_err(|_| anyhow!("failed to parse Hysteria2 certificate SAN extension"))?
        .ok_or_else(|| anyhow!("Hysteria2 certificate lacks a SAN extension"))?;

    let san_matches = if let Ok(ip) = expected_host_or_ip.parse::<IpAddr>() {
        san.value.general_names.iter().any(|name| match (name, ip) {
            (GeneralName::IPAddress(bytes), IpAddr::V4(v4)) => *bytes == v4.octets(),
            (GeneralName::IPAddress(bytes), IpAddr::V6(v6)) => *bytes == v6.octets(),
            _ => false,
        })
    } else {
        let target = expected_host_or_ip
            .trim_end_matches('.')
            .to_ascii_lowercase();
        san.value.general_names.iter().any(|name| match name {
            GeneralName::DNSName(dns) => {
                let d = dns.trim_end_matches('.').to_ascii_lowercase();
                d == target
                    || (d.starts_with("*.")
                        && target.ends_with(&d[1..])
                        && target.matches('.').count() == d.matches('.').count())
            }
            _ => false,
        })
    };
    if !san_matches {
        bail!("Hysteria2 certificate SAN does not match {expected_host_or_ip}");
    }

    let cert_hash = Sha256::digest(&pem.contents);
    let spki_hash = Sha256::digest(cert.public_key().raw);
    Ok(CertPins {
        cert_sha256_hex: hex_encode(&cert_hash),
        spki_sha256_b64: STANDARD.encode(spki_hash),
    })
}

pub fn generate_awg_obfuscation() -> AwgObfuscation {
    let mut rng = rand::rng();
    let jc = rng.random_range(4..=8);
    let jmin = rng.random_range(50..=100);
    let jmax = rng.random_range((jmin + 80)..=250);

    let s1 = rng.random_range(16..=150);
    let s2 = loop {
        let cand = rng.random_range(16..=150);
        if u32::from(s1) + 148 != u32::from(cand) + 92 && u32::from(s1) + 24 != u32::from(cand) {
            break cand;
        }
    };
    let s3 = rng.random_range(16..=150);
    let s4 = rng.random_range(16..=150);

    let mut headers = Vec::with_capacity(4);
    while headers.len() < 4 {
        let h: u32 = rng.random_range(100_000_000..=2_100_000_000);
        if !headers.contains(&h) {
            headers.push(h);
        }
    }
    headers.sort_unstable();

    let pad_lo = rng.random_range(12..=24);
    let pad_hi = rng.random_range((pad_lo + 16)..=(pad_lo + 36));
    let cps_len = rng.random_range(32..=64);

    AwgObfuscation {
        jc,
        jmin,
        jmax,
        s1,
        s2,
        s3,
        s4,
        h1: IntOrRange::Int(headers[0]),
        h2: IntOrRange::Int(headers[1]),
        h3: IntOrRange::Int(headers[2]),
        h4: IntOrRange::Int(headers[3]),
        i1: format!("<r {cps_len}>"),
        i2: None,
        i3: None,
        i4: None,
        i5: None,
        header_protection_key: generate_awg_hpk(),
        content_padding_addition: IntOrRange::Range(format!("{pad_lo}-{pad_hi}")),
    }
}
