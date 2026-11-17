use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::crypto::sha256_hex;
use crate::state::ArtifactSettings;

const XRAY_VERSION: &str = "v26.11.9";
const XRAY_ZIP_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip";
const XRAY_ZIP_SHA256: &str = "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82";
const XRAY_BIN_SHA256: &str = "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d";
const XRAY_GEOIP_SHA256: &str = "283119b5c7679d3cc9a750e1b6da693ecfd42e5d5036b57f0c2d0505f76e36f4";
const XRAY_GEOSITE_SHA256: &str =
    "daaae9760ab5e687845817967257a6e9883d42ac9c09f4b774a32bd5cb39b4d7";

pub const AWG_VERSION: &str = "v3.1.20260828";
const AWG_REPO_URL: &str = "https://github.com/amnezia-vpn/amneziawg-go.git";
const AWG_COMMIT_SHA1: &str = "b5928efb6ca19f0153958460c3d141f04abc5c2e";
const AWG_PREBUILT_URL: Option<&str> = Some(concat!(
    env!("CARGO_PKG_REPOSITORY"),
    "/releases/download/v",
    env!("CARGO_PKG_VERSION"),
    "/amneziawg-go-v3.1.20260828-linux-amd64"
));
const AWG_PREBUILT_SHA256: Option<&str> =
    Some("fa81c45e5a54ea73b09aad93cc2dc69b2f51f673fc62f9cf2b7482fa9472ad66");
const MAX_XRAY_ZIP_BYTES: u64 = 128 * 1024 * 1024;
const MAX_XRAY_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_GEODATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AWG_BINARY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ArtifactStatus {
    pub xray_cached: bool,
    pub xray_path: PathBuf,
    pub geodata_cached: bool,
    pub awg_cached: bool,
    pub awg_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct XrayArtifacts {
    pub bin_bytes: Vec<u8>,
    pub bin_sha256: String,
    pub geoip_bytes: Vec<u8>,
    pub geoip_sha256: String,
    pub geosite_bytes: Vec<u8>,
    pub geosite_sha256: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeArtifacts {
    pub xray_bytes: Vec<u8>,
    pub xray_sha256: String,
    pub geoip_bytes: Vec<u8>,
    pub geoip_sha256: String,
    pub geosite_bytes: Vec<u8>,
    pub geosite_sha256: String,
    pub awg_bytes: Vec<u8>,
    pub awg_sha256: String,
}

fn download_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into()
}

pub(crate) fn artifacts_cache_dir() -> Result<PathBuf> {
    if let Some(override_dir) = read_nonempty_env("KINVEIL_CACHE_DIR") {
        return Ok(PathBuf::from(override_dir));
    }
    if let Some(xdg) = read_nonempty_env("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg).join("kinveil").join("artifacts"));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("cannot determine HOME directory for artifact cache"))?;
    Ok(PathBuf::from(home)
        .join(".cache")
        .join("kinveil")
        .join("artifacts"))
}

fn read_nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn normalize_sha256_hex(input: &str, label: &str) -> Result<String> {
    let normalized = input.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid {label} expected SHA-256 digest (expected 64 hex characters)");
    }
    Ok(normalized)
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    if fs::symlink_metadata(dir).is_err() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let meta = fs::symlink_metadata(dir)
        .with_context(|| format!("inspecting cache directory {}", dir.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "refusing to use symlinked cache directory {}",
            dir.display()
        );
    }
    if !meta.is_dir() {
        bail!("cache path {} is not a directory", dir.display());
    }
    let mode = meta.permissions().mode() & 0o777;
    if (mode & 0o077) != 0 {
        bail!(
            "cache directory {} has overly permissive mode {mode:04o}; expected 0700",
            dir.display()
        );
    }
    Ok(())
}

fn write_atomic_file(
    dest: &Path,
    bytes: &[u8],
    mode: u32,
    sha256_file: Option<(&Path, &str)>,
) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("missing parent directory for {}", dest.display()))?;
    ensure_private_dir(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp.")
        .permissions(fs::Permissions::from_mode(mode))
        .tempfile_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(dest)
        .map_err(|e| anyhow!("persisting {}: {}", dest.display(), e.error))?;
    if let Some((sidecar, hex)) = sha256_file {
        fs::write(sidecar, format!("{hex}\n"))?;
    }
    Ok(())
}

fn read_cached_if_valid(
    bin_path: &Path,
    sidecar_path: &Path,
    required_sha256: Option<&str>,
) -> Result<Option<(Vec<u8>, String)>> {
    if !bin_path.is_file() || !sidecar_path.is_file() {
        return Ok(None);
    }
    if let Some(parent) = bin_path.parent() {
        ensure_private_dir(parent)?;
    }
    let expected = fs::read_to_string(sidecar_path)?
        .trim()
        .to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    if let Some(req) = required_sha256
        && expected != req
    {
        return Ok(None);
    }
    let bytes = fs::read(bin_path)?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Ok(None);
    }
    Ok(Some((bytes, actual)))
}

fn verify_linux_amd64_elf(bytes: &[u8], name: &str) -> Result<()> {
    if !bytes.starts_with(b"\x7fELF") {
        bail!("{name} artifact is not a valid ELF executable");
    }
    if bytes.len() < 20
        || bytes[4] != 2
        || bytes[5] != 1
        || u16::from_le_bytes([bytes[18], bytes[19]]) != 0x3e
    {
        bail!("{name} artifact is not a 64-bit little-endian Linux x86_64 ELF executable");
    }
    Ok(())
}

fn read_local_elf_override(env_name: &str, path: &str, label: &str) -> Result<(Vec<u8>, String)> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {env_name} at {path}"))?;
    verify_linux_amd64_elf(&bytes, label)?;
    let hex = sha256_hex(&bytes);
    Ok((bytes, hex))
}

pub fn default_xray_cache_pair(cache_dir: &Path) -> (PathBuf, PathBuf) {
    (
        cache_dir.join(format!("xray-{XRAY_VERSION}-linux-amd64")),
        cache_dir.join(format!("xray-{XRAY_VERSION}-linux-amd64.sha256")),
    )
}

pub fn default_xray_geodata_cache_pairs(
    cache_dir: &Path,
) -> ((PathBuf, PathBuf), (PathBuf, PathBuf)) {
    (
        (
            cache_dir.join(format!("xray-{XRAY_VERSION}-geoip.dat")),
            cache_dir.join(format!("xray-{XRAY_VERSION}-geoip.dat.sha256")),
        ),
        (
            cache_dir.join(format!("xray-{XRAY_VERSION}-geosite.dat")),
            cache_dir.join(format!("xray-{XRAY_VERSION}-geosite.dat.sha256")),
        ),
    )
}

fn custom_xray_cache_pair(
    cache_dir: &Path,
    zip_sha256: &str,
) -> Result<(PathBuf, PathBuf, String)> {
    let norm = normalize_sha256_hex(zip_sha256, "artifacts.xray_zip_sha256")?;
    let prefix = &norm[..16];
    Ok((
        cache_dir.join(format!("xray-custom-{prefix}-linux-amd64")),
        cache_dir.join(format!("xray-custom-{prefix}-linux-amd64.sha256")),
        norm,
    ))
}

fn custom_geodata_cache_pair(
    cache_dir: &Path,
    kind: &str,
    sha256: &str,
    field: &str,
) -> Result<(PathBuf, PathBuf, String)> {
    let norm = normalize_sha256_hex(sha256, field)?;
    let prefix = &norm[..16];
    Ok((
        cache_dir.join(format!("{kind}-custom-{prefix}.dat")),
        cache_dir.join(format!("{kind}-custom-{prefix}.dat.sha256")),
        norm,
    ))
}

fn custom_xray_geodata_cache_pairs(
    cache_dir: &Path,
    norm_zip_sha: &str,
) -> ((PathBuf, PathBuf), (PathBuf, PathBuf)) {
    let prefix = &norm_zip_sha[..16];
    (
        (
            cache_dir.join(format!("xray-custom-{prefix}-geoip.dat")),
            cache_dir.join(format!("xray-custom-{prefix}-geoip.dat.sha256")),
        ),
        (
            cache_dir.join(format!("xray-custom-{prefix}-geosite.dat")),
            cache_dir.join(format!("xray-custom-{prefix}-geosite.dat.sha256")),
        ),
    )
}

pub fn default_awg_cache_pair(cache_dir: &Path) -> (PathBuf, PathBuf) {
    (
        cache_dir.join(format!("amneziawg-go-{AWG_VERSION}-linux-amd64")),
        cache_dir.join(format!("amneziawg-go-{AWG_VERSION}-linux-amd64.sha256")),
    )
}

fn custom_awg_cache_pair(cache_dir: &Path, sha256: &str) -> Result<(PathBuf, PathBuf, String)> {
    let norm = normalize_sha256_hex(sha256, "artifacts.amneziawg_sha256")?;
    let prefix = &norm[..16];
    Ok((
        cache_dir.join(format!("amneziawg-go-custom-{prefix}-linux-amd64")),
        cache_dir.join(format!("amneziawg-go-custom-{prefix}-linux-amd64.sha256")),
        norm,
    ))
}

fn default_bundled_artifact_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        dirs.push(exe_dir.join("artifacts"));
        if let Some(prefix) = exe_dir.parent() {
            dirs.push(prefix.join("share").join("kinveil").join("artifacts"));
        }
    }
    dirs
}

fn read_bundled_if_valid(
    dirs: &[PathBuf],
    filename: &str,
    expected_sha256: &str,
    max_bytes: u64,
    verify_elf: bool,
    label: &str,
) -> Option<(PathBuf, Vec<u8>, String)> {
    for dir in dirs {
        let path = dir.join(filename);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() || meta.len() > max_bytes {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.len() as u64 > max_bytes
            || (verify_elf && verify_linux_amd64_elf(&bytes, label).is_err())
        {
            continue;
        }
        let actual = sha256_hex(&bytes);
        if actual.eq_ignore_ascii_case(expected_sha256) {
            return Some((path, bytes, actual));
        }
    }
    None
}

fn has_valid_cached_file(bin_path: &Path, sidecar_path: &Path, required_sha: Option<&str>) -> bool {
    bin_path.is_file()
        && fs::read_to_string(sidecar_path).ok().is_some_and(|s| {
            let trimmed = s.trim();
            match required_sha {
                Some(req) => trimmed.eq_ignore_ascii_case(req),
                None => trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()),
            }
        })
}

pub fn inspect_artifact_status(
    artifacts: &ArtifactSettings,
    need_xray_geodata: bool,
    need_country_geoip: bool,
) -> Result<ArtifactStatus> {
    let cache_dir = artifacts_cache_dir()?;
    let bundled_dirs = default_bundled_artifact_dirs();
    let need_geoip = need_xray_geodata || need_country_geoip;
    let need_geosite = need_xray_geodata;

    let (xray_cached, xray_path, zip_geoip_ok, zip_geosite_ok) = if let Some(p) =
        read_nonempty_env("KINVEIL_XRAY_BIN")
    {
        let pb = PathBuf::from(p);
        let dir = pb.parent();
        let geoip_ok = !need_geoip || dir.is_some_and(|d| d.join("geoip.dat").is_file());
        let geosite_ok = !need_geosite || dir.is_some_and(|d| d.join("geosite.dat").is_file());
        (pb.is_file(), pb, geoip_ok, geosite_ok)
    } else if let Some(zip_sha) = artifacts.xray_zip_sha256.as_deref() {
        let (bin, sha, norm_zip) = custom_xray_cache_pair(&cache_dir, zip_sha)?;
        let ((geoip, geoip_sha), (geosite, geosite_sha)) =
            custom_xray_geodata_cache_pairs(&cache_dir, &norm_zip);
        let bin_ok = has_valid_cached_file(&bin, &sha, None);
        let geoip_ok = has_valid_cached_file(&geoip, &geoip_sha, None);
        let geosite_ok = has_valid_cached_file(&geosite, &geosite_sha, None);
        (bin_ok, bin, geoip_ok, geosite_ok)
    } else {
        let (bin, sha) = default_xray_cache_pair(&cache_dir);
        let ((geoip, geoip_sha), (geosite, geosite_sha)) =
            default_xray_geodata_cache_pairs(&cache_dir);

        let (bin_ok, resolved_path) = if has_valid_cached_file(&bin, &sha, Some(XRAY_BIN_SHA256)) {
            (true, bin)
        } else if let Some((bundled_path, _, _)) = read_bundled_if_valid(
            &bundled_dirs,
            &format!("xray-{XRAY_VERSION}-linux-amd64"),
            XRAY_BIN_SHA256,
            MAX_XRAY_BINARY_BYTES,
            true,
            "bundled xray",
        ) {
            (true, bundled_path)
        } else {
            (false, bin)
        };

        let geoip_ok = has_valid_cached_file(&geoip, &geoip_sha, Some(XRAY_GEOIP_SHA256))
            || read_bundled_if_valid(
                &bundled_dirs,
                &format!("xray-{XRAY_VERSION}-geoip.dat"),
                XRAY_GEOIP_SHA256,
                MAX_GEODATA_BYTES,
                false,
                "bundled geoip.dat",
            )
            .is_some();
        let geosite_ok = has_valid_cached_file(&geosite, &geosite_sha, Some(XRAY_GEOSITE_SHA256))
            || read_bundled_if_valid(
                &bundled_dirs,
                &format!("xray-{XRAY_VERSION}-geosite.dat"),
                XRAY_GEOSITE_SHA256,
                MAX_GEODATA_BYTES,
                false,
                "bundled geosite.dat",
            )
            .is_some();

        (bin_ok, resolved_path, geoip_ok, geosite_ok)
    };

    let xray_env_set = read_nonempty_env("KINVEIL_XRAY_BIN").is_some();
    let geoip_ok = if !need_geoip {
        true
    } else if !xray_env_set && let Some(sha) = artifacts.geoip_sha256.as_deref() {
        let (dat, sidecar, norm) =
            custom_geodata_cache_pair(&cache_dir, "geoip", sha, "artifacts.geoip_sha256")?;
        has_valid_cached_file(&dat, &sidecar, Some(&norm))
    } else {
        zip_geoip_ok
    };
    let geosite_ok = if !need_geosite {
        true
    } else if !xray_env_set && let Some(sha) = artifacts.geosite_sha256.as_deref() {
        let (dat, sidecar, norm) =
            custom_geodata_cache_pair(&cache_dir, "geosite", sha, "artifacts.geosite_sha256")?;
        has_valid_cached_file(&dat, &sidecar, Some(&norm))
    } else {
        zip_geosite_ok
    };
    let geodata_cached = geoip_ok && geosite_ok;

    let (awg_cached, awg_path) = if let Some(p) = read_nonempty_env("KINVEIL_AMNEZIAWG_BIN") {
        let pb = PathBuf::from(p);
        (pb.is_file(), pb)
    } else if let Some(custom_sha) = artifacts.amneziawg_sha256.as_deref() {
        let (bin, sha, norm_sha) = custom_awg_cache_pair(&cache_dir, custom_sha)?;
        let ok = has_valid_cached_file(&bin, &sha, Some(&norm_sha));
        (ok, bin)
    } else {
        let (bin, sha) = default_awg_cache_pair(&cache_dir);
        let cached_ok = has_valid_cached_file(&bin, &sha, AWG_PREBUILT_SHA256);
        if cached_ok {
            (true, bin)
        } else if let Some(req) = AWG_PREBUILT_SHA256
            && let Some((bundled_path, _, _)) = read_bundled_if_valid(
                &bundled_dirs,
                &format!("amneziawg-go-{AWG_VERSION}-linux-amd64"),
                req,
                MAX_AWG_BINARY_BYTES,
                true,
                "bundled amneziawg-go",
            )
        {
            (true, bundled_path)
        } else {
            (false, bin)
        }
    };

    Ok(ArtifactStatus {
        xray_cached,
        xray_path,
        geodata_cached,
        awg_cached,
        awg_path,
    })
}

fn ensure_paired_override<'a>(
    url: Option<&'a str>,
    sha: Option<&'a str>,
    msg: &str,
) -> Result<Option<(&'a str, &'a str)>> {
    match (url, sha) {
        (Some(u), Some(s)) => Ok(Some((u, s))),
        (None, None) => Ok(None),
        _ => bail!("{msg}"),
    }
}

fn ensure_standalone_geodata(
    cache_dir: &Path,
    kind: &str,
    url: &str,
    raw_sha256: &str,
    sha_field: &str,
) -> Result<(Vec<u8>, String)> {
    let (dat_path, sidecar_path, expected_sha) =
        custom_geodata_cache_pair(cache_dir, kind, raw_sha256, sha_field)?;
    if let Some(hit) = read_cached_if_valid(&dat_path, &sidecar_path, Some(&expected_sha))? {
        return Ok(hit);
    }
    eprintln!("Downloading custom {kind}.dat from {url}...");
    let agent = download_agent();
    let mut resp = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to download {kind}.dat from {url}"))?;
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(MAX_GEODATA_BYTES)
        .read_to_vec()
        .with_context(|| format!("failed reading {kind}.dat body from {url}"))?;
    let actual_sha = sha256_hex(&bytes);
    if actual_sha != expected_sha {
        bail!("{kind}.dat SHA-256 mismatch: expected {expected_sha}, got {actual_sha}");
    }
    write_atomic_file(&dat_path, &bytes, 0o644, Some((&sidecar_path, &actual_sha)))?;
    Ok((bytes, actual_sha))
}

fn ensure_xray_artifacts(
    cache_dir: &Path,
    artifacts: &ArtifactSettings,
    need_xray: bool,
    need_geoip: bool,
    need_geosite: bool,
) -> Result<XrayArtifacts> {
    let custom_bin = read_nonempty_env("KINVEIL_XRAY_BIN");
    let zip_source = ensure_paired_override(
        artifacts.xray_zip_url.as_deref(),
        artifacts.xray_zip_sha256.as_deref(),
        "artifacts.xray_zip_url and artifacts.xray_zip_sha256 must both be set when overriding Xray-core",
    )?;
    let custom_geoip = ensure_paired_override(
        artifacts.geoip_url.as_deref(),
        artifacts.geoip_sha256.as_deref(),
        "artifacts.geoip_url and artifacts.geoip_sha256 must both be set when overriding geoip.dat",
    )?;
    let custom_geosite = ensure_paired_override(
        artifacts.geosite_url.as_deref(),
        artifacts.geosite_sha256.as_deref(),
        "artifacts.geosite_url and artifacts.geosite_sha256 must both be set when overriding geosite.dat",
    )?;
    let bundled_dirs = default_bundled_artifact_dirs();
    ensure_xray_artifacts_with_geodata(
        cache_dir,
        &bundled_dirs,
        custom_bin.as_deref(),
        zip_source,
        custom_geoip,
        custom_geosite,
        need_xray,
        need_geoip,
        need_geosite,
    )
}

fn extract_zip_entry(
    archive: &mut zip::ZipArchive<Cursor<Vec<u8>>>,
    name: &str,
    max_bytes: u64,
    required: bool,
) -> Result<Option<(Vec<u8>, String)>> {
    let entry = match archive.by_name(name) {
        Ok(e) => e,
        Err(_) if !required => return Ok(None),
        Err(e) => {
            return Err(anyhow!(
                "downloaded Xray-core zip does not contain '{name}': {e}"
            ));
        }
    };
    if entry.size() > max_bytes {
        bail!("downloaded '{name}' exceeds size limit");
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        bail!("downloaded '{name}' exceeds size limit");
    }
    let hex = sha256_hex(&bytes);
    Ok(Some((bytes, hex)))
}

fn read_adjacent_geodata(bin_path: &Path, filename: &str) -> Result<(Vec<u8>, String)> {
    let dir = bin_path
        .parent()
        .ok_or_else(|| anyhow!("cannot resolve parent directory of {}", bin_path.display()))?;
    let dat_path = dir.join(filename);
    let bytes = fs::read(&dat_path).with_context(|| {
        format!(
            "failed reading {filename} next to KINVEIL_XRAY_BIN at {}",
            dat_path.display()
        )
    })?;
    if bytes.len() as u64 > MAX_GEODATA_BYTES {
        bail!("{filename} at {} exceeds size limit", dat_path.display());
    }
    let hex = sha256_hex(&bytes);
    Ok((bytes, hex))
}

#[allow(clippy::too_many_arguments)]
pub fn ensure_xray_artifacts_with_geodata(
    cache_dir: &Path,
    bundled_dirs: &[PathBuf],
    custom_bin: Option<&str>,
    custom_zip_source: Option<(&str, &str)>,
    custom_geoip: Option<(&str, &str)>,
    custom_geosite: Option<(&str, &str)>,
    need_xray: bool,
    need_geoip: bool,
    need_geosite: bool,
) -> Result<XrayArtifacts> {
    if let Some(custom) = custom_bin {
        let (bin_bytes, bin_sha256) = if need_xray {
            read_local_elf_override("KINVEIL_XRAY_BIN", custom, "xray")?
        } else {
            (Vec::new(), String::new())
        };
        let p = Path::new(custom);
        let (geoip_bytes, geoip_sha256) = if need_geoip {
            read_adjacent_geodata(p, "geoip.dat")?
        } else {
            (Vec::new(), String::new())
        };
        let (geosite_bytes, geosite_sha256) = if need_geosite {
            read_adjacent_geodata(p, "geosite.dat")?
        } else {
            (Vec::new(), String::new())
        };
        return Ok(XrayArtifacts {
            bin_bytes,
            bin_sha256,
            geoip_bytes,
            geoip_sha256,
            geosite_bytes,
            geosite_sha256,
        });
    }

    let standalone_geoip = if need_geoip && let Some((url, sha)) = custom_geoip {
        Some(ensure_standalone_geodata(
            cache_dir,
            "geoip",
            url,
            sha,
            "artifacts.geoip_sha256",
        )?)
    } else {
        None
    };
    let standalone_geosite = if need_geosite && let Some((url, sha)) = custom_geosite {
        Some(ensure_standalone_geodata(
            cache_dir,
            "geosite",
            url,
            sha,
            "artifacts.geosite_sha256",
        )?)
    } else {
        None
    };

    let need_zip_geoip = need_geoip && standalone_geoip.is_none();
    let need_zip_geosite = need_geosite && standalone_geosite.is_none();
    if !need_xray && !need_zip_geoip && !need_zip_geosite {
        let (geoip_bytes, geoip_sha256) = standalone_geoip.unwrap_or_default();
        let (geosite_bytes, geosite_sha256) = standalone_geosite.unwrap_or_default();
        return Ok(XrayArtifacts {
            bin_bytes: Vec::new(),
            bin_sha256: String::new(),
            geoip_bytes,
            geoip_sha256,
            geosite_bytes,
            geosite_sha256,
        });
    }

    let (
        bin_path,
        bin_sidecar,
        (geoip_path, geoip_sidecar),
        (geosite_path, geosite_sidecar),
        url,
        expected_zip_sha,
        expected_bin_sha,
        expected_geoip_sha,
        expected_geosite_sha,
    ) = match custom_zip_source {
        Some((url, raw_zip_sha)) => {
            let (bin, sidecar, zip_sha) = custom_xray_cache_pair(cache_dir, raw_zip_sha)?;
            let (geoip_pair, geosite_pair) = custom_xray_geodata_cache_pairs(cache_dir, &zip_sha);
            (
                bin,
                sidecar,
                geoip_pair,
                geosite_pair,
                url,
                zip_sha,
                None,
                None,
                None,
            )
        }
        None => {
            let (bin, sidecar) = default_xray_cache_pair(cache_dir);
            let (geoip_pair, geosite_pair) = default_xray_geodata_cache_pairs(cache_dir);
            (
                bin,
                sidecar,
                geoip_pair,
                geosite_pair,
                XRAY_ZIP_URL,
                XRAY_ZIP_SHA256.to_owned(),
                Some(XRAY_BIN_SHA256),
                Some(XRAY_GEOIP_SHA256),
                Some(XRAY_GEOSITE_SHA256),
            )
        }
    };

    let bin_hit = if need_xray {
        match read_cached_if_valid(&bin_path, &bin_sidecar, expected_bin_sha)? {
            Some(hit) => Some(hit),
            None if custom_zip_source.is_none() => read_bundled_if_valid(
                bundled_dirs,
                &format!("xray-{XRAY_VERSION}-linux-amd64"),
                XRAY_BIN_SHA256,
                MAX_XRAY_BINARY_BYTES,
                true,
                "bundled xray",
            )
            .map(|(_, bytes, hex)| (bytes, hex)),
            None => None,
        }
    } else {
        None
    };

    let geoip_hit = if standalone_geoip.is_some() {
        standalone_geoip
    } else {
        match read_cached_if_valid(&geoip_path, &geoip_sidecar, expected_geoip_sha)? {
            Some(hit) => Some(hit),
            None if custom_zip_source.is_none() => read_bundled_if_valid(
                bundled_dirs,
                &format!("xray-{XRAY_VERSION}-geoip.dat"),
                XRAY_GEOIP_SHA256,
                MAX_GEODATA_BYTES,
                false,
                "bundled geoip.dat",
            )
            .map(|(_, bytes, hex)| (bytes, hex)),
            None => None,
        }
    };

    let geosite_hit = if standalone_geosite.is_some() {
        standalone_geosite
    } else {
        match read_cached_if_valid(&geosite_path, &geosite_sidecar, expected_geosite_sha)? {
            Some(hit) => Some(hit),
            None if custom_zip_source.is_none() => read_bundled_if_valid(
                bundled_dirs,
                &format!("xray-{XRAY_VERSION}-geosite.dat"),
                XRAY_GEOSITE_SHA256,
                MAX_GEODATA_BYTES,
                false,
                "bundled geosite.dat",
            )
            .map(|(_, bytes, hex)| (bytes, hex)),
            None => None,
        }
    };

    if (!need_xray || bin_hit.is_some())
        && (!need_geoip || geoip_hit.is_some())
        && (!need_geosite || geosite_hit.is_some())
    {
        let (bin_bytes, bin_sha256) = bin_hit.unwrap_or_default();
        let (geoip_bytes, geoip_sha256) = if need_geoip {
            geoip_hit.unwrap_or_default()
        } else {
            (Vec::new(), String::new())
        };
        let (geosite_bytes, geosite_sha256) = if need_geosite {
            geosite_hit.unwrap_or_default()
        } else {
            (Vec::new(), String::new())
        };
        return Ok(XrayArtifacts {
            bin_bytes,
            bin_sha256,
            geoip_bytes,
            geoip_sha256,
            geosite_bytes,
            geosite_sha256,
        });
    }

    if custom_zip_source.is_some() {
        eprintln!("Downloading custom Xray-core from {url}...");
    } else {
        eprintln!("Downloading Xray-core {XRAY_VERSION} from {url}...");
    }
    let agent = download_agent();
    let mut resp = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to download Xray-core from {url}"))?;
    let zip_bytes = resp
        .body_mut()
        .with_config()
        .limit(MAX_XRAY_ZIP_BYTES)
        .read_to_vec()
        .context("failed reading Xray-core release zip body")?;

    let actual_zip_sha = sha256_hex(&zip_bytes);
    if actual_zip_sha != expected_zip_sha {
        bail!("Xray-core zip SHA-256 mismatch: expected {expected_zip_sha}, got {actual_zip_sha}");
    }

    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .context("failed to open downloaded Xray-core zip")?;

    let (bin_bytes, bin_sha256) =
        extract_zip_entry(&mut archive, "xray", MAX_XRAY_BINARY_BYTES, true)?
            .expect("required xray binary");
    verify_linux_amd64_elf(&bin_bytes, "extracted xray")?;
    if let Some(req_bin_sha) = expected_bin_sha
        && bin_sha256 != req_bin_sha
    {
        bail!(
            "extracted Xray-core binary SHA-256 mismatch: expected {req_bin_sha}, got {bin_sha256}"
        );
    }

    let require_zip_geoip = custom_zip_source.is_none() || need_zip_geoip;
    let require_zip_geosite = custom_zip_source.is_none() || need_zip_geosite;
    let geoip_opt = extract_zip_entry(
        &mut archive,
        "geoip.dat",
        MAX_GEODATA_BYTES,
        require_zip_geoip,
    )?;
    let geosite_opt = extract_zip_entry(
        &mut archive,
        "geosite.dat",
        MAX_GEODATA_BYTES,
        require_zip_geosite,
    )?;

    if let (Some((_, hex)), Some(req)) = (&geoip_opt, expected_geoip_sha)
        && hex != req
    {
        bail!("extracted geoip.dat SHA-256 mismatch: expected {req}, got {hex}");
    }
    if let (Some((_, hex)), Some(req)) = (&geosite_opt, expected_geosite_sha)
        && hex != req
    {
        bail!("extracted geosite.dat SHA-256 mismatch: expected {req}, got {hex}");
    }

    write_atomic_file(
        &bin_path,
        &bin_bytes,
        0o755,
        Some((&bin_sidecar, &bin_sha256)),
    )?;
    if let Some((bytes, hex)) = &geoip_opt {
        write_atomic_file(&geoip_path, bytes, 0o644, Some((&geoip_sidecar, hex)))?;
    }
    if let Some((bytes, hex)) = &geosite_opt {
        write_atomic_file(&geosite_path, bytes, 0o644, Some((&geosite_sidecar, hex)))?;
    }

    let (geoip_bytes, geoip_sha256) = if need_geoip {
        geoip_hit.or(geoip_opt).unwrap_or_default()
    } else {
        (Vec::new(), String::new())
    };
    let (geosite_bytes, geosite_sha256) = if need_geosite {
        geosite_hit.or(geosite_opt).unwrap_or_default()
    } else {
        (Vec::new(), String::new())
    };
    let (out_bin_bytes, out_bin_sha256) = if need_xray {
        (bin_bytes, bin_sha256)
    } else {
        (Vec::new(), String::new())
    };
    Ok(XrayArtifacts {
        bin_bytes: out_bin_bytes,
        bin_sha256: out_bin_sha256,
        geoip_bytes,
        geoip_sha256,
        geosite_bytes,
        geosite_sha256,
    })
}

fn fetch_awg_url_bytes(url: &str) -> Result<Vec<u8>> {
    let agent = download_agent();
    let mut resp = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to download amneziawg-go from {url}"))?;
    resp.body_mut()
        .with_config()
        .limit(MAX_AWG_BINARY_BYTES)
        .read_to_vec()
        .with_context(|| format!("failed reading amneziawg-go body from {url}"))
}

fn verify_awg_binary_bytes(bytes: &[u8], expected_sha256: &str) -> Result<String> {
    let expected = normalize_sha256_hex(expected_sha256, "amneziawg-go")?;
    let actual_sha = sha256_hex(bytes);
    if actual_sha != expected {
        bail!("amneziawg-go binary SHA-256 mismatch: expected {expected}, got {actual_sha}");
    }
    verify_linux_amd64_elf(bytes, "downloaded amneziawg-go")?;
    Ok(actual_sha)
}

pub struct PrebuiltAwgSource {
    pub url: String,
    pub sha256: String,
    pub custom_cache: bool,
    pub allow_fallback_to_go_build: bool,
}

pub fn has_prebuilt_awg_source(artifacts: &ArtifactSettings) -> bool {
    read_nonempty_env("KINVEIL_AMNEZIAWG_BIN").is_some()
        || artifacts.amneziawg_url.is_some()
        || AWG_PREBUILT_URL.is_some()
}

fn ensure_awg_bytes(cache_dir: &Path, artifacts: &ArtifactSettings) -> Result<(Vec<u8>, String)> {
    let custom_bin = read_nonempty_env("KINVEIL_AMNEZIAWG_BIN");
    let prebuilt = match (
        artifacts.amneziawg_url.as_deref(),
        artifacts.amneziawg_sha256.as_deref(),
    ) {
        (Some(url), Some(sha)) => Some(PrebuiltAwgSource {
            url: url.to_owned(),
            sha256: sha.to_owned(),
            custom_cache: true,
            allow_fallback_to_go_build: false,
        }),
        (None, None) => {
            AWG_PREBUILT_URL
                .zip(AWG_PREBUILT_SHA256)
                .map(|(url, sha)| PrebuiltAwgSource {
                    url: url.to_owned(),
                    sha256: sha.to_owned(),
                    custom_cache: false,
                    allow_fallback_to_go_build: true,
                })
        }
        _ => bail!(
            "artifacts.amneziawg_url and artifacts.amneziawg_sha256 must both be set when overriding amneziawg-go"
        ),
    };
    let bundled_dirs = default_bundled_artifact_dirs();
    ensure_awg_bytes_inner(cache_dir, &bundled_dirs, custom_bin.as_deref(), prebuilt)
}

pub fn ensure_awg_bytes_inner(
    cache_dir: &Path,
    bundled_dirs: &[PathBuf],
    custom_bin: Option<&str>,
    prebuilt: Option<PrebuiltAwgSource>,
) -> Result<(Vec<u8>, String)> {
    if let Some(custom) = custom_bin {
        return read_local_elf_override("KINVEIL_AMNEZIAWG_BIN", custom, "amneziawg-go");
    }

    let (bin_path, sidecar_path, required_sha) = match prebuilt.as_ref() {
        Some(src) if src.custom_cache => {
            let (bin, sidecar, norm) = custom_awg_cache_pair(cache_dir, &src.sha256)?;
            (bin, sidecar, Some(norm))
        }
        Some(src) => {
            let (bin, sidecar) = default_awg_cache_pair(cache_dir);
            let norm = normalize_sha256_hex(&src.sha256, "amneziawg-go")?;
            (bin, sidecar, Some(norm))
        }
        None => {
            let (bin, sidecar) = default_awg_cache_pair(cache_dir);
            (bin, sidecar, None)
        }
    };

    if let Some(hit) = read_cached_if_valid(&bin_path, &sidecar_path, required_sha.as_deref())? {
        return Ok(hit);
    }
    if prebuilt.as_ref().is_some_and(|s| !s.custom_cache)
        && let Some(req) = required_sha.as_deref()
        && let Some((_, bytes, hex)) = read_bundled_if_valid(
            bundled_dirs,
            &format!("amneziawg-go-{AWG_VERSION}-linux-amd64"),
            req,
            MAX_AWG_BINARY_BYTES,
            true,
            "bundled amneziawg-go",
        )
    {
        return Ok((bytes, hex));
    }
    if let Some(src) = prebuilt {
        if src.custom_cache {
            eprintln!("Downloading custom amneziawg-go from {}...", src.url);
        } else {
            eprintln!("Downloading amneziawg-go {AWG_VERSION} from {}...", src.url);
        }
        match fetch_awg_url_bytes(&src.url) {
            Ok(awg_bytes) => {
                // Integrity/format failures abort unconditionally instead of falling back to Go build.
                let hex = verify_awg_binary_bytes(&awg_bytes, &src.sha256)?;
                write_atomic_file(&bin_path, &awg_bytes, 0o755, Some((&sidecar_path, &hex)))?;
                return Ok((awg_bytes, hex));
            }
            Err(err) if src.allow_fallback_to_go_build => {
                eprintln!(
                    "Warning: failed downloading prebuilt amneziawg-go ({err:#}); falling back to local go build"
                );
            }
            Err(err) => return Err(err),
        }
    }

    let go_ok = Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let git_ok = Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !go_ok || !git_ok {
        bail!(
            "local Go toolchain ('go') and 'git' are required to compile amneziawg-go {AWG_VERSION} for linux/amd64 when no prebuilt artifact is configured; set KINVEIL_AMNEZIAWG_BIN or configure [artifacts] in `kinveil config`"
        );
    }

    ensure_private_dir(cache_dir)?;
    let build_dir = tempfile::Builder::new()
        .prefix(".build-awg-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(cache_dir)?;
    let build_root = build_dir.path();

    let src_dir = build_root.join("src");
    eprintln!("Cloning amneziawg-go {AWG_VERSION} from {AWG_REPO_URL}...");
    let clone = Command::new("git")
        .env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("GIT_SSH_COMMAND")
        .env_remove("GIT_EXTERNAL_DIFF")
        .args([
            "clone",
            "--depth",
            "1",
            "--branch",
            AWG_VERSION,
            AWG_REPO_URL,
        ])
        .arg(&src_dir)
        .output()?;
    if !clone.status.success() {
        bail!(
            "git clone of amneziawg-go {AWG_VERSION} failed: {}",
            String::from_utf8_lossy(&clone.stderr)
        );
    }

    let rev = Command::new("git")
        .env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .current_dir(&src_dir)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !rev.status.success() {
        bail!("failed verifying checked out amneziawg-go commit");
    }
    let actual_commit = String::from_utf8_lossy(&rev.stdout).trim().to_owned();
    if actual_commit != AWG_COMMIT_SHA1 {
        bail!(
            "amneziawg-go commit mismatch for {AWG_VERSION}: expected {AWG_COMMIT_SHA1}, got {actual_commit}"
        );
    }

    let out_bin = build_root.join("amneziawg-go");
    eprintln!("Building static linux/amd64 amneziawg-go binary locally...");
    let build = Command::new("go")
        .env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .current_dir(&src_dir)
        .env("CGO_ENABLED", "0")
        .env("GOOS", "linux")
        .env("GOARCH", "amd64")
        .args([
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-s -w -buildid=",
            "-o",
        ])
        .arg(&out_bin)
        .arg(".")
        .output()?;
    if !build.status.success() {
        bail!(
            "go build of amneziawg-go failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
    }

    let awg_bytes = fs::read(&out_bin)?;
    verify_linux_amd64_elf(&awg_bytes, "built amneziawg-go")?;
    let hex = sha256_hex(&awg_bytes);
    let (def_bin, def_sidecar) = default_awg_cache_pair(cache_dir);
    write_atomic_file(&def_bin, &awg_bytes, 0o755, Some((&def_sidecar, &hex)))?;
    Ok((awg_bytes, hex))
}

pub fn prepare_artifacts(
    need_xray: bool,
    need_xray_geodata: bool,
    need_country_geoip: bool,
    need_awg: bool,
    artifacts: &ArtifactSettings,
) -> Result<RuntimeArtifacts> {
    let cache_dir = artifacts_cache_dir()?;
    let need_geoip = need_xray_geodata || need_country_geoip;
    let need_geosite = need_xray_geodata;
    let xray = if need_xray || need_geoip {
        ensure_xray_artifacts(&cache_dir, artifacts, need_xray, need_geoip, need_geosite)?
    } else {
        XrayArtifacts {
            bin_bytes: Vec::new(),
            bin_sha256: String::new(),
            geoip_bytes: Vec::new(),
            geoip_sha256: String::new(),
            geosite_bytes: Vec::new(),
            geosite_sha256: String::new(),
        }
    };
    let (awg_bytes, awg_sha256) = if need_awg {
        ensure_awg_bytes(&cache_dir, artifacts)?
    } else {
        (Vec::new(), String::new())
    };
    Ok(RuntimeArtifacts {
        xray_bytes: xray.bin_bytes,
        xray_sha256: xray.bin_sha256,
        geoip_bytes: xray.geoip_bytes,
        geoip_sha256: xray.geoip_sha256,
        geosite_bytes: xray.geosite_bytes,
        geosite_sha256: xray.geosite_sha256,
        awg_bytes,
        awg_sha256,
    })
}
