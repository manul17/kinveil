use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::crypto::sha256_hex;
use crate::state::ArtifactSettings;

pub const XRAY_VERSION: &str = "v26.11.9";
pub const XRAY_ZIP_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip";
pub const XRAY_ZIP_SHA256: &str =
    "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82";
pub const XRAY_BIN_SHA256: &str =
    "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d";

pub const AWG_VERSION: &str = "v3.1.20260828";
pub const AWG_REPO_URL: &str = "https://github.com/amnezia-vpn/amneziawg-go.git";
pub const AWG_COMMIT_SHA1: &str = "b5928efb6ca19f0153958460c3d141f04abc5c2e";
pub const AWG_RELEASE_TAG: &str = "v0.1.0";
pub const AWG_PREBUILT_URL: Option<&str> = Some(
    "https://github.com/manul17/kinveil/releases/download/v0.1.0/amneziawg-go-v3.1.20260828-linux-amd64",
);
pub const AWG_PREBUILT_SHA256: Option<&str> =
    Some("fa81c45e5a54ea73b09aad93cc2dc69b2f51f673fc62f9cf2b7482fa9472ad66");
const MAX_XRAY_ZIP_BYTES: u64 = 128 * 1024 * 1024;
const MAX_XRAY_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_AWG_BINARY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ArtifactStatus {
    pub xray_cached: bool,
    pub xray_path: PathBuf,
    pub awg_cached: bool,
    pub awg_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RuntimeArtifacts {
    pub xray_bytes: Vec<u8>,
    pub xray_sha256: String,
    pub awg_bytes: Vec<u8>,
    pub awg_sha256: String,
}

fn download_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into()
}

pub fn artifacts_cache_dir() -> Result<PathBuf> {
    if let Some(override_dir) = read_nonempty_env("KINVEIL_CACHE_DIR") {
        return Ok(PathBuf::from(override_dir));
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
        fs::create_dir_all(dir)?;
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

fn write_atomic_executable(
    dest: &Path,
    bytes: &[u8],
    sha256_file: Option<(&Path, &str)>,
) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("missing parent directory for {}", dest.display()))?;
    ensure_private_dir(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp.")
        .permissions(fs::Permissions::from_mode(0o755))
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

fn default_xray_cache_pair(cache_dir: &Path) -> (PathBuf, PathBuf) {
    (
        cache_dir.join(format!("xray-{XRAY_VERSION}-linux-amd64")),
        cache_dir.join(format!("xray-{XRAY_VERSION}-linux-amd64.sha256")),
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

fn default_awg_cache_pair(cache_dir: &Path) -> (PathBuf, PathBuf) {
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
        if bytes.len() as u64 > max_bytes || verify_linux_amd64_elf(&bytes, label).is_err() {
            continue;
        }
        let actual = sha256_hex(&bytes);
        if actual.eq_ignore_ascii_case(expected_sha256) {
            return Some((path, bytes, actual));
        }
    }
    None
}

pub fn inspect_artifact_status(artifacts: &ArtifactSettings) -> Result<ArtifactStatus> {
    let cache_dir = artifacts_cache_dir()?;
    let bundled_dirs = default_bundled_artifact_dirs();

    let (xray_cached, xray_path) = if let Some(p) = read_nonempty_env("KINVEIL_XRAY_BIN") {
        let pb = PathBuf::from(p);
        (pb.is_file(), pb)
    } else if let Some(zip_sha) = artifacts.xray_zip_sha256.as_deref() {
        let (bin, sha, _) = custom_xray_cache_pair(&cache_dir, zip_sha)?;
        (bin.is_file() && sha.is_file(), bin)
    } else {
        let (bin, sha) = default_xray_cache_pair(&cache_dir);
        if bin.is_file()
            && fs::read_to_string(&sha)
                .ok()
                .is_some_and(|s| s.trim().eq_ignore_ascii_case(XRAY_BIN_SHA256))
        {
            (true, bin)
        } else if let Some((bundled_path, _, _)) = read_bundled_if_valid(
            &bundled_dirs,
            &format!("xray-{XRAY_VERSION}-linux-amd64"),
            XRAY_BIN_SHA256,
            MAX_XRAY_BINARY_BYTES,
            "bundled xray",
        ) {
            (true, bundled_path)
        } else {
            (false, bin)
        }
    };

    let (awg_cached, awg_path) = if let Some(p) = read_nonempty_env("KINVEIL_AMNEZIAWG_BIN") {
        let pb = PathBuf::from(p);
        (pb.is_file(), pb)
    } else if let Some(custom_sha) = artifacts.amneziawg_sha256.as_deref() {
        let (bin, sha, norm_sha) = custom_awg_cache_pair(&cache_dir, custom_sha)?;
        let ok = bin.is_file()
            && fs::read_to_string(&sha)
                .ok()
                .is_some_and(|s| s.trim().eq_ignore_ascii_case(&norm_sha));
        (ok, bin)
    } else {
        let (bin, sha) = default_awg_cache_pair(&cache_dir);
        let cached_ok = bin.is_file()
            && if let Some(req) = AWG_PREBUILT_SHA256 {
                fs::read_to_string(&sha)
                    .ok()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case(req))
            } else {
                sha.is_file()
            };
        if cached_ok {
            (true, bin)
        } else if let Some(req) = AWG_PREBUILT_SHA256
            && let Some((bundled_path, _, _)) = read_bundled_if_valid(
                &bundled_dirs,
                &format!("amneziawg-go-{AWG_VERSION}-linux-amd64"),
                req,
                MAX_AWG_BINARY_BYTES,
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
        awg_cached,
        awg_path,
    })
}

fn ensure_xray_bytes(cache_dir: &Path, artifacts: &ArtifactSettings) -> Result<(Vec<u8>, String)> {
    let custom_bin = read_nonempty_env("KINVEIL_XRAY_BIN");
    let zip_source = match (
        artifacts.xray_zip_url.as_deref(),
        artifacts.xray_zip_sha256.as_deref(),
    ) {
        (Some(url), Some(sha)) => Some((url, sha)),
        (None, None) => None,
        _ => bail!(
            "artifacts.xray_zip_url and artifacts.xray_zip_sha256 must both be set when overriding Xray-core"
        ),
    };
    let bundled_dirs = default_bundled_artifact_dirs();
    ensure_xray_bytes_inner(cache_dir, &bundled_dirs, custom_bin.as_deref(), zip_source)
}

#[cfg(test)]
fn ensure_xray_bytes_with_source(
    cache_dir: &Path,
    custom_bin: Option<&str>,
    custom_zip_source: Option<(&str, &str)>,
) -> Result<(Vec<u8>, String)> {
    ensure_xray_bytes_inner(cache_dir, &[], custom_bin, custom_zip_source)
}

fn ensure_xray_bytes_inner(
    cache_dir: &Path,
    bundled_dirs: &[PathBuf],
    custom_bin: Option<&str>,
    custom_zip_source: Option<(&str, &str)>,
) -> Result<(Vec<u8>, String)> {
    if let Some(custom) = custom_bin {
        return read_local_elf_override("KINVEIL_XRAY_BIN", custom, "xray");
    }

    let (bin_path, sidecar_path, url, expected_zip_sha, expected_bin_sha) = match custom_zip_source
    {
        Some((url, raw_zip_sha)) => {
            let (bin, sidecar, zip_sha) = custom_xray_cache_pair(cache_dir, raw_zip_sha)?;
            (bin, sidecar, url, zip_sha, None)
        }
        None => {
            let (bin, sidecar) = default_xray_cache_pair(cache_dir);
            (
                bin,
                sidecar,
                XRAY_ZIP_URL,
                XRAY_ZIP_SHA256.to_owned(),
                Some(XRAY_BIN_SHA256),
            )
        }
    };

    if let Some((bytes, hex)) = read_cached_if_valid(&bin_path, &sidecar_path, expected_bin_sha)? {
        return Ok((bytes, hex));
    }
    if custom_zip_source.is_none()
        && let Some((_, bytes, hex)) = read_bundled_if_valid(
            bundled_dirs,
            &format!("xray-{XRAY_VERSION}-linux-amd64"),
            XRAY_BIN_SHA256,
            MAX_XRAY_BINARY_BYTES,
            "bundled xray",
        )
    {
        return Ok((bytes, hex));
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
    let entry = archive
        .by_name("xray")
        .context("downloaded Xray-core zip does not contain 'xray' binary")?;
    if entry.size() > MAX_XRAY_BINARY_BYTES {
        bail!("downloaded Xray-core binary exceeds size limit");
    }
    let mut xray_bytes = Vec::with_capacity(entry.size() as usize);
    entry
        .take(MAX_XRAY_BINARY_BYTES + 1)
        .read_to_end(&mut xray_bytes)?;
    if xray_bytes.len() as u64 > MAX_XRAY_BINARY_BYTES {
        bail!("downloaded Xray-core binary exceeds size limit");
    }
    verify_linux_amd64_elf(&xray_bytes, "extracted xray")?;
    let hex = sha256_hex(&xray_bytes);
    if let Some(req_bin_sha) = expected_bin_sha
        && hex != req_bin_sha
    {
        bail!("extracted Xray-core binary SHA-256 mismatch: expected {req_bin_sha}, got {hex}");
    }
    write_atomic_executable(&bin_path, &xray_bytes, Some((&sidecar_path, &hex)))?;
    Ok((xray_bytes, hex))
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

struct PrebuiltAwgSource {
    url: String,
    sha256: String,
    custom_cache: bool,
    allow_fallback_to_go_build: bool,
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

#[cfg(test)]
fn ensure_awg_bytes_with_source(
    cache_dir: &Path,
    custom_bin: Option<&str>,
    prebuilt: Option<PrebuiltAwgSource>,
) -> Result<(Vec<u8>, String)> {
    ensure_awg_bytes_inner(cache_dir, &[], custom_bin, prebuilt)
}

fn ensure_awg_bytes_inner(
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
                write_atomic_executable(&bin_path, &awg_bytes, Some((&sidecar_path, &hex)))?;
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
    write_atomic_executable(&def_bin, &awg_bytes, Some((&def_sidecar, &hex)))?;
    Ok((awg_bytes, hex))
}

pub fn prepare_artifacts(
    need_xray: bool,
    need_awg: bool,
    artifacts: &ArtifactSettings,
) -> Result<RuntimeArtifacts> {
    let cache_dir = artifacts_cache_dir()?;
    let (xray_bytes, xray_sha256) = if need_xray {
        ensure_xray_bytes(&cache_dir, artifacts)?
    } else {
        (Vec::new(), String::new())
    };
    let (awg_bytes, awg_sha256) = if need_awg {
        ensure_awg_bytes(&cache_dir, artifacts)?
    } else {
        (Vec::new(), String::new())
    };
    Ok(RuntimeArtifacts {
        xray_bytes,
        xray_sha256,
        awg_bytes,
        awg_sha256,
    })
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn spawn_mock_http_server(
        path: &'static str,
        body: Vec<u8>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mock server");
        let addr = listener.local_addr().expect("mock local_addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept http request");
            let mut req_buf = [0u8; 1024];
            let _ = stream.read(&mut req_buf);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).expect("write header");
            stream.write_all(&body).expect("write body");
            stream.flush().expect("flush response");
        });
        (format!("http://{addr}{path}"), handle)
    }

    fn build_mock_zip(filename: &str, payload: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            zw.start_file(filename, zip::write::SimpleFileOptions::default())
                .expect("start zip entry");
            zw.write_all(payload).expect("write zip entry");
            zw.finish().expect("finish zip");
        }
        cursor.into_inner()
    }

    #[test]
    fn custom_awg_caches_isolated_from_default_and_checks_sha256() {
        let elf_payload =
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00fake-awg-binary"
                .to_vec();
        let expected_sha = sha256_hex(&elf_payload);
        let (url, handle) = spawn_mock_http_server("/amneziawg-go", elf_payload.clone());
        let cache = tempfile::Builder::new()
            .prefix("awg-cache-ok-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("create cache tempdir");

        let (got_bytes, got_sha) = ensure_awg_bytes_with_source(
            cache.path(),
            None,
            Some(PrebuiltAwgSource {
                url,
                sha256: expected_sha.clone(),
                custom_cache: true,
                allow_fallback_to_go_build: false,
            }),
        )
        .expect("verified custom download succeeds");
        handle.join().expect("join server");
        assert_eq!(got_bytes, elf_payload);
        assert_eq!(got_sha, expected_sha);

        // Matching custom SHA hits disk cache without any network request.
        let (cached_bytes, cached_sha) = ensure_awg_bytes_with_source(
            cache.path(),
            None,
            Some(PrebuiltAwgSource {
                url: "http://127.0.0.1:9/unreachable".to_owned(),
                sha256: expected_sha.clone(),
                custom_cache: true,
                allow_fallback_to_go_build: false,
            }),
        )
        .expect("custom cache hit succeeds offline");
        assert_eq!(cached_bytes, elf_payload);
        assert_eq!(cached_sha, expected_sha);

        // Switching to a different SHA does not reuse the custom cache entry,
        // and the default AWG cache path remains unpopulated (isolated).
        let (default_bin, _) = default_awg_cache_pair(cache.path());
        assert!(!default_bin.exists());

        let err = ensure_awg_bytes_with_source(
            cache.path(),
            None,
            Some(PrebuiltAwgSource {
                url: "http://127.0.0.1:9/unreachable".to_owned(),
                sha256: "f".repeat(64),
                custom_cache: true,
                allow_fallback_to_go_build: false,
            }),
        )
        .expect_err("different SHA must miss cache and fail on unreachable URL");
        assert!(err.to_string().contains("failed to download"), "{err}");
    }

    #[test]
    fn custom_xray_zip_verifies_sha256_extracts_elf_and_caches_isolated() {
        let elf_payload =
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00fake-xray-bin"
                .to_vec();
        let zip_bytes = build_mock_zip("xray", &elf_payload);
        let zip_sha = sha256_hex(&zip_bytes);
        let expected_bin_sha = sha256_hex(&elf_payload);
        let (url, handle) = spawn_mock_http_server("/Xray-linux-64.zip", zip_bytes);
        let cache = tempfile::Builder::new()
            .prefix("xray-cache-ok-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("create cache tempdir");

        let (got_bytes, got_sha) =
            ensure_xray_bytes_with_source(cache.path(), None, Some((&url, &zip_sha)))
                .expect("custom xray zip succeeds");
        handle.join().expect("join server");
        assert_eq!(got_bytes, elf_payload);
        assert_eq!(got_sha, expected_bin_sha);

        let (default_bin, _) = default_xray_cache_pair(cache.path());
        assert!(!default_bin.exists());

        let (cached_bytes, cached_sha) = ensure_xray_bytes_with_source(
            cache.path(),
            None,
            Some(("http://127.0.0.1:9/unreachable", &zip_sha)),
        )
        .expect("custom xray hits disk cache without network");
        assert_eq!(cached_bytes, elf_payload);
        assert_eq!(cached_sha, expected_bin_sha);

        let err = ensure_xray_bytes_with_source(
            cache.path(),
            None,
            Some(("http://127.0.0.1:9/unreachable", &"a".repeat(64))),
        )
        .expect_err("different custom zip SHA must not hit previous custom cache");
        assert!(err.to_string().contains("failed to download"), "{err}");
    }

    #[test]
    fn download_verified_awg_rejects_sha256_mismatch() {
        let elf_payload =
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00fake-awg-binary"
                .to_vec();
        let wrong_sha = "0".repeat(64);
        let (url, handle) = spawn_mock_http_server("/amneziawg-go", elf_payload);
        let cache = tempfile::Builder::new()
            .prefix("awg-cache-badsha-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("create cache tempdir");

        let err = ensure_awg_bytes_with_source(
            cache.path(),
            None,
            Some(PrebuiltAwgSource {
                url,
                sha256: wrong_sha,
                custom_cache: true,
                allow_fallback_to_go_build: false,
            }),
        )
        .expect_err("wrong sha256 must fail");
        handle.join().expect("join server");

        assert!(err.to_string().contains("SHA-256 mismatch"), "{err}");
    }

    #[test]
    fn download_verified_awg_rejects_non_elf_even_with_matching_sha256() {
        let html_payload = b"<html>not an elf binary</html>".to_vec();
        let matching_sha = sha256_hex(&html_payload);
        let (url, handle) = spawn_mock_http_server("/amneziawg-go", html_payload);
        let cache = tempfile::Builder::new()
            .prefix("awg-cache-badelf-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("create cache tempdir");

        let err = ensure_awg_bytes_with_source(
            cache.path(),
            None,
            Some(PrebuiltAwgSource {
                url,
                sha256: matching_sha,
                custom_cache: false,
                allow_fallback_to_go_build: true,
            }),
        )
        .expect_err("non-ELF bytes must fail even with matching sha256");
        handle.join().expect("join server");

        assert!(err.to_string().contains("not a valid ELF"), "{err}");
    }

    #[test]
    fn custom_binary_rejects_wrong_arch_elf_and_non_elf() {
        let cache = tempfile::Builder::new()
            .prefix("awg-arch-test-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("create cache tempdir");

        // aarch64 ELF (e_machine = 0x00b7)
        let arm64_path = cache.path().join("awg-arm64");
        fs::write(
            &arm64_path,
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00arm64",
        )
        .unwrap();
        let arm_err =
            ensure_awg_bytes_with_source(cache.path(), Some(arm64_path.to_str().unwrap()), None)
                .expect_err("aarch64 ELF must fail");
        assert!(arm_err.to_string().contains("x86_64"), "{arm_err}");

        // macOS Mach-O magic
        let macho_path = cache.path().join("awg-macos");
        fs::write(&macho_path, b"\xcf\xfa\xed\xfe\x00\x00").unwrap();
        let mac_err =
            ensure_awg_bytes_with_source(cache.path(), Some(macho_path.to_str().unwrap()), None)
                .expect_err("Mach-O must fail");
        assert!(mac_err.to_string().contains("not a valid ELF"), "{mac_err}");
    }

    #[test]
    fn bundled_artifacts_hit_offline_and_ignore_tampered_files() {
        let root = tempfile::Builder::new()
            .prefix("awg-bundled-test-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("create bundled tempdir");
        let cache_dir = root.path().join("cache");
        let bad_dir = root.path().join("bad");
        let good_dir = root.path().join("good");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::create_dir_all(&bad_dir).unwrap();
        fs::create_dir_all(&good_dir).unwrap();

        let elf_payload =
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00bundled-awg-bin"
                .to_vec();
        let valid_sha = sha256_hex(&elf_payload);
        let awg_filename = format!("amneziawg-go-{AWG_VERSION}-linux-amd64");

        fs::write(bad_dir.join(&awg_filename), b"tampered-not-an-elf").unwrap();
        fs::write(good_dir.join(&awg_filename), &elf_payload).unwrap();

        let err = ensure_awg_bytes_inner(
            &cache_dir,
            std::slice::from_ref(&bad_dir),
            None,
            Some(PrebuiltAwgSource {
                url: "http://127.0.0.1:9/unreachable".to_owned(),
                sha256: valid_sha.clone(),
                custom_cache: false,
                allow_fallback_to_go_build: false,
            }),
        )
        .expect_err("tampered bundled artifact must be ignored");
        assert!(err.to_string().contains("failed to download"), "{err}");

        let (got_bytes, got_sha) = ensure_awg_bytes_inner(
            &cache_dir,
            &[bad_dir, good_dir],
            None,
            Some(PrebuiltAwgSource {
                url: "http://127.0.0.1:9/unreachable".to_owned(),
                sha256: valid_sha.clone(),
                custom_cache: false,
                allow_fallback_to_go_build: false,
            }),
        )
        .expect("valid bundled artifact should succeed offline");
        assert_eq!(got_bytes, elf_payload);
        assert_eq!(got_sha, valid_sha);
    }
}
