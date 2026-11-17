//! Encrypted vault I/O (`KVEL\x01` Argon2id + AES-256-GCM envelope) and file locking.
//!
//! ## Storage Invariants
//! - **Envelope (`KVEL\x01`):** 45-byte binary header (`magic[4]="KVEL"`, `format=1`,
//!   Argon2id `m_kib`/`t_cost`/`p_cost` LE `u32`s, 16-byte salt, 12-byte nonce) is bound
//!   as AES-256-GCM AAD so header tampering fails authentication.
//! - **Schema check:** [`decode_state`] pre-probes `schema_version == 1` before full
//!   deserialization; both outer `state.enc` JSON structs and embedded `config.toml` reject
//!   unknown keys strictly (`#[serde(deny_unknown_fields)]`).
//! - **Filesystem safety:** State files require `0700` non-symlink parent dirs, `0600`
//!   non-symlink files, advisory `.state.enc.lock`, atomic temp-file writes with `fsync`,
//!   and 20 retained rolling backups under `backups/`.

use crate::state::{SCHEMA_VERSION, State};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng as _;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::Builder as TempFileBuilder;
use zeroize::Zeroizing;

/// Envelope magic header for `kinveil` vaults.
pub const MAGIC: &[u8; 4] = b"KVEL";
const FORMAT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 45;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

const DEFAULT_ARGON2_M_KIB: u32 = 131_072;
const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_P_COST: u32 = 1;

const MIN_ARGON2_M_KIB: u32 = 8_192;
const MAX_ARGON2_M_KIB: u32 = 1_048_576;
const MIN_ARGON2_T_COST: u32 = 1;
const MAX_ARGON2_T_COST: u32 = 32;
const MIN_ARGON2_P_COST: u32 = 1;
const MAX_ARGON2_P_COST: u32 = 16;

const DEFAULT_STATE_FILENAME: &str = "state.enc";

/// Exclusive advisory file lock held for the lifetime of the guard.
pub struct StateLock {
    file: File,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Returns the default encrypted vault path (`$XDG_DATA_HOME/kinveil/state.enc` or
/// `~/.local/share/kinveil/state.enc`).
pub fn default_state_path() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg)
            .join("kinveil")
            .join(DEFAULT_STATE_FILENAME));
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("cannot determine default state path: HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("kinveil")
        .join(DEFAULT_STATE_FILENAME))
}

/// Ensures `dir` exists as a private (`0o700`, non-symlink) directory.
pub fn verify_private_dir(dir: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(dir)
        .with_context(|| format!("inspecting directory {}", dir.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "refusing to use symlinked state directory {}",
            dir.display()
        );
    }
    if !meta.is_dir() {
        bail!("state parent path {} is not a directory", dir.display());
    }
    let mode = meta.permissions().mode() & 0o777;
    if (mode & 0o077) != 0 {
        bail!(
            "state directory {} has overly permissive mode {mode:04o}; expected 0700 (no group/other access)",
            dir.display()
        );
    }
    Ok(())
}

fn effective_parent(path: &Path) -> Result<&Path> {
    match path.parent() {
        Some(p) if p.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(p) => Ok(p),
        None => bail!("state path {} has no parent directory", path.display()),
    }
}

fn ensure_private_parent(path: &Path) -> Result<&Path> {
    let parent = effective_parent(path)?;
    if fs::symlink_metadata(parent).is_err() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(parent)
            .with_context(|| format!("creating state directory {}", parent.display()))?;
    }
    verify_private_dir(parent)?;
    Ok(parent)
}

/// Ensures `path` (if it exists) is a regular, non-symlink `0600` file.
pub fn verify_private_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting state file {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to use symlinked state file {}", path.display());
    }
    if !meta.is_file() {
        bail!("state path {} is not a regular file", path.display());
    }
    let mode = meta.permissions().mode() & 0o777;
    if (mode & 0o077) != 0 {
        bail!(
            "state file {} has overly permissive mode {mode:04o}; expected 0600 (no group/other access)",
            path.display()
        );
    }
    Ok(())
}

/// Acquires an exclusive advisory lock alongside `state_path` (`.state.enc.lock`).
pub fn acquire_state_lock(state_path: &Path) -> Result<StateLock> {
    let parent = ensure_private_parent(state_path)?;
    let file_name = state_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("invalid state filename in {}", state_path.display()))?;
    let lock_path = parent.join(format!(".{file_name}.lock"));

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .with_context(|| format!("opening lock file {}", lock_path.display()))?;

    match file.try_lock() {
        Ok(()) => Ok(StateLock { file }),
        Err(TryLockError::WouldBlock) => {
            bail!(
                "another kinveil process holds the state lock at {}",
                lock_path.display()
            )
        }
        Err(TryLockError::Error(err)) => {
            Err(anyhow!("acquiring lock on {}: {err}", lock_path.display()))
        }
    }
}

/// Deserializes raw UTF-8 JSON bytes into [`State`] and verifies `schema_version`.
pub fn decode_state(plaintext: &[u8]) -> Result<State> {
    #[derive(serde::Deserialize)]
    struct SchemaProbe {
        schema_version: u32,
    }

    let probe: SchemaProbe =
        serde_json::from_slice(plaintext).context("parsing decrypted state JSON")?;
    if probe.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported state schema_version {}; this kinveil binary supports schema_version {SCHEMA_VERSION}",
            probe.schema_version
        );
    }
    serde_json::from_slice(plaintext).context("parsing decrypted state JSON")
}

fn validate_argon2_params(m_kib: u32, t_cost: u32, p_cost: u32) -> Result<Params> {
    if !(MIN_ARGON2_M_KIB..=MAX_ARGON2_M_KIB).contains(&m_kib) {
        bail!(
            "Argon2 m_kib {m_kib} out of supported range {MIN_ARGON2_M_KIB}..={MAX_ARGON2_M_KIB}"
        );
    }
    if !(MIN_ARGON2_T_COST..=MAX_ARGON2_T_COST).contains(&t_cost) {
        bail!(
            "Argon2 t_cost {t_cost} out of supported range {MIN_ARGON2_T_COST}..={MAX_ARGON2_T_COST}"
        );
    }
    if !(MIN_ARGON2_P_COST..=MAX_ARGON2_P_COST).contains(&p_cost) {
        bail!(
            "Argon2 p_cost {p_cost} out of supported range {MIN_ARGON2_P_COST}..={MAX_ARGON2_P_COST}"
        );
    }
    Params::new(m_kib, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    let params = validate_argon2_params(m_kib, t_cost, p_cost)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypts arbitrary plaintext bytes into an authenticated `KVEL\x01` envelope using custom
/// Argon2id parameters (primarily for tests or re-keying).
pub fn encrypt_bytes_with_params(
    plaintext: &[u8],
    passphrase: &str,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt, m_kib, t_cost, p_cost)?;

    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = FORMAT_VERSION;
    header[5..9].copy_from_slice(&m_kib.to_le_bytes());
    header[9..13].copy_from_slice(&t_cost.to_le_bytes());
    header[13..17].copy_from_slice(&p_cost.to_le_bytes());
    header[17..33].copy_from_slice(&salt);
    header[33..45].copy_from_slice(&nonce);

    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| anyhow!("initializing AES-256-GCM: {e}"))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|e| anyhow!("AES-256-GCM encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Encrypts `plaintext` with the default Argon2id parameters into a `KVEL\x01` envelope.
pub fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    encrypt_bytes_with_params(
        plaintext,
        passphrase,
        DEFAULT_ARGON2_M_KIB,
        DEFAULT_ARGON2_T_COST,
        DEFAULT_ARGON2_P_COST,
    )
}

/// Decrypts a `KVEL\x01` envelope and verifies the 45-byte authenticated header.
pub fn decrypt_bytes(envelope: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.len() < HEADER_LEN + 16 {
        bail!("encrypted state envelope is truncated or invalid");
    }
    let (header, ciphertext) = envelope.split_at(HEADER_LEN);
    if &header[0..4] != MAGIC {
        bail!("invalid state file magic (expected KVEL envelope)");
    }
    if header[4] != FORMAT_VERSION {
        bail!(
            "unsupported state envelope format version {} (expected {FORMAT_VERSION})",
            header[4]
        );
    }

    let m_kib = u32::from_le_bytes(header[5..9].try_into().expect("4 bytes"));
    let t_cost = u32::from_le_bytes(header[9..13].try_into().expect("4 bytes"));
    let p_cost = u32::from_le_bytes(header[13..17].try_into().expect("4 bytes"));
    let salt: [u8; SALT_LEN] = header[17..33].try_into().expect("16 bytes");
    let nonce: [u8; NONCE_LEN] = header[33..45].try_into().expect("12 bytes");

    let key = derive_key(passphrase, &salt, m_kib, t_cost, p_cost)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| anyhow!("initializing AES-256-GCM: {e}"))?;

    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt state (wrong passphrase or corrupted file)"))?;
    Ok(Zeroizing::new(plaintext))
}

fn encrypt_state(state: &State, passphrase: &str) -> Result<Vec<u8>> {
    let mut json = Zeroizing::new(serde_json::to_vec_pretty(state)?);
    json.push(b'\n');
    encrypt_bytes(&json, passphrase)
}

/// Reads and decrypts [`State`] from an encrypted vault file at `path`.
pub fn read_encrypted_file(path: &Path, passphrase: &str) -> Result<State> {
    verify_private_dir(effective_parent(path)?)?;
    verify_private_file(path)?;
    let envelope = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let plaintext = decrypt_bytes(&envelope, passphrase)?;
    decode_state(&plaintext)
}

/// Atomically writes `state` encrypted with `passphrase` to `path` with mode `0600`.
pub fn write_encrypted_atomic(path: &Path, state: &State, passphrase: &str) -> Result<()> {
    let _parent = ensure_private_parent(path)?;
    let envelope = encrypt_state(state, passphrase)?;
    write_ciphertext_atomic(path, &envelope)
}

const MAX_ROLLING_BACKUPS: usize = 20;

fn state_backup_stem(state_path: &Path) -> &str {
    state_path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("state")
}

fn parse_backup_revision(stem: &str, name: &str) -> Option<u64> {
    let rest = name
        .strip_prefix(stem)?
        .strip_prefix('.')?
        .strip_suffix(".enc")?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

/// Returns the highest rolling backup revision found in `<parent>/backups/`, or `0` if none exist.
pub fn max_backup_revision(state_path: &Path) -> Result<u64> {
    let parent = effective_parent(state_path)?;
    let backup_dir = parent.join("backups");
    if !backup_dir.exists() {
        return Ok(0);
    }
    verify_private_dir(&backup_dir)?;
    let stem = state_backup_stem(state_path);
    let mut max_rev = 0u64;
    for entry in fs::read_dir(&backup_dir)
        .with_context(|| format!("listing backups in {}", backup_dir.display()))?
    {
        let entry = entry?;
        let fname = entry.file_name();
        let Some(name_str) = fname.to_str() else {
            continue;
        };
        if let Some(rev) = parse_backup_revision(stem, name_str) {
            max_rev = max_rev.max(rev);
        }
    }
    Ok(max_rev)
}

/// Ensures the private `backups/` sibling directory exists with mode `0700`.
pub fn ensure_backup_dir(state_path: &Path) -> Result<PathBuf> {
    let parent = effective_parent(state_path)?;
    let backup_dir = parent.join("backups");
    if fs::symlink_metadata(&backup_dir).is_err() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&backup_dir)
            .with_context(|| format!("creating backup directory {}", backup_dir.display()))?;
    }
    verify_private_dir(&backup_dir)?;
    Ok(backup_dir)
}

/// Writes `raw` ciphertext bytes atomically to `dest` with mode `0600`.
pub fn write_ciphertext_atomic(dest: &Path, raw: &[u8]) -> Result<()> {
    let parent = effective_parent(dest)?;
    let mut tmp = TempFileBuilder::new()
        .prefix(".kvel.")
        .suffix(".tmp")
        .permissions(fs::Permissions::from_mode(0o600))
        .tempfile_in(parent)
        .with_context(|| format!("creating temp file in {}", parent.display()))?;
    tmp.write_all(raw).context("writing temp file")?;
    tmp.as_file().sync_all().context("flushing temp file")?;
    tmp.persist(dest)
        .map_err(|e| anyhow!("persisting {}: {}", dest.display(), e.error))?;
    let dir_handle = File::open(parent)
        .with_context(|| format!("opening {} for directory fsync", parent.display()))?;
    dir_handle
        .sync_all()
        .with_context(|| format!("fsyncing directory {}", parent.display()))?;
    Ok(())
}

/// Copies the current encrypted vault at `state_path` into `<parent>/backups/<stem>.<old_revision>.enc`
/// (`0600`) before overwriting it, pruning older `<stem>.<rev>.enc` backups beyond the 20 newest revisions.
pub fn backup_existing_state(state_path: &Path, old_revision: u64) -> Result<()> {
    if fs::symlink_metadata(state_path).is_err() {
        return Ok(());
    }
    verify_private_file(state_path)?;
    let raw = fs::read(state_path)
        .with_context(|| format!("reading {} for rolling backup", state_path.display()))?;
    let backup_dir = ensure_backup_dir(state_path)?;
    let stem = state_backup_stem(state_path);
    let dest = backup_dir.join(format!("{stem}.{old_revision}.enc"));
    write_ciphertext_atomic(&dest, &raw)?;

    let mut entries = Vec::new();
    for entry in fs::read_dir(&backup_dir)
        .with_context(|| format!("listing backups in {}", backup_dir.display()))?
    {
        let entry = entry?;
        let fname = entry.file_name();
        let Some(name_str) = fname.to_str() else {
            continue;
        };
        if let Some(rev) = parse_backup_revision(stem, name_str) {
            entries.push((std::cmp::Reverse(rev), entry.path()));
        }
    }
    entries.sort_by_key(|(rev, _)| *rev);
    for (_, old_path) in entries.into_iter().skip(MAX_ROLLING_BACKUPS) {
        fs::remove_file(&old_path)
            .with_context(|| format!("pruning old backup {}", old_path.display()))?;
    }
    Ok(())
}

/// Bumps revision/timestamp, validates, backs up `old_revision`, and atomically writes `state`.
pub fn commit_state_mutation(
    state_path: &Path,
    state: &mut State,
    passphrase: &str,
    old_revision: u64,
) -> Result<u64> {
    state.touch();
    crate::validate::validate_state(state)?;
    backup_existing_state(state_path, old_revision)?;
    write_encrypted_atomic(state_path, state, passphrase)?;
    Ok(state.revision)
}
