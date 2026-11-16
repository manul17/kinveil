//! Safe RAM-backed TOML configuration viewer/editor (`kinveil config`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use tempfile::TempDir;

use crate::state::{DEFAULT_CONFIG_TOML, parse_config_toml};
use crate::store::{backup_existing_state, commit_state_mutation, write_encrypted_atomic};
use crate::validate::validate_state;

use super::load_locked_state;
use super::secrets::{SecretReader, confirm_destructive, prompt_yes_no};

/// Linux `TMPFS_MAGIC` from `<linux/magic.h>`.
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: rustix::fs::FsWord = 0x0102_1994;

#[cfg(target_os = "linux")]
pub(crate) fn ensure_shm_tmpfs() -> Result<&'static Path> {
    let shm = Path::new("/dev/shm");
    let meta = fs::symlink_metadata(shm).context("failed to inspect /dev/shm")?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!("/dev/shm must be a real directory");
    }
    let st = rustix::fs::statfs(shm).context("statfs(/dev/shm) failed")?;
    if st.f_type != TMPFS_MAGIC {
        bail!("/dev/shm is not mounted as RAM-backed tmpfs; refusing to write plaintext temp data");
    }
    Ok(shm)
}

pub(crate) fn open_private_new_file(path: &Path, mode: u32) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
}

pub(crate) struct EditTempDir {
    dir: TempDir,
}

impl EditTempDir {
    pub(crate) fn create(prefix: &str) -> Result<Self> {
        let perms = fs::Permissions::from_mode(0o700);
        #[cfg(target_os = "linux")]
        let dir = {
            let shm = ensure_shm_tmpfs()?;
            tempfile::Builder::new()
                .prefix(prefix)
                .permissions(perms)
                .tempdir_in(shm)
                .with_context(|| format!("failed to create tmpfs dir in {}", shm.display()))?
        };

        #[cfg(not(target_os = "linux"))]
        let dir = {
            eprintln!(
                "Warning: host OS lacks /dev/shm tmpfs verification; editing temporary config inside OS temp directory"
            );
            tempfile::Builder::new()
                .prefix(prefix)
                .permissions(perms)
                .tempdir()
                .context("failed to create temporary edit directory")?
        };

        Ok(Self { dir })
    }

    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for EditTempDir {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(self.dir.path()) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Ok(meta) = fs::symlink_metadata(&p)
                    && meta.is_file()
                    && let Ok(mut f) = OpenOptions::new()
                        .write(true)
                        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
                        .open(&p)
                {
                    let len = usize::try_from(meta.len()).unwrap_or(0);
                    let zeros = vec![0u8; len];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_data();
                }
            }
        }
    }
}

fn apply_config_toml(
    state_path: &Path,
    new_toml: &str,
    secrets: &mut SecretReader,
    unchanged_msg: &str,
    success_prefix: &str,
) -> Result<()> {
    let (_lock, passphrase, mut state) = load_locked_state(state_path, secrets)?;
    if new_toml == state.config_toml {
        println!("{unchanged_msg}");
        return Ok(());
    }
    let old_revision = state.revision;
    state.set_config_toml(new_toml)?;
    let new_rev = commit_state_mutation(state_path, &mut state, &passphrase, old_revision)?;
    println!(
        "{success_prefix} (revision={new_rev}) in {}.",
        state_path.display()
    );
    Ok(())
}

pub(crate) fn cmd_config(
    state_path: &Path,
    print: bool,
    file: Option<PathBuf>,
    reset: bool,
    yes: bool,
    secrets: &mut SecretReader,
) -> Result<()> {
    if print {
        let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
        print!("{}", state.config_toml);
        if !state.config_toml.ends_with('\n') {
            println!();
        }
        return Ok(());
    }

    if let Some(src_path) = file {
        let raw = fs::read_to_string(&src_path)
            .with_context(|| format!("reading configuration file {}", src_path.display()))?;
        parse_config_toml(&raw)?;
        return apply_config_toml(
            state_path,
            &raw,
            secrets,
            "No changes made.",
            "Updated configuration",
        );
    }

    if reset {
        confirm_destructive(
            "Reset configuration in state.enc to built-in defaults?",
            yes,
        )?;
        return apply_config_toml(
            state_path,
            DEFAULT_CONFIG_TOML,
            secrets,
            "Configuration already matches defaults.",
            "Reset configuration to defaults",
        );
    }

    let (_lock, passphrase, original_state) = load_locked_state(state_path, secrets)?;
    let tmp_dir = EditTempDir::create("kinveil-config-")?;
    let edit_path = tmp_dir.path().join("config.toml");
    {
        let mut f = open_private_new_file(&edit_path, 0o600)?;
        f.write_all(original_state.config_toml.as_bytes())?;
        f.sync_all()?;
    }

    let editor_raw = std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "vi".to_owned());
    let editor_parts =
        shlex::split(&editor_raw).ok_or_else(|| anyhow!("invalid quoted EDITOR/VISUAL command"))?;
    let (editor_bin, editor_args) = editor_parts
        .split_first()
        .ok_or_else(|| anyhow!("empty EDITOR command"))?;

    loop {
        let status = Command::new(editor_bin)
            .args(editor_args)
            .arg(&edit_path)
            .env_remove("LD_PRELOAD")
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("DYLD_INSERT_LIBRARIES")
            .status()
            .with_context(|| format!("failed launching editor '{editor_bin}'"))?;
        if !status.success() {
            bail!("editor exited with status {status}; aborting without saving");
        }

        let new_bytes = fs::read(&edit_path)?;
        let edited = match String::from_utf8(new_bytes) {
            Ok(s) => s,
            Err(e) => {
                let err = anyhow!("configuration file must be valid UTF-8: {e}");
                eprintln!("Validation error: {err}");
                if prompt_yes_no("Re-open editor to fix?")? {
                    continue;
                }
                return Err(err);
            }
        };

        if edited == original_state.config_toml {
            println!("No changes made.");
            return Ok(());
        }

        let mut candidate = original_state.clone();
        let validate_res = candidate.set_config_toml(edited).and_then(|()| {
            candidate.touch();
            validate_state(&candidate)
        });
        if let Err(e) = validate_res {
            eprintln!("Validation error: {e:#}");
            if prompt_yes_no("Re-open editor to fix?")? {
                continue;
            }
            return Err(e);
        }

        backup_existing_state(state_path, original_state.revision)?;
        write_encrypted_atomic(state_path, &candidate, &passphrase)?;
        println!(
            "Saved configuration (revision={}) to {}.",
            candidate.revision,
            state_path.display()
        );
        return Ok(());
    }
}
