use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use ssh_key::PublicKey;

use crate::state::AdminSsh;

fn record_host_key_candidate(
    key_type: &str,
    key_b64: &str,
    ed25519_match: &mut Option<String>,
    fallback_match: &mut Option<String>,
) {
    let candidate = format!("{key_type} {key_b64}");
    if PublicKey::from_openssh(&candidate).is_ok() {
        if key_type == "ssh-ed25519" && ed25519_match.is_none() {
            *ed25519_match = Some(candidate);
        } else if fallback_match.is_none() {
            *fallback_match = Some(candidate);
        }
    }
}

/// Look up an SSH host public key in `known_hosts` (supporting both plaintext and hashed entries),
/// preferring `ssh-ed25519` over other valid OpenSSH host key algorithms.
pub fn lookup_known_hosts_key(
    known_hosts_path: &Path,
    host: &str,
    port: u16,
) -> Result<Option<String>> {
    if !known_hosts_path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(known_hosts_path)?;
    let bracketed = format!("[{host}]:{port}");
    let mut ed25519_match: Option<String> = None;
    let mut fallback_match: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hosts_field) = parts.next() else {
            continue;
        };
        let Some(key_type) = parts.next() else {
            continue;
        };
        let Some(key_b64) = parts.next() else {
            continue;
        };
        if hosts_field.starts_with("|1|") {
            continue;
        }
        let host_matches = hosts_field.split(',').any(|entry| {
            if port == 22 {
                entry == host || entry == bracketed
            } else {
                entry == bracketed
            }
        });
        if !host_matches {
            continue;
        }
        record_host_key_candidate(key_type, key_b64, &mut ed25519_match, &mut fallback_match);
        if ed25519_match.is_some() {
            return Ok(ed25519_match);
        }
    }

    if ed25519_match.is_none() && fallback_match.is_none() {
        let queries: Vec<&str> = if port == 22 {
            vec![host, &bracketed]
        } else {
            vec![&bracketed]
        };
        for query in queries {
            let Ok(out) = Command::new("ssh-keygen")
                .env_remove("LD_PRELOAD")
                .env_remove("LD_LIBRARY_PATH")
                .args(["-F", query, "-f"])
                .arg(known_hosts_path)
                .stdin(Stdio::null())
                .output()
            else {
                break;
            };
            if !out.status.success() {
                continue;
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            for raw_line in stdout.lines() {
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let Some(_hosts_field) = parts.next() else {
                    continue;
                };
                let Some(key_type) = parts.next() else {
                    continue;
                };
                let Some(key_b64) = parts.next() else {
                    continue;
                };
                record_host_key_candidate(
                    key_type,
                    key_b64,
                    &mut ed25519_match,
                    &mut fallback_match,
                );
            }
            if ed25519_match.is_some() {
                break;
            }
        }
    }

    Ok(ed25519_match.or(fallback_match))
}

pub struct SshOutput {
    pub stdout: String,
    pub stderr: String,
}

struct EphemeralKnownHosts {
    file: tempfile::NamedTempFile,
}

impl EphemeralKnownHosts {
    fn create(line: &str) -> Result<Self> {
        let mut file = tempfile::Builder::new()
            .prefix("kinveil-kh-")
            .suffix(".txt")
            .permissions(fs::Permissions::from_mode(0o600))
            .tempfile()?;
        file.write_all(line.as_bytes())?;
        file.as_file().sync_all()?;
        Ok(Self { file })
    }
}

pub(crate) fn format_known_hosts_entry(host: &str, port: u16, pub_key: &str) -> String {
    if port == 22 {
        format!("{} {}", host, pub_key.trim())
    } else {
        format!("[{}]:{} {}", host, port, pub_key.trim())
    }
}

pub fn format_known_hosts_line(admin: &AdminSsh) -> String {
    format!(
        "{}\n",
        format_known_hosts_entry(&admin.host, admin.port.get(), &admin.host_public_key)
    )
}

pub(crate) fn shell_single_quote(s: &str) -> String {
    let escaped = s.replace('\'', r#"'\''"#);
    format!("'{escaped}'")
}

pub fn build_ssh_args(admin: &AdminSsh, known_hosts_path: &Path, remote_cmd: &str) -> Vec<String> {
    let port_str = admin.port.to_string();
    let kh_opt = format!("UserKnownHostsFile={}", known_hosts_path.display());
    let target = format!("{}@{}", admin.user, admin.host);

    let mut args = vec![
        "-T".to_owned(),
        "-p".to_owned(),
        port_str,
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        kh_opt,
        "-o".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
        "-o".to_owned(),
        "ForwardAgent=no".to_owned(),
        "-o".to_owned(),
        "ForwardX11=no".to_owned(),
        "-o".to_owned(),
        "PermitLocalCommand=no".to_owned(),
        "-o".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=15".to_owned(),
        "-o".to_owned(),
        "ServerAliveInterval=10".to_owned(),
        "-o".to_owned(),
        "ServerAliveCountMax=3".to_owned(),
    ];
    if let Some(ref key_path) = admin.identity_file {
        args.push("-o".to_owned());
        args.push("IdentitiesOnly=yes".to_owned());
        args.push("-i".to_owned());
        args.push(key_path.clone());
    }
    args.push("--".to_owned());
    args.push(target);
    args.push(remote_cmd.to_owned());
    args
}

pub fn run_ssh(
    admin: &AdminSsh,
    remote_cmd: &str,
    stdin_payload: Option<&[u8]>,
) -> Result<SshOutput> {
    if let Some(ref key_path) = admin.identity_file {
        crate::validate::validate_ssh_identity_file(key_path, "admin_ssh.identity_file")?;
    }
    let kh = EphemeralKnownHosts::create(&format_known_hosts_line(admin))?;
    let args = build_ssh_args(admin, kh.file.path(), remote_cmd);

    let mut cmd = Command::new("ssh");
    cmd.env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .args(&args);

    if stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to launch ssh for {}", admin.host))?;

    if let Some(payload) = stdin_payload {
        let owned = payload.to_vec();
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to open stdin pipe to ssh"))?;
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            stdin.write_all(&owned)?;
            stdin.flush()?;
            Ok(())
        });
        let output = child.wait_with_output()?;
        match writer.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) if output.status.success() => {
                bail!("failed writing stdin payload over SSH: {e}");
            }
            Ok(Err(_)) => {}
            Err(_) => bail!("SSH stdin writer thread panicked"),
        }
        return finish_ssh_output(admin, output);
    }

    let output = child.wait_with_output()?;
    finish_ssh_output(admin, output)
}

fn finish_ssh_output(admin: &AdminSsh, output: std::process::Output) -> Result<SshOutput> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        bail!(
            "SSH command on {}:{} exited with {}: {}",
            admin.host,
            admin.port,
            output.status,
            stderr.trim()
        );
    }
    Ok(SshOutput { stdout, stderr })
}
