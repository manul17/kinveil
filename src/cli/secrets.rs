//! Passphrase and confirmation input helpers.

use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{self, BufRead as _, BufReader, IsTerminal as _, Write as _};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use zeroize::Zeroizing;

pub(crate) fn validate_new_passphrase(pass: &str) -> Result<()> {
    if pass.chars().count() < 12 {
        bail!("passphrase must be at least 12 characters long");
    }
    let distinct: BTreeSet<char> = pass.chars().collect();
    if distinct.len() < 4 {
        bail!("passphrase must contain at least 4 distinct characters");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretSource {
    InteractiveTty,
    PassphraseFd,
    PassphraseCommand,
}

impl SecretSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveTty => "interactive TTY",
            Self::PassphraseFd => "KINVEIL_PASSPHRASE_FD",
            Self::PassphraseCommand => "KINVEIL_PASSPHRASE_COMMAND",
        }
    }
}

pub(crate) struct SecretReader {
    fd_lines: Option<VecDeque<Zeroizing<String>>>,
    command_pass: Option<Zeroizing<String>>,
}

fn read_passphrase_from_command(cmd: &str) -> Result<Zeroizing<String>> {
    let out = Command::new("sh")
        .args(["-c", cmd])
        .env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("DYLD_INSERT_LIBRARIES")
        .output()
        .context("failed to execute KINVEIL_PASSPHRASE_COMMAND")?;
    if !out.status.success() {
        bail!(
            "KINVEIL_PASSPHRASE_COMMAND failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = Zeroizing::new(
        String::from_utf8(out.stdout)
            .context("KINVEIL_PASSPHRASE_COMMAND stdout was not valid UTF-8")?,
    );
    let first_line = stdout
        .split('\n')
        .next()
        .unwrap_or("")
        .trim_end_matches('\r');
    let pass = Zeroizing::new(first_line.to_owned());
    if pass.is_empty() {
        bail!("KINVEIL_PASSPHRASE_COMMAND returned an empty passphrase");
    }
    Ok(pass)
}

impl SecretReader {
    pub(crate) fn from_env() -> Result<Self> {
        let Ok(raw_fd) = std::env::var("KINVEIL_PASSPHRASE_FD") else {
            let command_pass = match std::env::var("KINVEIL_PASSPHRASE_COMMAND") {
                Ok(cmd) if !cmd.trim().is_empty() => Some(read_passphrase_from_command(&cmd)?),
                _ => None,
            };
            return Ok(Self {
                fd_lines: None,
                command_pass,
            });
        };
        let fd_num: i32 = raw_fd
            .trim()
            .parse()
            .map_err(|_| anyhow!("KINVEIL_PASSPHRASE_FD must be an integer file descriptor"))?;
        if fd_num < 0 {
            bail!("KINVEIL_PASSPHRASE_FD must be non-negative");
        }
        let file = File::open(format!("/proc/self/fd/{fd_num}"))
            .or_else(|_| File::open(format!("/dev/fd/{fd_num}")))
            .context("failed to read from KINVEIL_PASSPHRASE_FD")?;
        let mut reader = BufReader::new(file);
        let mut lines = VecDeque::new();
        loop {
            let mut buf = Zeroizing::new(String::new());
            let n = reader.read_line(&mut buf)?;
            if n == 0 {
                break;
            }
            let trimmed_len = buf.trim_end_matches(['\r', '\n']).len();
            buf.truncate(trimmed_len);
            if !buf.is_empty() {
                lines.push_back(buf);
            }
        }
        if lines.is_empty() {
            bail!("KINVEIL_PASSPHRASE_FD provided no secret lines");
        }
        Ok(Self {
            fd_lines: Some(lines),
            command_pass: None,
        })
    }

    pub(crate) fn prompt_one(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        if let Some(queue) = &mut self.fd_lines {
            return queue
                .pop_front()
                .ok_or_else(|| anyhow!("KINVEIL_PASSPHRASE_FD exhausted before '{prompt}'"));
        }
        if !io::stdin().is_terminal() {
            bail!("interactive TTY required for '{prompt}' (or set KINVEIL_PASSPHRASE_FD)");
        }
        let val = Zeroizing::new(
            rpassword::prompt_password(prompt)
                .with_context(|| format!("failed reading secret prompt '{prompt}'"))?,
        );
        if val.is_empty() {
            bail!("secret input must not be empty");
        }
        Ok(val)
    }

    pub(crate) fn prompt_passphrase_with_source(
        &mut self,
        prompt: &str,
    ) -> Result<(Zeroizing<String>, SecretSource)> {
        if let Some(pass) = self.command_pass.take() {
            return Ok((pass, SecretSource::PassphraseCommand));
        }
        if self.fd_lines.is_some() {
            return self
                .prompt_one(prompt)
                .map(|pass| (pass, SecretSource::PassphraseFd));
        }
        if !io::stdin().is_terminal() {
            bail!(
                "interactive TTY required for '{prompt}' (or set KINVEIL_PASSPHRASE_FD / KINVEIL_PASSPHRASE_COMMAND)"
            );
        }
        self.prompt_one(prompt)
            .map(|pass| (pass, SecretSource::InteractiveTty))
    }

    pub(crate) fn prompt_passphrase(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        self.prompt_passphrase_with_source(prompt)
            .map(|(pass, _)| pass)
    }

    pub(crate) fn prompt_new_passphrase(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        let non_interactive = self.fd_lines.is_some() || self.command_pass.is_some();
        let first = self.prompt_passphrase(prompt)?;
        validate_new_passphrase(&first)?;
        if non_interactive {
            return Ok(first);
        }
        let second = Zeroizing::new(
            rpassword::prompt_password("Confirm passphrase: ")
                .context("failed reading confirmation passphrase")?,
        );
        if first.as_str() != second.as_str() {
            bail!("passphrases did not match");
        }
        Ok(first)
    }
}

pub(crate) fn prompt_yes_no(question: &str) -> Result<bool> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{question} [y/N]: ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(matches!(ans.as_str(), "y" | "yes"))
}

pub(crate) fn confirm_destructive(question: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        bail!(
            "{question} (refusing destructive operation on non-interactive stdin; pass --yes to confirm)"
        );
    }
    if !prompt_yes_no(question)? {
        bail!("operation aborted");
    }
    Ok(())
}
