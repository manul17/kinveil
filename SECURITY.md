# Security Policy

## Supported Versions

Only the latest release on the `0.1.x` line receives security fixes.

## Security Model & Scope

- **Local vault:** `state.enc` (`KVEL\x01`) is encrypted with Argon2id (`128 MiB`, `t=3`, `p=1`) and AES-256-GCM with header AAD. All private keys, user tokens, server inventory, and `config.toml` remain inside the encrypted vault.
- **Editor isolation:** `kinveil config` decrypts only global non-key settings (`config.toml`) into RAM-backed `/dev/shm` tmpfs (`0700`/`0600`) and zeroes temp files on exit; private keys never open in `$EDITOR`. Child processes spawned for `EDITOR`/`KINVEIL_PASSPHRASE_COMMAND`, `git`, `go`, and `ssh` strip `LD_PRELOAD`, `LD_LIBRARY_PATH`, and `DYLD_INSERT_LIBRARIES`.
- **Verified transport & artifacts:** Deployments verify pinned OpenSSH host public keys (`StrictHostKeyChecking=yes`, `ClearAllForwardings=yes`, `-T`) with `--` argument separation and input validation. Upstream `xray` is verified by release zip and extracted/bundled binary SHA-256 (`XRAY_BIN_SHA256`), and `amneziawg-go` is verified against bundled/prebuilt release SHA-256 (`AWG_PREBUILT_SHA256`), a pinned upstream commit build, or a verified SHA-256 `[artifacts]` URL; optional `[artifacts]` TOML overrides enforce strict HTTPS + SHA-256 pairs and reject local/private destinations, and `KINVEIL_XRAY_BIN` / `KINVEIL_AMNEZIAWG_BIN` verify Linux `x86_64` ELF headers.
- **Server isolation & egress filtering:** Caddy runs with `admin off` over mode `0710` subscription directories. Xray runs unprivileged as user `kinveil` with `freedom` outbound `domainStrategy: UseIP` (mitigating DNS-rebinding SSRF); both Xray and forwarding-only OpenSSH (`vpnssh*` with `/usr/sbin/nologin`) are further restricted at the kernel layer via `/etc/kinveil/nft-egress.nft` inside `table inet kinveil`, always rejecting loopback, unspecified, link-local, multicast/reserved, and cloud IMDS (`169.254.0.0/16`, `100.100.100.200/32`, `fd00:ec2::254/128`) destinations regardless of `[firewall] block_private_networks`, while AmneziaWG `kv0` blocks peer-to-peer lateral traffic and clamps TCP MSS.
- **Redacted diagnostics:** Probe failures and debug output redact secret subscription `base_path`s, tokens, private keys, and API credentials.

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories (**Security -> Advisories -> Report a vulnerability**) rather than opening a public issue. Include reproduction steps, affected version, and impact assessment.
