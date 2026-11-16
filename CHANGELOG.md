# Changelog

All notable changes to `kinveil` will be documented in this file.

## [Unreleased]

## [0.1.0] - 2026-11-15

- Initial release of `kinveil`:
  - **Encrypted local vault (`KVEL\x01`, `schema_version = 1`):** Argon2id (`128 MiB`, `t=3`, `p=1`) + AES-256-GCM authenticated vault, `0700`/`0600` file-permission checks, `.state.enc.lock` locking, rolling `<stem>.<rev>.enc` backups (20 retained), monotonic restore revisions, `user add/update/enable/disable/rotate/remove/share/amneziawg-conf`, and `server add/update/rotate/enable/disable/remove`.
  - **Protocol stack:** Symmetrical roles (`vpn`, `subscription`) and per-node protocols (`vless`, `hysteria2`, `amneziawg`, `ssh-forwarding`), with global commented TOML sections (`[firewall]`, `[subscription]`, `[vless]`, `[hysteria2]`, `[amneziawg]`, `[ssh_forwarding]`, `[sysctl]`, `[artifacts]`), VLESS REALITY XHTTP (`stream-up` & `packet-up` toggleable independently), Hysteria2 + Salamander (with Throne SPKI SHA-256 pinning and self-signed IP-SAN certs), AmneziaWG 3.1 (`kv0`, `10.8.0.0/16` default subnet, per-peer `PresharedKey`, `I1`..`I5` CPS tags, `RandomTrailers`, `DisableCookies`), and forwarding-only OpenSSH (`vpnssh*`).
  - **Hardened zero-panel deployer:** Bundled & prebuilt SHA-256-verified server binaries (`XRAY_BIN_SHA256`, `AWG_PREBUILT_SHA256`) with pinned `amneziawg-go` commit fallback, SHA-256-pinned `[artifacts]` TOML overrides and `KINVEIL_XRAY_BIN` / `KINVEIL_AMNEZIAWG_BIN`, pinned-host-key SSH streaming, clean-host pre-flight guard (`--takeover`), `table inet kinveil` with `nft -c` pre-check, `kv0` isolation + TCP MSS clamping, unified kernel-level `/etc/kinveil/nft-egress.nft` blocking loopback and cloud IMDS endpoints for both Xray and `vpnssh*`, Caddy HTTPS subscriptions (`admin off`, `0710` sub directory), Cloudflare DNS automation, `kinveil config` `/dev/shm` TOML editor, `kinveil debug render`, and two-layer `kinveil check`.
