# Admin Guide

This guide covers planning, provisioning, automating, deploying, troubleshooting, and maintaining a `kinveil` fleet from Linux or macOS.

## 1. Prerequisites

### Local workstation (`kinveil` CLI host)

- **`kinveil` binary** installed from a tagged GitHub Release archive (`./install.sh`, which bundles preverified `xray` and `amneziawg-go` server binaries) or built from source (`cargo build --release --locked`).
- **OpenSSH client (`ssh`)** in `PATH`.
- **No Go compiler or `git` required:** bundled/prebuilt SHA-256-verified `xray` and `amneziawg-go` binaries work out of the box. Local `go >= 1.25` and `git` are only used as a fallback if prebuilt downloads are unreachable and neither `[artifacts]` nor `KINVEIL_AMNEZIAWG_BIN` is set (see [Section 8](#8-environment-variables-artifact-overrides--automation)).

### Target VPS nodes

- **Debian 12 or Debian 13** (`x86_64`) dedicated to `kinveil`. Deployment validates `--arch x86_64`. Enable Debian `unattended-upgrades` on the VPS for automatic OS security patches (`kinveil deploy` manages VPN packages/configs only when you invoke it).
- **KVM / full virtualization** recommended (`/dev/net/tun` is required when AmneziaWG is enabled).
- Key-based (`ssh-copy-id`, non-interactive `BatchMode=yes`) SSH access as `root` or passwordless `sudo` on port `22` (or a custom `--ssh-port`).

> [!WARNING]
> **Host firewall & takeover guard:** `deploy` disables `ufw` if installed and replaces `/etc/nftables.conf` with `flush ruleset` + `table inet kinveil` using default-`drop` `input` and `forward` policies. Initial deployment aborts if `docker`, `podman`, `firewalld`, `netfilter-persistent`, existing web proxies, active `ufw`, or non-default nftables tables (on disk or live in the kernel) are detected unless you pass `--takeover`.

---

## 2. Port Layout & Cloud Firewalls

Open these ports in your VPS provider's cloud firewall **before** running `kinveil deploy`:

| Role / Protocol | Port / Proto | Purpose |
| --- | --- | --- |
| All servers | `22/tcp` (or `--ssh-port`) | Admin SSH management |
| `vpn` (`vless`) | `8443/tcp` | VLESS REALITY XHTTP (`vless-stream` / `vless-packet`) |
| `vpn` (`hysteria2`) | `9443/udp` | Hysteria2 + Salamander |
| `vpn` (`amneziawg`) | `7443/udp` | AmneziaWG 3.1 (`kv0`) |
| `vpn` (`ssh-forwarding`) | `2222/tcp` | Per-user forwarding-only OpenSSH (`vpnssh<uid>`) |
| `subscription` | `80/tcp`, `443/tcp` | Caddy ACME HTTP-01 + HTTPS subscriptions |

Disabled roles or protocols do not open ports in `table inet kinveil`.

### Recommended Port-443 Layout for Censored Networks

1. **Hysteria2 on `443/udp` alongside Caddy:** Caddy serves `HTTP/1.1` and `HTTP/2` over `443/tcp` only, leaving `443/udp` free for Hysteria2:

   ```bash
   kinveil server update <id> --hysteria2-port 443
   ```

2. **VLESS + Hysteria2 on `443` on dedicated `vpn` nodes:** Any server without the `subscription` role does not run Caddy on `443/tcp`. You can pass port overrides when adding the server or update them later:

   ```bash
   kinveil server add <ip> --label "FI Finland" --sni dl.google.com --vless-port 443 --hysteria2-port 443
   kinveil server update <vpn-node-id> --vless-port 443 --hysteria2-port 443
   ```

Run `kinveil server update <id> --clear-ports` to revert per-server overrides back to global defaults in `kinveil config` (`[vless].port = 8443`, `[hysteria2].port = 9443`, `[amneziawg].port = 7443`, `[ssh_forwarding].port = 2222`).

---

## 3. Domain, DNS & IPv6 Setup

Client apps fetch profiles from `https://<domain>/<random-base-path>/<user-token>` and auto-refresh every `12` hours by default (`[subscription].update_interval_hours`).

- **Manual DNS:** Point an unproxied (DNS-only) `A` record (and `AAAA` if `--ipv6` is set) for your subdomain directly to your `subscription` server IP before deploying.
- **IPv6 notes:** Only pass `--ipv6` if the VPS has working global IPv6 connectivity (clearing a broken address is `kinveil server update <id> --clear-ipv6`). Xray, Hysteria2, and Caddy bind dual-stack (`::`), while AmneziaWG (`kv0`) is IPv4-only and blocks IPv6 traffic in `nftables` to prevent leaks.
- **Cloudflare automation (optional):** Create a scoped API token (`Zone : DNS : Edit`), save it into the vault, and deploy normally (`--skip-dns` bypasses sync temporarily; `kinveil cloudflare clear` reverts to manual DNS):

  ```bash
  kinveil cloudflare set --zone-id <CLOUDFLARE_ZONE_ID>
  ```

- **Migrate blocked domain:** Change the subscription hostname (and optionally rotate the secret base path) without reprovisioning user keys:

  ```bash
  kinveil set-domain sub2.example.com --rotate-base-path
  kinveil deploy
  ```

---

## 4. Choosing a REALITY `--sni` Target

VLESS REALITY disguises handshakes as ordinary TLS 1.3 + HTTP/2 (`h2`) traffic to a real destination domain (`--sni`), forwarding unauthenticated probes to `--target` (defaults to `<sni>:443`).

Pick a domain carefully:
- **Must support TLS 1.3 + ALPN `h2`** cleanly (never TLS 1.2-only) and have low latency from the VPS.
- **Must be reachable for your users**, outside censorship blocklists in their network, and free of anti-bot CDN interstitial challenges.
- **Never use your own `subscription` domain or a managed VPS IP** as `--sni`, `--target`, or `--xhttp-host` (rejected by `kinveil validate`).

Good starting candidates to test from your VPS include large developer/cloud hosts (e.g., `dl.google.com`, `www.microsoft.com`, `www.apple.com`) or ordinary non-blocked websites hosted near the VPS region. Verify from the VPS before adding/deploying:

```bash
openssl s_client -connect dl.google.com:443 -servername dl.google.com -alpn h2 </dev/null 2>/dev/null | grep -E "Protocol|ALPN"
```

Confirm both exact lines appear in output:

```text
Protocol  : TLSv1.3
ALPN protocol: h2
```

By default `--target` uses `<sni>:443`. Override dialback or XHTTP headers with `--target` and `--xhttp-host` if needed (loopback, private, link-local, unspecified, CGNAT, and `*.localhost` targets are rejected).

To change a server's SNI later without losing user links:

```bash
kinveil server update <id> --sni <new-domain>
kinveil deploy
kinveil check --ssh
```

Changing `--sni` automatically resets custom `--target` to `<new-domain>:443` and clears custom `--xhttp-host` unless you pass them in the same `server update` call. Active VLESS users pick up the new SNI on the next client subscription refresh (within 12 hours, or immediately if they refresh manually).

---

## 5. Vault, Servers & Users

### Initialize the vault

```bash
kinveil init --domain sub.example.com
```

Creates `~/.local/share/kinveil/state.enc` (`0700` dir, `0600` file). Passphrases for `init` and `passwd` require >= 12 characters and >= 4 distinct characters. Check full vault status and deploy readiness anytime with `kinveil show` and `kinveil validate`.

> [!TIP]
> Set `KINVEIL_PASSPHRASE_COMMAND` to pull your passphrase from an OS keychain (`secret-tool`, macOS `security`, or `pass`) so CLI commands run without repeated prompts (see Section 8).

### Add, update, and tune servers

```bash
kinveil server add 203.0.113.10 --label "DE Germany" --sni dl.google.com
```

- `--id` defaults to a slug of `--label` (`de-germany`). List servers anytime with `kinveil server list`.
- Roles are `vpn` and `subscription`. The first server added auto-receives `subscription` (alongside `vpn` when `--roles` is omitted) if no subscription host is configured yet.
- Configure per-node roles, active protocols (`vless`, `hysteria2`, `amneziawg`, `ssh-forwarding` — all four default on when `vpn` is enabled unless `--protocols` specifies a subset), SNI, ports, metadata, IPv4/IPv6, or SSH settings via `kinveil server update`, and rotate server keys cleanly via `kinveil server rotate`:

  ```bash
  kinveil server update <id> --roles vpn,subscription --sni dl.google.com
  kinveil server update <id> --protocols vless,hysteria2,ssh-forwarding
  kinveil server update <id> --sni www.microsoft.com
  kinveil server update <id> --label "DE Frankfurt" --ssh-port 2220 --note "Hetzner fsn1"
  kinveil server update <id> --ipv4 198.51.100.42   # also refreshes Hysteria2 cert SAN & ssh_host if unset
  kinveil server rotate <id> --all                  # or --vless / --hysteria2 / --amneziawg / --ssh-forwarding
  ```

- On first SSH connection (and whenever `update` changes `--ssh-host`, `--ssh-port`, or a matching `--ipv4`), `kinveil` checks `~/.ssh/known_hosts` or prompts you to confirm the Ed25519 host key fingerprint (verify in your VPS provider console via `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`, or pass `--ssh-host-key "ssh-ed25519 AAAA..."` directly).

### Manage users

Every enabled user automatically receives credentials for all active node protocols (`vless`, `hysteria2`, `amneziawg`, and `ssh-forwarding` inside Throne subscriptions — Happ skips `ssh://` URIs):

```bash
kinveil user list                                 # list UIDs, creation dates, and notes
kinveil user add alice bob
kinveil user add carol --note "Backup phone"
kinveil user update alice --note "Laptop + iOS"   # pass "" to clear note
kinveil deploy
kinveil user share alice                          # prints URL, QR code, setup steps, and usage tips
kinveil user share alice --url-only
```

- **Pause / resume:** `kinveil user disable <name>` / `kinveil user enable <name>` + `kinveil deploy` (stops access immediately server-side).
- **Rotate keys:** `kinveil user rotate <name>` + `kinveil deploy`. Old credentials stop working immediately server-side; client apps pick up rotated keys automatically within `12` hours (or immediately via manual refresh).
- **Revoke subscription URL too:** `kinveil user rotate <name> --rotate-url` + `kinveil deploy`, then resend `kinveil user share <name>`.
- **Export raw AmneziaWG INI:** `kinveil user amneziawg-conf <name> [--server <id>]`.
- **Remove user:** `kinveil user remove <name> [--yes]` + `kinveil deploy`.

Destructive operations (`user remove`, `server remove`, `config --reset`, `restore`, and `deploy --takeover`) prompt for interactive confirmation unless `--yes` (`-y`) is passed (required in non-interactive scripts).

---

## 6. Topologies, Partial Deployments & VPS Replacement

Separate your `subscription` endpoint from high-throughput `vpn` exit nodes:

```bash
kinveil server add 203.0.113.10 --label "Sub Host" --roles subscription
kinveil server add 198.51.100.20 --label "FI Finland" --roles vpn --sni <sni>
kinveil server add 192.0.2.30 --label "NL Netherlands" --roles vpn --protocols vless,ssh-forwarding --sni <sni>
kinveil deploy
```

`kinveil deploy` converges pure `vpn` nodes first, syncs Cloudflare DNS (if configured), and then deploys the `subscription` host so clients never fetch unprovisioned endpoints and Caddy's ACME check immediately matches DNS. Passing `--server <id>` deploys only that node and skips Cloudflare DNS and HTTPS verification unless `<id>` is the `subscription` server. Always preview changes first with `kinveil deploy --dry-run`.

To replace a blocked or retired VPS without changing client subscription links:

1. Provision a new Debian 12/13 VPS with required firewall ports open, then add it (`kinveil server add ...`).
2. If replacing the `subscription` host, assign the role to the new node (`kinveil server update <new-id> --roles vpn,subscription`) and update DNS (or let Cloudflare sync handle it during `deploy`).
3. Remove the old node (`kinveil server remove <old-id>` if already terminated, or `--wipe` to stop units, delete `vpnssh*` users, restore `.kinveil-orig` firewall/Caddy configs if saved, and remove `/etc/kinveil`, BBR sysctl files, and Caddy first).
4. Run `kinveil deploy`.

---

## 7. Global Configuration & Protocol Tuning (`kinveil config`)

All global defaults live in a single symmetric 8-section TOML file (`[firewall]`, `[subscription]`, `[vless]` + `[vless.xhttp]`/`[vless.xmux]`, `[hysteria2]`, `[amneziawg]`, `[ssh_forwarding]`, `[sysctl]`, and `[artifacts]`) stored encrypted inside `state.enc` and seeded from [`../config.example.toml`](../config.example.toml).

```bash
kinveil config                    # opens ONLY config.toml in /dev/shm under $EDITOR (no keys exposed)
kinveil config --print            # inspect active config.toml (comments preserved verbatim)
kinveil config --file my.toml     # load local TOML file and validate before saving
kinveil config --reset [--yes]    # restore built-in commented template
```

- **BitTorrent blocking (`[firewall].block_bittorrent = true`):** Blocks BitTorrent DPI signatures inside Xray (`vless` and `hysteria2`); `amneziawg` and `ssh-forwarding` forward raw packets/TCP streams outside Xray.
- **After saving changes:** Run `kinveil deploy` to push updated firewall rules, sysctl values, Xray/Caddy/AmneziaWG settings, and client subscriptions.

Use `kinveil debug render <dir>` to inspect generated `xray.json`, `Caddyfile`, `nftables.conf`, `install.sh`, and decoded Happ/Throne subscriptions locally without touching remote servers (`--allow-non-tmpfs` outside `/dev/shm`).

---

## 8. Environment Variables, Artifact Overrides & Automation

| Variable | Effect |
| --- | --- |
| `KINVEIL_STATE` | Override vault path (`--state <PATH>`). |
| `KINVEIL_PASSPHRASE_FD` | File descriptor number supplying one secret line per prompt (`/proc/self/fd/<N>` on Linux, `/dev/fd/<N>` on macOS). Takes precedence over `_COMMAND`. |
| `KINVEIL_PASSPHRASE_COMMAND` | Shell command (`sh -c`) printing the vault passphrase on stdout (`LD_PRELOAD`/`LD_LIBRARY_PATH` stripped). |
| `KINVEIL_CACHE_DIR` | Override binary artifact cache directory (`~/.cache/kinveil/artifacts`). |
| `KINVEIL_XRAY_BIN` | Local Linux `x86_64` `xray` ELF binary path (highest precedence, air-gapped override). |
| `KINVEIL_AMNEZIAWG_BIN` | Local Linux `x86_64` `amneziawg-go` ELF binary path (highest precedence, air-gapped override). |

### Pinned Runtime Artifact Overrides (`[artifacts]`)

To update upstream `Xray-core` or prebuilt `amneziawg-go` versions (e.g. for CVE patches) without waiting for a new `kinveil` binary, uncomment the HTTPS URL + 64-hex SHA-256 pairs in `[artifacts]` via `kinveil config`:

```toml
[artifacts]
xray_zip_url = "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip"
xray_zip_sha256 = "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"
```

- Pairs must specify **both** `*_url` (`https://`, non-local host) and lowercase 64-hex `*_sha256` (`amneziawg_url` must serve a direct Linux `x86_64` ELF executable; `xray_zip_url` serves the official Xray zip archive).
- Custom artifacts cache separately under `$KINVEIL_CACHE_DIR` keyed by URL hash, validate ELF architecture/headers before staging, and fail cleanly on digest mismatch without falling back to unverified defaults.
- **Resolution order** when deploying in-scope protocols:
  - `xray`: `KINVEIL_XRAY_BIN` -> `[artifacts]` (`xray_zip_url` + `xray_zip_sha256`) -> local cache (`XRAY_BIN_SHA256`) -> bundled release binary (`<exe_dir>/artifacts` or `<prefix>/share/kinveil/artifacts`, verified against `XRAY_BIN_SHA256`) -> built-in pinned `XRAY_ZIP_URL` (`XRAY_ZIP_SHA256` + `XRAY_BIN_SHA256`).
  - `amneziawg-go`: `KINVEIL_AMNEZIAWG_BIN` -> `[artifacts]` (`amneziawg_url` + `amneziawg_sha256`) -> local cache (`AWG_PREBUILT_SHA256`) -> bundled release binary (`<exe_dir>/artifacts` or `<prefix>/share/kinveil/artifacts`, verified against `AWG_PREBUILT_SHA256`) -> built-in `AWG_PREBUILT_URL` (`AWG_PREBUILT_SHA256`) -> fallback local `git` + `go build` at pinned commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`.

OS keychain examples for `KINVEIL_PASSPHRASE_COMMAND`:

```bash
# Linux (GNOME Keyring / libsecret)
export KINVEIL_PASSPHRASE_COMMAND="secret-tool lookup service kinveil account default"

# macOS Keychain
export KINVEIL_PASSPHRASE_COMMAND="security find-generic-password -s kinveil -w"

# pass (standard Unix password store)
export KINVEIL_PASSPHRASE_COMMAND="pass show kinveil/vault"
```

Non-interactive multi-prompt example (`kinveil passwd`):

```bash
printf '%s\n%s\n' "$OLD_PASS" "$NEW_PASS" | KINVEIL_PASSPHRASE_FD=0 kinveil passwd
```

Shell completions (`bash`, `zsh`, `fish`, `elvish`, `powershell`):

```bash
kinveil completions bash > ~/.local/share/bash-completion/completions/kinveil
```

---

## 9. Backups & Passphrase Rotation

- **Automatic rolling backups:** Every vault write saves `<state_dir>/backups/<stem>.<rev>.enc` (`0700`/`0600`), retaining the newest 20 revisions. Rolling backups stay encrypted with the passphrase active when written.
- **Manual backups & restore:** `kinveil backup <path>` and `kinveil restore <path> [--yes]` (both verify decryption and vault/config integrity; `restore` bumps `revision` strictly above existing backups). Because `config.toml` lives inside `state.enc`, backups remain single-file.
- **Rotate passphrase:** `kinveil passwd` re-encrypts `state.enc` with a new salt and nonce.

---

## 10. Health Checks & Troubleshooting

Start with `kinveil check` (local TCP probes + pinned-IP HTTPS subscription checks) and `kinveil check --ssh` (inspects remote systemd units, listening UDP sockets via `ss -H -uln`, `table inet kinveil`, and outbound TLS 1.3 + `h2` reachability to active `--sni` targets):

- **ACME / HTTPS fails (`caddy`):** Confirm `A`/`AAAA` DNS records point directly to the `subscription` host (Cloudflare proxy cloud **OFF**), `80/tcp` + `443/tcp` are open in the cloud firewall, and inspect `journalctl -u caddy -n 50 --no-pager`.
- **VLESS REALITY stalls:** Verify `kinveil check --ssh` shows `reality` OK, confirm VPS/client clock accuracy, suggest switching between `vless-stream` and `vless-packet`, or move VLESS to `443/tcp` on non-subscription `vpn` nodes. Avoid **Karing `1.2.25`** (fails `X25519MLKEM768` handshakes—use Happ, Throne, or a newer release).
- **Hysteria2 timeouts:** Confirm UDP ingress is allowed in the provider firewall (many providers block UDP by default), move Hysteria2 to `443/udp`, and ensure Throne imports the subscription URL rather than manually URL-escaping `tls_certificate_public_key_sha256`.
- **AmneziaWG drops or crashes:** Use an AmneziaWG 3.1-compatible client supporting `I1`..`I5` CPS tags, `RandomTrailers`, and `DisableCookies`. Each user receives one `/32` IP inside `[amneziawg].subnet`, so connect at most **1 device per user** on `amneziawg` simultaneously (`vless-*` / `hysteria` support multiple devices). If `kinveil-awg` fails to start, verify `/dev/net/tun` is enabled (`journalctl -u kinveil-awg -n 50 --no-pager`). Lower `[amneziawg].mtu` via `kinveil config` if PPPoE links clip packets.
- **SSH forwarding issues (`ssh-forwarding`):** Confirm `ssh-forwarding` is enabled both globally (`[ssh_forwarding].enabled`) and on the `vpn` node (`kinveil server update <id> --protocols ...`), and note that Happ intentionally skips `ssh://` entries while Throne includes them. `kinveil-ssh.service` runs `/etc/kinveil/ssh/sshd_config` for `vpnssh<uid>` system accounts, and `/etc/kinveil/nft-egress.nft` filters both `kinveil` Xray and `@vpnssh_users` egress—rejecting loopback/unspecified/link-local/cloud IMDS ranges plus private/reserved IPv4/IPv6 ranges when `[firewall].block_private_networks = true`.
- **Missing local `go`/`git` during `deploy`:** Configure `[artifacts]` (`amneziawg_url` + `amneziawg_sha256`), pass `KINVEIL_AMNEZIAWG_BIN` (see [Section 8](#8-environment-variables-artifact-overrides--automation)), or disable AmneziaWG (`[amneziawg].enabled = false`).
