# Admin Guide

Operational Day-1 and Day-2 runbook for provisioning, tuning, inspecting, and maintaining a `kinveil` fleet from Linux or macOS. (See [README.md](../README.md) for initial Quickstart and [config.example.toml](../config.example.toml) for every commented TOML key.)

## 1. Prerequisites

- **Workstation:** `kinveil` binary, OpenSSH (`ssh`), and optional `KINVEIL_PASSPHRASE_COMMAND` (see [Section 8](#8-environment-variables-artifact-overrides--automation)). Neither Go nor `git` is needed in normal use because bundled/prebuilt `xray` and `amneziawg-go` binaries are SHA-256-verified.
- **Target VPS nodes:** Dedicated **Debian 12 or Debian 13 (`x86_64`)** with KVM (`/dev/net/tun` required for AmneziaWG) and key-based SSH login as `root` (or passwordless `sudo`). Enable Debian `unattended-upgrades` on each VPS for OS security patches.

> [!WARNING]
> **Host firewall & `--takeover` guard:** On an unmanaged host (`/etc/kinveil/.managed` absent), `kinveil deploy` aborts if `docker`, `podman`, `firewalld`, `netfilter-persistent`, existing web proxies, active `ufw`, or non-default nftables tables exist unless `--takeover` is passed. `deploy` disables `ufw` and replaces `/etc/nftables.conf` with `flush ruleset` + `table inet kinveil` (`input` and `forward` default-`drop`). Original `/etc/nftables.conf` and `/etc/caddy/Caddyfile` are backed up once as `*.kinveil-orig` and restored on `kinveil server remove --wipe`.

---

## 2. Port Layout & Cloud Firewalls

Open active ports in your VPS provider's cloud firewall before `kinveil deploy`:

| Role / Protocol | Default Port | Purpose |
| --- | --- | --- |
| All servers | `22/tcp` (or `--ssh-port`) | Admin SSH management |
| `vpn` (`vless`) | `8443/tcp` | VLESS REALITY XHTTP (`vless-stream` / `vless-packet`) |
| `vpn` (`hysteria2`) | `443/udp` | Hysteria2 + Salamander |
| `vpn` (`amneziawg`) | `7443/udp` | AmneziaWG 3.1 (`kv0`) |
| `vpn` (`ssh-forwarding`) | `2222/tcp` | Per-user forwarding-only OpenSSH (`vpnssh<uid>`) |
| `subscription` | `80/tcp`, `443/tcp` | Caddy ACME HTTP-01 + HTTPS subscriptions |

Disabled roles or protocols do not open ports in `table inet kinveil`.

### Port `443` Under Censorship

- **Single VPS (`vpn,subscription`):** Caddy serves `HTTP/1.1` and `HTTP/2` strictly on `443/tcp`, so Hysteria2 (`443/udp`) coexists natively out of the box without proxies. Keep Caddy on `443/tcp` so client auto-refresh works on restrictive mobile/corporate networks.
- **Dedicated `vpn` nodes (no `subscription` role):** Put VLESS on `443/tcp` alongside Hysteria2 (`443/udp`):

  ```bash
  kinveil server add <ip> --label "FI Finland" --vless-sni www.example.com --vless-port 443
  kinveil server update <id> --clear-vless-port   # or --clear-ports to revert all overrides
  ```

---

## 3. Subscriptions, DNS & IPv6

Clients fetch profiles from `https://<domain>/<base-path><user-token>` and refresh every `12` hours by default (`[subscription].update_interval_hours`).

- **Inspect subscription settings:** `kinveil subscription show` (pass `--routing` to print compiled Happ and Throne deep links)
- **Manual DNS:** Point an unproxied (DNS-only) `A` record (and `AAAA` when `--ipv6` is set) directly to your `subscription` server IP before deploying.
- **Cloudflare automation:**

  ```bash
  kinveil subscription cloudflare set --zone-id <CLOUDFLARE_ZONE_ID>   # prompts securely for API token
  kinveil subscription cloudflare update --ttl 300                    # updates TTL/zone without re-entering token
  kinveil subscription cloudflare clear                               # revert to manual DNS
  ```

  Pass `--skip-dns` on `kinveil deploy` to bypass Cloudflare sync for a single run.
- **Rotate blocked domain or secret URL path:**

  ```bash
  kinveil subscription set-domain sub2.example.com --rotate-path
  kinveil subscription set-path --rotate          # or --path /custom-prefix/
  kinveil deploy
  ```

- **IPv6 notes:** Pass `--ipv6 <addr>` only if the VPS has working global IPv6 connectivity (`--clear-ipv6` removes it). `kinveil check` probes all active TCP ports (`vless`, `ssh-forwarding`, `https`) over IPv6 when `--ipv6` is set and a local IPv6 route exists. AmneziaWG (`kv0`) stays IPv4-only and rejects IPv6 forwarding in `nftables` to prevent leaks. Updating `--ipv6` keeps Hysteria2's IPv4 TLS pin intact so existing clients do not break.

---

## 4. Choosing a REALITY `--vless-sni` Target

VLESS REALITY relays unauthenticated probes on the VLESS port to `--vless-target` (default `<effective_sni>:443`) using `--vless-sni` in TLS `serverNames`:

- **Requirements:** TLS 1.3 + ALPN `h2`, low RTT from the VPS, reachable for your users without anti-bot interstitials, and **never** your `subscription` domain or a managed VPS IP (rejected by `kinveil validate`).
- Verify directly from the VPS before deploying:

  ```bash
  openssl s_client -connect dl.google.com:443 -servername dl.google.com -alpn h2 </dev/null 2>/dev/null | grep -E "Protocol|ALPN"
  # Expect both:
  # Protocol  : TLSv1.3
  # ALPN protocol: h2
  ```

- **2-layer inheritance:** Built-in `vless.sni` is unset so fleet nodes do not share one hardcoded fingerprint. Set an optional fleet default (`sni`, `target`, `xhttp_host`) under `[vless]` (or `path` under `[vless.xhttp]`) in `kinveil config`, override per server with `--vless-sni` / `--vless-target` / `--vless-xhttp-host`, or omit `--vless-sni` completely when VLESS is disabled (`[vless].enabled = false` or `--protocols` excludes `vless`).
- Changing `--vless-sni` (or `--clear-vless-sni`) automatically resets per-server `--vless-target` and `--vless-xhttp-host` overrides unless passed together in the same `server update` call.

---

## 5. Inventory, Inspection & Emergency Export

### Servers

```bash
kinveil server list
kinveil server show <id>                          # shows effective sources, host FP, Hysteria2 cert expiry, public keys
kinveil server add <ip> --label "NL Node" --roles vpn --protocols vless,hysteria2 --vless-sni www.microsoft.com --ssh-key ~/.ssh/id_kinveil
kinveil server update <id> --rename nl1 --ssh-key ~/.ssh/new_key   # or --clear-ssh-key / --clear-vless-sni / --clear-vless-target / --clear-vless-xhttp-host / --clear-note
kinveil server update <id> --protocols hysteria2,ssh-forwarding    # override config.toml protocol defaults (or --clear-protocols)
kinveil server update <id> --traffic              # enable per-server traffic accounting (--no-traffic disables & wipes)
kinveil server rotate <id> --all                  # or --vless / --hysteria2 / --amneziawg / --ssh-forwarding
kinveil server disable <id1> <id2>                # or enable / remove [--wipe] [-y]
```

On first SSH connection (or when `--ssh-host` / `--ssh-port` changes), `kinveil` reads `~/.ssh/known_hosts` or prompts you to trust the scanned host key (`--ssh-host-key "ssh-ed25519 AAAA..."` skips prompting).

### Users

```bash
kinveil user list                                 # shows UIDs, status, AmneziaWG /32 IP, creation dates, notes
kinveil user show <name>                          # non-secret details: AWG IP, vpnssh<uid>, public keys
kinveil user add alice bob [--note "..."] [--disabled]
kinveil user update alice --rename alice-laptop   # or --note "..." / --clear-note
kinveil user rotate alice --vless                 # --all | --vless | --hysteria2 | --amneziawg | --ssh-forwarding | --rotate-url
kinveil user disable <u1> <u2>                    # or enable / remove [-y]
kinveil user share alice [--url-only]
```

**Out-of-band / emergency export** (when `subscription.domain` is unreachable or setting up native tools):

```bash
kinveil user export alice --format urls [--server <id>]       # raw vless://, hysteria2://, vpn://, ssh:// lines
kinveil user export alice --format happ                       # base64 Happ subscription payload
kinveil user export alice --format throne                     # base64 Throne subscription payload
kinveil user export alice --format amneziawg [--server <id>]  # raw AmneziaWG .conf INI
kinveil user export alice --format ssh [--server <id>]        # OpenSSH key, known_hosts entry, and `ssh -N -D 1080` command
```

Destructive commands (`user remove`, `server remove`, `config --reset`, `restore`, `deploy --takeover`) prompt interactively unless `--yes` (`-y`) is supplied.

### Traffic Accounting (Opt-In)

Keep servers zero-state by default, or enable UID-keyed daily byte rollups per capped node via `--traffic` (`--no-traffic` disables and wipes on next deploy) and re-run `kinveil deploy`:

```bash
kinveil server update md1 --traffic
kinveil deploy --server md1
kinveil traffic --from 2026-11-01 --to 2026-11-30 [--server md1] [--user alice] [--by-protocol]
```

`kinveil traffic` defaults to the current UTC month (`YYYY-MM-01` .. today UTC), flushes live counters over pinned SSH so totals are up to the second, and reports both public NIC bytes (`tx` and `rx+tx`) and per-user totals sorted highest-first across all active protocols (`vless`, `hysteria2`, `amneziawg`, `ssh-forwarding`). Because proxied traffic enters and leaves the VPS, each `1 GiB` of VPN usage generates ~`1 GiB` `tx` and ~`2 GiB` `rx+tx` on the public NIC—compare whichever metric matches your VPS provider's bandwidth cap.

---

## 6. Topologies, VPS Replacement & Managed Footprint

Separate your `subscription` endpoint from high-throughput `vpn` exit nodes:

```bash
kinveil server add 203.0.113.10 --label "Sub Host" --roles subscription
kinveil server add 198.51.100.20 --label "FI Finland" --roles vpn --vless-sni <sni> --vless-port 443
kinveil deploy --dry-run
kinveil deploy
```

`kinveil deploy` converges non-subscription `vpn` nodes in parallel, syncs Cloudflare DNS, deploys the `subscription` host, verifies HTTPS subscriptions end-to-end, and finally retires stale Caddy installs or stops disabled nodes in parallel. Passing `--server <id>` targets one node and skips DNS/HTTPS verification unless `<id>` is the `subscription` server.

To replace a throttled/retired VPS without changing client subscription links:

1. Provision a fresh Debian 12/13 VPS with open cloud firewall ports and run `kinveil server add ...`.
2. If replacing the `subscription` host, update roles on the new server (`kinveil server update <new-id> --roles vpn,subscription`).
3. Remove the old node (`kinveil server remove <old-id>` if destroyed, or `--wipe` on a live host) and run `kinveil deploy`.

### Managed VPS Footprint

| Component | Managed Paths / Names | Notes |
| --- | --- | --- |
| Markers & backups | `/etc/kinveil/.managed`, `.managed-sub`, `*.kinveil-orig` | Tracks takeover state and restores original firewall/Caddyfile on `--wipe`. |
| Binaries & geodata | `/usr/local/lib/kinveil/xray/{xray,geoip.dat,geosite.dat}`, `.../awg/amneziawg-go` | SHA-256 verified before deploy; skipped via remote preflight when unchanged. |
| Xray (`kinveil-xray.service`) | `/etc/kinveil/xray.json`, `/etc/kinveil/tls/hysteria.{crt,key}` | Unprivileged system user `kinveil` (`nologin`), `CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`. |
| AmneziaWG (`kinveil-awg.service`) | `/etc/kinveil/awg/{uapi.conf,apply-uapi.sh}`, interface `kv0` | Userspace `amneziawg-go` with `RandomTrailers`, `DisableCookies`, and `/run/amneziawg` (`0700`). |
| SSH fwd (`kinveil-ssh.service`) | `/etc/kinveil/ssh/{sshd_config,host_ed25519,authorized_keys/vpnssh*}` | Forwarding-only (`[ssh_forwarding].enabled = false` by default), `AllowTcpForwarding local`, `ForceCommand /usr/sbin/nologin`, per-user `vpnssh<uid>`. |
| Host hardening | `/etc/systemd/resolved.conf.d/90-kinveil.conf`, `/etc/ssh/sshd_config.d/0-00-kinveil-admin.conf` | Disables LLMNR (`5355`) + opportunistic DoT; locks admin `sshd` to `Port` + key-only auth when `authorized_keys` is present. |
| Subscriptions (`caddy.service`) | `/etc/caddy/Caddyfile`, `/var/lib/kinveil/sub` (`0710` `root:caddy`) | `admin off`, `protocols h1 h2`, `0640` static files, `404` on unknown tokens. |
| Kernel & firewall | `/etc/nftables.conf`, `/etc/kinveil/nft-{blocked,egress}.nft`, `/etc/kinveil/firewall/*`, `/usr/local/lib/kinveil/firewall/update-firewall.sh`, `kinveil-firewall-update.{service,timer}`, `/etc/sysctl.d/9{0,1}-kinveil*.conf` | `table inet kinveil` (`input`/`forward` drop, `kv0` MSS clamp + isolation, `@egress_blocked_{v4,v6}` enforced across all 4 protocols, `output` SSRF guard for `kinveil` + `@vpnssh_users`, optional atomic timer updates, BBR + UDP buffers). |
| Traffic (`kinveil-traffic.timer`) | `/etc/kinveil/traffic/{config.env,users.conf}`, `/etc/kinveil/nft-traffic.nft`, `/usr/local/lib/kinveil/traffic/snapshot-traffic.sh`, `/var/lib/kinveil/traffic/YYYY-MM-DD.tsv` (`0700`), `kinveil-traffic{.service,.timer,-flush.service}` | Strictly opt-in per server (`--traffic`). Snapshots Xray `StatsService` (`/run/kinveil-xray/api.sock`), `nftables` `kv0`/`vpnssh` counters, and public NIC bytes into root-only UID-keyed daily UTC TSVs; wiped on `--no-traffic`, `disable`, or `--wipe`. |

---

## 7. Global Configuration & AmneziaWG CPS Tuning (`kinveil config`)

All fleet policy lives in a single commented TOML document stored encrypted inside `state.enc`:

```bash
kinveil config                    # opens ONLY config.toml in /dev/shm under $EDITOR (no keys exposed)
kinveil config --print            # print verbatim TOML with comments
kinveil config --file my.toml     # validate and replace config.toml
kinveil config --reset [--yes]    # restore built-in commented defaults
```

- **Kernel egress firewall & dynamic blocklists (`[firewall]`, `[firewall.auto_update]`):** `block_private_networks`, `block_countries`, `block_cidrs`, and `block_ip_lists` compile into `/etc/kinveil/nft-blocked.nft` (`@egress_blocked_v4` / `@egress_blocked_v6`) inside `table inet kinveil`, enforcing egress blocks in the Linux kernel across **all four VPN protocols** (`vless`, `hysteria2`, `amneziawg`, and `ssh-forwarding`) while `ct direction reply accept` allows clients in blocked countries to connect to the server. When `[firewall.auto_update].enabled = true` and country or URL IP lists are configured, `kinveil-firewall-update.timer` refreshes and atomically reloads `nftables` sets hitlessly without restarting VPN daemons.
- **Xray L7 rules & fleet DNS (`[firewall.xray]`, `[dns]`):** `[firewall.xray]` enforces BitTorrent blocking (`block_bittorrent = true`), domain/geosite selectors (`block_domains`), and remote plain-text domain blocklists (`block_domain_lists`) inside Xray (`vless` and `hysteria2`). `[dns]` configures both `[dns].xray_servers` (`https+local://` DoH) and `[dns].amneziawg_servers`.
- **Client split-tunneling (`[subscription.routing]`):** Set `bypass_countries` and/or `block_countries` (ISO 3166-1 alpha-2 codes), custom `direct_*`/`proxy_*`/`block_*` domain/IP selectors, and Split-DoH (`domestic_*` / `remote_*`) to compile native `routing` HTTP headers for both Happ (`happ://routing/onadd/...`) and Throne (`throne://route/...`).
- **AmneziaWG 3.1 CPS (`I1`..`I5`) & obfuscation:** Set `jc`, `jmin`, `jmax`, `s1..s4`, `h1..h4`, `i1..i5`, or `content_padding_addition` under `[amneziawg.obfuscation]` in `kinveil config` to override per-server random defaults (maintaining `12 <= s* <= 1024` and `148 + s1 != 92 + s2`; `header_protection_key` always remains per-server secret entropy). Toggle `random_trailers` / `disable_cookies` under `[amneziawg]` if older clients are used.
- **Traffic rollup retention (`[traffic]`):** Set `retention_days` (`90` by default, `1..=3650`) for automatic pruning of daily `/var/lib/kinveil/traffic/YYYY-MM-DD.tsv` rollups on `--traffic` servers.
- **Local inspection:** Run `kinveil debug render /dev/shm/inspect` to unpack every server bundle, decoded subscription, and compiled routing JSON locally (`--allow-non-tmpfs` outside `/dev/shm`), then run `kinveil deploy` to push changes.

---

## 8. Environment Variables, Artifact Overrides & Automation

| Variable | Effect |
| --- | --- |
| `KINVEIL_STATE` | Override vault path (`--state <PATH>`). |
| `KINVEIL_PASSPHRASE_FD` | File descriptor supplying one secret line per prompt (`/proc/self/fd/<N>` on Linux, `/dev/fd/<N>` on macOS). Takes precedence over `_COMMAND`. |
| `KINVEIL_PASSPHRASE_COMMAND` | Shell command (`sh -c`) printing the vault passphrase on stdout (`LD_PRELOAD`/`LD_LIBRARY_PATH` stripped). |
| `KINVEIL_CACHE_DIR` | Override binary artifact cache directory (`~/.cache/kinveil/artifacts`). |
| `KINVEIL_XRAY_BIN` | Local Linux `x86_64` `xray` ELF binary path (highest precedence, air-gapped override). |
| `KINVEIL_AMNEZIAWG_BIN` | Local Linux `x86_64` `amneziawg-go` ELF binary path (highest precedence, air-gapped override). |

### Pinned Runtime Artifact Overrides (`[artifacts]`)

Update `Xray-core`, `geoip.dat`/`geosite.dat`, or prebuilt `amneziawg-go` independently via `[artifacts]` in `kinveil config` (requires both `*_url` (`https://`, non-local) and 64-hex `*_sha256`—failing cleanly on digest mismatch):

- **Resolution order:** `KINVEIL_*_BIN` -> `[artifacts]` URL + SHA-256 -> local `$KINVEIL_CACHE_DIR` -> bundled release binary (`share/kinveil/artifacts`) -> built-in pinned download (plus local `git` + `go >= 1.25` fallback for `amneziawg-go` only).

**Automation examples & completions:**

```bash
export KINVEIL_PASSPHRASE_COMMAND="secret-tool lookup service kinveil account default" # Linux GNOME Keyring
export KINVEIL_PASSPHRASE_COMMAND="security find-generic-password -s kinveil -w"      # macOS Keychain
export KINVEIL_PASSPHRASE_COMMAND="pass show kinveil/vault"                           # pass
printf '%s\n%s\n' "$OLD_PASS" "$NEW_PASS" | KINVEIL_PASSPHRASE_FD=0 kinveil passwd    # non-interactive passwd
kinveil completions bash > ~/.local/share/bash-completion/completions/kinveil
```

---

## 9. Backups & Passphrase Rotation

- **Automatic rolling backups:** Every vault write saves `<state_dir>/backups/<stem>.<rev>.enc` (`0700`/`0600`), retaining the newest 20 revisions encrypted with the passphrase active when written.
- **Manual backups & restore:** `kinveil backup <path>` and `kinveil restore <path> [-y]` verify decryption and state integrity, and `restore` advances `revision` above both the current vault and `backups/`.
- **Rotate passphrase:** `kinveil passwd` re-encrypts `state.enc` with a fresh salt and nonce.

---

## 10. Health Checks & Troubleshooting

Start with `kinveil check` (parallel external TCP + IPv6 + pinned-IP HTTPS checks) and `kinveil check --ssh` (remote systemd units including `kinveil-firewall-update.timer` when active, `ss -H -uln` UDP sockets, `table inet kinveil`, and outbound TLS 1.3 + `h2` checks to active VLESS SNI targets):

- **ACME / HTTPS fails (`caddy`):** Confirm `A`/`AAAA` DNS records point directly to the `subscription` host (Cloudflare proxy **OFF**), `80/tcp` + `443/tcp` are open in the cloud firewall, and check `journalctl -u caddy -n 50 --no-pager`.
- **VLESS REALITY stalls:** Confirm `reality` OK in `kinveil check --ssh`, check VPS/client clock sync, switch between `vless-stream` and `vless-packet`, or move VLESS to `443/tcp` (`--vless-port 443`) on non-subscription `vpn` nodes. Avoid **Karing `1.2.25`** (`X25519MLKEM768` bug).
- **Hysteria2 timeouts:** Confirm `443/udp` ingress is allowed in your cloud firewall (many providers block UDP by default), and ensure Throne imports the subscription URL instead of manually escaping `tls_certificate_public_key_sha256`.
- **AmneziaWG drops or crashes:** Use an AmneziaWG 3.1-compatible client supporting `I1`..`I5`, `RandomTrailers`, and `DisableCookies`. Connect at most **1 device per user** simultaneously on `amneziawg` (create separate `alice-phone` / `alice-laptop` users when simultaneous AWG is needed). If `kinveil-awg` fails, verify `/dev/net/tun` exists (`journalctl -u kinveil-awg -n 50 --no-pager`), and lower `[amneziawg].mtu` for PPPoE links.
- **SSH forwarding (`ssh-forwarding`, disabled by default in `[ssh_forwarding]`):** Enable `[ssh_forwarding].enabled = true` in `kinveil config` globally or opt in per server via `kinveil server update <id> --protocols ...` (`ssh-forwarding` shows as `{port}/tcp(ssh-fwd)` in `check`). Happ skips `ssh://` links intentionally while Throne imports them; export raw OpenSSH keys anytime via `kinveil user export <name> --format ssh`.
- **Wrong passphrase on `restore`:** If `KINVEIL_PASSPHRASE_COMMAND` or `_FD` holds your *new* passphrase when restoring an *older* backup encrypted with a previous passphrase, unset/override it so `restore` prompts for the backup's passphrase.
