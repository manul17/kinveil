umask 022

if [ "$(id -u)" -ne 0 ]; then
    echo "remote provisioning must run as root" >&2
    exit 1
fi
if [ "$(uname -m)" != "x86_64" ]; then
    echo "kinveil requires x86_64 (amd64) target hosts (got $(uname -m))" >&2
    exit 1
fi
if [ ! -f /etc/debian_version ]; then
    echo "kinveil requires a Debian host (/etc/debian_version missing)" >&2
    exit 1
fi
if [ ! -d /run/systemd/system ]; then
    echo "systemd is required on target Debian hosts" >&2
    exit 1
fi

# Anti-lockout guard: verify the active SSH session's local port matches admin_ssh.port.
if [ -n "${SSH_CONNECTION:-}" ]; then
    CURRENT_SSH_PORT="$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')"
    if [ -n "$CURRENT_SSH_PORT" ] && [ "$CURRENT_SSH_PORT" != "$ADMIN_SSH_PORT" ]; then
        echo "Refusing firewall apply: SSH session connected on port $CURRENT_SSH_PORT, expected admin_ssh.port=$ADMIN_SSH_PORT" >&2
        exit 1
    fi
fi

# BEGIN_TAKEOVER_GUARD
# First-install conflict guard: prevent accidental takeover of non-dedicated hosts unless --takeover is set.
check_first_install_conflicts() {
    local managed_file="$1"
    local nft_conf="$2"
    local has_sub="$3"
    local allow_takeover="$4"

    if [ -f "$managed_file" ] || [ "$allow_takeover" -eq 1 ]; then
        return 0
    fi

    local conflicts=()
    local unit
    for unit in docker.service docker.socket podman.service firewalld.service netfilter-persistent.service nginx.service apache2.service traefik.service haproxy.service x-ui.service marzban.service; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            conflicts+=("$unit is active")
        fi
    done
    if [ "$has_sub" -eq 0 ] && systemctl is-active --quiet caddy.service 2>/dev/null; then
        conflicts+=("caddy.service is active (subscription role is on another server)")
    fi
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -q 'Status: active'; then
            conflicts+=("ufw firewall is active")
        fi
    fi
    if [ -f "$nft_conf" ]; then
        local other_tables
        other_tables="$(awk '$1 == "table" { fam=$2; name=$3; sub(/\{.*/, "", name); tbl=fam " " name; if (tbl != "inet filter" && tbl != "inet kinveil") print tbl }' "$nft_conf" || true)"
        if [ -n "$other_tables" ]; then
            conflicts+=("$nft_conf defines non-default firewall tables")
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        local live_tables
        live_tables="$(nft list tables 2>/dev/null | awk '$1 == "table" { tbl=$2 " " $3; if (tbl != "inet filter" && tbl != "inet kinveil") print tbl }' || true)"
        if [ -n "$live_tables" ]; then
            conflicts+=("live nftables ruleset defines non-default firewall tables")
        fi
    fi
    if [ "${#conflicts[@]}" -gt 0 ]; then
        echo "Refusing initial kinveil install on a host with existing services/firewall:" >&2
        local c
        for c in "${conflicts[@]}"; do
            echo "  - $c" >&2
        done
        echo "Use a clean Debian 12/13 VPS, or re-run with 'kinveil deploy --takeover' to proceed anyway (kinveil replaces /etc/nftables.conf and disables ufw)." >&2
        return 1
    fi
    return 0
}
# END_TAKEOVER_GUARD

if ! check_first_install_conflicts /etc/kinveil/.managed /etc/nftables.conf "$HAS_SUB" "${ALLOW_TAKEOVER:-0}"; then
    exit 1
fi

PKGS=(nftables iproute2 openssh-server ca-certificates)
if [ "$HAS_AWG" -eq 1 ]; then
    PKGS+=(socat)
fi
if [ "$HAS_SUB" -eq 1 ]; then
    PKGS+=(caddy)
fi

MISSING=()
for pkg in "${PKGS[@]}"; do
    STATUS="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)"
    if [ "$STATUS" != "install ok installed" ]; then
        MISSING+=("$pkg")
    fi
done
if [ "${#MISSING[@]}" -gt 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=120 update -qq
    apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "${MISSING[@]}"
fi

install_if_changed() {
    local src="$1"
    local dst="$2"
    local mode="$3"
    local owner="${4:-root:root}"
    mkdir -p "$(dirname "$dst")"
    if [ ! -f "$dst" ] || ! cmp -s "$src" "$dst"; then
        local tmp
        tmp="$(mktemp "$(dirname "$dst")/.tmp.XXXXXX")"
        cp "$src" "$tmp"
        chmod "$mode" "$tmp"
        chown "$owner" "$tmp"
        mv -f "$tmp" "$dst"
        return 0
    fi
    chmod "$mode" "$dst"
    chown "$owner" "$dst"
    return 1
}

mkdir -p /etc/kinveil
chmod 0755 /etc/kinveil
chown root:root /etc/kinveil

# BEGIN_NFT_EGRESS_GENERATOR
is_valid_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        return 1
    fi
    local i oct
    for i in 1 2 3 4; do
        oct="${BASH_REMATCH[$i]}"
        if [ "$((10#$oct))" -gt 255 ]; then
            return 1
        fi
    done
    return 0
}

is_valid_unscoped_ipv6() {
    local ip="$1"
    case "$ip" in
        *%*|*:::*) return 1 ;;
        *:*) ;;
        *) return 1 ;;
    esac
    if [[ ! "$ip" =~ ^[0-9A-Fa-f:]+$ ]]; then
        return 1
    fi
    if [[ "$ip" =~ ^:[^:] ]] || [[ "$ip" =~ [^:]:$ ]]; then
        return 1
    fi
    local dbl="${ip#*::}"
    if [ "$dbl" != "$ip" ] && [[ "$dbl" == *::* ]]; then
        return 1
    fi
    local rest="$ip" part non_empty=0 total=0
    while :; do
        part="${rest%%:*}"
        total=$((total + 1))
        if [ -n "$part" ]; then
            [ "${#part}" -le 4 ] || return 1
            non_empty=$((non_empty + 1))
        fi
        [ "$rest" != "${rest#*:}" ] || break
        rest="${rest#*:}"
    done
    if [[ "$ip" == *::* ]]; then
        [ "$non_empty" -le 7 ]
    else
        [ "$total" -eq 8 ] && [ "$non_empty" -eq 8 ]
    fi
}

write_nft_egress_rules() {
    local out_file="$1"
    local resolv_file="$2"
    local xray_uid="$3"
    local sub_ipv4="$4"
    local sub_ipv6="$5"
    local active_ssh_uids="$6"
    local ipv4_list="$7"
    local ipv6_list="$8"

    if [ -z "$xray_uid" ] && [ -z "$active_ssh_uids" ]; then
        printf '    # No active Xray or vpnssh egress UIDs\n' > "$out_file"
        return 0
    fi

    local resolvers=()
    if [ -f "$resolv_file" ]; then
        local ns
        while IFS= read -r ns; do
            if is_valid_unscoped_ipv6 "$ns" || is_valid_ipv4 "$ns"; then
                resolvers+=("$ns")
            fi
        done < <(awk '$1 == "nameserver" && NF >= 2 { print $2 }' "$resolv_file")
    fi

    {
        if [ -n "$active_ssh_uids" ]; then
            printf '    set vpnssh_users { type uid; elements = { %s }; }\n' "$active_ssh_uids"
        fi
        printf '    chain output {\n'
        printf '        type filter hook output priority -10; policy accept;\n'
        printf '        ct direction reply accept\n'

        if [ -n "$xray_uid" ]; then
            local ns
            for ns in "${resolvers[@]}"; do
                if is_valid_unscoped_ipv6 "$ns"; then
                    printf '        meta skuid %s ip6 daddr %s meta l4proto { tcp, udp } th dport 53 accept\n' "$xray_uid" "$ns"
                else
                    printf '        meta skuid %s ip daddr %s meta l4proto { tcp, udp } th dport 53 accept\n' "$xray_uid" "$ns"
                fi
            done
            if [ -n "$sub_ipv4" ]; then
                printf '        meta skuid %s ip daddr %s tcp dport { 80, 443 } accept\n' "$xray_uid" "$sub_ipv4"
            fi
            if [ -n "$sub_ipv6" ]; then
                printf '        meta skuid %s ip6 daddr %s tcp dport { 80, 443 } accept\n' "$xray_uid" "$sub_ipv6"
            fi
            printf '        meta skuid %s fib daddr type local reject\n' "$xray_uid"
            printf '        meta skuid %s ip daddr { %s } reject\n' "$xray_uid" "$ipv4_list"
            printf '        meta skuid %s ip6 daddr { %s } reject\n' "$xray_uid" "$ipv6_list"
        fi

        if [ -n "$active_ssh_uids" ]; then
            local ns
            for ns in "${resolvers[@]}"; do
                if is_valid_unscoped_ipv6 "$ns"; then
                    printf '        meta skuid @vpnssh_users ip6 daddr %s meta l4proto { tcp, udp } th dport 53 accept\n' "$ns"
                else
                    printf '        meta skuid @vpnssh_users ip daddr %s meta l4proto { tcp, udp } th dport 53 accept\n' "$ns"
                fi
            done
            printf '        meta skuid @vpnssh_users fib daddr type local reject\n'
            printf '        meta skuid @vpnssh_users ip daddr { %s } reject\n' "$ipv4_list"
            printf '        meta skuid @vpnssh_users ip6 daddr { %s } reject\n' "$ipv6_list"
        fi

        printf '    }\n'
    } > "$out_file"
}
# END_NFT_EGRESS_GENERATOR

XRAY_CHANGED=0
AWG_BIN_OR_UNIT_CHANGED=0
AWG_UAPI_CHANGED=0
SSH_CHANGED=0
CADDY_CHANGED=0
XRAY_UID=""
ACTIVE_SSH_UIDS=""

if [ "$HAS_XRAY" -eq 1 ]; then
    if ! id kinveil >/dev/null 2>&1; then
        useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --password '*' --comment "kinveil Xray runtime" kinveil
    else
        XRAY_SHELL="$(getent passwd kinveil | cut -d: -f7)"
        case "$XRAY_SHELL" in
            /usr/sbin/nologin|/bin/false) ;;
            *)
                echo "Refusing to reuse existing account kinveil with unexpected shell $XRAY_SHELL" >&2
                exit 1
                ;;
        esac
    fi
    if ! getent group kinveil >/dev/null 2>&1; then
        groupadd --system kinveil
        usermod -g kinveil kinveil
    fi
    XRAY_UID="$(id -u kinveil)"

    mkdir -p /usr/local/lib/kinveil/xray /etc/kinveil/tls
    chmod 0755 /usr/local/lib/kinveil /usr/local/lib/kinveil/xray
    chown root:root /usr/local/lib/kinveil /usr/local/lib/kinveil/xray
    chmod 0750 /etc/kinveil/tls
    chown root:kinveil /etc/kinveil/tls

    if [ -f "$STAGE/bin/xray" ]; then
        if install_if_changed "$STAGE/bin/xray" /usr/local/lib/kinveil/xray/xray 0755; then XRAY_CHANGED=1; fi
    elif [ ! -x /usr/local/lib/kinveil/xray/xray ]; then
        echo "missing /usr/local/lib/kinveil/xray/xray and bin/xray omitted from bundle" >&2
        exit 1
    fi
    if [ -f "$STAGE/files/etc/kinveil/tls/hysteria.crt" ] && [ -f "$STAGE/files/etc/kinveil/tls/hysteria.key" ]; then
        if install_if_changed "$STAGE/files/etc/kinveil/tls/hysteria.crt" /etc/kinveil/tls/hysteria.crt 0640 root:kinveil; then XRAY_CHANGED=1; fi
        if install_if_changed "$STAGE/files/etc/kinveil/tls/hysteria.key" /etc/kinveil/tls/hysteria.key 0640 root:kinveil; then XRAY_CHANGED=1; fi
    else
        if [ -e /etc/kinveil/tls/hysteria.crt ] || [ -e /etc/kinveil/tls/hysteria.key ]; then
            XRAY_CHANGED=1
        fi
        rm -f /etc/kinveil/tls/hysteria.crt /etc/kinveil/tls/hysteria.key
    fi
    if ! XRAY_TEST_OUT="$(/usr/local/lib/kinveil/xray/xray run -test -config "$STAGE/files/etc/kinveil/xray.json" 2>&1)"; then
        printf '%s\n' "$XRAY_TEST_OUT" >&2
        exit 1
    fi
    if install_if_changed "$STAGE/files/etc/kinveil/xray.json" /etc/kinveil/xray.json 0640 root:kinveil; then XRAY_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-xray.service" /etc/systemd/system/kinveil-xray.service 0644; then XRAY_CHANGED=1; fi
fi

if [ "$HAS_AWG" -eq 1 ]; then
    mkdir -p /usr/local/lib/kinveil/awg /etc/kinveil/awg
    chmod 0755 /usr/local/lib/kinveil /usr/local/lib/kinveil/awg
    chown root:root /usr/local/lib/kinveil /usr/local/lib/kinveil/awg /etc/kinveil/awg
    chmod 0700 /etc/kinveil/awg

    if [ -f "$STAGE/bin/amneziawg-go" ]; then
        if install_if_changed "$STAGE/bin/amneziawg-go" /usr/local/lib/kinveil/awg/amneziawg-go 0755; then AWG_BIN_OR_UNIT_CHANGED=1; fi
    elif [ ! -x /usr/local/lib/kinveil/awg/amneziawg-go ]; then
        echo "missing /usr/local/lib/kinveil/awg/amneziawg-go and bin/amneziawg-go omitted from bundle" >&2
        exit 1
    fi
    if install_if_changed "$STAGE/files/etc/kinveil/awg/apply-uapi.sh" /etc/kinveil/awg/apply-uapi.sh 0755; then AWG_BIN_OR_UNIT_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-awg.service" /etc/systemd/system/kinveil-awg.service 0644; then AWG_BIN_OR_UNIT_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/kinveil/awg/uapi.conf" /etc/kinveil/awg/uapi.conf 0600; then AWG_UAPI_CHANGED=1; fi
fi

if [ "$HAS_SSH" -eq 1 ]; then
    mkdir -p /etc/kinveil/ssh/authorized_keys
    chmod 0755 /etc/kinveil/ssh /etc/kinveil/ssh/authorized_keys
    chown root:root /etc/kinveil/ssh /etc/kinveil/ssh/authorized_keys

    # Phase A: revoke removed or key-changed vpnssh[0-9]+ accounts BEFORE activating new state.
    for existing in /etc/kinveil/ssh/authorized_keys/vpnssh*; do
        [ -e "$existing" ] || continue
        uname="$(basename "$existing")"
        [[ "$uname" =~ ^vpnssh[0-9]+$ ]] || continue
        staged_key="$STAGE/files/etc/kinveil/ssh/authorized_keys/$uname"
        if [ ! -f "$staged_key" ] || ! cmp -s "$staged_key" "$existing"; then
            rm -f "$existing"
            if id "$uname" >/dev/null 2>&1; then
                pkill -KILL -u "$uname" >/dev/null 2>&1 || true
            fi
        fi
    done

    while IFS= read -r sysuser; do
        if [ ! -f "$STAGE/files/etc/kinveil/ssh/authorized_keys/$sysuser" ]; then
            rm -f "/etc/kinveil/ssh/authorized_keys/$sysuser"
            pkill -KILL -u "$sysuser" >/dev/null 2>&1 || true
            userdel "$sysuser" >/dev/null 2>&1 || true
        fi
    done < <(awk -F: '$1 ~ /^vpnssh[0-9]+$/ {print $1}' /etc/passwd)

    for keyfile in "$STAGE"/files/etc/kinveil/ssh/authorized_keys/vpnssh*; do
        [ -e "$keyfile" ] || continue
        uname="$(basename "$keyfile")"
        [[ "$uname" =~ ^vpnssh[0-9]+$ ]] || continue
        if ! id "$uname" >/dev/null 2>&1; then
            useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --password '*' --comment "kinveil SSH forwarding" "$uname"
        else
            CURRENT_SHELL="$(getent passwd "$uname" | cut -d: -f7)"
            if [ "$CURRENT_SHELL" != "/usr/sbin/nologin" ]; then
                echo "Refusing to reuse existing account $uname with unexpected shell $CURRENT_SHELL" >&2
                exit 1
            fi
        fi
        install_if_changed "$keyfile" "/etc/kinveil/ssh/authorized_keys/$uname" 0644 || true
        uid_num="$(id -u "$uname")"
        if [ -z "$ACTIVE_SSH_UIDS" ]; then
            ACTIVE_SSH_UIDS="$uid_num"
        else
            ACTIVE_SSH_UIDS="$ACTIVE_SSH_UIDS, $uid_num"
        fi
    done

    if install_if_changed "$STAGE/files/etc/kinveil/ssh/host_ed25519" /etc/kinveil/ssh/host_ed25519 0600; then SSH_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/kinveil/ssh/host_ed25519.pub" /etc/kinveil/ssh/host_ed25519.pub 0644; then SSH_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/kinveil/ssh/sshd_config" /etc/kinveil/ssh/sshd_config 0644; then SSH_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-ssh.service" /etc/systemd/system/kinveil-ssh.service 0644; then SSH_CHANGED=1; fi
    install -d -m 0755 -o root -g root /run/sshd
    /usr/sbin/sshd -t -f /etc/kinveil/ssh/sshd_config
fi

if [ "$HAS_XRAY" -eq 1 ] || [ "$HAS_SSH" -eq 1 ]; then
    NFT_EGRESS_TMP="$(mktemp /etc/kinveil/.nft-egress.XXXXXX)"
    write_nft_egress_rules "$NFT_EGRESS_TMP" /etc/resolv.conf "$XRAY_UID" "${CO_LOCATED_SUB_V4:-}" "${CO_LOCATED_SUB_V6:-}" "$ACTIVE_SSH_UIDS" "$PRIVATE_IPV4_LIST" "$PRIVATE_IPV6_LIST"
    chmod 0644 "$NFT_EGRESS_TMP"
    chown root:root "$NFT_EGRESS_TMP"
    mv -f "$NFT_EGRESS_TMP" /etc/kinveil/nft-egress.nft
else
    rm -f /etc/kinveil/nft-egress.nft
fi

install_if_changed "$STAGE/files/etc/sysctl.d/90-kinveil.conf" /etc/sysctl.d/90-kinveil.conf 0644 || true
sysctl --system >/dev/null 2>&1 || true
sysctl -p /etc/sysctl.d/90-kinveil.conf >/dev/null
modprobe tcp_bbr >/dev/null 2>&1 || true
if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ] && grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
    mkdir -p /etc/modules-load.d
    printf 'tcp_bbr\n' > /etc/modules-load.d/kinveil.conf
    chmod 0644 /etc/modules-load.d/kinveil.conf
    printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' > /etc/sysctl.d/91-kinveil-bbr.conf
    chmod 0644 /etc/sysctl.d/91-kinveil-bbr.conf
    sysctl -p /etc/sysctl.d/91-kinveil-bbr.conf >/dev/null 2>&1 || true
fi

# Preserve original host configs once on fresh install before kinveil mutates them.
if [ -f /etc/nftables.conf ] && [ ! -f /etc/nftables.conf.kinveil-orig ] && [ ! -f /etc/kinveil/.managed ]; then
    cp -a /etc/nftables.conf /etc/nftables.conf.kinveil-orig
fi
if [ "$HAS_SUB" -eq 1 ] && [ -f /etc/caddy/Caddyfile ] && [ ! -f /etc/caddy/Caddyfile.kinveil-orig ] && [ ! -f /etc/kinveil/.managed ]; then
    cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.kinveil-orig
fi

# Validate nftables BEFORE disabling ufw or mutating /etc/nftables.conf.
nft -c -f "$STAGE/files/etc/nftables.conf"
install_if_changed "$STAGE/files/etc/nftables.conf" /etc/nftables.conf 0644 || true
if command -v ufw >/dev/null 2>&1; then
    ufw --force disable >/dev/null 2>&1 || true
fi
systemctl enable nftables >/dev/null 2>&1 || true
nft -f /etc/nftables.conf

if [ "$HAS_SUB" -eq 1 ]; then
    install -d -m 0755 -o root -g root /var/lib/kinveil
    SUB_NEW="/var/lib/kinveil/sub.new.$$"
    SUB_OLD="/var/lib/kinveil/sub.old.$$"
    rm -rf "$SUB_NEW" "$SUB_OLD"
    mkdir -p "$SUB_NEW"
    if [ -d "$STAGE/sub" ]; then
        cp -a "$STAGE"/sub/. "$SUB_NEW"/
    fi
    chown -R root:caddy "$SUB_NEW"
    find "$SUB_NEW" -type d -exec chmod 0710 {} +
    find "$SUB_NEW" -type f -exec chmod 0640 {} +
    if [ -e /var/lib/kinveil/sub ]; then
        mv /var/lib/kinveil/sub "$SUB_OLD"
    fi
    mv "$SUB_NEW" /var/lib/kinveil/sub
    rm -rf "$SUB_OLD"

    printf 'managed-by=kinveil\n' > /etc/kinveil/.managed-sub
    chmod 0644 /etc/kinveil/.managed-sub
    chown root:root /etc/kinveil/.managed-sub

    if install_if_changed "$STAGE/files/etc/caddy/Caddyfile" /etc/caddy/Caddyfile 0644; then CADDY_CHANGED=1; fi
    if ! CADDY_TEST_OUT="$(caddy validate --config /etc/caddy/Caddyfile 2>&1)"; then
        printf '%s\n' "$CADDY_TEST_OUT" >&2
        exit 1
    fi
fi

if [ "$HAS_XRAY" -eq 0 ]; then
    systemctl disable --now kinveil-xray.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kinveil-xray.service
    rm -rf /etc/kinveil/xray.json /etc/kinveil/tls /usr/local/lib/kinveil/xray
    if id kinveil >/dev/null 2>&1; then
        pkill -KILL -u kinveil >/dev/null 2>&1 || true
        userdel kinveil >/dev/null 2>&1 || true
    fi
    if command -v getent >/dev/null 2>&1 && getent group kinveil >/dev/null 2>&1; then
        groupdel kinveil >/dev/null 2>&1 || true
    fi
fi

if [ "$HAS_AWG" -eq 0 ]; then
    systemctl disable --now kinveil-awg.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kinveil-awg.service
    rm -rf /etc/kinveil/awg /usr/local/lib/kinveil/awg
fi

if [ "$HAS_XRAY" -eq 0 ] && [ "$HAS_AWG" -eq 0 ]; then
    rmdir /usr/local/lib/kinveil >/dev/null 2>&1 || true
fi

if [ "$HAS_SSH" -eq 0 ]; then
    systemctl disable --now kinveil-ssh.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kinveil-ssh.service
    rm -rf /etc/kinveil/ssh
    while IFS= read -r sysuser; do
        pkill -KILL -u "$sysuser" >/dev/null 2>&1 || true
        userdel "$sysuser" >/dev/null 2>&1 || true
    done < <(awk -F: '$1 ~ /^vpnssh[0-9]+$/ {print $1}' /etc/passwd)
fi

systemctl daemon-reload

if [ "$HAS_XRAY" -eq 1 ]; then
    systemctl enable kinveil-xray.service >/dev/null 2>&1 || true
    if [ "$XRAY_CHANGED" -eq 1 ] || ! systemctl is-active --quiet kinveil-xray.service; then
        systemctl restart kinveil-xray.service
    fi
fi

if [ "$HAS_AWG" -eq 1 ]; then
    systemctl enable kinveil-awg.service >/dev/null 2>&1 || true
    if [ "$AWG_BIN_OR_UNIT_CHANGED" -eq 1 ] || ! systemctl is-active --quiet kinveil-awg.service; then
        systemctl restart kinveil-awg.service
    elif [ "$AWG_UAPI_CHANGED" -eq 1 ]; then
        /etc/kinveil/awg/apply-uapi.sh || systemctl restart kinveil-awg.service
    fi
fi

if [ "$HAS_SSH" -eq 1 ]; then
    systemctl enable kinveil-ssh.service >/dev/null 2>&1 || true
    if [ "$SSH_CHANGED" -eq 1 ] || ! systemctl is-active --quiet kinveil-ssh.service; then
        systemctl restart kinveil-ssh.service
    fi
fi

if [ "$HAS_SUB" -eq 1 ]; then
    systemctl enable caddy.service >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet caddy.service; then
        systemctl start caddy.service
    elif [ "$CADDY_CHANGED" -eq 1 ]; then
        systemctl restart caddy.service
    fi
elif [ "$DEFER_CADDY_RETIRE" -eq 0 ]; then
    if [ -f /etc/kinveil/.managed-sub ]; then
        systemctl disable --now caddy.service >/dev/null 2>&1 || true
    fi
    rm -rf /var/lib/kinveil/sub /etc/kinveil/.managed-sub
fi

if [ ! -f /etc/kinveil/.managed ]; then
    printf 'managed-by=kinveil\n' > /etc/kinveil/.managed
    chmod 0644 /etc/kinveil/.managed
    chown root:root /etc/kinveil/.managed
fi

# Verify runtime state.
require_active() {
    local unit="$1"
    if ! systemctl is-active --quiet "$unit"; then
        echo "Service failed to become active: $unit" >&2
        journalctl -u "$unit" -n 15 --no-pager >&2 || true
        exit 1
    fi
}

if [ "$HAS_XRAY" -eq 1 ]; then
    require_active kinveil-xray.service
fi
if [ "$HAS_AWG" -eq 1 ]; then
    require_active kinveil-awg.service
fi
if [ "$HAS_SSH" -eq 1 ]; then
    require_active kinveil-ssh.service
fi
if [ "$HAS_SUB" -eq 1 ]; then
    require_active caddy.service
fi
ss -H -lntu >/dev/null
echo "deploy_ok"
