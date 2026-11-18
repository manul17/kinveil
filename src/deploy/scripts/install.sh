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

# shellcheck disable=SC2153
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
if [ "$HAS_FW_UPDATE" -eq 1 ]; then
    PKGS+=(curl)
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

write_nft_egress_subject() {
    local subject="$1"
    local sub_ipv4="$2"
    local sub_ipv6="$3"
    shift 3
    local ns
    for ns in "$@"; do
        if is_valid_unscoped_ipv6 "$ns"; then
            printf '        %s ip6 daddr %s meta l4proto { tcp, udp } th dport 53 accept\n' "$subject" "$ns"
        else
            printf '        %s ip daddr %s meta l4proto { tcp, udp } th dport 53 accept\n' "$subject" "$ns"
        fi
    done
    if [ -n "$sub_ipv4" ]; then
        printf '        %s ip daddr %s tcp dport { 80, 443 } accept\n' "$subject" "$sub_ipv4"
    fi
    if [ -n "$sub_ipv6" ]; then
        printf '        %s ip6 daddr %s tcp dport { 80, 443 } accept\n' "$subject" "$sub_ipv6"
    fi
    printf '        %s fib daddr type local reject\n' "$subject"
    printf '        %s ip daddr @egress_blocked_v4 reject\n' "$subject"
    printf '        %s ip6 daddr @egress_blocked_v6 reject\n' "$subject"
}

write_nft_egress_rules() {
    local out_file="$1"
    local resolv_file="$2"
    local xray_uid="$3"
    local sub_ipv4="$4"
    local sub_ipv6="$5"
    local active_ssh_uids="$6"

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
            write_nft_egress_subject "meta skuid $xray_uid" "$sub_ipv4" "$sub_ipv6" ${resolvers[@]+"${resolvers[@]}"}
        fi

        if [ -n "$active_ssh_uids" ]; then
            write_nft_egress_subject "meta skuid @vpnssh_users" "$sub_ipv4" "$sub_ipv6" ${resolvers[@]+"${resolvers[@]}"}
        fi

        printf '    }\n'
    } > "$out_file"
}
# END_NFT_EGRESS_GENERATOR

# BEGIN_NFT_TRAFFIC_GENERATOR
write_nft_map_block() {
    local name="$1"
    local map_type="$2"
    shift 2
    local count="$#"
    local i=0 entry
    printf '    map %s {\n' "$name"
    printf '        type %s\n' "$map_type"
    printf '        elements = {\n'
    for entry in "$@"; do
        i=$((i + 1))
        if [ "$i" -lt "$count" ]; then
            printf '            %s,\n' "$entry"
        else
            printf '            %s\n' "$entry"
        fi
    done
    printf '        }\n'
    printf '    }\n'
}

write_nft_traffic_rules() {
    local out_file="$1"
    local awg_enabled="$2"
    local users_conf="$3"
    local ssh_enabled="$4"
    local ssh_uid_pairs="$5"

    local awg_uids=() awg_ips=()
    if [ "$awg_enabled" -eq 1 ] && [ -f "$users_conf" ]; then
        local u ip
        while read -r u ip; do
            if [ -z "$u" ] || [ -z "$ip" ]; then
                continue
            fi
            awg_uids+=("$u")
            awg_ips+=("$ip")
        done < <(awk 'NF >= 2 && $1 ~ /^[0-9]+$/ { print $1, $2 }' "$users_conf" | LC_ALL=C sort -n -u -k1,1)
    fi

    local ssh_uids=() ssh_skuids=()
    if [ "$ssh_enabled" -eq 1 ] && [ -n "$ssh_uid_pairs" ]; then
        local su sk
        while IFS=: read -r su sk; do
            if [ -z "$su" ] || [ -z "$sk" ]; then
                continue
            fi
            [ "$su" -gt 0 ] || continue
            ssh_uids+=("$su")
            ssh_skuids+=("$sk")
        done < <(tr ' ' '\n' <<< "$ssh_uid_pairs" | awk -F: 'NF == 2 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ { print $1 ":" $2 }' | LC_ALL=C sort -t: -n -u -k1,1)
    fi

    if [ "${#awg_uids[@]}" -eq 0 ] && [ "${#ssh_uids[@]}" -eq 0 ]; then
        printf '    # No active nftables traffic counters\n' > "$out_file"
        return 0
    fi

    {
        local idx u ip su sk hex
        if [ "${#awg_uids[@]}" -gt 0 ]; then
            for u in "${awg_uids[@]}"; do
                printf '    counter awg_up_%s {}\n' "$u"
                printf '    counter awg_down_%s {}\n' "$u"
            done
        fi
        if [ "${#ssh_uids[@]}" -gt 0 ]; then
            for su in "${ssh_uids[@]}"; do
                printf '    counter ssh_up_%s {}\n' "$su"
                printf '    counter ssh_down_%s {}\n' "$su"
            done
        fi

        if [ "${#awg_uids[@]}" -gt 0 ]; then
            local awg_up_entries=() awg_down_entries=()
            for ((idx = 0; idx < ${#awg_uids[@]}; idx++)); do
                u="${awg_uids[$idx]}"
                ip="${awg_ips[$idx]}"
                awg_up_entries+=("$ip : \"awg_up_$u\"")
                awg_down_entries+=("$ip : \"awg_down_$u\"")
            done
            write_nft_map_block "awg_up_acct" "ipv4_addr : counter" "${awg_up_entries[@]}"
            write_nft_map_block "awg_down_acct" "ipv4_addr : counter" "${awg_down_entries[@]}"
            printf '    chain acct_forward {\n'
            printf '        type filter hook forward priority 5; policy accept;\n'
            printf '        iifname "kv0" counter name ip saddr map @awg_up_acct\n'
            printf '        oifname "kv0" counter name ip daddr map @awg_down_acct\n'
            printf '    }\n'
        fi

        if [ "${#ssh_uids[@]}" -gt 0 ]; then
            local ssh_mark_entries=() ssh_up_entries=() ssh_down_entries=()
            for ((idx = 0; idx < ${#ssh_uids[@]}; idx++)); do
                su="${ssh_uids[$idx]}"
                sk="${ssh_skuids[$idx]}"
                hex="$(printf '0x%x' "$su")"
                ssh_mark_entries+=("$sk : $hex")
                ssh_up_entries+=("$hex : \"ssh_up_$su\"")
                ssh_down_entries+=("$hex : \"ssh_down_$su\"")
            done
            write_nft_map_block "ssh_uid_mark" "uid : mark" "${ssh_mark_entries[@]}"
            write_nft_map_block "ssh_up_acct" "mark : counter" "${ssh_up_entries[@]}"
            write_nft_map_block "ssh_down_acct" "mark : counter" "${ssh_down_entries[@]}"
            printf '    chain acct_output {\n'
            printf '        type filter hook output priority 5; policy accept;\n'
            printf '        ct state new ct direction original ct mark set meta skuid map @ssh_uid_mark\n'
            printf '        ct mark != 0 ct direction original counter name ct mark map @ssh_up_acct\n'
            printf '    }\n'
            printf '    chain acct_input {\n'
            printf '        type filter hook input priority 5; policy accept;\n'
            printf '        ct mark != 0 ct direction reply counter name ct mark map @ssh_down_acct\n'
            printf '    }\n'
        fi
    } > "$out_file"
}
# END_NFT_TRAFFIC_GENERATOR

XRAY_CHANGED=0
AWG_BIN_OR_UNIT_CHANGED=0
AWG_UAPI_CHANGED=0
SSH_CHANGED=0
CADDY_CHANGED=0
FW_TIMER_CHANGED=0
TRAFFIC_CHANGED=0
XRAY_UID=""
ACTIVE_SSH_UIDS=""
SSH_UID_PAIRS=""

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
    for dat in geoip.dat geosite.dat; do
        if [ -f "$STAGE/bin/$dat" ]; then
            if install_if_changed "$STAGE/bin/$dat" "/usr/local/lib/kinveil/xray/$dat" 0644; then XRAY_CHANGED=1; fi
        fi
    done
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
        pair="${uname#vpnssh}:$uid_num"
        if [ -z "$ACTIVE_SSH_UIDS" ]; then
            ACTIVE_SSH_UIDS="$uid_num"
            SSH_UID_PAIRS="$pair"
        else
            ACTIVE_SSH_UIDS="$ACTIVE_SSH_UIDS, $uid_num"
            SSH_UID_PAIRS="$SSH_UID_PAIRS $pair"
        fi
    done

    if install_if_changed "$STAGE/files/etc/kinveil/ssh/host_ed25519" /etc/kinveil/ssh/host_ed25519 0600; then SSH_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/kinveil/ssh/host_ed25519.pub" /etc/kinveil/ssh/host_ed25519.pub 0644; then SSH_CHANGED=1; fi
    install -d -m 0755 -o root -g root /run/sshd
    /usr/sbin/sshd -t -f "$STAGE/files/etc/kinveil/ssh/sshd_config"
    if install_if_changed "$STAGE/files/etc/kinveil/ssh/sshd_config" /etc/kinveil/ssh/sshd_config 0644; then SSH_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-ssh.service" /etc/systemd/system/kinveil-ssh.service 0644; then SSH_CHANGED=1; fi
fi

if [ "$HAS_XRAY" -eq 1 ] || [ "$HAS_SSH" -eq 1 ]; then
    NFT_EGRESS_TMP="$(mktemp /etc/kinveil/.nft-egress.XXXXXX)"
    write_nft_egress_rules "$NFT_EGRESS_TMP" /etc/resolv.conf "$XRAY_UID" "${CO_LOCATED_SUB_V4:-}" "${CO_LOCATED_SUB_V6:-}" "$ACTIVE_SSH_UIDS"
    chmod 0644 "$NFT_EGRESS_TMP"
    chown root:root "$NFT_EGRESS_TMP"
    mv -f "$NFT_EGRESS_TMP" /etc/kinveil/nft-egress.nft
else
    rm -f /etc/kinveil/nft-egress.nft
fi

if [ -f "$STAGE/files/etc/systemd/resolved.conf.d/90-kinveil.conf" ] && systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
    if install_if_changed "$STAGE/files/etc/systemd/resolved.conf.d/90-kinveil.conf" /etc/systemd/resolved.conf.d/90-kinveil.conf 0644; then
        systemctl restart systemd-resolved.service || true
    fi
fi

if [ -f "$STAGE/files/etc/ssh/sshd_config.d/0-00-kinveil-admin.conf" ] && grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
    ADMIN_SSH_HOME=""
    if [ -n "${ADMIN_SSH_USER:-}" ]; then
        ADMIN_SSH_HOME="$(getent passwd "$ADMIN_SSH_USER" 2>/dev/null | cut -d: -f6 || true)"
    fi
    if [ -n "$ADMIN_SSH_HOME" ] && [ -s "$ADMIN_SSH_HOME/.ssh/authorized_keys" ]; then
        if install_if_changed "$STAGE/files/etc/ssh/sshd_config.d/0-00-kinveil-admin.conf" /etc/ssh/sshd_config.d/0-00-kinveil-admin.conf 0644; then
            install -d -m 0755 -o root -g root /run/sshd
            if /usr/sbin/sshd -t >/dev/null 2>&1; then
                systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service 2>/dev/null || true
            else
                rm -f /etc/ssh/sshd_config.d/0-00-kinveil-admin.conf
                echo "Reverted invalid admin sshd drop-in after sshd -t failure" >&2
                exit 1
            fi
        fi
    fi
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
if [ "$HAS_SUB" -eq 1 ] && [ -f /etc/caddy/Caddyfile ] && [ ! -f /etc/caddy/Caddyfile.kinveil-orig ] && [ ! -f /etc/kinveil/.managed-sub ]; then
    cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.kinveil-orig
fi

if [ "$HAS_VPN" -eq 1 ]; then
    install_if_changed "$STAGE/files/etc/kinveil/nft-blocked.nft" /etc/kinveil/nft-blocked.nft 0644 || true
else
    rm -f /etc/kinveil/nft-blocked.nft
fi

if [ "$HAS_FW_UPDATE" -eq 1 ]; then
    mkdir -p /usr/local/lib/kinveil/firewall /etc/kinveil/firewall
    chmod 0755 /usr/local/lib/kinveil /usr/local/lib/kinveil/firewall /etc/kinveil/firewall
    chown root:root /usr/local/lib/kinveil /usr/local/lib/kinveil/firewall /etc/kinveil/firewall
    install_if_changed "$STAGE/bin/update-firewall.sh" /usr/local/lib/kinveil/firewall/update-firewall.sh 0755 || true
    install_if_changed "$STAGE/files/etc/kinveil/firewall/base-ipv4.txt" /etc/kinveil/firewall/base-ipv4.txt 0644 || true
    install_if_changed "$STAGE/files/etc/kinveil/firewall/base-ipv6.txt" /etc/kinveil/firewall/base-ipv6.txt 0644 || true
    install_if_changed "$STAGE/files/etc/kinveil/firewall/urls.txt" /etc/kinveil/firewall/urls.txt 0644 || true
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-firewall-update.service" /etc/systemd/system/kinveil-firewall-update.service 0644; then FW_TIMER_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-firewall-update.timer" /etc/systemd/system/kinveil-firewall-update.timer 0644; then FW_TIMER_CHANGED=1; fi
fi

if [ "$HAS_TRAFFIC" -eq 1 ]; then
    if [ -x /usr/local/lib/kinveil/traffic/snapshot-traffic.sh ]; then
        /usr/local/lib/kinveil/traffic/snapshot-traffic.sh || true
    fi
    mkdir -p /usr/local/lib/kinveil/traffic /etc/kinveil/traffic /var/lib/kinveil /var/lib/kinveil/traffic
    chmod 0755 /usr/local/lib/kinveil /usr/local/lib/kinveil/traffic /var/lib/kinveil
    chmod 0700 /etc/kinveil/traffic /var/lib/kinveil/traffic
    chown root:root /usr/local/lib/kinveil /usr/local/lib/kinveil/traffic /etc/kinveil/traffic /var/lib/kinveil /var/lib/kinveil/traffic
    install_if_changed "$STAGE/bin/snapshot-traffic.sh" /usr/local/lib/kinveil/traffic/snapshot-traffic.sh 0755 || true
    install_if_changed "$STAGE/files/etc/kinveil/traffic/config.env" /etc/kinveil/traffic/config.env 0600 || true
    install_if_changed "$STAGE/files/etc/kinveil/traffic/users.conf" /etc/kinveil/traffic/users.conf 0600 || true
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-traffic.service" /etc/systemd/system/kinveil-traffic.service 0644; then TRAFFIC_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-traffic.timer" /etc/systemd/system/kinveil-traffic.timer 0644; then TRAFFIC_CHANGED=1; fi
    if install_if_changed "$STAGE/files/etc/systemd/system/kinveil-traffic-flush.service" /etc/systemd/system/kinveil-traffic-flush.service 0644; then TRAFFIC_CHANGED=1; fi
    NFT_TRAFFIC_TMP="$(mktemp /etc/kinveil/.nft-traffic.XXXXXX)"
    write_nft_traffic_rules "$NFT_TRAFFIC_TMP" "$HAS_AWG" /etc/kinveil/traffic/users.conf "$HAS_SSH" "$SSH_UID_PAIRS"
    chmod 0644 "$NFT_TRAFFIC_TMP"
    chown root:root "$NFT_TRAFFIC_TMP"
    mv -f "$NFT_TRAFFIC_TMP" /etc/kinveil/nft-traffic.nft
else
    rm -f /etc/kinveil/nft-traffic.nft
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

    if ! CADDY_TEST_OUT="$(caddy validate --config "$STAGE/files/etc/caddy/Caddyfile" --adapter caddyfile 2>&1)"; then
        printf '%s\n' "$CADDY_TEST_OUT" >&2
        exit 1
    fi
    if install_if_changed "$STAGE/files/etc/caddy/Caddyfile" /etc/caddy/Caddyfile 0644; then CADDY_CHANGED=1; fi
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

if [ "$HAS_FW_UPDATE" -eq 0 ]; then
    systemctl disable --now kinveil-firewall-update.timer kinveil-firewall-update.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kinveil-firewall-update.timer /etc/systemd/system/kinveil-firewall-update.service
    rm -rf /etc/kinveil/firewall /usr/local/lib/kinveil/firewall
fi

if [ "$HAS_TRAFFIC" -eq 0 ]; then
    systemctl disable --now kinveil-traffic.timer kinveil-traffic.service kinveil-traffic-flush.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kinveil-traffic.timer /etc/systemd/system/kinveil-traffic.service /etc/systemd/system/kinveil-traffic-flush.service /etc/kinveil/nft-traffic.nft /run/kinveil-traffic.lock
    rm -rf /etc/kinveil/traffic /usr/local/lib/kinveil/traffic /var/lib/kinveil/traffic
fi

if [ "$HAS_XRAY" -eq 0 ] && [ "$HAS_AWG" -eq 0 ] && [ "$HAS_FW_UPDATE" -eq 0 ] && [ "$HAS_TRAFFIC" -eq 0 ]; then
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

if [ "$HAS_SUB" -eq 0 ] && [ "$DEFER_CADDY_RETIRE" -eq 0 ]; then
    if [ -f /etc/kinveil/.managed-sub ]; then
        systemctl disable --now caddy.service >/dev/null 2>&1 || true
    fi
    rm -rf /var/lib/kinveil/sub /etc/kinveil/.managed-sub
fi

if [ "$HAS_SUB" -eq 0 ] && [ "$HAS_TRAFFIC" -eq 0 ]; then
    rmdir /var/lib/kinveil >/dev/null 2>&1 || true
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

if [ "$HAS_FW_UPDATE" -eq 1 ]; then
    systemctl enable kinveil-firewall-update.timer >/dev/null 2>&1 || true
    if [ "$FW_TIMER_CHANGED" -eq 1 ] || ! systemctl is-active --quiet kinveil-firewall-update.timer; then
        systemctl restart kinveil-firewall-update.timer
    fi
fi

if [ "$HAS_SUB" -eq 1 ]; then
    systemctl enable caddy.service >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet caddy.service; then
        systemctl start caddy.service
    elif [ "$CADDY_CHANGED" -eq 1 ]; then
        systemctl restart caddy.service
    fi
fi

if [ "$HAS_TRAFFIC" -eq 1 ]; then
    systemctl enable kinveil-traffic.timer kinveil-traffic-flush.service >/dev/null 2>&1 || true
    if [ "$TRAFFIC_CHANGED" -eq 1 ] || ! systemctl is-active --quiet kinveil-traffic.timer; then
        systemctl restart kinveil-traffic.timer
    fi
    if [ "$TRAFFIC_CHANGED" -eq 1 ] || ! systemctl is-active --quiet kinveil-traffic-flush.service; then
        systemctl restart kinveil-traffic-flush.service
    fi
    /usr/local/lib/kinveil/traffic/snapshot-traffic.sh
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
if [ "$HAS_FW_UPDATE" -eq 1 ]; then
    require_active kinveil-firewall-update.timer
fi
if [ "$HAS_SUB" -eq 1 ]; then
    require_active caddy.service
fi
if [ "$HAS_TRAFFIC" -eq 1 ]; then
    require_active kinveil-traffic.timer
    require_active kinveil-traffic-flush.service
fi
ss -H -lntu >/dev/null
echo "deploy_ok"
