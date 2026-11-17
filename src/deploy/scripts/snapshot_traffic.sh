#!/usr/bin/env bash
set -euo pipefail
umask 077

CONF_FILE="${KINVEIL_TRAFFIC_CONF:-/etc/kinveil/traffic/config.env}"
DATA_DIR="${KINVEIL_TRAFFIC_DIR:-/var/lib/kinveil/traffic}"
LOCK_FILE="${KINVEIL_TRAFFIC_LOCK:-/run/kinveil-traffic.lock}"
XRAY_BIN="${KINVEIL_XRAY_BIN:-/usr/local/lib/kinveil/xray/xray}"
XRAY_SOCK="${KINVEIL_XRAY_SOCK:-/run/kinveil-xray/api.sock}"
NFT_BIN="${KINVEIL_NFT_BIN:-/usr/sbin/nft}"
IP_BIN="${KINVEIL_IP_BIN:-ip}"
SYS_NET_DIR="${KINVEIL_SYS_NET_DIR:-/sys/class/net}"
TODAY="${KINVEIL_TRAFFIC_DATE_UTC:-$(date -u +%Y-%m-%d)}"

if [[ ! "$TODAY" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "invalid UTC traffic date: $TODAY" >&2
    exit 1
fi

if [ ! -x "$NFT_BIN" ] && [ -z "${KINVEIL_NFT_BIN:-}" ]; then
    NFT_BIN="$(command -v nft 2>/dev/null || true)"
fi

RETENTION_DAYS=90
if [ -f "$CONF_FILE" ]; then
    cfg_ret="$(awk -F= '$1 == "RETENTION_DAYS" { print $2; exit }' "$CONF_FILE" | tr -d '[:space:]')"
    if [[ "$cfg_ret" =~ ^[0-9]+$ ]] && [ "$cfg_ret" -ge 1 ]; then
        RETENTION_DAYS="$cfg_ret"
    fi
fi

mkdir -p "$DATA_DIR"
chmod 0700 "$DATA_DIR"

LOCK_DIR="$(dirname "$LOCK_FILE")"
mkdir -p "$LOCK_DIR"
exec 9>"$LOCK_FILE"
flock -w 15 9

detect_primary_iface() {
    local dev=""
    dev="$("$IP_BIN" -o -4 route show to default 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev" && i<NF) {print $(i+1); exit}}' || true)"
    if [ -z "$dev" ] || [ "$dev" = "lo" ] || [ "$dev" = "kv0" ]; then
        dev="$("$IP_BIN" -o -6 route show to default 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev" && i<NF) {print $(i+1); exit}}' || true)"
    fi
    if [ -n "$dev" ] && [ "$dev" != "lo" ] && [ "$dev" != "kv0" ]; then
        printf '%s\n' "$dev"
    fi
}

NIC_OBSERVED=0
NIC_RX_DELTA=0
NIC_TX_DELTA=0
IFACE="$(detect_primary_iface || true)"
if [ -n "$IFACE" ] && [ -r "$SYS_NET_DIR/$IFACE/statistics/rx_bytes" ] && [ -r "$SYS_NET_DIR/$IFACE/statistics/tx_bytes" ]; then
    CUR_RX="$(tr -d '[:space:]' < "$SYS_NET_DIR/$IFACE/statistics/rx_bytes")"
    CUR_TX="$(tr -d '[:space:]' < "$SYS_NET_DIR/$IFACE/statistics/tx_bytes")"
    if [[ "$CUR_RX" =~ ^[0-9]+$ ]] && [[ "$CUR_TX" =~ ^[0-9]+$ ]]; then
        NIC_OBSERVED=1
        NIC_STATE_FILE="$DATA_DIR/.nic_state"
        if [ -f "$NIC_STATE_FILE" ]; then
            PREV_IFACE=""
            PREV_RX=""
            PREV_TX=""
            read -r PREV_IFACE PREV_RX PREV_TX < "$NIC_STATE_FILE" || true
            if [ "$PREV_IFACE" = "$IFACE" ] && [[ "$PREV_RX" =~ ^[0-9]+$ ]] && [[ "$PREV_TX" =~ ^[0-9]+$ ]]; then
                if [ "$CUR_RX" -ge "$PREV_RX" ]; then
                    NIC_RX_DELTA=$((CUR_RX - PREV_RX))
                else
                    NIC_RX_DELTA="$CUR_RX"
                fi
                if [ "$CUR_TX" -ge "$PREV_TX" ]; then
                    NIC_TX_DELTA=$((CUR_TX - PREV_TX))
                else
                    NIC_TX_DELTA="$CUR_TX"
                fi
            else
                NIC_RX_DELTA="$CUR_RX"
                NIC_TX_DELTA="$CUR_TX"
            fi
        fi
        NIC_TMP="$(mktemp "$DATA_DIR/.nic_state.XXXXXX")"
        printf '%s %s %s\n' "$IFACE" "$CUR_RX" "$CUR_TX" > "$NIC_TMP"
        chmod 0600 "$NIC_TMP"
        mv -f "$NIC_TMP" "$NIC_STATE_FILE"
    fi
fi

declare -A UP_MAP=()
declare -A DOWN_MAP=()
declare -A KEY_SEEN=()

add_proto_delta() {
    local uid="$1"
    local proto="$2"
    local dir="$3"
    local val="$4"
    [[ "$uid" =~ ^[0-9]+$ ]] || return 0
    [[ "$val" =~ ^[0-9]+$ ]] || return 0
    [ "$val" -gt 0 ] || return 0
    local key="${uid}:${proto}"
    KEY_SEEN["$key"]=1
    if [ "$dir" = "up" ]; then
        UP_MAP["$key"]=$(( ${UP_MAP["$key"]:-0} + val ))
    else
        DOWN_MAP["$key"]=$(( ${DOWN_MAP["$key"]:-0} + val ))
    fi
}

DAY_FILE="$DATA_DIR/$TODAY.tsv"
NIC_RX_TOTAL="$NIC_RX_DELTA"
NIC_TX_TOTAL="$NIC_TX_DELTA"
if [ -f "$DAY_FILE" ]; then
    while IFS=$'\t' read -r kind f2 f3 f4 f5 _; do
        case "$kind" in
            nic)
                if [[ "${f2:-}" =~ ^[0-9]+$ ]] && [[ "${f3:-}" =~ ^[0-9]+$ ]]; then
                    NIC_OBSERVED=1
                    NIC_RX_TOTAL=$((NIC_RX_TOTAL + f2))
                    NIC_TX_TOTAL=$((NIC_TX_TOTAL + f3))
                fi
                ;;
            uid)
                if [[ "${f2:-}" =~ ^[0-9]+$ ]] && [ -n "${f3:-}" ] && [[ "${f4:-}" =~ ^[0-9]+$ ]] && [[ "${f5:-}" =~ ^[0-9]+$ ]]; then
                    add_proto_delta "$f2" "$f3" "up" "$f4"
                    add_proto_delta "$f2" "$f3" "down" "$f5"
                fi
                ;;
        esac
    done < "$DAY_FILE"
fi

if [ -x "$XRAY_BIN" ] && [ -S "$XRAY_SOCK" ]; then
    XRAY_OUT=""
    if XRAY_OUT="$("$XRAY_BIN" api statsquery --server="unix:$XRAY_SOCK" -reset 2>/dev/null)"; then
        while IFS=$'\t' read -r x_uid x_proto x_dir x_val; do
            add_proto_delta "$x_uid" "$x_proto" "$x_dir" "$x_val"
        done < <(printf '%s\n' "$XRAY_OUT" | awk '
        BEGIN { name = "" }
        /"name"[[:space:]]*:/ {
            line = $0
            sub(/^.*"name"[[:space:]]*:[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            name = line
        }
        /"value"[[:space:]]*:/ {
            val = $0
            sub(/^.*"value"[[:space:]]*:[[:space:]]*"?/, "", val)
            sub(/[^0-9].*$/, "", val)
            if (name ~ /^user>>>uid-[0-9]+:(vless|hysteria2)>>>traffic>>>(uplink|downlink)$/ && val ~ /^[0-9]+$/) {
                split(name, parts, ">>>")
                tag = parts[2]
                dir = parts[4]
                sub(/^uid-/, "", tag)
                split(tag, tp, ":")
                out_dir = (dir == "uplink") ? "up" : "down"
                printf "%s\t%s\t%s\t%s\n", tp[1], tp[2], out_dir, val
            }
            name = ""
        }
        /^[[:space:]]*\}/ { name = "" }
        ')
    fi
fi

if [ -n "$NFT_BIN" ] && [ -x "$NFT_BIN" ] && "$NFT_BIN" list table inet kinveil >/dev/null 2>&1; then
    NFT_OUT=""
    if NFT_OUT="$("$NFT_BIN" reset counters table inet kinveil 2>/dev/null)"; then
        while IFS=$'\t' read -r n_uid n_proto n_dir n_val; do
            add_proto_delta "$n_uid" "$n_proto" "$n_dir" "$n_val"
        done < <(printf '%s\n' "$NFT_OUT" | awk '
        BEGIN { proto = ""; dir = ""; uid = "" }
        /^[[:space:]]*counter[[:space:]]+(awg|ssh)_(up|down)_[0-9]+[[:space:]]*\{/ {
            line = $0
            sub(/^[[:space:]]*counter[[:space:]]+/, "", line)
            sub(/[[:space:]]*\{.*$/, "", line)
            split(line, parts, "_")
            proto = (parts[1] == "awg") ? "amneziawg" : "ssh-forwarding"
            dir = parts[2]
            uid = parts[3]
            next
        }
        /bytes[[:space:]]+[0-9]+/ && uid != "" {
            line = $0
            sub(/^.*bytes[[:space:]]+/, "", line)
            sub(/[^0-9].*$/, "", line)
            if (line ~ /^[0-9]+$/) {
                printf "%s\t%s\t%s\t%s\n", uid, proto, dir, line
            }
            proto = ""; dir = ""; uid = ""
            next
        }
        /^[[:space:]]*\}/ { proto = ""; dir = ""; uid = "" }
        ')
    fi
fi

TMP_DAY="$(mktemp "$DATA_DIR/.tmp.XXXXXX")"
{
    if [ "$NIC_OBSERVED" -eq 1 ] || [ "$NIC_RX_TOTAL" -gt 0 ] || [ "$NIC_TX_TOTAL" -gt 0 ]; then
        printf 'nic\t%s\t%s\n' "$NIC_RX_TOTAL" "$NIC_TX_TOTAL"
    fi
    if [ "${#KEY_SEEN[@]}" -gt 0 ]; then
        for key in "${!KEY_SEEN[@]}"; do
            u="${key%%:*}"
            p="${key#*:}"
            up="${UP_MAP["$key"]:-0}"
            down="${DOWN_MAP["$key"]:-0}"
            if [ "$up" -gt 0 ] || [ "$down" -gt 0 ]; then
                printf 'uid\t%s\t%s\t%s\t%s\n' "$u" "$p" "$up" "$down"
            fi
        done | sort -t$'\t' -k2,2n -k3,3
    fi
} > "$TMP_DAY"
chmod 0600 "$TMP_DAY"
mv -f "$TMP_DAY" "$DAY_FILE"

if CUTOFF="$(date -u -d "$TODAY - $RETENTION_DAYS days" +%Y-%m-%d 2>/dev/null)"; then
    for f in "$DATA_DIR"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].tsv; do
        [ -e "$f" ] || continue
        base="$(basename "$f" .tsv)"
        if [[ "$base" < "$CUTOFF" ]]; then
            rm -f "$f"
        fi
    done
fi
