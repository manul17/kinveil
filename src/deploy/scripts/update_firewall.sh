#!/usr/bin/env bash
set -euo pipefail
umask 022

CONF_DIR="${KINVEIL_FW_CONF_DIR:-/etc/kinveil/firewall}"
OUT_NFT="${KINVEIL_NFT_BLOCKED_FILE:-/etc/kinveil/nft-blocked.nft}"
NFT_BIN="${KINVEIL_NFT_BIN:-/usr/sbin/nft}"
APPLY_LIVE="${KINVEIL_FW_APPLY_LIVE:-1}"

BASE_V4="$CONF_DIR/base-ipv4.txt"
BASE_V6="$CONF_DIR/base-ipv6.txt"
URLS_FILE="$CONF_DIR/urls.txt"

if [ ! -f "$BASE_V4" ] || [ ! -f "$BASE_V6" ] || [ ! -f "$URLS_FILE" ]; then
    echo "missing kinveil firewall config files under $CONF_DIR" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kinveil-fw.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

RAW_DYN="$TMP_DIR/raw-dyn.txt"
DYN_V4="$TMP_DIR/dyn-v4.txt"
DYN_V6="$TMP_DIR/dyn-v6.txt"
BASE_V4_CANON="$TMP_DIR/base-v4.txt"
BASE_V6_CANON="$TMP_DIR/base-v6.txt"
ALL_V4="$TMP_DIR/all-v4.txt"
ALL_V6="$TMP_DIR/all-v6.txt"
NFT_TMP="$TMP_DIR/nft-blocked.nft"
CHECK_NFT="$TMP_DIR/check.nft"
RELOAD_NFT="$TMP_DIR/reload.nft"

parse_cidr_stream() {
    local v4_dest="$1"
    local v6_dest="$2"
    awk -v v4_out="$v4_dest" -v v6_out="$v6_dest" '
    function hexval(ch,    pos) {
        pos = index("0123456789abcdef", tolower(ch))
        return pos ? pos - 1 : -1
    }
    function parse_hex16(s,    i, n, d, v) {
        n = length(s)
        if (n < 1 || n > 4) return -1
        v = 0
        for (i = 1; i <= n; i++) {
            d = hexval(substr(s, i, 1))
            if (d < 0) return -1
            v = v * 16 + d
        }
        return v
    }
    function canonical_v4(addr, pfx_str,    n, o, i, v, rem, bits, step, out) {
        n = split(addr, o, ".")
        if (n != 4) return ""
        for (i = 1; i <= 4; i++) {
            if (o[i] !~ /^[0-9]+$/ || length(o[i]) > 3) return ""
            v = o[i] + 0
            if (v < 0 || v > 255) return ""
            o[i] = v
        }
        if (pfx_str == "") {
            rem = 32
        } else {
            if (pfx_str !~ /^[0-9]+$/ || length(pfx_str) > 2) return ""
            rem = pfx_str + 0
            if (rem < 0 || rem > 32) return ""
        }
        for (i = 1; i <= 4; i++) {
            if (rem >= 8) {
                bits = 8
                rem -= 8
            } else {
                bits = rem
                rem = 0
            }
            if (bits == 0) {
                o[i] = 0
            } else if (bits < 8) {
                step = 2 ^ (8 - bits)
                o[i] = int(o[i] / step) * step
            }
        }
        out = o[1] "." o[2] "." o[3] "." o[4]
        if (pfx_str == "") {
            return out "/32"
        }
        return out "/" (pfx_str + 0)
    }
    function canonical_v6(addr, pfx_str,    last_c, v4_tail, vo, parts, np, lhs_s, rhs_s, nl, nr, lhs, rhs, missing, g, i, val, rem, bits, step, out) {
        if (addr ~ /:::/ || addr ~ /%/) return ""
        if (index(addr, ".") > 0) {
            last_c = 0
            for (i = length(addr); i >= 1; i--) {
                if (substr(addr, i, 1) == ":") {
                    last_c = i
                    break
                }
            }
            if (last_c == 0) return ""
            v4_tail = substr(addr, last_c + 1)
            if (split(v4_tail, vo, ".") != 4) return ""
            for (i = 1; i <= 4; i++) {
                if (vo[i] !~ /^[0-9]+$/ || length(vo[i]) > 3 || (vo[i] + 0) > 255) return ""
            }
            addr = substr(addr, 1, last_c) sprintf("%x:%x", (vo[1] + 0) * 256 + (vo[2] + 0), (vo[3] + 0) * 256 + (vo[4] + 0))
        }
        if (addr ~ /^:[^:]/ || addr ~ /[^:]:$/) return ""
        np = split(addr, parts, "::")
        if (np > 2) return ""
        for (i = 1; i <= 8; i++) g[i] = 0
        if (np == 2) {
            lhs_s = parts[1]
            rhs_s = parts[2]
            nl = (lhs_s == "") ? 0 : split(lhs_s, lhs, ":")
            nr = (rhs_s == "") ? 0 : split(rhs_s, rhs, ":")
            if (nl + nr >= 8) return ""
            for (i = 1; i <= nl; i++) {
                val = parse_hex16(lhs[i])
                if (val < 0) return ""
                g[i] = val
            }
            missing = 8 - nl - nr
            for (i = 1; i <= nr; i++) {
                val = parse_hex16(rhs[i])
                if (val < 0) return ""
                g[nl + missing + i] = val
            }
        } else {
            nl = split(addr, lhs, ":")
            if (nl != 8) return ""
            for (i = 1; i <= 8; i++) {
                val = parse_hex16(lhs[i])
                if (val < 0) return ""
                g[i] = val
            }
        }
        if (pfx_str == "") {
            rem = 128
        } else {
            if (pfx_str !~ /^[0-9]+$/ || length(pfx_str) > 3) return ""
            rem = pfx_str + 0
            if (rem < 0 || rem > 128) return ""
        }
        for (i = 1; i <= 8; i++) {
            if (rem >= 16) {
                bits = 16
                rem -= 16
            } else {
                bits = rem
                rem = 0
            }
            if (bits == 0) {
                g[i] = 0
            } else if (bits < 16) {
                step = 2 ^ (16 - bits)
                g[i] = int(g[i] / step) * step
            }
        }
        out = sprintf("%x:%x:%x:%x:%x:%x:%x:%x", g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8])
        if (pfx_str == "") {
            return out "/128"
        }
        return out "/" (pfx_str + 0)
    }
    BEGIN {
        printf "" > v4_out
        printf "" > v6_out
    }
    {
        line = $0
        sub(/\r$/, "", line)
        sub(/[#;].*$/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line == "") next
        ns = split(line, seg, "/")
        if (ns > 2) {
            printf "invalid CIDR entry: %s\n", line > "/dev/stderr"
            exit 2
        }
        addr = seg[1]
        pfx = (ns == 2) ? seg[2] : ""
        if (index(addr, ":") > 0) {
            c = canonical_v6(addr, pfx)
            if (c == "") {
                printf "invalid IPv6 CIDR entry: %s\n", line > "/dev/stderr"
                exit 2
            }
            print c > v6_out
        } else {
            c = canonical_v4(addr, pfx)
            if (c == "") {
                printf "invalid IPv4 CIDR entry: %s\n", line > "/dev/stderr"
                exit 2
            }
            print c > v4_out
        }
    }
    END {
        close(v4_out)
        close(v6_out)
    }
    '
}

: > "$RAW_DYN"
URL_COUNT=0
while IFS= read -r raw_url; do
    raw_url="${raw_url%$'\r'}"
    url="${raw_url#"${raw_url%%[![:space:]]*}"}"
    url="${url%"${url##*[![:space:]]}"}"
    [ -n "$url" ] || continue
    URL_COUNT=$((URL_COUNT + 1))
    curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --max-time 60 --max-filesize 33554432 -- "$url" >> "$RAW_DYN"
    printf '\n' >> "$RAW_DYN"
done < "$URLS_FILE"

if [ "$URL_COUNT" -gt 0 ]; then
    parse_cidr_stream "$DYN_V4" "$DYN_V6" < "$RAW_DYN"
    if [ ! -s "$DYN_V4" ] && [ ! -s "$DYN_V6" ]; then
        echo "dynamic firewall URLs yielded zero CIDR entries" >&2
        exit 1
    fi
else
    : > "$DYN_V4"
    : > "$DYN_V6"
fi

parse_cidr_stream "$BASE_V4_CANON" /dev/null < "$BASE_V4"
parse_cidr_stream /dev/null "$BASE_V6_CANON" < "$BASE_V6"

LC_ALL=C sort -u "$BASE_V4_CANON" "$DYN_V4" > "$ALL_V4"
LC_ALL=C sort -u "$BASE_V6_CANON" "$DYN_V6" > "$ALL_V6"

if [ ! -s "$ALL_V4" ] || [ ! -s "$ALL_V6" ]; then
    echo "refusing empty IPv4 or IPv6 firewall set" >&2
    exit 1
fi

write_set_elements() {
    local src="$1"
    awk '
    NR > 1 {
        if ((NR - 1) % 8 == 0) {
            printf ",\n            "
        } else {
            printf ", "
        }
    }
    { printf "%s", $0 }
    ' "$src"
}

{
    printf '    set egress_blocked_v4 {\n'
    printf '        type ipv4_addr\n'
    printf '        flags interval\n'
    printf '        auto-merge\n'
    printf '        elements = {\n            '
    write_set_elements "$ALL_V4"
    printf '\n        }\n'
    printf '    }\n'
    printf '    set egress_blocked_v6 {\n'
    printf '        type ipv6_addr\n'
    printf '        flags interval\n'
    printf '        auto-merge\n'
    printf '        elements = {\n            '
    write_set_elements "$ALL_V6"
    printf '\n        }\n'
    printf '    }\n'
} > "$NFT_TMP"

{
    printf 'table inet kinveil_check {\n'
    cat "$NFT_TMP"
    printf '}\n'
} > "$CHECK_NFT"
"$NFT_BIN" -c -f "$CHECK_NFT"

if [ "$APPLY_LIVE" -eq 1 ]; then
    {
        printf 'flush set inet kinveil egress_blocked_v4\n'
        printf 'add element inet kinveil egress_blocked_v4 {\n            '
        write_set_elements "$ALL_V4"
        printf '\n        }\n'
        printf 'flush set inet kinveil egress_blocked_v6\n'
        printf 'add element inet kinveil egress_blocked_v6 {\n            '
        write_set_elements "$ALL_V6"
        printf '\n        }\n'
    } > "$RELOAD_NFT"
    "$NFT_BIN" -f "$RELOAD_NFT"
fi

OUT_DIR="$(dirname "$OUT_NFT")"
mkdir -p "$OUT_DIR"
OUT_STAGE="$(mktemp "$OUT_DIR/.nft-blocked.XXXXXX")"
cp "$NFT_TMP" "$OUT_STAGE"
chmod 0644 "$OUT_STAGE"
chown root:root "$OUT_STAGE" 2>/dev/null || true
mv -f "$OUT_STAGE" "$OUT_NFT"
