SOCK="/var/run/amneziawg/kv0.sock"
CONF="/etc/kinveil/awg/uapi.conf"

for _ in $(seq 1 50); do
    if [ -S "$SOCK" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S "$SOCK" ]; then
    echo "Timed out waiting for $SOCK" >&2
    exit 1
fi

RESP="$(socat - "UNIX-CONNECT:$SOCK" < "$CONF")"
if ! printf '%s\n' "$RESP" | grep -qx 'errno=0'; then
    echo "AmneziaWG UAPI rejected configuration: $RESP" >&2
    exit 1
fi

ip -4 addr replace "$SERVER_CIDR" dev kv0
ip link set mtu "$AWG_MTU" up dev kv0
