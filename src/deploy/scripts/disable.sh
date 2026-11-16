umask 022
if [ "$(id -u)" -ne 0 ]; then exit 1; fi
if [ -n "${SSH_CONNECTION:-}" ]; then
    CURRENT_SSH_PORT="$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')"
    if [ -n "$CURRENT_SSH_PORT" ] && [ "$CURRENT_SSH_PORT" != "$ADMIN_SSH_PORT" ]; then
        echo "Refusing firewall apply on mismatched SSH port" >&2
        exit 1
    fi
fi
for u in kinveil-xray.service kinveil-awg.service kinveil-ssh.service; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
done
if [ -f /etc/kinveil/.managed-sub ]; then
    systemctl disable --now caddy.service >/dev/null 2>&1 || true
fi
while IFS= read -r sysuser; do
    pkill -KILL -u "$sysuser" >/dev/null 2>&1 || true
    userdel "$sysuser" >/dev/null 2>&1 || true
done < <(awk -F: '$1 ~ /^vpnssh[0-9]+$/ {print $1}' /etc/passwd)
rm -rf /var/lib/kinveil/sub /etc/kinveil/xray.json /etc/kinveil/tls /etc/kinveil/awg /etc/kinveil/ssh /etc/kinveil/nft-egress.nft /etc/kinveil/.managed-sub
nft -c -f "$STAGE/files/etc/nftables.conf"
cp "$STAGE/files/etc/nftables.conf" /etc/nftables.conf
chmod 0644 /etc/nftables.conf
nft -f /etc/nftables.conf
echo "stopped_ok"
