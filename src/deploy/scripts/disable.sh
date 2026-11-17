umask 022
if [ "$(id -u)" -ne 0 ]; then exit 1; fi
if [ -n "${SSH_CONNECTION:-}" ]; then
    CURRENT_SSH_PORT="$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')"
    if [ -n "$CURRENT_SSH_PORT" ] && [ "$CURRENT_SSH_PORT" != "$ADMIN_SSH_PORT" ]; then
        echo "Refusing firewall apply on mismatched SSH port" >&2
        exit 1
    fi
fi
for u in kinveil-traffic.timer kinveil-traffic.service kinveil-traffic-flush.service kinveil-firewall-update.timer kinveil-firewall-update.service kinveil-xray.service kinveil-awg.service kinveil-ssh.service; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
done
if [ -f /etc/kinveil/.managed-sub ]; then
    systemctl disable --now caddy.service >/dev/null 2>&1 || true
fi
while IFS= read -r sysuser; do
    pkill -KILL -u "$sysuser" >/dev/null 2>&1 || true
    userdel "$sysuser" >/dev/null 2>&1 || true
done < <(awk -F: '$1 ~ /^vpnssh[0-9]+$/ {print $1}' /etc/passwd)
rm -rf /var/lib/kinveil/sub /var/lib/kinveil/traffic /etc/kinveil/xray.json /etc/kinveil/tls /etc/kinveil/awg /etc/kinveil/ssh /etc/kinveil/firewall /etc/kinveil/traffic /etc/kinveil/nft-blocked.nft /etc/kinveil/nft-egress.nft /etc/kinveil/nft-traffic.nft /etc/kinveil/.managed-sub /run/kinveil-traffic.lock
rm -f /etc/systemd/system/kinveil-firewall-update.timer /etc/systemd/system/kinveil-firewall-update.service /etc/systemd/system/kinveil-traffic.timer /etc/systemd/system/kinveil-traffic.service /etc/systemd/system/kinveil-traffic-flush.service
rm -rf /usr/local/lib/kinveil/firewall /usr/local/lib/kinveil/traffic
rmdir /var/lib/kinveil >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
install -m 0644 "$STAGE/files/etc/sysctl.d/90-kinveil.conf" /etc/sysctl.d/90-kinveil.conf
sysctl -p /etc/sysctl.d/90-kinveil.conf >/dev/null 2>&1 || true
nft -c -f "$STAGE/files/etc/nftables.conf"
install -m 0644 "$STAGE/files/etc/nftables.conf" /etc/nftables.conf
nft -f /etc/nftables.conf
echo "stopped_ok"
