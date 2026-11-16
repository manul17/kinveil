for u in kinveil-xray.service kinveil-awg.service kinveil-ssh.service; do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$u"
done
CADDY_MANAGED=0
if [ -f /etc/kinveil/.managed-sub ] || [ -f /etc/caddy/Caddyfile.kinveil-orig ]; then
    CADDY_MANAGED=1
    systemctl disable --now caddy.service >/dev/null 2>&1 || true
fi
systemctl daemon-reload || true
VPNSSH_USERS="$(awk -F: '$1 ~ /^vpnssh[0-9]+$/ {print $1}' /etc/passwd)"
printf '%s\n' "$VPNSSH_USERS" | while IFS= read -r sysuser; do
    [ -n "$sysuser" ] || continue
    pkill -KILL -u "$sysuser" >/dev/null 2>&1 || true
    userdel "$sysuser" >/dev/null 2>&1 || true
done
if id kinveil >/dev/null 2>&1; then
    pkill -KILL -u kinveil >/dev/null 2>&1 || true
    userdel kinveil >/dev/null 2>&1 || true
fi
if command -v getent >/dev/null 2>&1 && getent group kinveil >/dev/null 2>&1; then
    groupdel kinveil >/dev/null 2>&1 || true
fi
rm -rf /etc/kinveil /usr/local/lib/kinveil /var/lib/kinveil /etc/sysctl.d/90-kinveil.conf /etc/sysctl.d/91-kinveil-bbr.conf /etc/modules-load.d/kinveil.conf
if [ "$CADDY_MANAGED" -eq 1 ]; then
    if [ -f /etc/caddy/Caddyfile.kinveil-orig ]; then
        mv -f /etc/caddy/Caddyfile.kinveil-orig /etc/caddy/Caddyfile
    else
        rm -f /etc/caddy/Caddyfile
    fi
fi
if [ -f /etc/nftables.conf.kinveil-orig ]; then
    mv -f /etc/nftables.conf.kinveil-orig /etc/nftables.conf
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet kinveil >/dev/null 2>&1 || true
        nft -f /etc/nftables.conf >/dev/null 2>&1 || true
    fi
else
    rm -f /etc/nftables.conf
    systemctl disable nftables >/dev/null 2>&1 || true
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet kinveil >/dev/null 2>&1 || true
    fi
fi
sysctl --system >/dev/null 2>&1 || true
echo "wiped (admin port $ADMIN_SSH_PORT preserved)"
