use std::fmt::Write as _;

use anyhow::Result;

use crate::render::firewall::collect_awg_traffic_users;
use crate::state::State;

pub fn render_traffic_config_env(retention_days: u32) -> String {
    format!("RETENTION_DAYS={retention_days}\n")
}

pub fn render_traffic_users_conf(state: &State) -> Result<String> {
    let mut out = String::new();
    for (uid, ip) in collect_awg_traffic_users(state)? {
        let _ = writeln!(out, "{uid} {ip}");
    }
    Ok(out)
}

pub fn render_traffic_service() -> String {
    r#"[Unit]
Description=Kinveil traffic counter snapshot
After=network-online.target nftables.service

[Service]
Type=oneshot
ExecStart=/usr/local/lib/kinveil/traffic/snapshot-traffic.sh
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/kinveil /run
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
"#
    .to_owned()
}

pub fn render_traffic_timer() -> String {
    r#"[Unit]
Description=Periodic Kinveil traffic counter snapshot

[Timer]
OnCalendar=*-*-* *:00,15,30,45:00 UTC
OnCalendar=*-*-* 23:59:50 UTC
AccuracySec=5s
Persistent=true

[Install]
WantedBy=timers.target
"#
    .to_owned()
}

pub fn render_traffic_flush_service(has_xray: bool) -> String {
    let (after_xray, part_of) = if has_xray {
        (" kinveil-xray.service", "\nPartOf=kinveil-xray.service")
    } else {
        ("", "")
    };
    format!(
        r#"[Unit]
Description=Kinveil traffic counter flush on service stop
After=nftables.service{after_xray}{part_of}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
ExecStop=/usr/local/lib/kinveil/traffic/snapshot-traffic.sh
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/kinveil /run
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
"#
    )
}
