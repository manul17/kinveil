use anyhow::Result;

use crate::state::{Server, State};

pub fn render_sshd_config(state: &State, server: &Server) -> Result<String> {
    let port = server
        .effective_config(&state.settings, false)
        .ssh_forwarding_port;
    let mut listen_lines = String::from("ListenAddress 0.0.0.0\n");
    if server.public_ipv6.is_some() {
        listen_lines.push_str("ListenAddress ::\n");
    }
    Ok(format!(
        r#"Port {port}
{listen_lines}HostKey /etc/kinveil/ssh/host_ed25519
PidFile /run/kinveil-ssh.pid
AllowUsers vpnssh*
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
AuthorizedKeysFile /etc/kinveil/ssh/authorized_keys/%u
AllowTcpForwarding local
AllowStreamLocalForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
PermitUserRC no
GatewayPorts no
MaxSessions 0
ForceCommand /usr/sbin/nologin
LoginGraceTime 20
MaxAuthTries 3
MaxStartups 10:30:60
ClientAliveInterval 30
ClientAliveCountMax 3
LogLevel ERROR
"#
    ))
}

pub fn render_authorized_keys(state: &State) -> Result<Vec<(String, String)>> {
    let mut keys = Vec::new();
    for (_, p) in state.enabled_users_by_uid() {
        let pub_key = p.ssh_public_key()?;
        keys.push((
            p.ssh_username(),
            format!("restrict,port-forwarding {}\n", pub_key.trim()),
        ));
    }
    Ok(keys)
}

pub fn render_systemd_unit() -> String {
    r#"[Unit]
Description=Kinveil forwarding-only SSH service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/bin/install -d -m 0755 -o root -g root /run/sshd
ExecStartPre=/usr/sbin/sshd -t -f /etc/kinveil/ssh/sshd_config
ExecStart=/usr/sbin/sshd -D -e -f /etc/kinveil/ssh/sshd_config
Restart=on-failure
RestartSec=3
ProtectSystem=strict
ReadWritePaths=/run
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
"#
    .to_owned()
}
