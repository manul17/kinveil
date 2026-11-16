use std::io::Write;

use anyhow::{Result, bail};
use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, EntryType, Header};

use crate::deploy::artifacts::RuntimeArtifacts;
use crate::render::amneziawg::{
    render_apply_script, render_server_uapi, render_systemd_unit as render_awg_unit,
};
use crate::render::caddy::render_caddyfile;
use crate::render::firewall::{
    egress_blocked_ipv4_list, egress_blocked_ipv6_list, render_nftables_for_host, render_sysctl,
};
use crate::render::ssh_forwarding::{
    render_authorized_keys, render_sshd_config, render_systemd_unit as render_ssh_unit,
};
use crate::render::subscriptions::{SubVariant, render_subscription_body};
use crate::render::xray::{render_systemd_unit as render_xray_unit, render_xray_config};
use crate::state::{Server, State};

fn append_tar_bytes<W: Write>(
    builder: &mut Builder<W>,
    path: &str,
    mode: u32,
    data: &[u8],
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1_700_000_000);
    header.set_cksum();
    builder.append_data(&mut header, path, data)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_install_script(
    admin_ssh_port: u16,
    has_xray: bool,
    has_awg: bool,
    has_sub: bool,
    has_ssh: bool,
    sub_ipv4: Option<std::net::Ipv4Addr>,
    sub_ipv6: Option<std::net::Ipv6Addr>,
    defer_caddy_retire: bool,
    allow_takeover: bool,
    block_private_networks: bool,
) -> String {
    let ipv4_list = egress_blocked_ipv4_list(block_private_networks);
    let ipv6_list = egress_blocked_ipv6_list(block_private_networks);
    let xray_flag = u8::from(has_xray);
    let awg_flag = u8::from(has_awg);
    let sub_flag = u8::from(has_sub);
    let ssh_flag = u8::from(has_ssh);
    let sub_v4 = sub_ipv4.map(|ip| ip.to_string()).unwrap_or_default();
    let sub_v6 = sub_ipv6.map(|ip| ip.to_string()).unwrap_or_default();
    let defer_flag = u8::from(defer_caddy_retire);
    let takeover_flag = u8::from(allow_takeover);
    let body = include_str!("scripts/install.sh");

    format!(
        "#!/usr/bin/env bash\n\
         set -euo pipefail\n\n\
         STAGE=\"${{1:?missing staging directory}}\"\n\
         ADMIN_SSH_PORT={admin_ssh_port}\n\
         HAS_XRAY={xray_flag}\n\
         HAS_AWG={awg_flag}\n\
         HAS_SUB={sub_flag}\n\
         HAS_SSH={ssh_flag}\n\
         CO_LOCATED_SUB_V4=\"{sub_v4}\"\n\
         CO_LOCATED_SUB_V6=\"{sub_v6}\"\n\
         DEFER_CADDY_RETIRE={defer_flag}\n\
         ALLOW_TAKEOVER={takeover_flag}\n\
         PRIVATE_IPV4_LIST=\"{ipv4_list}\"\n\
         PRIVATE_IPV6_LIST=\"{ipv6_list}\"\n\n\
         {body}"
    )
}

pub fn build_server_bundle(
    state: &State,
    server: &Server,
    artifacts: &RuntimeArtifacts,
    defer_caddy_retire: bool,
    include_xray_bin: bool,
    include_awg_bin: bool,
    allow_takeover: bool,
) -> Result<Vec<u8>> {
    if !server.enabled {
        bail!(
            "build_server_bundle called for disabled server {}",
            server.id
        );
    }
    let has_xray = server.has_xray(&state.settings);
    let has_hysteria2 = server.has_hysteria2(&state.settings);
    let has_awg = server.has_amneziawg(&state.settings);
    let has_sub = state.is_subscription_server(&server.id);
    let has_ssh = server.has_ssh_forwarding(&state.settings);

    let gz = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(gz);

    let script = render_install_script(
        server.admin_ssh.port.get(),
        has_xray,
        has_awg,
        has_sub,
        has_ssh,
        has_sub.then_some(server.public_ipv4),
        if has_sub { server.public_ipv6 } else { None },
        defer_caddy_retire,
        allow_takeover,
        state.settings.firewall.block_private_networks,
    );
    append_tar_bytes(&mut tar, "install.sh", 0o755, script.as_bytes())?;

    let sysctl = render_sysctl(state, server);
    append_tar_bytes(
        &mut tar,
        "files/etc/sysctl.d/90-kinveil.conf",
        0o644,
        sysctl.as_bytes(),
    )?;

    let nft = render_nftables_for_host(state, server)?;
    append_tar_bytes(&mut tar, "files/etc/nftables.conf", 0o644, nft.as_bytes())?;

    if has_xray {
        let vpn = server
            .vpn
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn config", server.id))?;
        if include_xray_bin {
            append_tar_bytes(&mut tar, "bin/xray", 0o755, &artifacts.xray_bytes)?;
        }
        let xray_json = render_xray_config(state, server)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/xray.json",
            0o600,
            xray_json.as_bytes(),
        )?;
        if has_hysteria2 {
            append_tar_bytes(
                &mut tar,
                "files/etc/kinveil/tls/hysteria.crt",
                0o644,
                vpn.hysteria2.cert_pem.as_bytes(),
            )?;
            append_tar_bytes(
                &mut tar,
                "files/etc/kinveil/tls/hysteria.key",
                0o600,
                vpn.hysteria2.key_pem.as_bytes(),
            )?;
        }
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-xray.service",
            0o644,
            render_xray_unit().as_bytes(),
        )?;
    }

    if has_awg {
        if include_awg_bin {
            append_tar_bytes(&mut tar, "bin/amneziawg-go", 0o755, &artifacts.awg_bytes)?;
        }
        let uapi = render_server_uapi(state, server)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/awg/uapi.conf",
            0o600,
            uapi.as_bytes(),
        )?;
        let apply = render_apply_script(state)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/awg/apply-uapi.sh",
            0o755,
            apply.as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-awg.service",
            0o644,
            render_awg_unit().as_bytes(),
        )?;
    }

    if has_ssh {
        let vpn = server
            .vpn
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn config", server.id))?;
        let ssh_fwd = &vpn.ssh_forwarding;
        let host_pub = ssh_fwd.host_public_key()?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/ssh/host_ed25519",
            0o600,
            ssh_fwd.host_private_key.as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/ssh/host_ed25519.pub",
            0o644,
            host_pub.as_bytes(),
        )?;
        let sshd_conf = render_sshd_config(state, server)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/ssh/sshd_config",
            0o644,
            sshd_conf.as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-ssh.service",
            0o644,
            render_ssh_unit().as_bytes(),
        )?;
        for (user, line) in render_authorized_keys(state)? {
            append_tar_bytes(
                &mut tar,
                &format!("files/etc/kinveil/ssh/authorized_keys/{user}"),
                0o644,
                line.as_bytes(),
            )?;
        }
    }

    if has_sub {
        let caddyfile = render_caddyfile(state)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/caddy/Caddyfile",
            0o644,
            caddyfile.as_bytes(),
        )?;
        for (name, user) in state.enabled_users_by_uid() {
            let happ = render_subscription_body(state, name, user, SubVariant::Happ)?;
            let throne = render_subscription_body(state, name, user, SubVariant::Throne)?;
            append_tar_bytes(
                &mut tar,
                &format!("sub/{}/happ", user.subscription_token.as_str()),
                0o640,
                happ.as_bytes(),
            )?;
            append_tar_bytes(
                &mut tar,
                &format!("sub/{}/throne", user.subscription_token.as_str()),
                0o640,
                throne.as_bytes(),
            )?;
        }
    }

    let gz_encoder = tar.into_inner()?;
    let bytes = gz_encoder.finish()?;
    Ok(bytes)
}

fn wrap_sh_command(user: &str, inner: &str) -> String {
    if user == "root" {
        let quoted = shell_single_quote(inner);
        format!("sh -c {quoted}")
    } else {
        let sudo_inner = shell_single_quote(&format!(
            "if [ -n \"${{1:-}}\" ]; then SSH_CONNECTION=\"$1\"; export SSH_CONNECTION; fi; {inner}"
        ));
        format!("sudo -n sh -c {sudo_inner} sh \"${{SSH_CONNECTION:-}}\"")
    }
}

pub fn remote_stage_and_exec_cmd(user: &str) -> String {
    let inner = r#"umask 077; STAGE="$(mktemp -d /run/kinveil-stage.XXXXXX 2>/dev/null || mktemp -d /tmp/kinveil-stage.XXXXXX)"; trap 'rm -rf "$STAGE"' EXIT; tar -xzf - -C "$STAGE" && bash "$STAGE/install.sh" "$STAGE""#;
    wrap_sh_command(user, inner)
}

pub fn remote_retire_caddy_cmd(user: &str) -> String {
    let inner = "if [ -f /etc/kinveil/.managed-sub ]; then systemctl disable --now caddy.service >/dev/null 2>&1 || true; fi; rm -rf /var/lib/kinveil/sub /etc/kinveil/.managed-sub";
    wrap_sh_command(user, inner)
}

pub fn remote_wipe_cmd(user: &str, admin_ssh_port: u16) -> String {
    let body = include_str!("scripts/wipe.sh");
    let inner = format!("set -eu\numask 022\nADMIN_SSH_PORT={admin_ssh_port}\n{body}");
    wrap_sh_command(user, &inner)
}

pub fn build_disabled_server_bundle(state: &State, server: &Server) -> Result<Vec<u8>> {
    let mut disabled_srv = server.clone();
    disabled_srv.enabled = false;
    let nft = render_nftables_for_host(state, &disabled_srv)?;
    let port = server.admin_ssh.port.get();
    let body = include_str!("scripts/disable.sh");
    let script = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSTAGE=\"${{1:?missing staging directory}}\"\nADMIN_SSH_PORT={port}\n{body}"
    );

    let gz = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(gz);
    append_tar_bytes(&mut tar, "install.sh", 0o755, script.as_bytes())?;
    append_tar_bytes(&mut tar, "files/etc/nftables.conf", 0o644, nft.as_bytes())?;
    let gz_encoder = tar.into_inner()?;
    Ok(gz_encoder.finish()?)
}

pub(crate) fn remote_bash_stdin_cmd(user: &str) -> &'static str {
    if user == "root" {
        "bash -s"
    } else {
        "sudo -n bash -s"
    }
}

fn shell_single_quote(s: &str) -> String {
    let escaped = s.replace('\'', r#"'\''"#);
    format!("'{escaped}'")
}
