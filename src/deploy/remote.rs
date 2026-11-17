use std::io::Write;

use anyhow::{Result, bail};
use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, EntryType, Header};

use crate::deploy::artifacts::RuntimeArtifacts;
use crate::deploy::ssh::shell_single_quote;
use crate::render::ResolvedFirewallLists;
use crate::render::amneziawg::{
    render_apply_script, render_server_uapi, render_systemd_unit as render_awg_unit,
};
use crate::render::caddy::render_caddyfile;
use crate::render::firewall::{
    render_admin_sshd_dropin, render_firewall_update_service, render_firewall_update_timer,
    render_firewall_update_urls, render_nft_blocked_sets, render_nftables_for_host,
    render_resolved_conf, render_sysctl, static_egress_cidrs,
};
use crate::render::ssh_forwarding::{
    render_authorized_keys, render_sshd_config, render_systemd_unit as render_ssh_unit,
};
use crate::render::subscriptions::{SubVariant, render_subscription_body};
use crate::render::traffic::{
    render_traffic_config_env, render_traffic_flush_service, render_traffic_service,
    render_traffic_timer, render_traffic_users_conf,
};
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
    admin_ssh_user: &str,
    admin_ssh_port: u16,
    has_vpn: bool,
    has_xray: bool,
    has_awg: bool,
    has_sub: bool,
    has_ssh: bool,
    has_fw_update: bool,
    has_traffic: bool,
    sub_ipv4: Option<std::net::Ipv4Addr>,
    sub_ipv6: Option<std::net::Ipv6Addr>,
    defer_caddy_retire: bool,
    allow_takeover: bool,
) -> String {
    let vpn_flag = u8::from(has_vpn);
    let xray_flag = u8::from(has_xray);
    let awg_flag = u8::from(has_awg);
    let sub_flag = u8::from(has_sub);
    let ssh_flag = u8::from(has_ssh);
    let fw_update_flag = u8::from(has_fw_update);
    let traffic_flag = u8::from(has_traffic);
    let sub_v4 = sub_ipv4.map(|ip| ip.to_string()).unwrap_or_default();
    let sub_v6 = sub_ipv6.map(|ip| ip.to_string()).unwrap_or_default();
    let defer_flag = u8::from(defer_caddy_retire);
    let takeover_flag = u8::from(allow_takeover);
    let body = include_str!("scripts/install.sh");

    format!(
        "#!/usr/bin/env bash\n\
         set -euo pipefail\n\n\
         STAGE=\"${{1:?missing staging directory}}\"\n\
         ADMIN_SSH_USER=\"{admin_ssh_user}\"\n\
         ADMIN_SSH_PORT={admin_ssh_port}\n\
         HAS_VPN={vpn_flag}\n\
         HAS_XRAY={xray_flag}\n\
         HAS_AWG={awg_flag}\n\
         HAS_SUB={sub_flag}\n\
         HAS_SSH={ssh_flag}\n\
         HAS_FW_UPDATE={fw_update_flag}\n\
         CO_LOCATED_SUB_V4=\"{sub_v4}\"\n\
         CO_LOCATED_SUB_V6=\"{sub_v6}\"\n\
         DEFER_CADDY_RETIRE={defer_flag}\n\
         ALLOW_TAKEOVER={takeover_flag}\n\
         HAS_TRAFFIC={traffic_flag}\n\n\
         {body}"
    )
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BundleOptions {
    pub defer_caddy_retire: bool,
    pub include_xray_bin: bool,
    pub include_geodata: bool,
    pub include_awg_bin: bool,
    pub allow_takeover: bool,
}

fn join_lines<T: std::fmt::Display>(items: &[T]) -> String {
    let mut out = items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

pub fn build_server_bundle(
    state: &State,
    server: &Server,
    artifacts: &RuntimeArtifacts,
    fw_lists: &ResolvedFirewallLists,
    opts: BundleOptions,
) -> Result<Vec<u8>> {
    if !server.enabled {
        bail!(
            "build_server_bundle called for disabled server {}",
            server.id
        );
    }
    let has_sub = state.is_subscription_server(&server.id);
    let eff = server.effective_config(&state.settings, has_sub);
    let has_vpn = eff.has_any_vpn_protocol;
    let has_xray = eff.has_xray;
    let has_hysteria2 = eff.has_hysteria2;
    let has_awg = eff.has_amneziawg;
    let has_ssh = eff.has_ssh_forwarding;
    let has_fw_update = has_vpn && state.settings.firewall.auto_update_active();
    let has_traffic = eff.has_traffic;

    let gz = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(gz);

    let script = render_install_script(
        &server.admin_ssh.user,
        server.admin_ssh.port.get(),
        has_vpn,
        has_xray,
        has_awg,
        has_sub,
        has_ssh,
        has_fw_update,
        has_traffic,
        has_sub.then_some(server.public_ipv4),
        if has_sub { server.public_ipv6 } else { None },
        opts.defer_caddy_retire,
        opts.allow_takeover,
    );
    append_tar_bytes(&mut tar, "install.sh", 0o755, script.as_bytes())?;

    let sysctl = render_sysctl(state, server);
    append_tar_bytes(
        &mut tar,
        "files/etc/sysctl.d/90-kinveil.conf",
        0o644,
        sysctl.as_bytes(),
    )?;

    append_tar_bytes(
        &mut tar,
        "files/etc/systemd/resolved.conf.d/90-kinveil.conf",
        0o644,
        render_resolved_conf().as_bytes(),
    )?;

    let admin_sshd_dropin = render_admin_sshd_dropin(server.admin_ssh.port.get());
    append_tar_bytes(
        &mut tar,
        "files/etc/ssh/sshd_config.d/0-00-kinveil-admin.conf",
        0o644,
        admin_sshd_dropin.as_bytes(),
    )?;

    let nft = render_nftables_for_host(state, server)?;
    append_tar_bytes(&mut tar, "files/etc/nftables.conf", 0o644, nft.as_bytes())?;

    if has_vpn {
        let nft_blocked = render_nft_blocked_sets(&state.settings.firewall, fw_lists)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/nft-blocked.nft",
            0o644,
            nft_blocked.as_bytes(),
        )?;
    }

    if has_fw_update {
        append_tar_bytes(
            &mut tar,
            "bin/update-firewall.sh",
            0o755,
            include_bytes!("scripts/update_firewall.sh"),
        )?;
        let (base_v4, base_v6) = static_egress_cidrs(&state.settings.firewall)?;
        let base_v4_txt = join_lines(&base_v4);
        let base_v6_txt = join_lines(&base_v6);
        let urls_txt = render_firewall_update_urls(&state.settings.firewall)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/firewall/base-ipv4.txt",
            0o644,
            base_v4_txt.as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/firewall/base-ipv6.txt",
            0o644,
            base_v6_txt.as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/firewall/urls.txt",
            0o644,
            urls_txt.as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-firewall-update.service",
            0o644,
            render_firewall_update_service().as_bytes(),
        )?;
        let timer =
            render_firewall_update_timer(state.settings.firewall.auto_update.interval_hours);
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-firewall-update.timer",
            0o644,
            timer.as_bytes(),
        )?;
    }

    if has_xray {
        let vpn = server
            .vpn
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server {} lacks vpn config", server.id))?;
        if opts.include_xray_bin {
            append_tar_bytes(&mut tar, "bin/xray", 0o755, &artifacts.xray_bytes)?;
        }
        if opts.include_geodata {
            append_tar_bytes(&mut tar, "bin/geoip.dat", 0o644, &artifacts.geoip_bytes)?;
            append_tar_bytes(&mut tar, "bin/geosite.dat", 0o644, &artifacts.geosite_bytes)?;
        }
        let xray_json = render_xray_config(state, server, fw_lists)?;
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
            render_xray_unit(has_traffic).as_bytes(),
        )?;
    }

    if has_traffic {
        append_tar_bytes(
            &mut tar,
            "bin/snapshot-traffic.sh",
            0o755,
            include_bytes!("scripts/snapshot_traffic.sh"),
        )?;
        let config_env = render_traffic_config_env(state.settings.traffic.retention_days);
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/traffic/config.env",
            0o600,
            config_env.as_bytes(),
        )?;
        let users_conf = render_traffic_users_conf(state)?;
        append_tar_bytes(
            &mut tar,
            "files/etc/kinveil/traffic/users.conf",
            0o600,
            users_conf.as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-traffic.service",
            0o644,
            render_traffic_service().as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-traffic.timer",
            0o644,
            render_traffic_timer().as_bytes(),
        )?;
        append_tar_bytes(
            &mut tar,
            "files/etc/systemd/system/kinveil-traffic-flush.service",
            0o644,
            render_traffic_flush_service(has_xray).as_bytes(),
        )?;
    }

    if has_awg {
        if opts.include_awg_bin {
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
    let sysctl = render_sysctl(state, &disabled_srv);
    let port = server.admin_ssh.port.get();
    let body = include_str!("scripts/disable.sh");
    let script = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nSTAGE=\"${{1:?missing staging directory}}\"\nADMIN_SSH_PORT={port}\n{body}"
    );

    let gz = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(gz);
    append_tar_bytes(&mut tar, "install.sh", 0o755, script.as_bytes())?;
    append_tar_bytes(&mut tar, "files/etc/nftables.conf", 0o644, nft.as_bytes())?;
    append_tar_bytes(
        &mut tar,
        "files/etc/sysctl.d/90-kinveil.conf",
        0o644,
        sysctl.as_bytes(),
    )?;
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
