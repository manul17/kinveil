//! Local bundle and subscription inspection helpers (`kinveil debug render`).

use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::read::GzDecoder;
use tar::Archive;

use crate::deploy::artifacts::RuntimeArtifacts;
use crate::deploy::remote::{BundleOptions, build_disabled_server_bundle, build_server_bundle};
use crate::render::ResolvedFirewallLists;
use crate::render::amneziawg::render_client_ini;
use crate::render::caddy::compile_subscription_routing;
use crate::render::firewall::render_nftables;
use crate::render::subscriptions::{SubVariant, render_subscription_body};
use crate::validate::{validate_server_id, validate_state, validate_user_name};

use super::config::open_private_new_file;
use super::load_locked_state;
use super::secrets::SecretReader;

fn create_dir_private_recursive(target: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut cur = target;
    while fs::symlink_metadata(cur).is_err() {
        missing.push(cur);
        cur = cur
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| anyhow!("invalid output path {}", target.display()))?;
    }
    for dir in missing.into_iter().rev() {
        fs::create_dir(dir)
            .with_context(|| format!("failed to create directory {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to chmod 0700 {}", dir.display()))?;
    }
    Ok(())
}

fn verify_debug_render_dest(dir: &Path, allow_non_tmpfs: bool) -> Result<()> {
    if dir.exists() || fs::symlink_metadata(dir).is_ok() {
        bail!(
            "output directory {} already exists; choose a fresh directory",
            dir.display()
        );
    }
    if allow_non_tmpfs {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let shm = super::config::ensure_shm_tmpfs()?;
        let abs = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            std::env::current_dir()?.join(dir)
        };
        let mut cur: Option<&Path> = Some(abs.as_path());
        let mut saw_parent_dir = false;
        let existing_ancestor = loop {
            match cur {
                Some(p) if fs::symlink_metadata(p).is_ok() => break p,
                Some(p) => {
                    if matches!(p.file_name(), Some(name) if name == "..") {
                        saw_parent_dir = true;
                    }
                    cur = p.parent();
                }
                None => bail!("cannot resolve ancestor directory for {}", dir.display()),
            }
        };
        if saw_parent_dir {
            bail!(
                "refusing '..' traversal in output path {} when targeting /dev/shm",
                dir.display()
            );
        }
        let canon = fs::canonicalize(existing_ancestor)?;
        let shm_canon = fs::canonicalize(shm)?;
        if !canon.starts_with(&shm_canon) {
            bail!(
                "refusing to write plaintext debug output outside /dev/shm tmpfs ({}); pass --allow-non-tmpfs to override",
                dir.display()
            );
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!(
            "non-Linux hosts lack /dev/shm tmpfs verification; pass --allow-non-tmpfs explicitly"
        );
    }
}

fn write_secret_file(root: &Path, rel: &Path, data: &[u8]) -> Result<()> {
    let mut dest: PathBuf = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => dest.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("refusing unsafe relative path {}", rel.display());
            }
        }
    }
    if let Some(parent) = dest.parent() {
        create_dir_private_recursive(parent)?;
    }
    let mut f = open_private_new_file(&dest, 0o600)
        .with_context(|| format!("failed to write secret render file {}", dest.display()))?;
    f.write_all(data)?;
    f.flush()?;
    Ok(())
}

pub(crate) fn cmd_debug_render(
    state_path: &Path,
    dir: &Path,
    allow_non_tmpfs: bool,
    secrets: &mut SecretReader,
) -> Result<()> {
    verify_debug_render_dest(dir, allow_non_tmpfs)?;
    let (_lock, _pass, state) = load_locked_state(state_path, secrets)?;
    validate_state(&state)?;

    create_dir_private_recursive(dir)?;

    let dummy_artifacts = RuntimeArtifacts {
        xray_bytes: Vec::new(),
        xray_sha256: String::new(),
        geoip_bytes: Vec::new(),
        geoip_sha256: String::new(),
        geosite_bytes: Vec::new(),
        geosite_sha256: String::new(),
        awg_bytes: Vec::new(),
        awg_sha256: String::new(),
    };
    let sample_dns = [
        "1.1.1.1".parse().expect("valid static IPv4"),
        "2606:4700:4700::1111".parse().expect("valid static IPv6"),
    ];

    let enabled_user_count = state.enabled_users_by_uid().len();
    let sample_ssh_uids: Vec<u32> = if enabled_user_count == 0 {
        vec![1001, 1002]
    } else {
        (0..enabled_user_count).map(|i| 1001 + i as u32).collect()
    };

    let empty_lists = ResolvedFirewallLists::default();
    for server in &state.servers {
        validate_server_id(&server.id)?;
        let is_sub = state.is_subscription_server(&server.id);
        let eff = server.effective_config(&state.settings, is_sub);
        let bundle = if server.enabled {
            build_server_bundle(
                &state,
                server,
                &dummy_artifacts,
                &empty_lists,
                BundleOptions {
                    defer_caddy_retire: eff.should_defer_caddy_retire(),
                    ..BundleOptions::default()
                },
            )?
        } else {
            build_disabled_server_bundle(&state, server)?
        };

        let srv_dir = dir.join("servers").join(&server.id);
        let dec = GzDecoder::new(Cursor::new(&bundle));
        let mut archive = Archive::new(dec);
        let mut modes: Vec<(String, u32)> = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.header().entry_type().is_dir() {
                continue;
            }
            let rel_path = entry.path()?.into_owned();
            let rel_str = rel_path.to_string_lossy().into_owned();
            let mode = entry.header().mode()?;
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            write_secret_file(&srv_dir, &rel_path, &data)?;
            modes.push((rel_str, mode));
        }
        modes.sort_by(|a, b| a.0.cmp(&b.0));
        let mut modes_txt = String::new();
        for (p, m) in modes {
            use std::fmt::Write as _;
            let _ = writeln!(modes_txt, "{p} {m:04o}");
        }
        write_secret_file(&srv_dir, Path::new("_tar_modes.txt"), modes_txt.as_bytes())?;

        let standalone_nft = render_nftables(
            &state,
            server,
            Some(999),
            &sample_ssh_uids,
            &sample_dns,
            &empty_lists,
        )?;
        let standalone_dir = dir.join("standalone").join(&server.id);
        write_secret_file(
            &standalone_dir,
            Path::new("nftables.conf"),
            standalone_nft.as_bytes(),
        )?;
    }

    let enabled_vpn_servers: Vec<_> = state
        .servers
        .iter()
        .filter(|s| {
            s.enabled
                && s.effective_config(&state.settings, false)
                    .has_any_vpn_protocol
        })
        .collect();

    for (user_name, user) in state.enabled_users_by_uid() {
        validate_user_name(user_name)?;
        let sub_dir = dir.join("subscriptions").join(user_name);
        let sub_url = format!("{}\n", state.user_subscription_url(user));
        write_secret_file(&sub_dir, Path::new("sub_url.txt"), sub_url.as_bytes())?;

        if !enabled_vpn_servers.is_empty() {
            let happ_b64 = render_subscription_body(&state, user_name, user, SubVariant::Happ)?;
            if !happ_b64.is_empty() {
                let happ_body = STANDARD
                    .decode(happ_b64.trim())
                    .context("failed decoding rendered Happ subscription")?;
                write_secret_file(&sub_dir, Path::new("happ.txt"), &happ_body)?;
            }

            let throne_b64 = render_subscription_body(&state, user_name, user, SubVariant::Throne)?;
            let throne_body = STANDARD
                .decode(throne_b64.trim())
                .context("failed decoding rendered Throne subscription")?;
            write_secret_file(&sub_dir, Path::new("throne.txt"), &throne_body)?;

            for srv in &enabled_vpn_servers {
                if srv.effective_config(&state.settings, false).has_amneziawg {
                    let ini = render_client_ini(&state, srv, user)?;
                    write_secret_file(
                        &sub_dir,
                        Path::new(&format!("awg-{}.conf", srv.id)),
                        ini.as_bytes(),
                    )?;
                }
            }
        }
    }

    let compiled_routing = compile_subscription_routing(&state.settings.subscription.routing)?;
    if state.settings.subscription.routing.is_active() {
        let routing_dir = dir.join("subscriptions").join("_routing");
        if let Some(ref link) = compiled_routing.happ_header {
            write_secret_file(
                &routing_dir,
                Path::new("happ_link.txt"),
                format!("{link}\n").as_bytes(),
            )?;
        }
        if let Some(ref json) = compiled_routing.happ_json {
            write_secret_file(
                &routing_dir,
                Path::new("happ.json"),
                format!("{json}\n").as_bytes(),
            )?;
        }
        if let Some(ref link) = compiled_routing.throne_header {
            write_secret_file(
                &routing_dir,
                Path::new("throne_link.txt"),
                format!("{link}\n").as_bytes(),
            )?;
        }
        if let Some(ref json) = compiled_routing.throne_json {
            write_secret_file(
                &routing_dir,
                Path::new("throne.json"),
                format!("{json}\n").as_bytes(),
            )?;
        }
    }

    println!(
        "Rendered debug output ({} server(s)) to {}",
        state.servers.len(),
        dir.display()
    );
    Ok(())
}
