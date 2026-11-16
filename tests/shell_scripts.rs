mod common;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::multi_server_state;
use kinveil::render::firewall::{
    egress_blocked_ipv4_list, egress_blocked_ipv6_list, render_nft_egress_fragment,
    render_nftables, render_nftables_for_host,
};
use tempfile::TempDir;

fn extract_install_section(start_marker: &str, end_marker: &str) -> &'static str {
    let install_sh = include_str!("../src/deploy/scripts/install.sh");
    let start = install_sh
        .find(start_marker)
        .unwrap_or_else(|| panic!("locate {start_marker} in install.sh"));
    let end = install_sh[start..]
        .find(end_marker)
        .map(|off| start + off + end_marker.len())
        .unwrap_or_else(|| panic!("locate {end_marker} in install.sh"));
    &install_sh[start..end]
}

fn run_install_nft_egress_generator(
    xray_uid: &str,
    sub_ipv4: &str,
    sub_ipv6: &str,
    active_uids: &str,
    resolv_conf_body: Option<&str>,
    block_private_networks: bool,
) -> String {
    let generator_funcs =
        extract_install_section("# BEGIN_NFT_EGRESS_GENERATOR", "# END_NFT_EGRESS_GENERATOR");

    let dir = TempDir::new().expect("create tempdir");
    let out_path = dir.path().join("nft-egress.nft");
    let resolv_path = dir.path().join("resolv.conf");
    if let Some(body) = resolv_conf_body {
        fs::write(&resolv_path, body).expect("write test resolv.conf");
    }

    let script = format!(
        "set -euo pipefail\n\
         {generator_funcs}\n\
         write_nft_egress_rules {out:?} {resolv:?} {xray_uid:?} {sub_ipv4:?} {sub_ipv6:?} {active_uids:?} {ipv4:?} {ipv6:?}\n",
        ipv4 = egress_blocked_ipv4_list(block_private_networks),
        ipv6 = egress_blocked_ipv6_list(block_private_networks),
        out = out_path.to_string_lossy(),
        resolv = resolv_path.to_string_lossy(),
    );

    let output = Command::new("bash")
        .args(["-c", &script])
        .output()
        .expect("execute bash nft-egress generator");
    assert!(
        output.status.success(),
        "bash failed (status={}):\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read_to_string(&out_path).expect("read generated nft-egress.nft")
}

#[test]
fn install_sh_nft_egress_generator_matches_rust_renderer_across_modes() {
    let empty_out =
        run_install_nft_egress_generator("", "", "", "", Some("nameserver 1.1.1.1\n"), true);
    let rust_empty = render_nft_egress_fragment(None, None, &[], &[], true);
    assert_eq!(empty_out, rust_empty);

    let resolv = "\
# test resolv.conf
search example.com
nameserver 1.1.1.1
nameserver 2606:4700:4700::1111
";
    let dns: Vec<IpAddr> = vec![
        "1.1.1.1".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
    ];
    let sub_v4: Ipv4Addr = "198.51.100.10".parse().unwrap();
    let sub_v6: Ipv6Addr = "2001:db8::10".parse().unwrap();

    // Xray + @vpnssh_users + co-located subscription IPs (block_private_networks = true)
    let shell_both = run_install_nft_egress_generator(
        "998",
        "198.51.100.10",
        "2001:db8::10",
        "1001, 1002",
        Some(resolv),
        true,
    );
    let rust_both = render_nft_egress_fragment(
        Some(998),
        Some((sub_v4, Some(sub_v6))),
        &[1002, 1001],
        &dns,
        true,
    );
    assert_eq!(shell_both, rust_both);
    assert!(shell_both.contains("::ffff:0:0/96"));
    assert!(
        shell_both.contains("meta skuid 998 ip daddr 198.51.100.10 tcp dport { 80, 443 } accept")
    );

    // Xray only (no SSH forwarding), co-located IPv4 only, block_private_networks = false
    let shell_xray_only =
        run_install_nft_egress_generator("998", "198.51.100.10", "", "", Some(resolv), false);
    let rust_xray_only =
        render_nft_egress_fragment(Some(998), Some((sub_v4, None)), &[], &dns, false);
    assert_eq!(shell_xray_only, rust_xray_only);
    assert!(shell_xray_only.contains("169.254.0.0/16"));
    assert!(shell_xray_only.contains("100.100.100.200/32"));
    assert!(shell_xray_only.contains("fd00:ec2::254/128"));
    assert!(!shell_xray_only.contains("10.0.0.0/8"));
    assert!(!shell_xray_only.contains("vpnssh_users"));

    // SSH forwarding only (no Xray)
    let shell_ssh_only =
        run_install_nft_egress_generator("", "", "", "1001, 1002", Some(resolv), false);
    let rust_ssh_only = render_nft_egress_fragment(None, None, &[1001, 1002], &dns, false);
    assert_eq!(shell_ssh_only, rust_ssh_only);
    assert!(shell_ssh_only.contains("vpnssh_users"));
    assert!(!shell_ssh_only.contains("meta skuid 998"));
}

#[test]
fn install_sh_nft_egress_generator_rejects_scoped_and_invalid_resolvers() {
    let resolv = "\
# noisy resolv.conf from systemd-resolved / link-local interfaces
nameserver fe80::1%eth0
nameserver 127.0.0.53#53
nameserver 999.1.1.1
nameserver 2001:::1
nameserver ::1%lo
nameserver 1.1.1.1
nameserver 2606:4700:4700::1111
nameserver ::1
";
    let shell_out = run_install_nft_egress_generator("", "", "", "1001", Some(resolv), true);
    let dns: Vec<IpAddr> = vec![
        "1.1.1.1".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
        "::1".parse().unwrap(),
    ];
    let rust_out = render_nft_egress_fragment(None, None, &[1001], &dns, true);
    assert_eq!(shell_out, rust_out);
    assert!(!shell_out.contains('%'));
    assert!(!shell_out.contains("999.1.1.1"));
    assert!(!shell_out.contains("2001:::1"));
    assert!(!shell_out.contains("127.0.0.53"));
}

#[test]
fn rendered_nftables_pass_kernel_nft_syntax_check_when_available() {
    #[cfg(target_os = "linux")]
    {
        use std::io::Write as _;

        let nft_bin = Path::new("/usr/sbin/nft");
        if !nft_bin.exists() {
            return;
        }
        let Ok(probe) = Command::new("unshare").args(["-rn", "/bin/true"]).output() else {
            return;
        };
        if !probe.status.success() {
            return;
        }

        let state = multi_server_state();
        let mut allow_priv_state = state.clone();
        allow_priv_state
            .set_config_toml("[firewall]\nblock_private_networks = false\n")
            .unwrap();
        let dns_ips: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        let configs = [
            render_nftables(
                &state,
                &state.servers[0],
                Some(999),
                &[1001, 1002],
                &dns_ips,
            )
            .unwrap(),
            render_nftables(&state, &state.servers[1], Some(999), &[], &dns_ips).unwrap(),
            render_nftables(
                &allow_priv_state,
                &allow_priv_state.servers[0],
                Some(999),
                &[1001],
                &dns_ips,
            )
            .unwrap(),
            render_nftables_for_host(&state, &state.servers[2]).unwrap(),
        ];
        for cfg in configs {
            let mut child = Command::new("unshare")
                .args(["-rn", "/usr/sbin/nft", "-c", "-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn unshare nft -c");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(cfg.as_bytes())
                .expect("write nft config to stdin");
            let out = child.wait_with_output().expect("wait unshare nft");
            assert!(
                out.status.success(),
                "nft -c failed:\nstderr:\n{}\nconfig:\n{cfg}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

fn run_takeover_guard(
    bin_dir: &Path,
    managed_file: &Path,
    nft_conf: &Path,
    has_sub: u8,
    allow_takeover: u8,
) -> Output {
    let guard_fn = extract_install_section("# BEGIN_TAKEOVER_GUARD", "# END_TAKEOVER_GUARD");
    let script = format!(
        "set -euo pipefail\n\
         {guard_fn}\n\
         check_first_install_conflicts {managed:?} {nft:?} {has_sub} {allow_takeover}\n",
        managed = managed_file.to_string_lossy(),
        nft = nft_conf.to_string_lossy(),
    );
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new("bash")
        .args(["-c", &script])
        .env("PATH", path_env)
        .output()
        .expect("execute takeover guard")
}

fn write_mock_exe(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    fs::write(&p, format!("#!/usr/bin/env bash\n{body}\n")).expect("write mock exe");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod mock exe");
}

#[test]
fn install_sh_takeover_guard_protects_dirty_hosts_and_allows_upgrades() {
    let dir = TempDir::new().expect("create tempdir");
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create mock bin dir");

    let managed = dir.path().join("managed");
    let nft = dir.path().join("nftables.conf");

    // 1. Clean Debian host with stock `table inet filter` passes.
    write_mock_exe(&bin_dir, "systemctl", "exit 3");
    write_mock_exe(&bin_dir, "ufw", "echo 'Status: inactive'");
    write_mock_exe(&bin_dir, "nft", "echo 'table inet filter'");
    fs::write(
        &nft,
        "#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n  chain input { type filter hook input priority filter; }\n}\n",
    )
    .unwrap();
    let ok_clean = run_takeover_guard(&bin_dir, &managed, &nft, 0, 0);
    assert!(
        ok_clean.status.success(),
        "{}",
        String::from_utf8_lossy(&ok_clean.stderr)
    );

    // 2. Custom nftables table on disk blocks fresh install without --takeover.
    fs::write(&nft, "table inet custom_firewall {\n}\n").unwrap();
    let bad_nft = run_takeover_guard(&bin_dir, &managed, &nft, 0, 0);
    assert!(!bad_nft.status.success());
    assert!(String::from_utf8_lossy(&bad_nft.stderr).contains("kinveil deploy --takeover"));

    // 2b. Live kernel non-default table (e.g. iptables-nft `ip nat`) and firewalld block without --takeover.
    fs::write(&nft, "table inet filter {\n}\n").unwrap();
    write_mock_exe(
        &bin_dir,
        "nft",
        "printf 'table inet filter\\ntable ip nat\\n'",
    );
    write_mock_exe(
        &bin_dir,
        "systemctl",
        r#"case " $* " in *" firewalld.service "*) exit 0 ;; *) exit 3 ;; esac"#,
    );
    let bad_live_nft = run_takeover_guard(&bin_dir, &managed, &nft, 0, 0);
    assert!(!bad_live_nft.status.success());
    let stderr_live = String::from_utf8_lossy(&bad_live_nft.stderr);
    assert!(stderr_live.contains("firewalld.service is active"));
    assert!(stderr_live.contains("live nftables ruleset defines non-default firewall tables"));

    // 3. Active docker + ufw + non-sub caddy block without --takeover.
    write_mock_exe(&bin_dir, "nft", "echo 'table inet filter'");
    fs::write(&nft, "table inet filter {\n}\n").unwrap();
    write_mock_exe(
        &bin_dir,
        "systemctl",
        r#"case " $* " in *" docker.service "*|*" caddy.service "*) exit 0 ;; *) exit 3 ;; esac"#,
    );
    write_mock_exe(&bin_dir, "ufw", "echo 'Status: active'");
    let bad_svcs = run_takeover_guard(&bin_dir, &managed, &nft, 0, 0);
    assert!(!bad_svcs.status.success());
    let stderr_svcs = String::from_utf8_lossy(&bad_svcs.stderr);
    assert!(stderr_svcs.contains("docker.service is active"));
    assert!(stderr_svcs.contains("caddy.service is active"));
    assert!(stderr_svcs.contains("ufw firewall is active"));

    // 4. --takeover (allow_takeover=1) bypasses conflict checks cleanly.
    let ok_takeover = run_takeover_guard(&bin_dir, &managed, &nft, 0, 1);
    assert!(ok_takeover.status.success());

    // 5. Already-managed kinveil host bypasses cleanly.
    fs::write(&managed, "managed-by=kinveil\n").unwrap();
    let ok_redeploy = run_takeover_guard(&bin_dir, &managed, &nft, 0, 0);
    assert!(ok_redeploy.status.success());

    // 6. Verify install.sh enforces 0710 directory mode and umask 022.
    let install_sh = include_str!("../src/deploy/scripts/install.sh");
    assert!(install_sh.contains("chmod 0710"));
    assert!(install_sh.starts_with("umask 022"));
}
