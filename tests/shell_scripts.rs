mod common;

use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kinveil::deploy::remote::{
    BundleOptions, build_disabled_server_bundle, build_server_bundle, remote_retire_caddy_cmd,
    remote_wipe_cmd,
};
use kinveil::render::ResolvedFirewallLists;
use kinveil::render::amneziawg::render_apply_script;
use kinveil::render::firewall::{
    render_nft_blocked_sets, render_nft_egress_fragment, render_nft_traffic_fragment,
    static_egress_cidrs,
};
use kinveil::state::FirewallSettings;
use tempfile::TempDir;

fn find_nft_bin() -> Option<PathBuf> {
    for candidate in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("nft");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn kernel_nft_in_userns() -> Option<PathBuf> {
    let nft_bin = find_nft_bin()?;
    let mut child = Command::new("unshare")
        .arg("-rn")
        .arg(&nft_bin)
        .args(["-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()?
        .write_all(b"table inet kinveil_probe {}\n")
        .ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(nft_bin)
}

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
         write_nft_egress_rules {out:?} {resolv:?} {xray_uid:?} {sub_ipv4:?} {sub_ipv6:?} {active_uids:?}\n",
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
    let empty_out = run_install_nft_egress_generator("", "", "", "", Some("nameserver 1.1.1.1\n"));
    let rust_empty = render_nft_egress_fragment(None, None, &[], &[]);
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

    // Xray + @vpnssh_users + co-located subscription IPs
    let shell_both = run_install_nft_egress_generator(
        "998",
        "198.51.100.10",
        "2001:db8::10",
        "1001, 1002",
        Some(resolv),
    );
    let rust_both =
        render_nft_egress_fragment(Some(998), Some((sub_v4, Some(sub_v6))), &[1002, 1001], &dns);
    assert_eq!(shell_both, rust_both);
    assert!(shell_both.contains("@egress_blocked_v4"));
    assert!(shell_both.contains("@egress_blocked_v6"));
    assert!(
        shell_both.contains("meta skuid 998 ip daddr 198.51.100.10 tcp dport { 80, 443 } accept")
    );
    assert!(
        shell_both.contains(
            "meta skuid @vpnssh_users ip daddr 198.51.100.10 tcp dport { 80, 443 } accept"
        )
    );

    // Xray only (no SSH forwarding), co-located IPv4 only
    let shell_xray_only =
        run_install_nft_egress_generator("998", "198.51.100.10", "", "", Some(resolv));
    let rust_xray_only = render_nft_egress_fragment(Some(998), Some((sub_v4, None)), &[], &dns);
    assert_eq!(shell_xray_only, rust_xray_only);
    assert!(!shell_xray_only.contains("vpnssh_users"));

    // SSH forwarding only (no Xray)
    let shell_ssh_only = run_install_nft_egress_generator("", "", "", "1001, 1002", Some(resolv));
    let rust_ssh_only = render_nft_egress_fragment(None, None, &[1001, 1002], &dns);
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
    let shell_out = run_install_nft_egress_generator("", "", "", "1001", Some(resolv));
    let dns: Vec<IpAddr> = vec![
        "1.1.1.1".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
        "::1".parse().unwrap(),
    ];
    let rust_out = render_nft_egress_fragment(None, None, &[1001], &dns);
    assert_eq!(shell_out, rust_out);
    assert!(!shell_out.contains('%'));
    assert!(!shell_out.contains("999.1.1.1"));
    assert!(!shell_out.contains("2001:::1"));
    assert!(!shell_out.contains("127.0.0.53"));
}

fn run_install_nft_traffic_generator(
    has_awg: u8,
    users_conf_body: &str,
    has_ssh: u8,
    ssh_uid_pairs: &str,
) -> String {
    let generator_funcs = extract_install_section(
        "# BEGIN_NFT_TRAFFIC_GENERATOR",
        "# END_NFT_TRAFFIC_GENERATOR",
    );

    let dir = TempDir::new().expect("create tempdir");
    let out_path = dir.path().join("nft-traffic.nft");
    let users_path = dir.path().join("users.conf");
    fs::write(&users_path, users_conf_body).expect("write test users.conf");

    let script = format!(
        "set -euo pipefail\n\
         {generator_funcs}\n\
         write_nft_traffic_rules {out:?} {has_awg} {users:?} {has_ssh} {ssh_uid_pairs:?}\n",
        out = out_path.to_string_lossy(),
        users = users_path.to_string_lossy(),
    );

    let output = Command::new("bash")
        .args(["-c", &script])
        .output()
        .expect("execute bash nft-traffic generator");
    assert!(
        output.status.success(),
        "bash failed (status={}):\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read_to_string(&out_path).expect("read generated nft-traffic.nft")
}

#[test]
fn install_sh_nft_traffic_generator_matches_rust_renderer_across_modes() {
    let rust_empty = render_nft_traffic_fragment(&[], &[]);
    assert_eq!(run_install_nft_traffic_generator(0, "", 0, ""), rust_empty);
    assert_eq!(run_install_nft_traffic_generator(1, "", 0, ""), rust_empty);

    // Unsorted UIDs including 10 verify numeric sort (1, 2, 10) and hex marks (0x1, 0x2, 0xa).
    let awg_users = vec![
        (10, "10.8.0.11".parse().unwrap()),
        (2, "10.8.0.3".parse().unwrap()),
        (1, "10.8.0.2".parse().unwrap()),
    ];
    let ssh_users = vec![(10, 1010), (2, 1002), (1, 1001)];
    let users_conf = "10 10.8.0.11\n2 10.8.0.3\n1 10.8.0.2\n";
    let ssh_pairs = "10:1010 2:1002 1:1001";

    let shell_both = run_install_nft_traffic_generator(1, users_conf, 1, ssh_pairs);
    let rust_both = render_nft_traffic_fragment(&awg_users, &ssh_users);
    assert_eq!(shell_both, rust_both);
    assert!(shell_both.contains("0xa : \"ssh_up_10\""));
    assert!(shell_both.contains("10.8.0.11 : \"awg_down_10\""));

    let shell_awg = run_install_nft_traffic_generator(1, users_conf, 0, ssh_pairs);
    let rust_awg = render_nft_traffic_fragment(&awg_users, &[]);
    assert_eq!(shell_awg, rust_awg);
    assert!(!shell_awg.contains("ssh_uid_mark"));

    let shell_ssh = run_install_nft_traffic_generator(0, users_conf, 1, ssh_pairs);
    let rust_ssh = render_nft_traffic_fragment(&[], &ssh_users);
    assert_eq!(shell_ssh, rust_ssh);
    assert!(!shell_ssh.contains("awg_up_acct"));
}

#[test]
fn rendered_nftables_pass_kernel_nft_syntax_check_when_available() {
    #[cfg(target_os = "linux")]
    {
        use common::multi_server_state;
        use kinveil::render::firewall::{render_nftables, render_nftables_for_host};

        let Some(nft_bin) = kernel_nft_in_userns() else {
            return;
        };

        let state = multi_server_state();
        let mut allow_priv_state = state.clone();
        allow_priv_state
            .set_config_toml("[firewall]\nblock_private_networks = false\nblock_cidrs = [\"203.0.113.5/24\", \"2001:db8:cafe::1/48\"]\n")
            .unwrap();
        let dns_ips: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        let empty_lists = ResolvedFirewallLists::default();
        let custom_lists = ResolvedFirewallLists {
            extra_ipv4: vec![
                "192.0.2.0/25".parse().unwrap(),
                "192.0.2.128/25".parse().unwrap(),
            ],
            extra_ipv6: vec!["2001:db8:abcd::/48".parse().unwrap()],
            ..Default::default()
        };

        let include_dir = TempDir::new().expect("create include tempdir");
        let blocked_path = include_dir.path().join("nft-blocked.nft");
        let egress_path = include_dir.path().join("nft-egress.nft");
        fs::write(
            &blocked_path,
            render_nft_blocked_sets(&state.settings.firewall, &custom_lists).unwrap(),
        )
        .unwrap();
        let srv1 = &state.servers[0];
        fs::write(
            &egress_path,
            render_nft_egress_fragment(
                Some(999),
                Some((srv1.public_ipv4, srv1.public_ipv6)),
                &[1001, 1002],
                &dns_ips,
            ),
        )
        .unwrap();
        let staged_host_nft = render_nftables_for_host(&state, srv1).unwrap().replace(
            "/etc/kinveil/",
            &format!("{}/", include_dir.path().display()),
        );

        let mut traffic_state = multi_server_state();
        traffic_state.servers[0].vpn.as_mut().unwrap().traffic = true;
        let traffic_path = include_dir.path().join("nft-traffic.nft");
        fs::write(
            &traffic_path,
            render_nft_traffic_fragment(
                &[
                    (1, "10.8.0.2".parse().unwrap()),
                    (2, "10.8.0.3".parse().unwrap()),
                ],
                &[(1, 1001), (2, 1002)],
            ),
        )
        .unwrap();
        let staged_traffic_host_nft =
            render_nftables_for_host(&traffic_state, &traffic_state.servers[0])
                .unwrap()
                .replace(
                    "/etc/kinveil/",
                    &format!("{}/", include_dir.path().display()),
                );

        let configs = [
            render_nftables(
                &state,
                srv1,
                Some(999),
                &[1001, 1002],
                &dns_ips,
                &empty_lists,
            )
            .unwrap(),
            render_nftables(
                &state,
                &state.servers[1],
                Some(999),
                &[],
                &dns_ips,
                &custom_lists,
            )
            .unwrap(),
            render_nftables(
                &allow_priv_state,
                &allow_priv_state.servers[0],
                Some(999),
                &[1001],
                &dns_ips,
                &custom_lists,
            )
            .unwrap(),
            render_nftables(
                &traffic_state,
                &traffic_state.servers[0],
                Some(999),
                &[1001, 1002],
                &dns_ips,
                &custom_lists,
            )
            .unwrap(),
            staged_host_nft,
            staged_traffic_host_nft,
            render_nftables_for_host(&state, &state.servers[2]).unwrap(),
        ];
        for cfg in configs {
            let mut child = Command::new("unshare")
                .arg("-rn")
                .arg(&nft_bin)
                .args(["-c", "-f", "-"])
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

#[test]
fn update_firewall_sh_validates_masks_host_bits_and_fails_closed() {
    let dir = TempDir::new().expect("create tempdir");
    let conf_dir = dir.path().join("conf");
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&conf_dir).expect("create conf dir");
    fs::create_dir_all(&bin_dir).expect("create bin dir");

    let script_path = dir.path().join("update-firewall.sh");
    fs::write(
        &script_path,
        include_str!("../src/deploy/scripts/update_firewall.sh"),
    )
    .expect("write update-firewall.sh");
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).expect("chmod script");

    let (base_v4, base_v6) = static_egress_cidrs(&FirewallSettings::default()).unwrap();
    fs::write(
        conf_dir.join("base-ipv4.txt"),
        base_v4
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    fs::write(
        conf_dir.join("base-ipv6.txt"),
        base_v6
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    fs::write(
        conf_dir.join("urls.txt"),
        "https://lists.example.com/v4.txt\nhttps://lists.example.com/v6.txt\n",
    )
    .unwrap();

    // Exercise Debian's mawk explicitly when installed.
    let mawk = Path::new("/usr/bin/mawk");
    if mawk.exists() {
        std::os::unix::fs::symlink(mawk, bin_dir.join("awk")).expect("symlink mawk");
    }

    write_mock_exe(
        &bin_dir,
        "curl",
        r#"case " $* " in *"--proto =https"*) ;; *) echo "missing --proto =https" >&2; exit 9 ;; esac
url="${*: -1}"
case "$KINVEIL_MOCK_MODE:$url" in
  ok:*/v4.txt)
    printf '# IPv4 test list\r\n192.0.2.99/24 ; host bits must mask\r\n198.51.100.7\r\n'
    ;;
  ok:*/v6.txt)
    printf '2001:db8:1:2::5/48 # host bits must mask\n2001:db8:2::1\n'
    ;;
  html:*/v4.txt)
    printf '<html><body>404 Not Found</body></html>\n'
    ;;
  html:*/v6.txt|empty:*)
    printf '# empty list\n'
    ;;
  fail:*)
    exit 22
    ;;
  *)
    exit 1
    ;;
esac"#,
    );

    let out_nft = dir.path().join("nft-blocked.nft");
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let kernel_nft = kernel_nft_in_userns();
    let nft_wrapper = if let Some(ref nft_bin) = kernel_nft {
        write_mock_exe(
            &bin_dir,
            "nft-check",
            &format!("exec unshare -rn {:?} \"$@\"", nft_bin.as_os_str()),
        );
        bin_dir.join("nft-check")
    } else {
        write_mock_exe(&bin_dir, "nft-check", "exit 0");
        bin_dir.join("nft-check")
    };

    if let Some(ref nft_bin) = kernel_nft {
        // Run inside a network namespace with a live `table inet kinveil` and both sets!
        let ns_runner = format!(
            "set -euo pipefail
{nft} -f - <<'EOF'
table inet kinveil {{
    set egress_blocked_v4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ 127.0.0.0/8 }}
    }}
    set egress_blocked_v6 {{
        type ipv6_addr
        flags interval
        auto-merge
        elements = {{ ::1/128 }}
    }}
}}
EOF
{script}
{nft} list set inet kinveil egress_blocked_v4
{nft} list set inet kinveil egress_blocked_v6
",
            nft = nft_bin.display(),
            script = script_path.display()
        );
        let ok_ns = Command::new("unshare")
            .args(["-rn", "bash", "-c", &ns_runner])
            .env("PATH", &path_env)
            .env("KINVEIL_FW_CONF_DIR", &conf_dir)
            .env("KINVEIL_NFT_BLOCKED_FILE", &out_nft)
            .env("KINVEIL_NFT_BIN", nft_bin)
            .env("KINVEIL_FW_APPLY_LIVE", "1")
            .env("KINVEIL_MOCK_MODE", "ok")
            .output()
            .expect("run update_firewall.sh in netns");
        assert!(
            ok_ns.status.success(),
            "netns update_firewall.sh failed:\nstderr:\n{}",
            String::from_utf8_lossy(&ok_ns.stderr)
        );
        let live_stdout = String::from_utf8_lossy(&ok_ns.stdout);
        assert!(live_stdout.contains("192.0.2.0/24"), "{live_stdout}");
        assert!(live_stdout.contains("198.51.100.7"), "{live_stdout}");
        assert!(live_stdout.contains("2001:db8:1::/48"), "{live_stdout}");
    } else {
        let ok = Command::new("bash")
            .arg(&script_path)
            .env("PATH", &path_env)
            .env("KINVEIL_FW_CONF_DIR", &conf_dir)
            .env("KINVEIL_NFT_BLOCKED_FILE", &out_nft)
            .env("KINVEIL_NFT_BIN", &nft_wrapper)
            .env("KINVEIL_FW_APPLY_LIVE", "0")
            .env("KINVEIL_MOCK_MODE", "ok")
            .output()
            .expect("run update_firewall.sh");
        assert!(
            ok.status.success(),
            "update_firewall.sh failed:\nstderr:\n{}",
            String::from_utf8_lossy(&ok.stderr)
        );
    }

    let rendered = fs::read_to_string(&out_nft).expect("read rendered nft-blocked.nft");
    assert!(rendered.contains("192.0.2.0/24"), "{rendered}");
    assert!(rendered.contains("198.51.100.7/32"), "{rendered}");
    assert!(rendered.contains("2001:db8:1:0:0:0:0:0/48"), "{rendered}");
    assert!(rendered.contains("0:0:0:0:0:ffff:0:0/96"), "{rendered}");

    // Fail-closed checks: HTML garbage, empty dynamic output, and curl failure must leave out_nft intact.
    for bad_mode in ["html", "empty", "fail"] {
        let bad = Command::new("bash")
            .arg(&script_path)
            .env("PATH", &path_env)
            .env("KINVEIL_FW_CONF_DIR", &conf_dir)
            .env("KINVEIL_NFT_BLOCKED_FILE", &out_nft)
            .env("KINVEIL_NFT_BIN", &nft_wrapper)
            .env("KINVEIL_FW_APPLY_LIVE", "0")
            .env("KINVEIL_MOCK_MODE", bad_mode)
            .output()
            .expect("run bad update_firewall.sh");
        assert!(
            !bad.status.success(),
            "mode '{bad_mode}' must fail closed and not overwrite output"
        );
        assert_eq!(fs::read_to_string(&out_nft).unwrap(), rendered);
    }
}

fn assert_shell_syntax(shell: &str, script: &str) {
    let mut child = Command::new(shell)
        .arg("-n")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {shell} -n: {e}"));
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())
        .expect("write script to stdin");
    let status = child.wait().expect("wait for shell syntax check");
    assert!(status.success(), "{shell} -n failed syntax check");
}

#[test]
fn snapshot_traffic_sh_accumulates_xray_nft_nic_handles_reboot_and_prunes() {
    use std::os::unix::net::UnixListener;

    let dir = TempDir::new().expect("create tempdir");
    let bin_dir = dir.path().join("bin");
    let conf_dir = dir.path().join("conf");
    let data_dir = dir.path().join("data");
    let sys_net_stats = dir.path().join("sys/class/net/eth0/statistics");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&conf_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&sys_net_stats).unwrap();

    // Exercise Debian's mawk explicitly when installed (guards 32-bit %d overflow pitfalls).
    let mawk = Path::new("/usr/bin/mawk");
    if mawk.exists() {
        std::os::unix::fs::symlink(mawk, bin_dir.join("awk")).expect("symlink mawk");
    }

    let script_path = dir.path().join("snapshot-traffic.sh");
    fs::write(
        &script_path,
        include_str!("../src/deploy/scripts/snapshot_traffic.sh"),
    )
    .unwrap();
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();

    let conf_file = conf_dir.join("config.env");
    fs::write(&conf_file, "RETENTION_DAYS=90\n").unwrap();

    let sock_path = dir.path().join("xray-api.sock");
    let _listener = UnixListener::bind(&sock_path).expect("bind dummy unix socket");

    let mock_ip = bin_dir.join("ip");
    write_mock_exe(
        &bin_dir,
        "ip",
        r#"if [ "${2:-}" = "-4" ]; then echo "default via 203.0.113.1 dev eth0 proto static"; fi"#,
    );

    let mock_xray = bin_dir.join("xray");
    write_mock_exe(
        &bin_dir,
        "xray",
        r#"case "$KINVEIL_MOCK_STEP" in
  1)
    cat <<'EOF'
{
    "stat": [
        { "name": "user>>>uid-1:vless>>>traffic>>>uplink", "value": 2500000000000 },
        { "name": "user>>>uid-1:vless>>>traffic>>>downlink" },
        { "name": "user>>>uid-2:hysteria2>>>traffic>>>downlink", "value": 1500 }
    ]
}
EOF
    ;;
  2)
    cat <<'EOF'
{
    "stat": [
        { "name": "user>>>uid-1:vless>>>traffic>>>uplink", "value": 1000 },
        { "name": "user>>>uid-1:vless>>>traffic>>>downlink", "value": 5000 }
    ]
}
EOF
    ;;
  3)
    echo '{}'
    ;;
esac"#,
    );

    let mock_nft = bin_dir.join("nft");
    write_mock_exe(
        &bin_dir,
        "nft",
        r#"if [ "${1:-}" = "list" ]; then exit 0; fi
case "$KINVEIL_MOCK_STEP" in
  1)
    cat <<'EOF'
table inet kinveil {
	counter awg_up_1 {
		packets 10 bytes 1750000000000
	}
	counter awg_down_1 {
		packets 5 bytes 200
	}
	counter ssh_up_2 {
		packets 2 bytes 300
	}
	counter ssh_down_2 {
		packets 3 bytes 400
	}
}
EOF
    ;;
  2)
    cat <<'EOF'
table inet kinveil {
	counter awg_up_1 {
		packets 1 bytes 500
	}
	counter ssh_down_2 {
		packets 1 bytes 100
	}
}
EOF
    ;;
  3)
    echo 'table inet kinveil {}'
    ;;
esac"#,
    );

    // Seed old files to verify retention pruning (cutoff for 2026-11-17 - 90d is 2026-08-19).
    let expired_tsv = data_dir.join("2026-08-18.tsv");
    let kept_tsv = data_dir.join("2026-08-19.tsv");
    fs::write(&expired_tsv, "nic\t1\t2\n").unwrap();
    fs::write(&kept_tsv, "nic\t3\t4\n").unwrap();

    let lock_file = dir.path().join("traffic.lock");
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let run_step = |step: &str, rx: u64, tx: u64| {
        fs::write(sys_net_stats.join("rx_bytes"), format!("{rx}\n")).unwrap();
        fs::write(sys_net_stats.join("tx_bytes"), format!("{tx}\n")).unwrap();
        let out = Command::new("bash")
            .arg(&script_path)
            .env("PATH", &path_env)
            .env("KINVEIL_TRAFFIC_CONF", &conf_file)
            .env("KINVEIL_TRAFFIC_DIR", &data_dir)
            .env("KINVEIL_TRAFFIC_LOCK", &lock_file)
            .env("KINVEIL_XRAY_BIN", &mock_xray)
            .env("KINVEIL_XRAY_SOCK", &sock_path)
            .env("KINVEIL_NFT_BIN", &mock_nft)
            .env("KINVEIL_IP_BIN", &mock_ip)
            .env("KINVEIL_SYS_NET_DIR", dir.path().join("sys/class/net"))
            .env("KINVEIL_TRAFFIC_DATE_UTC", "2026-11-17")
            .env("KINVEIL_MOCK_STEP", step)
            .output()
            .expect("run snapshot-traffic.sh");
        assert!(
            out.status.success(),
            "snapshot step {step} failed:\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    // Step 1: initial NIC baseline is delta 0, while multi-TB protocol stats are captured.
    run_step("1", 10_000, 20_000);
    assert!(
        !expired_tsv.exists(),
        "expired 2026-08-18.tsv must be pruned"
    );
    assert!(kept_tsv.exists(), "cutoff 2026-08-19.tsv must be kept");
    let day_tsv = data_dir.join("2026-11-17.tsv");
    assert_eq!(
        fs::read_to_string(&day_tsv).unwrap(),
        "nic\t0\t0\n\
         uid\t1\tamneziawg\t1750000000000\t200\n\
         uid\t1\tvless\t2500000000000\t0\n\
         uid\t2\thysteria2\t0\t1500\n\
         uid\t2\tssh-forwarding\t300\t400\n"
    );
    assert_eq!(
        fs::metadata(&day_tsv).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Step 2: accumulates NIC deltas + protocol deltas.
    run_step("2", 10_500, 22_500);
    assert_eq!(
        fs::read_to_string(&day_tsv).unwrap(),
        "nic\t500\t2500\n\
         uid\t1\tamneziawg\t1750000000500\t200\n\
         uid\t1\tvless\t2500000001000\t5000\n\
         uid\t2\thysteria2\t0\t1500\n\
         uid\t2\tssh-forwarding\t300\t500\n"
    );

    // Step 3: simulated reboot (NIC counters dropped below previous .nic_state).
    run_step("3", 300, 700);
    assert_eq!(
        fs::read_to_string(&day_tsv).unwrap(),
        "nic\t800\t3200\n\
         uid\t1\tamneziawg\t1750000000500\t200\n\
         uid\t1\tvless\t2500000001000\t5000\n\
         uid\t2\thysteria2\t0\t1500\n\
         uid\t2\tssh-forwarding\t300\t500\n"
    );
}

#[test]
fn rendered_shell_scripts_pass_syntax_checks() {
    let mut state = common::multi_server_state();
    state.servers[0].vpn.as_mut().unwrap().traffic = true;
    let srv1 = &state.servers[0];
    let srv3 = &state.servers[2];
    let artifacts = common::fake_artifacts();

    let empty_lists = ResolvedFirewallLists::default();
    let bundle1 = common::unpack_tar_gz(
        &build_server_bundle(
            &state,
            srv1,
            &artifacts,
            &empty_lists,
            BundleOptions {
                defer_caddy_retire: false,
                include_xray_bin: true,
                include_geodata: false,
                include_awg_bin: true,
                allow_takeover: false,
            },
        )
        .unwrap(),
    );
    let disabled_bundle =
        common::unpack_tar_gz(&build_disabled_server_bundle(&state, srv3).unwrap());
    let apply_sh = render_apply_script(&state).unwrap();

    assert_shell_syntax("bash", &String::from_utf8_lossy(&bundle1["install.sh"].1));
    assert_shell_syntax(
        "bash",
        &String::from_utf8_lossy(&disabled_bundle["install.sh"].1),
    );
    assert_shell_syntax("bash", &apply_sh);
    assert_shell_syntax(
        "bash",
        include_str!("../src/deploy/scripts/update_firewall.sh"),
    );
    assert_shell_syntax(
        "bash",
        include_str!("../src/deploy/scripts/snapshot_traffic.sh"),
    );
    assert_shell_syntax("sh", include_str!("../src/deploy/scripts/wipe.sh"));
    assert_shell_syntax("sh", include_str!("../scripts/install-release.sh"));
    for wrapper in [
        remote_wipe_cmd("root", 2220),
        remote_wipe_cmd("ops", 2220),
        remote_retire_caddy_cmd("root"),
        remote_retire_caddy_cmd("ops"),
    ] {
        let status = Command::new("sh")
            .args(["-n", "-c", &wrapper])
            .status()
            .expect("invoke sh -n");
        assert!(status.success(), "sh -n failed for: {wrapper}");
    }
}
