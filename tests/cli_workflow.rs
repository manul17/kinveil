mod common;

use std::fs::{self, Permissions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::TempPrivateDir;
use kinveil::crypto::{generate_openssh_ed25519, parse_and_verify_hysteria_cert};
use kinveil::state::{DEFAULT_CONFIG_TOML, State, ValueSource};
use kinveil::store::read_encrypted_file;

fn setup_env(prefix: &str) -> (TempPrivateDir, PathBuf) {
    let tmp = TempPrivateDir::new(prefix);
    let home_dir = tmp.path.join("home");
    fs::create_dir_all(&home_dir).expect("create fake HOME");
    fs::set_permissions(&home_dir, Permissions::from_mode(0o700)).expect("chmod HOME");
    (tmp, home_dir)
}

fn run_kinveil(state_path: &Path, home_dir: &Path, fd_lines: &[&str], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kinveil"));
    cmd.arg("--state")
        .arg(state_path)
        .args(args)
        .env("HOME", home_dir)
        .env("KINVEIL_PASSPHRASE_FD", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn kinveil binary");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        for line in fd_lines {
            writeln!(stdin, "{line}").expect("write passphrase line");
        }
    }
    child.wait_with_output().expect("wait on kinveil binary")
}

fn run_kinveil_ok(state_path: &Path, home_dir: &Path, fd_lines: &[&str], args: &[&str]) -> String {
    let out = run_kinveil(state_path, home_dir, fd_lines, args);
    assert!(
        out.status.success(),
        "kinveil {:?} failed (status={}):\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

fn run_kinveil_with_cmd_env(
    state_path: &Path,
    home_dir: &Path,
    pass_cmd: &str,
    args: &[&str],
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kinveil"));
    cmd.arg("--state")
        .arg(state_path)
        .args(args)
        .env("HOME", home_dir)
        .env_remove("KINVEIL_PASSPHRASE_FD")
        .env("KINVEIL_PASSPHRASE_COMMAND", pass_cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().expect("run kinveil with passphrase command")
}

fn user_sub_url(state: &State, user: &str) -> String {
    let u = state.user(user).expect("user in state");
    state.user_subscription_url(u)
}

#[test]
fn cli_vault_passphrase_backups_and_config() {
    let (tmp, home_dir) = setup_env("kinveil-cli-vault");
    let pass1 = "correct-horse-battery-staple";
    let pass2 = "second-passphrase-for-rotation-99";
    let wrong_pass = "wrong-passphrase-for-diagnostics";

    // Weak passphrases rejected on init (< 12 chars, < 4 distinct chars)
    let state_path = tmp.path.join("state.enc");
    let short_out = run_kinveil(
        &state_path,
        &home_dir,
        &["short12345"],
        &["init", "--domain", "sub.example.com"],
    );
    assert!(!short_out.status.success());
    assert!(String::from_utf8_lossy(&short_out.stderr).contains("at least 12 characters"));

    let low_ent_out = run_kinveil(
        &state_path,
        &home_dir,
        &["aaaaaaaaaaaaa"],
        &["init", "--domain", "sub.example.com"],
    );
    assert!(!low_ent_out.status.success());
    assert!(String::from_utf8_lossy(&low_ent_out.stderr).contains("at least 4 distinct"));

    // completions works without an existing vault or invoking KINVEIL_PASSPHRASE_COMMAND
    let comp_out = run_kinveil_with_cmd_env(
        &tmp.path.join("does-not-exist.enc"),
        &home_dir,
        "exit 99",
        &["completions", "bash"],
    );
    assert!(comp_out.status.success());
    assert!(String::from_utf8_lossy(&comp_out.stdout).contains("_kinveil"));

    // Initialize with a relative `--state state.enc` from tmp.path
    let mut init_cmd = Command::new(env!("CARGO_BIN_EXE_kinveil"));
    init_cmd
        .current_dir(&tmp.path)
        .args([
            "--state",
            "state.enc",
            "init",
            "--domain",
            "sub.example.com",
        ])
        .env("HOME", &home_dir)
        .env("KINVEIL_PASSPHRASE_FD", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut init_child = init_cmd.spawn().expect("spawn bare init");
    writeln!(init_child.stdin.take().unwrap(), "{pass1}").unwrap();
    let init_res = init_child.wait_with_output().unwrap();
    assert!(
        init_res.status.success(),
        "{}",
        String::from_utf8_lossy(&init_res.stderr)
    );
    assert!(String::from_utf8_lossy(&init_res.stdout).contains("KINVEIL_PASSPHRASE_COMMAND"));
    assert!(state_path.exists());

    // Passphrase-source attribution on failed decrypt + failing/empty KINVEIL_PASSPHRASE_COMMAND
    let bad_fd = run_kinveil(&state_path, &home_dir, &[wrong_pass], &["show"]);
    assert!(!bad_fd.status.success());
    assert!(String::from_utf8_lossy(&bad_fd.stderr).contains("KINVEIL_PASSPHRASE_FD"));

    let bad_cmd = run_kinveil_with_cmd_env(
        &state_path,
        &home_dir,
        &format!("printf '%s\\n' '{wrong_pass}'"),
        &["show"],
    );
    assert!(!bad_cmd.status.success());
    assert!(String::from_utf8_lossy(&bad_cmd.stderr).contains("KINVEIL_PASSPHRASE_COMMAND"));
    assert!(
        !run_kinveil_with_cmd_env(&state_path, &home_dir, "exit 7", &["show"])
            .status
            .success()
    );
    assert!(
        !run_kinveil_with_cmd_env(&state_path, &home_dir, "printf '\\n'", &["show"])
            .status
            .success()
    );

    // config --print / --file / interactive RAM-backed editor / --reset --yes
    assert_eq!(
        run_kinveil_ok(&state_path, &home_dir, &[pass1], &["config", "--print"]),
        DEFAULT_CONFIG_TOML
    );

    let custom_file = tmp.path.join("custom.toml");
    let custom_toml = "\
# User-owned top comment
[subscription]
profile_title = \"Family\"

[amneziawg]
# Keep PPPoE MTU low
mtu = 1320
";
    fs::write(&custom_file, custom_toml).expect("write custom toml");
    let apply_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["config", "--file", custom_file.to_str().unwrap()],
    );
    assert!(apply_out.contains("Updated configuration"));

    // User mutations preserve custom TOML verbatim
    run_kinveil_ok(&state_path, &home_dir, &[pass1], &["user", "add", "alice"]);
    assert_eq!(
        run_kinveil_ok(&state_path, &home_dir, &[pass1], &["config", "--print"]),
        custom_toml
    );

    let recorded_path = tmp.path.join("editor-seen-path.txt");
    let recorded_content = tmp.path.join("editor-seen-content.txt");
    let editor_script = tmp.path.join("fake-editor.sh");
    fs::write(
        &editor_script,
        format!(
            "#!/bin/sh\nset -eu\nprintf '%s' \"$1\" > \"{}\"\ncat \"$1\" > \"{}\"\nprintf '%s' \"$KINVEIL_TEST_NEW_TOML\" > \"$1\"\n",
            recorded_path.display(),
            recorded_content.display(),
        ),
    )
    .expect("write fake editor");
    fs::set_permissions(&editor_script, Permissions::from_mode(0o700)).expect("chmod editor");

    let bad_edit = Command::new(env!("CARGO_BIN_EXE_kinveil"))
        .args(["--state"])
        .arg(&state_path)
        .arg("config")
        .env("HOME", &home_dir)
        .env_remove("VISUAL")
        .env_remove("KINVEIL_PASSPHRASE_FD")
        .env(
            "KINVEIL_PASSPHRASE_COMMAND",
            format!("printf '%s\\n' '{pass1}'"),
        )
        .env("EDITOR", &editor_script)
        .env("KINVEIL_TEST_NEW_TOML", "unknown_key_not_allowed = true\n")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run invalid interactive kinveil config");
    assert!(!bad_edit.status.success());
    let seen_path = fs::read_to_string(&recorded_path).expect("read seen path");
    #[cfg(target_os = "linux")]
    assert!(seen_path.starts_with("/dev/shm/"), "got {seen_path}");
    let seen_content = fs::read_to_string(&recorded_content).expect("read seen content");
    assert_eq!(seen_content, custom_toml);
    assert!(!seen_content.contains("private_key"));
    assert_eq!(
        read_encrypted_file(&state_path, pass1).unwrap().config_toml,
        custom_toml
    );

    let updated_toml = "# Edited in RAM\n[firewall.xray]\nblock_bittorrent = false\n";
    let good_edit = Command::new(env!("CARGO_BIN_EXE_kinveil"))
        .args(["--state"])
        .arg(&state_path)
        .arg("config")
        .env("HOME", &home_dir)
        .env_remove("VISUAL")
        .env_remove("KINVEIL_PASSPHRASE_FD")
        .env(
            "KINVEIL_PASSPHRASE_COMMAND",
            format!("printf '%s\\n' '{pass1}'"),
        )
        .env("EDITOR", &editor_script)
        .env("KINVEIL_TEST_NEW_TOML", updated_toml)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run valid interactive kinveil config");
    assert!(good_edit.status.success());

    assert!(
        !run_kinveil(&state_path, &home_dir, &[pass1], &["config", "--reset"])
            .status
            .success()
    );
    let reset_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["config", "--reset", "--yes"],
    );
    assert!(reset_out.contains("Reset configuration to defaults"));
    assert_eq!(
        read_encrypted_file(&state_path, pass1).unwrap().config_toml,
        DEFAULT_CONFIG_TOML
    );

    // Manual backup, rolling backups, passwd, and restore (--yes + wrong-passphrase error source)
    let manual_backup = tmp.path.join("manual-backup.enc");
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["backup", manual_backup.to_str().unwrap()],
    );
    assert_eq!(
        fs::metadata(&manual_backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let url_at_backup = user_sub_url(&read_encrypted_file(&state_path, pass1).unwrap(), "alice");

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["user", "rotate", "alice", "--rotate-url"],
    );
    assert_ne!(
        user_sub_url(&read_encrypted_file(&state_path, pass1).unwrap(), "alice"),
        url_at_backup
    );

    let backups_dir = tmp.path.join("backups");
    assert_eq!(
        fs::metadata(&backups_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut revs: Vec<u64> = fs::read_dir(&backups_dir)
        .unwrap()
        .filter_map(|e| {
            let e = e.ok()?;
            assert_eq!(e.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            let name = e.file_name().into_string().ok()?;
            name.strip_prefix("state.")?
                .strip_suffix(".enc")?
                .parse()
                .ok()
        })
        .collect();
    revs.sort_unstable();
    let latest_old_rev = *revs.last().expect("rolling backup exists");

    assert!(
        !run_kinveil(&state_path, &home_dir, &[pass1, "weakpass"], &["passwd"])
            .status
            .success()
    );
    assert!(
        run_kinveil_ok(&state_path, &home_dir, &[pass1, pass2], &["passwd"])
            .contains("Updated state passphrase")
    );
    assert!(
        !run_kinveil(&state_path, &home_dir, &[pass1], &["validate"])
            .status
            .success()
    );
    run_kinveil_ok(&state_path, &home_dir, &[pass2], &["validate"]);
    run_kinveil_ok(
        &backups_dir.join(format!("state.{latest_old_rev}.enc")),
        &home_dir,
        &[pass1],
        &["validate"],
    );

    let bad_restore = run_kinveil(
        &state_path,
        &home_dir,
        &[wrong_pass],
        &["restore", "--yes", manual_backup.to_str().unwrap()],
    );
    assert!(!bad_restore.status.success());
    assert!(String::from_utf8_lossy(&bad_restore.stderr).contains("KINVEIL_PASSPHRASE_FD"));

    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass1],
            &["restore", manual_backup.to_str().unwrap()],
        )
        .status
        .success()
    );
    let rest_ok = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["restore", "--yes", manual_backup.to_str().unwrap()],
    );
    assert!(rest_ok.contains("Restored state"));
    let restored = read_encrypted_file(&state_path, pass1).unwrap();
    assert!(restored.revision > latest_old_rev);
    assert_eq!(user_sub_url(&restored, "alice"), url_at_backup);
}

#[test]
fn cli_fleet_servers_and_subscriptions() {
    let (tmp, home_dir) = setup_env("kinveil-cli-fleet");
    let state_path = tmp.path.join("state.enc");
    let pass = "correct-horse-battery-staple";

    let ssh_dir = home_dir.join(".ssh");
    fs::create_dir_all(&ssh_dir).expect("create .ssh");
    fs::set_permissions(&ssh_dir, Permissions::from_mode(0o700)).expect("chmod .ssh");
    let (_, host_pub_1) = generate_openssh_ed25519("host1").unwrap();
    let (_, host_pub_2) = generate_openssh_ed25519("host2").unwrap();
    let (_, host_pub_3) = generate_openssh_ed25519("host3").unwrap();
    let (_, host_pub_2_new) = generate_openssh_ed25519("host2-rotated").unwrap();
    fs::write(
        ssh_dir.join("known_hosts"),
        format!("198.51.100.10 {}\n", host_pub_1.trim()),
    )
    .unwrap();
    fs::set_permissions(ssh_dir.join("known_hosts"), Permissions::from_mode(0o600)).unwrap();

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "init",
            "--domain",
            "sub1.example.com",
            "--base-path",
            "/custom-sub-path/",
        ],
    );
    run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "add", "alice"]);

    // Subscription show, set-path, set-domain --rotate-path, and Cloudflare CRUD
    let sub_show = run_kinveil_ok(&state_path, &home_dir, &[pass], &["subscription", "show"]);
    assert!(sub_show.contains("Domain:          sub1.example.com"));
    assert!(sub_show.contains("Cloudflare DNS:  not configured"));

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["subscription", "set-path", "--path", "/custom-edge/"],
    );
    assert_eq!(
        read_encrypted_file(&state_path, pass)
            .unwrap()
            .subscription
            .base_path
            .as_str(),
        "/custom-edge/"
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["subscription", "set-path", "--rotate"],
    );
    let url_before = user_sub_url(&read_encrypted_file(&state_path, pass).unwrap(), "alice");
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "subscription",
            "set-domain",
            "sub2.example.com",
            "--rotate-path",
        ],
    );
    let url_after = user_sub_url(&read_encrypted_file(&state_path, pass).unwrap(), "alice");
    assert!(url_after.starts_with("https://sub2.example.com/"));
    assert_ne!(url_before.split('/').nth(3), url_after.split('/').nth(3));

    let cf_token = "cf-secret-token-fleet";
    assert!(
        run_kinveil_ok(
            &state_path,
            &home_dir,
            &[pass, cf_token],
            &[
                "subscription",
                "cloudflare",
                "set",
                "--zone-id",
                "0123456789abcdef0123456789abcdef",
                "--ttl",
                "120",
            ],
        )
        .contains("Saved Cloudflare DNS config")
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["subscription", "cloudflare", "update", "--ttl", "300"],
    );
    let after_cf = read_encrypted_file(&state_path, pass).unwrap();
    let cf = after_cf.subscription.cloudflare.as_ref().unwrap();
    assert_eq!(cf.ttl, 300);
    assert_eq!(cf.api_token.as_str(), cf_token);

    // SSH option injection rejected
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &[
                "server",
                "add",
                "198.51.100.10",
                "--id",
                "bad",
                "--label",
                "Bad",
                "--ssh-host",
                "-oProxyCommand=id",
                "--vless-sni",
                "example.com",
            ],
        )
        .status
        .success()
    );
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &[
                "server",
                "add",
                "198.51.100.10",
                "--id",
                "bad2",
                "--label",
                "Bad",
                "--ssh-user",
                "-bad",
                "--vless-sni",
                "example.com",
            ],
        )
        .status
        .success()
    );

    // server add without --vless-sni: fails when VLESS active + no config default, succeeds without vless,
    // first server auto-slugifies label, auto-assigns subscription, and reads known_hosts.
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &["server", "add", "198.51.100.10", "--label", "DE Germany"],
        )
        .status
        .success()
    );
    let srv1_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "add",
            "198.51.100.10",
            "--label",
            "DE Germany",
            "--protocols",
            "hysteria2,amneziawg",
            "--hysteria2-port",
            "10444",
            "--ssh-key",
            "/home/ops/.ssh/id_kinveil",
            "--note",
            "Primary node",
        ],
    );
    assert!(srv1_out.contains("Added server 'de-germany'"));
    assert!(srv1_out.contains("auto-assigned subscription role"));

    // Setting [vless].sni in config.toml allows adding VLESS servers without --vless-sni
    let cfg_file = tmp.path.join("vless-sni.toml");
    fs::write(&cfg_file, "[vless]\nsni = \"www.apple.com\"\n").unwrap();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["config", "--file", cfg_file.to_str().unwrap()],
    );

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "add",
            "198.51.100.20",
            "--id",
            "s2",
            "--label",
            "Edge Two",
            "--roles",
            "vpn",
            "--vless-port",
            "443",
            "--vless-target",
            "edge.apple.com:443",
            "--vless-xhttp-host",
            "XHTTP.APPLE.COM",
            "--ssh-host-key",
            &host_pub_2,
        ],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "add",
            "198.51.100.21",
            "--id",
            "s3",
            "--label",
            "Edge Three",
            "--roles",
            "vpn",
            "--ssh-host-key",
            &host_pub_3,
            "--traffic",
        ],
    );
    let s3_show = run_kinveil_ok(&state_path, &home_dir, &[pass], &["server", "show", "s3"]);
    assert!(s3_show.contains("Traffic:     enabled (retention=90d)"));
    let s3_dry = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["deploy", "--dry-run", "--server", "s3"],
    );
    assert!(s3_dry.contains("traffic=on"));

    // --traffic requires 'vpn' role
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &[
                "server",
                "add",
                "198.51.100.22",
                "--id",
                "subonly",
                "--label",
                "Sub Only",
                "--roles",
                "subscription",
                "--traffic",
                "--ssh-host-key",
                &host_pub_3,
            ],
        )
        .status
        .success()
    );

    // traffic CLI pre-SSH validation errors and --no-traffic / --clear-traffic toggles
    let bad_date = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &["traffic", "--from", "2026-02-30"],
    );
    assert!(!bad_date.status.success());
    let reversed_dates = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &["traffic", "--from", "2026-11-20", "--to", "2026-11-10"],
    );
    assert!(!reversed_dates.status.success());
    let bad_user = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &["traffic", "--user", "nonexistent"],
    );
    assert!(!bad_user.status.success());
    let disabled_srv_traffic = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &["traffic", "--server", "s2"],
    );
    assert!(!disabled_srv_traffic.status.success());
    assert!(
        String::from_utf8_lossy(&disabled_srv_traffic.stderr)
            .contains("traffic accounting is not enabled on server 's2'")
    );

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s3", "--no-traffic"],
    );
    assert!(
        run_kinveil_ok(&state_path, &home_dir, &[pass], &["server", "show", "s3"])
            .contains("Traffic:     disabled")
    );
    let no_traffic_servers = run_kinveil(&state_path, &home_dir, &[pass], &["traffic"]);
    assert!(!no_traffic_servers.status.success());
    assert!(
        String::from_utf8_lossy(&no_traffic_servers.stderr)
            .contains("no enabled servers have traffic accounting enabled")
    );

    // Enabling vless on de-germany without --vless-sni succeeds via [vless].sni, then update --vless-sni + coupled reset
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "de-germany",
            "--protocols",
            "vless,hysteria2,amneziawg,ssh-forwarding",
            "--vless-port",
            "10443",
            "--clear-ssh-key",
        ],
    );
    let de_after_proto = read_encrypted_file(&state_path, pass).unwrap();
    let de_srv_proto = de_after_proto.server("de-germany").unwrap();
    assert_eq!(de_srv_proto.admin_ssh.identity_file, None);
    let de_eff = de_srv_proto.effective_config(&de_after_proto.settings, true);
    assert!(
        de_eff.has_ssh_forwarding,
        "explicit --protocols override must enable ssh-forwarding even when config default is false"
    );
    assert_eq!(de_eff.protocols_source.as_str(), "server");
    assert!(
        run_kinveil_ok(
            &state_path,
            &home_dir,
            &[pass],
            &["server", "show", "de-germany"],
        )
        .contains(
            "Protocols:   [vless-stream,vless-packet,hysteria2,amneziawg,ssh-forwarding] (server)"
        )
    );

    // --protocols override and --clear-protocols + --rename (including subscription host sync)
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s3", "--protocols", "hysteria2"],
    );
    assert!(
        run_kinveil_ok(&state_path, &home_dir, &[pass], &["server", "show", "s3"])
            .contains("Protocols:   [hysteria2] (server)")
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s3", "--clear-protocols"],
    );
    assert!(
        run_kinveil_ok(&state_path, &home_dir, &[pass], &["server", "show", "s3"])
            .contains("Protocols:   [vless-stream,vless-packet,hysteria2,amneziawg] (config)")
    );
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &["server", "update", "de-germany", "--rename", "s2"],
        )
        .status
        .success()
    );
    let renamed_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "de-germany", "--rename", "de1"],
    );
    assert!(renamed_out.contains("Updated server 'de-germany' -> 'de1'"));
    assert_eq!(
        read_encrypted_file(&state_path, pass)
            .unwrap()
            .subscription
            .server_id
            .as_deref(),
        Some("de1")
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "de1", "--rename", "de-germany"],
    );

    // Passing --vless-sni without vpn role fails
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &[
                "server",
                "update",
                "de-germany",
                "--roles",
                "subscription",
                "--vless-sni",
                "bad.example",
            ],
        )
        .status
        .success()
    );

    // Coupled --vless-sni reset clears previous --vless-target/--vless-xhttp-host on s2
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s2", "--vless-sni", "WWW.MICROSOFT.COM"],
    );
    let s2_reset = read_encrypted_file(&state_path, pass).unwrap();
    let s2_srv = s2_reset.server("s2").unwrap();
    let s2_vl = &s2_srv.vpn.as_ref().unwrap().vless;
    assert_eq!(s2_vl.sni.as_deref(), Some("www.microsoft.com"));
    assert_eq!(s2_vl.target, None);
    assert_eq!(s2_vl.xhttp_host, None);
    assert_eq!(
        s2_srv
            .effective_config(&s2_reset.settings, false)
            .vless_target,
        Some(("www.microsoft.com:443".to_owned(), ValueSource::Derived))
    );

    // --ipv6 / --clear-ipv6 preserves Hysteria2 cert_pem; --ipv4 regenerates it
    let s2_cert_before = s2_srv.vpn.as_ref().unwrap().hysteria2.cert_pem.clone();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s2", "--ipv6", "2001:db8::20"],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "s2",
            "--ipv4",
            "198.51.100.55",
            "--ssh-port",
            "2220",
            "--ssh-user",
            "ops",
            "--ssh-host-key",
            &host_pub_2_new,
            "--clear-ipv6",
            "--clear-vless-port",
            "--clear-vless-sni",
            "--note",
            "moved",
        ],
    );
    let s2_upd = read_encrypted_file(&state_path, pass).unwrap();
    let s2_u = s2_upd.server("s2").unwrap();
    assert_eq!(s2_u.public_ipv4.to_string(), "198.51.100.55");
    assert_eq!(s2_u.public_ipv6, None);
    assert_eq!(s2_u.admin_ssh.port.get(), 2220);
    assert_eq!(s2_u.admin_ssh.user, "ops");
    assert_eq!(s2_u.note.as_deref(), Some("moved"));
    assert_eq!(s2_u.vpn.as_ref().unwrap().vless.port, None);
    assert_eq!(s2_u.vpn.as_ref().unwrap().vless.sni, None);
    assert_ne!(
        s2_u.vpn.as_ref().unwrap().hysteria2.cert_pem,
        s2_cert_before
    );
    parse_and_verify_hysteria_cert(
        &s2_u.vpn.as_ref().unwrap().hysteria2.cert_pem,
        &s2_u.vpn.as_ref().unwrap().hysteria2.key_pem,
        "198.51.100.55",
    )
    .expect("Hysteria2 cert SAN matches new IPv4");

    // Empty --protocols rejected; --clear-ports clears all protocol ports
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &["server", "update", "de-germany", "--protocols", ""],
        )
        .status
        .success()
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "de-germany",
            "--clear-ports",
            "--clear-note",
        ],
    );
    let de_clr = read_encrypted_file(&state_path, pass).unwrap();
    let de_srv = de_clr.server("de-germany").unwrap();
    assert_eq!(de_srv.note, None);
    assert_eq!(de_srv.vpn.as_ref().unwrap().vless.port, None);
    assert_eq!(de_srv.vpn.as_ref().unwrap().hysteria2.port, None);

    // server list / server show / server rotate --all
    let srv_list = run_kinveil_ok(&state_path, &home_dir, &[pass], &["server", "list"]);
    assert!(srv_list.contains("Servers (3):"));
    assert!(srv_list.contains("de-germany (DE Germany)"));

    let srv_show = run_kinveil_ok(&state_path, &home_dir, &[pass], &["server", "show", "s2"]);
    assert!(srv_show.contains("Server: s2 (Edge Two)"));
    assert!(srv_show.contains("SSH host fp:"));
    assert!(srv_show.contains("cert_sha256="));
    assert!(srv_show.contains("spki_sha256="));
    assert!(!srv_show.contains("BEGIN PRIVATE KEY"));

    // Enable global ssh_forwarding before testing server rotate SSH host key diff
    let ssh_cfg_file = tmp.path.join("enable-ssh.toml");
    fs::write(
        &ssh_cfg_file,
        "[vless]\nsni = \"www.apple.com\"\n\n[ssh_forwarding]\nenabled = true\n",
    )
    .unwrap();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["config", "--file", ssh_cfg_file.to_str().unwrap()],
    );

    let before_rot = read_encrypted_file(&state_path, pass).unwrap();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "rotate", "de-germany", "--all"],
    );
    let after_rot = read_encrypted_file(&state_path, pass).unwrap();
    assert_ne!(
        before_rot
            .server("de-germany")
            .unwrap()
            .vpn
            .as_ref()
            .unwrap()
            .vless
            .private_key
            .as_str(),
        after_rot
            .server("de-germany")
            .unwrap()
            .vpn
            .as_ref()
            .unwrap()
            .vless
            .private_key
            .as_str()
    );
    assert_ne!(
        before_rot
            .server("de-germany")
            .unwrap()
            .vpn
            .as_ref()
            .unwrap()
            .ssh_forwarding
            .host_private_key
            .as_str(),
        after_rot
            .server("de-germany")
            .unwrap()
            .vpn
            .as_ref()
            .unwrap()
            .ssh_forwarding
            .host_private_key
            .as_str()
    );

    // Server SSH forwarding rotation must preserve custom --ssh-forwarding-port override
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s2", "--ssh-forwarding-port", "2224"],
    );
    let s2_before_ssh_rot = read_encrypted_file(&state_path, pass).unwrap();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "rotate", "s2", "--ssh-forwarding"],
    );
    let s2_after_ssh_rot = read_encrypted_file(&state_path, pass).unwrap();
    let s2_ssh_before = &s2_before_ssh_rot
        .server("s2")
        .unwrap()
        .vpn
        .as_ref()
        .unwrap()
        .ssh_forwarding;
    let s2_ssh_after = &s2_after_ssh_rot
        .server("s2")
        .unwrap()
        .vpn
        .as_ref()
        .unwrap()
        .ssh_forwarding;
    assert_eq!(s2_ssh_after.port.map(|p| p.get()), Some(2224));
    assert_ne!(
        s2_ssh_before.host_private_key.as_str(),
        s2_ssh_after.host_private_key.as_str()
    );

    // validate & deploy --dry-run (full + --server), then clear Cloudflare
    assert!(
        run_kinveil_ok(&state_path, &home_dir, &[pass], &["validate"])
            .contains("users=1, servers=3, deploy=ready")
    );
    let dry_all = run_kinveil_ok(&state_path, &home_dir, &[pass], &["deploy", "--dry-run"]);
    assert!(dry_all.contains("[DEPLOY] de-germany (DE Germany, 198.51.100.10)"));
    assert!(dry_all.contains("[DNS] Cloudflare sync sub2.example.com -> A=198.51.100.10"));
    assert!(
        run_kinveil_ok(
            &state_path,
            &home_dir,
            &[pass],
            &["deploy", "--dry-run", "--server", "s2"],
        )
        .contains("[DEPLOY] s2")
    );

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["subscription", "cloudflare", "clear"],
    );
    assert!(
        read_encrypted_file(&state_path, pass)
            .unwrap()
            .subscription
            .cloudflare
            .is_none()
    );

    // Multi-server disable / enable / remove (--yes required non-interactively)
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "disable", "s2", "s3"],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "enable", "s2", "s3"],
    );
    assert!(
        !run_kinveil(&state_path, &home_dir, &[pass], &["server", "remove", "s2"])
            .status
            .success()
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "remove", "--yes", "s2", "s3"],
    );
    let remaining = read_encrypted_file(&state_path, pass).unwrap();
    assert_eq!(remaining.servers.len(), 1);
    assert_eq!(remaining.servers[0].id, "de-germany");
}

#[test]
fn cli_users_rotation_sharing_and_export() {
    let (tmp, home_dir) = setup_env("kinveil-cli-users");
    let state_path = tmp.path.join("state.enc");
    let pass = "correct-horse-battery-staple";

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["init", "--domain", "sub.example.com"],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "add", "alice", "bob"],
    );

    // Share before a server is added warns that vault is not yet deploy-ready
    let early_share = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "share", "alice", "--url-only"],
    );
    assert!(early_share.status.success());
    assert!(String::from_utf8_lossy(&early_share.stderr).contains("not yet deploy-ready"));

    let (_, host_pub) = generate_openssh_ed25519("s1-host").unwrap();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "add",
            "203.0.113.10",
            "--id",
            "s1",
            "--label",
            "Edge One",
            "--roles",
            "vpn,subscription",
            "--vless-sni",
            "www.microsoft.com",
            "--ssh-host-key",
            &host_pub,
        ],
    );

    // user add --disabled --note, user update --rename --note --clear-note (and empty note rejection)
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "add", "guest", "--disabled", "--note", "Temp guest"],
    );
    assert!(
        !read_encrypted_file(&state_path, pass)
            .unwrap()
            .user("guest")
            .unwrap()
            .enabled
    );
    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &["user", "update", "guest", "--note", ""],
        )
        .status
        .success()
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "user", "update", "guest", "--rename", "carol", "--note", "Laptop",
        ],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "update", "carol", "--clear-note"],
    );
    let carol_state = read_encrypted_file(&state_path, pass).unwrap();
    assert!(carol_state.user("guest").is_err());
    assert_eq!(carol_state.user("carol").unwrap().uid, 3);
    assert_eq!(carol_state.user("carol").unwrap().note, None);

    // show / user list / user show (secrets redacted) — ssh_forwarding is disabled by default
    let show_default = run_kinveil_ok(&state_path, &home_dir, &[pass], &["show"]);
    assert!(show_default.contains("protocols=[vless-stream,vless-packet,hysteria2,amneziawg]"));

    let ssh_on_cfg = tmp.path.join("ssh-on.toml");
    fs::write(&ssh_on_cfg, "[ssh_forwarding]\nenabled = true\n").unwrap();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["config", "--file", ssh_on_cfg.to_str().unwrap()],
    );

    let show_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["show"]);
    assert!(show_out.contains("Settings defaults:"));
    assert!(show_out.contains("Deploy status:       ready"));
    assert!(show_out.contains("Firewall (all):"));
    assert!(show_out.contains("Firewall (xray):     block_bittorrent=true"));
    assert!(show_out.contains("Traffic accounting:  0/1 enabled servers (retention=90d)"));
    assert!(show_out.contains("block_countries=[]"));
    assert!(show_out.contains("name=alice [enabled] awg=10.8.0.2"));
    assert!(show_out.contains("base_path=<redacted>"));
    assert!(!show_out.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(!show_out.contains("BEGIN PRIVATE KEY"));

    let ulist = run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "list"]);
    assert!(ulist.contains("Users (3, 2 enabled):"));

    let ushow = run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "show", "alice"]);
    assert!(ushow.contains("AmneziaWG IP:  10.8.0.2/32"));
    assert!(ushow.contains("SSH user:      vpnssh1"));
    assert!(ushow.contains("Sub token:     <redacted>"));
    assert!(!ushow.contains(carol_state.user("alice").unwrap().vless.uuid.as_str()));

    // user share QR + tips + --url-only
    let share_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "share", "alice"]);
    let url_1 = user_sub_url(&carol_state, "alice");
    assert!(share_out.contains(&url_1));
    assert!(share_out.contains('\u{2588}') || share_out.contains('\u{2580}'));
    assert!(share_out.contains("Happ") && share_out.contains("Throne"));
    assert!(share_out.contains("VLESS-Stream") && share_out.contains("Karing 1.2.25"));

    let bob_url = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "share", "bob", "--url-only"],
    )
    .trim()
    .to_owned();
    assert!(bob_url.starts_with("https://sub.example.com/"));
    assert_eq!(bob_url.matches('/').count(), 4);
    assert_ne!(url_1, bob_url);

    // Granular user rotate --vless, --all, and --rotate-url
    let alice_before = carol_state.user("alice").unwrap().clone();
    assert!(
        run_kinveil_ok(
            &state_path,
            &home_dir,
            &[pass],
            &["user", "rotate", "alice", "--vless"],
        )
        .contains("Rotated [vless] for 'alice'")
    );
    let after_vl = read_encrypted_file(&state_path, pass).unwrap();
    let alice_vl = after_vl.user("alice").unwrap();
    assert_ne!(
        alice_before.vless.uuid.as_str(),
        alice_vl.vless.uuid.as_str()
    );
    assert_eq!(
        alice_before.hysteria2.auth.as_str(),
        alice_vl.hysteria2.auth.as_str()
    );
    assert_eq!(url_1, user_sub_url(&after_vl, "alice"));

    let awg_1 = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "export", "alice", "--format", "amneziawg"],
    );
    assert!(awg_1.contains("Address = 10.8.0.2/32"));
    assert!(awg_1.contains("RandomTrailers = on"));
    assert!(
        run_kinveil_ok(
            &state_path,
            &home_dir,
            &[pass],
            &["user", "rotate", "alice", "--all"],
        )
        .contains("Rotated [vless,hysteria2,amneziawg,ssh-forwarding] for 'alice'")
    );
    assert_ne!(
        awg_1,
        run_kinveil_ok(
            &state_path,
            &home_dir,
            &[pass],
            &["user", "export", "alice", "--format", "amneziawg"],
        )
    );
    assert_eq!(url_1, user_sub_url(&after_vl, "alice"));

    let rot_url = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "rotate", "alice", "--rotate-url"],
    );
    assert!(rot_url.contains("Rotated [subscription-url] for 'alice'"));
    let after_rot_url = read_encrypted_file(&state_path, pass).unwrap();
    assert_ne!(url_1, user_sub_url(&after_rot_url, "alice"));

    // user export (urls, ssh) & debug render
    let urls = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "user", "export", "alice", "--format", "urls", "--server", "s1",
        ],
    );
    assert!(urls.contains("vless://") && urls.contains("#Edge%20One%20Hysteria2"));
    assert!(urls.contains("#Edge%20One%20SSH"));

    let render_dir = tmp.path.join("debug-render");
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "debug",
            "render",
            render_dir.to_str().unwrap(),
            "--allow-non-tmpfs",
        ],
    );
    assert!(
        render_dir
            .join("servers/s1/files/etc/caddy/Caddyfile")
            .is_file()
    );
    assert!(
        render_dir
            .join("servers/s1/files/etc/nftables.conf")
            .is_file()
    );
    assert!(render_dir.join("standalone/s1/nftables.conf").is_file());
    assert!(render_dir.join("subscriptions/alice/happ.txt").is_file());
    assert!(render_dir.join("subscriptions/alice/throne.txt").is_file());
    let ssh_export = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "user", "export", "alice", "--format", "ssh", "--server", "s1",
        ],
    );
    assert!(ssh_export.contains("vpnssh1@203.0.113.10:2222"));
    assert!(ssh_export.contains("ssh -N -D 1080"));

    // Multi-user enable / disable / remove (--yes required non-interactively)
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "enable", "carol"],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "disable", "alice", "bob", "carol"],
    );
    let all_disabled = read_encrypted_file(&state_path, pass).unwrap();
    assert!(all_disabled.users.values().all(|u| !u.enabled));

    assert!(
        !run_kinveil(
            &state_path,
            &home_dir,
            &[pass],
            &["user", "remove", "carol"]
        )
        .status
        .success()
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "remove", "--yes", "alice", "bob", "carol"],
    );
    assert!(
        read_encrypted_file(&state_path, pass)
            .unwrap()
            .users
            .is_empty()
    );
}
