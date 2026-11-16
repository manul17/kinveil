mod common;

use std::fs::{self, Permissions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::TempPrivateDir;
use kinveil::crypto::{generate_openssh_ed25519, parse_and_verify_hysteria_cert};
use kinveil::state::ServerArch;
use kinveil::store::read_encrypted_file;

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

fn user_sub_url(state_path: &Path, pass: &str, user: &str) -> String {
    let state = read_encrypted_file(state_path, pass).expect("read state");
    let u = state.user(user).expect("user in state");
    format!(
        "https://{}{}{}",
        state.subscription.domain,
        state.subscription.base_path.as_str(),
        u.subscription_token.as_str()
    )
}

#[test]
fn end_to_end_cli_state_and_dry_run_workflow() {
    let tmp = TempPrivateDir::new("kinveil-cli-e2e");
    let home_dir = tmp.path.join("home");
    fs::create_dir_all(&home_dir).expect("create fake HOME");
    fs::set_permissions(&home_dir, Permissions::from_mode(0o700)).expect("chmod HOME");
    let state_path = tmp.path.join("state.enc");
    let pass = "correct-horse-battery-staple";
    let cf_token = "cf-super-secret-api-token-e2e";

    // 1. init (default randomized subscription base_path)
    let init_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["init", "--domain", "sub.example.com"],
    );
    assert!(init_out.contains("Initialized encrypted state"));
    assert!(init_out.contains("KINVEIL_PASSPHRASE_COMMAND"));
    assert!(state_path.exists());

    // 2. cloudflare set (consumes state passphrase then API token from fd 0)
    let cf_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass, cf_token],
        &[
            "cloudflare",
            "set",
            "--zone-id",
            "0123456789abcdef0123456789abcdef",
            "--ttl",
            "120",
        ],
    );
    assert!(cf_out.contains("Saved Cloudflare DNS config"));

    // 3. server add (with explicit --ssh-host-key so no network scan occurs)
    let (_, admin_host_pub) = generate_openssh_ed25519("edge1-admin").expect("host key");
    let srv_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "add",
            "203.0.113.10",
            "--id",
            "edge1",
            "--label",
            "Edge One",
            "--roles",
            "vpn,subscription",
            "--sni",
            "www.microsoft.com",
            "--ssh-host-key",
            &admin_host_pub,
        ],
    );
    assert!(srv_out.contains("Added server 'edge1'"));

    // 4. user add
    let alice_add = run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "add", "alice"]);
    assert!(alice_add.contains("Added user 'alice'"));

    let bob_add = run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "add", "bob"]);
    assert!(bob_add.contains("Added user 'bob'"));

    // 5. show via KINVEIL_PASSPHRASE_COMMAND (summary visible, secrets redacted) + error paths
    let show_raw = run_kinveil_with_cmd_env(
        &state_path,
        &home_dir,
        &format!("printf '%s\\n' '{pass}'"),
        &["show"],
    );
    assert!(show_raw.status.success());
    let show_stdout = String::from_utf8_lossy(&show_raw.stdout);
    let show_stderr = String::from_utf8_lossy(&show_raw.stderr);
    assert!(show_stdout.contains("Settings defaults:"));
    assert!(show_stdout.contains("Firewall:"));
    assert!(show_stdout.contains("Deploy status:"));
    assert!(show_stdout.contains("edge1 (Edge One)"));
    assert!(show_stdout.contains("roles=[vpn,subscription]"));
    assert!(show_stdout.contains("sni=www.microsoft.com"));
    assert!(show_stdout.contains("name=alice [enabled]"));
    assert!(show_stdout.contains("name=bob [enabled]"));
    assert!(show_stdout.contains("api_token=<redacted>"));
    assert!(show_stdout.contains("base_path=<redacted>"));
    assert!(!show_stdout.contains(cf_token));
    assert!(!show_stderr.contains(cf_token));
    assert!(!show_stdout.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(!show_stdout.contains("BEGIN PRIVATE KEY"));

    let cmd_fail = run_kinveil_with_cmd_env(&state_path, &home_dir, "exit 7", &["show"]);
    assert!(!cmd_fail.status.success());
    let cmd_empty = run_kinveil_with_cmd_env(&state_path, &home_dir, "printf '\\n'", &["show"]);
    assert!(!cmd_empty.status.success());

    // completions does not require state.enc or invoke passphrase command
    let missing_state = tmp.path.join("does-not-exist.enc");
    let comp_out = run_kinveil_with_cmd_env(
        &missing_state,
        &home_dir,
        "exit 99",
        &["completions", "bash"],
    );
    assert!(comp_out.status.success());
    assert!(String::from_utf8_lossy(&comp_out.stdout).contains("_kinveil"));

    // 6. user list, server list, user share, user share --url-only, and user amneziawg-conf
    let user_list_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "list"]);
    assert!(user_list_out.contains("Users (2, 2 enabled):"));
    assert!(user_list_out.contains("name=alice [enabled]"));
    let server_list_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["server", "list"]);
    assert!(server_list_out.contains("Servers (1):"));
    assert!(server_list_out.contains("edge1 (Edge One)"));
    assert!(server_list_out.contains("sni=www.microsoft.com"));

    let alice_url_1 = user_sub_url(&state_path, pass, "alice");
    let share_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "share", "alice"]);
    assert!(share_out.contains(&alice_url_1));
    assert!(share_out.contains('\u{2588}') || share_out.contains('\u{2580}'));
    assert!(share_out.contains("Happ"));
    assert!(share_out.contains("Throne"));
    assert!(share_out.contains("SSH forwarding"));
    assert!(share_out.contains("Tips:"));
    assert!(share_out.contains("vless-stream"));
    assert!(share_out.contains("Karing 1.2.25"));
    assert!(share_out.contains("amneziawg"));

    let bob_url = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "share", "bob", "--url-only"],
    )
    .trim()
    .to_owned();
    assert!(bob_url.starts_with("https://sub.example.com/"));
    assert!(!bob_url.starts_with("https://sub.example.com/sub/"));
    assert_eq!(bob_url.matches('/').count(), 4);
    assert_ne!(alice_url_1, bob_url);

    let alice_awg_1 = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "amneziawg-conf", "alice"],
    );
    assert!(alice_awg_1.contains("[Interface]"));
    assert!(alice_awg_1.contains("Address = 10.8.0.2/32"));
    assert!(alice_awg_1.contains("Endpoint = 203.0.113.10:7443"));
    assert!(alice_awg_1.contains("RandomTrailers = on"));
    assert!(alice_awg_1.contains("DisableCookies = on"));

    // 7. user rotate without --rotate-url keeps URL while changing credentials
    let rot_keep = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "rotate", "alice"],
    );
    assert!(rot_keep.contains("Rotated credentials for 'alice'"));
    assert_eq!(alice_url_1, user_sub_url(&state_path, pass, "alice"));

    let alice_awg_2 = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "amneziawg-conf", "alice"],
    );
    assert_ne!(alice_awg_1, alice_awg_2);

    // 8. validate & deploy --dry-run
    let val_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["validate"]);
    assert!(val_out.contains("Validation OK:"));
    assert!(val_out.contains("users=2, servers=1, deploy=ready"));

    let dry_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["deploy", "--dry-run"]);
    assert!(dry_out.contains("DRY RUN"));
    assert!(dry_out.contains("Enabled users: 2"));
    assert!(dry_out.contains("[DEPLOY] edge1 (Edge One, 203.0.113.10)"));
    assert!(dry_out.contains("roles=[vpn,subscription]"));
    assert!(dry_out.contains("sni=www.microsoft.com"));
    assert!(dry_out.contains("[DNS] Cloudflare sync sub.example.com -> A=203.0.113.10"));
}

#[test]
fn cli_passphrase_guards_backups_passwd_and_restore() {
    let tmp = TempPrivateDir::new("kinveil-cli-ops");
    let home_dir = tmp.path.join("home");
    fs::create_dir_all(&home_dir).expect("create fake HOME");
    fs::set_permissions(&home_dir, Permissions::from_mode(0o700)).expect("chmod HOME");
    let state_path = tmp.path.join("state.enc");
    let pass1 = "correct-horse-battery-staple";
    let pass2 = "second-passphrase-for-rotation-99";

    // 1. Weak passphrases rejected on init (< 12 chars, < 4 distinct chars)
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

    // 2. --base-path override + share warning when vault is not yet deploy-ready
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &[
            "init",
            "--domain",
            "sub.example.com",
            "--base-path",
            "/custom-sub-path/",
        ],
    );
    run_kinveil_ok(&state_path, &home_dir, &[pass1], &["user", "add", "alice"]);

    let share_out = run_kinveil(
        &state_path,
        &home_dir,
        &[pass1],
        &["user", "share", "alice", "--url-only"],
    );
    assert!(share_out.status.success());
    let url_before = String::from_utf8(share_out.stdout)
        .expect("utf-8 url")
        .trim()
        .to_owned();
    let share_err = String::from_utf8_lossy(&share_out.stderr);
    assert!(url_before.starts_with("https://sub.example.com/custom-sub-path/"));
    assert_eq!(url_before.lines().count(), 1);
    assert!(share_err.contains("not yet deploy-ready"));

    // 3. Manual backup, token rotation, and rolling backups across disable/enable
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

    let rot_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["user", "rotate", "alice", "--rotate-url"],
    );
    assert!(rot_out.contains("subscription token"));
    assert!(rot_out.contains("Warning: subscription URL changed"));
    let url_after = user_sub_url(&state_path, pass1, "alice");
    assert_ne!(url_before, url_after);

    for action in ["disable", "enable"] {
        run_kinveil_ok(&state_path, &home_dir, &[pass1], &["user", action, "alice"]);
    }
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
            let n = name.strip_prefix("state.")?.strip_suffix(".enc")?;
            n.parse::<u64>().ok()
        })
        .collect();
    revs.sort_unstable();
    assert!(!revs.is_empty());

    // 4. passwd validation, passphrase change, old rolling backup decryption, and restore
    let weak_pw = run_kinveil(&state_path, &home_dir, &[pass1, "weakpass"], &["passwd"]);
    assert!(!weak_pw.status.success());

    let pw_ok = run_kinveil_ok(&state_path, &home_dir, &[pass1, pass2], &["passwd"]);
    assert!(pw_ok.contains("Updated state passphrase"));

    let old_pass_fails = run_kinveil(&state_path, &home_dir, &[pass1], &["validate"]);
    assert!(!old_pass_fails.status.success());
    run_kinveil_ok(&state_path, &home_dir, &[pass2], &["validate"]);

    let latest_old_rev = *revs.last().unwrap();
    let old_rolling = backups_dir.join(format!("state.{latest_old_rev}.enc"));
    run_kinveil_ok(&old_rolling, &home_dir, &[pass1], &["validate"]);

    // Overwriting an existing vault without --yes fails non-interactively without altering state.enc
    let rest_needs_yes = run_kinveil(
        &state_path,
        &home_dir,
        &[pass1],
        &["restore", manual_backup.to_str().unwrap()],
    );
    assert!(!rest_needs_yes.status.success());
    run_kinveil_ok(&state_path, &home_dir, &[pass2], &["validate"]);

    let rest_ok = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["restore", "--yes", manual_backup.to_str().unwrap()],
    );
    assert!(rest_ok.contains("Restored state"));
    let restored_state = read_encrypted_file(&state_path, pass1).expect("read restored state");
    assert!(restored_state.revision > latest_old_rev);
    let restored_url = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass1],
        &["user", "share", "alice", "--url-only"],
    )
    .trim()
    .to_owned();
    assert_eq!(restored_url, url_before);
}

#[test]
fn cli_config_preserves_comments_uses_ram_editor_and_validates() {
    let tmp = TempPrivateDir::new("kinveil-cli-config");
    let home_dir = tmp.path.join("home");
    fs::create_dir_all(&home_dir).expect("create fake HOME");
    fs::set_permissions(&home_dir, Permissions::from_mode(0o700)).expect("chmod HOME");
    let state_path = tmp.path.join("state.enc");
    let pass = "correct-horse-battery-staple";

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["init", "--domain", "sub.example.com"],
    );

    // 1. config --print starts with default commented template
    let printed_default = run_kinveil_ok(&state_path, &home_dir, &[pass], &["config", "--print"]);
    assert_eq!(printed_default, kinveil::state::DEFAULT_CONFIG_TOML);

    // 2. config --file imports commented TOML and preserves comments across mutations
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
        &[pass],
        &["config", "--file", custom_file.to_str().unwrap()],
    );
    assert!(apply_out.contains("Updated configuration"));

    run_kinveil_ok(&state_path, &home_dir, &[pass], &["user", "add", "alice"]);
    let printed_after_user =
        run_kinveil_ok(&state_path, &home_dir, &[pass], &["config", "--print"]);
    assert_eq!(printed_after_user, custom_toml);

    // 3. Interactive `kinveil config` writes only config.toml under /dev/shm on Linux
    let recorded_path = tmp.path.join("editor-seen-path.txt");
    let recorded_content = tmp.path.join("editor-seen-content.txt");
    let editor_script = tmp.path.join("fake-editor.sh");
    let bad_toml = "unknown_key_not_allowed = true\n";
    let script_body = format!(
        "#!/bin/sh\nset -eu\nprintf '%s' \"$1\" > \"{}\"\ncat \"$1\" > \"{}\"\nprintf '%s' \"$KINVEIL_TEST_NEW_TOML\" > \"$1\"\n",
        recorded_path.display(),
        recorded_content.display(),
    );
    fs::write(&editor_script, script_body).expect("write fake editor");
    fs::set_permissions(&editor_script, Permissions::from_mode(0o700)).expect("chmod editor");

    // 3a. Invalid edit fails cleanly without mutating vault
    let bad_edit = Command::new(env!("CARGO_BIN_EXE_kinveil"))
        .arg("--state")
        .arg(&state_path)
        .arg("config")
        .env("HOME", &home_dir)
        .env_remove("VISUAL")
        .env_remove("KINVEIL_PASSPHRASE_FD")
        .env(
            "KINVEIL_PASSPHRASE_COMMAND",
            format!("printf '%s\\n' '{pass}'"),
        )
        .env("EDITOR", &editor_script)
        .env("KINVEIL_TEST_NEW_TOML", bad_toml)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run invalid interactive kinveil config");
    assert!(!bad_edit.status.success());

    let seen_path = fs::read_to_string(&recorded_path).expect("read seen path");
    #[cfg(target_os = "linux")]
    assert!(
        seen_path.starts_with("/dev/shm/"),
        "expected tmpfs path under /dev/shm, got {seen_path}"
    );
    let seen_content = fs::read_to_string(&recorded_content).expect("read seen content");
    assert_eq!(seen_content, custom_toml);
    assert!(!seen_content.contains("users"));
    assert!(!seen_content.contains("servers"));
    assert!(!seen_content.contains("base_path"));
    assert!(!seen_content.contains("private_key"));

    assert_eq!(
        read_encrypted_file(&state_path, pass).unwrap().config_toml,
        custom_toml
    );

    // 3b. Valid interactive edit saves new TOML
    let updated_toml = "# Edited in RAM\n[firewall]\nblock_bittorrent = false\n";
    let good_edit = Command::new(env!("CARGO_BIN_EXE_kinveil"))
        .arg("--state")
        .arg(&state_path)
        .arg("config")
        .env("HOME", &home_dir)
        .env_remove("VISUAL")
        .env_remove("KINVEIL_PASSPHRASE_FD")
        .env(
            "KINVEIL_PASSPHRASE_COMMAND",
            format!("printf '%s\\n' '{pass}'"),
        )
        .env("EDITOR", &editor_script)
        .env("KINVEIL_TEST_NEW_TOML", updated_toml)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run valid interactive kinveil config");
    assert!(
        good_edit.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&good_edit.stderr)
    );
    assert_eq!(
        read_encrypted_file(&state_path, pass).unwrap().config_toml,
        updated_toml
    );

    // 4. config --reset requires --yes non-interactively before restoring defaults
    let reset_denied = run_kinveil(&state_path, &home_dir, &[pass], &["config", "--reset"]);
    assert!(!reset_denied.status.success());
    assert_eq!(
        read_encrypted_file(&state_path, pass).unwrap().config_toml,
        updated_toml
    );

    let reset_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["config", "--reset", "--yes"],
    );
    assert!(reset_out.contains("Reset configuration to defaults"));
    assert_eq!(
        read_encrypted_file(&state_path, pass).unwrap().config_toml,
        kinveil::state::DEFAULT_CONFIG_TOML
    );
}

#[test]
fn cli_convenience_commands_bare_state_and_ssh_rejection() {
    let tmp = TempPrivateDir::new("kinveil-cli-convenience");
    let home_dir = tmp.path.join("home");
    fs::create_dir_all(&home_dir).expect("create fake HOME");
    fs::set_permissions(&home_dir, Permissions::from_mode(0o700)).expect("chmod HOME");
    let pass = "correct-horse-battery-staple";

    // Write a fake known_hosts matching the server host IPs we add
    let ssh_dir = home_dir.join(".ssh");
    fs::create_dir_all(&ssh_dir).expect("create .ssh");
    fs::set_permissions(&ssh_dir, Permissions::from_mode(0o700)).expect("chmod .ssh");
    let (_, host_pub) = generate_openssh_ed25519("host-test").expect("generate ed25519");
    fs::write(
        ssh_dir.join("known_hosts"),
        format!(
            "198.51.100.10 {}\n198.51.100.11 {}\n",
            host_pub.trim(),
            host_pub.trim(),
        ),
    )
    .expect("write known_hosts");
    fs::set_permissions(ssh_dir.join("known_hosts"), Permissions::from_mode(0o600))
        .expect("chmod known_hosts");

    // Initialize in `tmp.path` with bare `--state barefile.enc`
    let mut init_cmd = Command::new(env!("CARGO_BIN_EXE_kinveil"));
    init_cmd
        .current_dir(&tmp.path)
        .args([
            "--state",
            "barefile.enc",
            "init",
            "--domain",
            "sub1.example.com",
        ])
        .env("HOME", &home_dir)
        .env("KINVEIL_PASSPHRASE_FD", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut init_child = init_cmd.spawn().expect("spawn bare init");
    writeln!(init_child.stdin.take().unwrap(), "{pass}").unwrap();
    let init_bare = init_child.wait_with_output().unwrap();
    assert!(
        init_bare.status.success(),
        "bare init failed:\n{}",
        String::from_utf8_lossy(&init_bare.stderr)
    );
    let state_path = tmp.path.join("barefile.enc");
    assert!(state_path.exists());

    // Multi-user add
    let multi_add = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "add", "carol", "dave"],
    );
    assert!(multi_add.contains("carol") && multi_add.contains("dave"));

    // SSH option-injection rejections
    let bad_host = run_kinveil(
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
            "Bad Host",
            "--ssh-host",
            "-oProxyCommand=id",
            "--roles",
            "vpn",
            "--sni",
            "example.com",
        ],
    );
    assert!(!bad_host.status.success());

    let bad_user = run_kinveil(
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
            "Bad User",
            "--ssh-user",
            "-bad",
            "--roles",
            "vpn",
            "--sni",
            "example.com",
        ],
    );
    assert!(!bad_user.status.success());

    // First server omits --id and --roles -> derives slug, auto-assigns subscription, uses known_hosts, sets inline ports
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
            "--sni",
            "cdn.cloudflare.com",
            "--vless-port",
            "10443",
            "--hysteria2-port",
            "10444",
        ],
    );
    assert!(srv1_out.contains("Added server 'de-germany'"));
    assert!(srv1_out.contains("auto-assigned subscription role"));

    // server update --sni updates existing server SNI
    let set_sni_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "de-germany", "--sni", "dl.google.com"],
    );
    assert!(set_sni_out.contains("de-germany"));

    // Second server with vpn (selected protocols) and subscription switch + SNI via server update
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "add",
            "198.51.100.11",
            "--id",
            "srv2",
            "--label",
            "Server Two",
            "--roles",
            "vpn",
            "--protocols",
            "vless,ssh-forwarding",
            "--sni",
            "yahoo.com",
        ],
    );
    let set_roles_sni = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "srv2",
            "--roles",
            "vpn,subscription",
            "--sni",
            "WWW.MICROSOFT.COM",
        ],
    );
    assert!(set_roles_sni.contains("srv2"));

    // Passing --sni when vpn role is omitted must fail
    let bad_roles_sni = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "de-germany",
            "--roles",
            "subscription",
            "--sni",
            "bad.example",
        ],
    );
    assert!(!bad_roles_sni.status.success());

    // set-domain + --rotate-base-path updates rendered subscription URLs
    let url_before = user_sub_url(&state_path, pass, "carol");
    assert!(url_before.starts_with("https://sub1.example.com/"));

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["set-domain", "sub2.example.com", "--rotate-base-path"],
    );
    let url_after = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "share", "carol", "--url-only"],
    )
    .trim()
    .to_owned();
    assert!(url_after.starts_with("https://sub2.example.com/"));
    assert_ne!(
        url_before.split('/').nth(3),
        url_after.split('/').nth(3),
        "expected base_path rotation to change URL prefix"
    );

    // Server update + show summary + clear-ipv6
    let (_, rotated_host_pub) = generate_openssh_ed25519("srv1-rotated-host").expect("rotated key");
    let update_out = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "de-germany",
            "--label",
            "DE Germany Updated",
            "--ipv6",
            "2001:db8::42",
            "--ssh-port",
            "2220",
            "--ssh-user",
            "ops",
            "--ssh-host-key",
            &rotated_host_pub,
        ],
    );
    assert!(update_out.contains("Updated server 'de-germany'"));

    let show_out = run_kinveil_ok(&state_path, &home_dir, &[pass], &["show"]);
    assert!(
        show_out.contains("de-germany (DE Germany Updated)"),
        "{show_out}"
    );
    assert!(show_out.contains("ipv6=2001:db8::42"), "{show_out}");
    assert!(
        show_out.contains("ssh=ops@198.51.100.10:2220"),
        "{show_out}"
    );
    assert!(show_out.contains("vless=10443/tcp"), "{show_out}");
    assert!(show_out.contains("10444/udp"), "{show_out}");
    assert!(show_out.contains("name=dave [enabled]"), "{show_out}");

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "de-germany", "--clear-ipv6"],
    );

    let loaded = read_encrypted_file(&state_path, pass).unwrap();
    assert_eq!(loaded.servers[0].public_ipv6, None);
    assert_eq!(loaded.servers[0].admin_ssh.port.get(), 2220);
    assert_eq!(loaded.servers[0].admin_ssh.user, "ops");
    assert_eq!(loaded.servers[0].ports.vless.map(|p| p.get()), Some(10443));
    assert_eq!(
        loaded.servers[0].ports.hysteria2.map(|p| p.get()),
        Some(10444)
    );
    let srv2_vpn = loaded.servers[1].vpn.as_ref().unwrap();
    assert_eq!(srv2_vpn.vless.server_name, "www.microsoft.com");
    assert!(srv2_vpn.vless.enabled);
    assert!(srv2_vpn.ssh_forwarding.enabled);
    assert!(!srv2_vpn.hysteria2.enabled);
    assert!(!srv2_vpn.amneziawg.enabled);
}

#[test]
fn cli_notes_protocols_rotation_ipv4_and_destructive_confirmations() {
    let tmp = TempPrivateDir::new("kinveil-cli-v1-features");
    let home_dir = tmp.path.join("home");
    fs::create_dir_all(&home_dir).expect("create fake HOME");
    fs::set_permissions(&home_dir, Permissions::from_mode(0o700)).expect("chmod HOME");
    let state_path = tmp.path.join("state.enc");
    let pass = "correct-horse-battery-staple";

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["init", "--domain", "sub.example.com"],
    );
    let (_, key1) = generate_openssh_ed25519("s1-host").expect("key1");
    let (_, key2) = generate_openssh_ed25519("s2-host").expect("key2");
    let (_, key2_new) = generate_openssh_ed25519("s2-new-host").expect("key2_new");

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
            "--sni",
            "dl.google.com",
            "--ssh-host-key",
            &key1,
            "--note",
            "Primary sub node",
        ],
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
            "--sni",
            "dl.google.com",
            "--ssh-host-key",
            &key2,
        ],
    );

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "add", "alice", "--note", "Phone only"],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "add", "tempuser"],
    );
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "update", "alice", "--note", "Laptop + Phone"],
    );
    let alice_state = read_encrypted_file(&state_path, pass).unwrap();
    assert_eq!(
        alice_state.user("alice").unwrap().note.as_deref(),
        Some("Laptop + Phone")
    );

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "update", "alice", "--note", ""],
    );
    let alice_cleared = read_encrypted_file(&state_path, pass).unwrap();
    assert_eq!(alice_cleared.user("alice").unwrap().note, None);

    let url_before = user_sub_url(&state_path, pass, "alice");
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "rotate", "alice", "--rotate-url"],
    );
    let url_after = user_sub_url(&state_path, pass, "alice");
    assert_ne!(url_before, url_after);

    // server update --sni auto-resets custom target/xhttp_host unless passed together
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "s1",
            "--target",
            "edge.dl.google.com:443",
            "--xhttp-host",
            "XHTTP.DL.GOOGLE.COM",
        ],
    );
    let before_sni_reset = read_encrypted_file(&state_path, pass).unwrap();
    let s1_vless_before = &before_sni_reset
        .server("s1")
        .unwrap()
        .vpn
        .as_ref()
        .unwrap()
        .vless;
    assert_eq!(s1_vless_before.target, "edge.dl.google.com:443");
    assert_eq!(
        s1_vless_before.xhttp_host.as_deref(),
        Some("xhttp.dl.google.com")
    );

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s1", "--sni", "WWW.MICROSOFT.COM"],
    );
    let after_sni_reset = read_encrypted_file(&state_path, pass).unwrap();
    let s1_vless_after = &after_sni_reset
        .server("s1")
        .unwrap()
        .vpn
        .as_ref()
        .unwrap()
        .vless;
    assert_eq!(s1_vless_after.server_name, "www.microsoft.com");
    assert_eq!(s1_vless_after.target, "www.microsoft.com:443");
    assert_eq!(s1_vless_after.xhttp_host, None);

    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &[
            "server",
            "update",
            "s1",
            "--sni",
            "dl.google.com",
            "--target",
            "custom.dl.google.com:443",
            "--xhttp-host",
            "xhttp.dl.google.com",
        ],
    );
    let explicit_override = read_encrypted_file(&state_path, pass).unwrap();
    let s1_vless_explicit = &explicit_override
        .server("s1")
        .unwrap()
        .vpn
        .as_ref()
        .unwrap()
        .vless;
    assert_eq!(s1_vless_explicit.target, "custom.dl.google.com:443");
    assert_eq!(
        s1_vless_explicit.xhttp_host.as_deref(),
        Some("xhttp.dl.google.com")
    );

    // server update --protocols declaratively replaces enabled protocols per node
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s2", "--protocols", "vless"],
    );
    let s2_vless_only = read_encrypted_file(&state_path, pass).unwrap();
    let s2_vpn = s2_vless_only.server("s2").unwrap().vpn.as_ref().unwrap();
    assert!(s2_vpn.vless.enabled);
    assert!(!s2_vpn.hysteria2.enabled);
    assert!(!s2_vpn.amneziawg.enabled);
    assert!(!s2_vpn.ssh_forwarding.enabled);

    let bad_all_off = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s2", "--protocols", ""],
    );
    assert!(!bad_all_off.status.success());
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s2", "--protocols", "vless,amneziawg"],
    );

    // server rotate changes server keys while preserving user subscription URL
    let before_rot = read_encrypted_file(&state_path, pass).unwrap();
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "rotate", "s1", "--all"],
    );
    let after_rot = read_encrypted_file(&state_path, pass).unwrap();
    assert_ne!(
        before_rot
            .server("s1")
            .unwrap()
            .vpn
            .as_ref()
            .unwrap()
            .vless
            .private_key
            .as_str(),
        after_rot
            .server("s1")
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
            .server("s1")
            .unwrap()
            .vpn
            .as_ref()
            .unwrap()
            .ssh_forwarding
            .host_private_key
            .as_str(),
        after_rot
            .server("s1")
            .unwrap()
            .vpn
            .as_ref()
            .unwrap()
            .ssh_forwarding
            .host_private_key
            .as_str()
    );
    assert_eq!(user_sub_url(&state_path, pass, "alice"), url_after);

    // server update --ipv4 updates IP, admin_ssh.host, and Hysteria2 TLS cert SAN
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
            "--ssh-host-key",
            &key2_new,
            "--arch",
            "aarch64",
            "--note",
            "arm test",
        ],
    );
    let s2_updated = read_encrypted_file(&state_path, pass).unwrap();
    let s2 = s2_updated.server("s2").unwrap();
    assert_eq!(s2.public_ipv4.to_string(), "198.51.100.55");
    assert_eq!(s2.admin_ssh.host, "198.51.100.55");
    assert_eq!(s2.arch, ServerArch::Aarch64);
    assert_eq!(s2.note.as_deref(), Some("arm test"));
    parse_and_verify_hysteria_cert(
        &s2.vpn.as_ref().unwrap().hysteria2.cert_pem,
        &s2.vpn.as_ref().unwrap().hysteria2.key_pem,
        "198.51.100.55",
    )
    .expect("Hysteria2 cert SAN updated with new --ipv4");

    // Partial dry-run targeting non-subscription server succeeds once x86_64 is restored
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "update", "s2", "--arch", "x86_64"],
    );
    let dry_s2 = run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["deploy", "--dry-run", "--server", "s2"],
    );
    assert!(dry_s2.contains("[DEPLOY] s2"));

    // Destructive removals require --yes non-interactively
    let rm_user_denied = run_kinveil(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "remove", "tempuser"],
    );
    assert!(!rm_user_denied.status.success());
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["user", "remove", "--yes", "tempuser"],
    );

    let rm_srv_denied = run_kinveil(&state_path, &home_dir, &[pass], &["server", "remove", "s2"]);
    assert!(!rm_srv_denied.status.success());
    run_kinveil_ok(
        &state_path,
        &home_dir,
        &[pass],
        &["server", "remove", "--yes", "s2"],
    );
    let final_state = read_encrypted_file(&state_path, pass).unwrap();
    assert!(final_state.user("tempuser").is_err());
    assert!(final_state.server("s2").is_err());
}
