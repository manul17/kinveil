mod common;

use std::fs::{self, Permissions};
use std::num::NonZeroU16;
use std::os::unix::fs::{PermissionsExt, symlink};

use common::{TempPrivateDir, make_user, valid_deployable_state};
use kinveil::crypto::{
    generate_hysteria_self_signed_cert, generate_openssh_ed25519, generate_x25519_reality_keypair,
};
use kinveil::deploy::ssh::lookup_known_hosts_key;
use kinveil::state::{
    ArtifactSettings, DEFAULT_CONFIG_TOML, IntOrRange, SCHEMA_VERSION, SecretString, ServerArch,
    Settings, State, parse_config_toml,
};
use kinveil::store::{
    HEADER_LEN, MAGIC, acquire_state_lock, backup_existing_state, decode_state, decrypt_bytes,
    encrypt_bytes, encrypt_bytes_with_params, encrypt_state, max_backup_revision,
    read_encrypted_file, verify_private_dir, with_state_mut, write_encrypted_atomic,
};
use kinveil::validate::{validate_for_deploy, validate_state};

#[test]
fn vault_encrypt_decrypt_wrong_passphrase_and_aad_tamper() {
    let enc = encrypt_bytes_with_params(b"hello-state", "correct-passphrase", 8_192, 1, 1)
        .expect("encrypt fast");
    assert!(enc.starts_with(MAGIC));

    let dec = decrypt_bytes(&enc, "correct-passphrase").expect("decrypt fast");
    assert_eq!(dec.as_slice(), b"hello-state");

    assert!(decrypt_bytes(&enc, "wrong-passphrase").is_err());

    // Tamper header (AAD): format version, salt byte, and nonce byte
    let mut bad_ver = enc.clone();
    bad_ver[4] = 99;
    assert!(decrypt_bytes(&bad_ver, "correct-passphrase").is_err());

    let mut bad_salt = enc.clone();
    bad_salt[20] ^= 0xff;
    assert!(decrypt_bytes(&bad_salt, "correct-passphrase").is_err());

    let mut bad_nonce = enc.clone();
    bad_nonce[HEADER_LEN - 1] ^= 0x01;
    assert!(decrypt_bytes(&bad_nonce, "correct-passphrase").is_err());

    // Tamper ciphertext byte
    let mut bad_ct = enc.clone();
    bad_ct[HEADER_LEN + 2] ^= 0x42;
    assert!(decrypt_bytes(&bad_ct, "correct-passphrase").is_err());

    // Truncated envelope
    assert!(decrypt_bytes(&enc[..HEADER_LEN], "correct-passphrase").is_err());

    // Empty passphrase rejected
    assert!(encrypt_bytes(b"{}", "").is_err());
}

#[test]
fn argon2_header_bounds_and_schema_version_check() {
    let enc = encrypt_bytes_with_params(b"{}", "secret-passphrase", 8_192, 1, 1).expect("encrypt");

    // Memory below minimum (8192 KiB)
    let mut low_mem = enc.clone();
    low_mem[5..9].copy_from_slice(&4_096u32.to_le_bytes());
    assert!(decrypt_bytes(&low_mem, "secret-passphrase").is_err());

    // Memory above maximum (1 GiB)
    let mut high_mem = enc.clone();
    high_mem[5..9].copy_from_slice(&2_000_000u32.to_le_bytes());
    assert!(decrypt_bytes(&high_mem, "secret-passphrase").is_err());

    // Zero t_cost / p_cost / huge t_cost
    let mut zero_t = enc.clone();
    zero_t[9..13].copy_from_slice(&0u32.to_le_bytes());
    assert!(decrypt_bytes(&zero_t, "secret-passphrase").is_err());

    let mut zero_p = enc.clone();
    zero_p[13..17].copy_from_slice(&0u32.to_le_bytes());
    assert!(decrypt_bytes(&zero_p, "secret-passphrase").is_err());

    let mut huge_t = enc;
    huge_t[9..13].copy_from_slice(&99u32.to_le_bytes());
    assert!(decrypt_bytes(&huge_t, "secret-passphrase").is_err());

    // decode_state validates schema_version directly
    assert!(decode_state(b"{}").is_err());
    let mut raw = serde_json::to_value(State::new("sub.example.com".to_owned()).unwrap()).unwrap();
    raw["schema_version"] = serde_json::json!(99);
    let bad_ver_bytes = serde_json::to_vec(&raw).unwrap();
    let err = decode_state(&bad_ver_bytes).expect_err("schema_version 99 must fail");
    assert!(
        err.to_string().contains("unsupported state schema_version"),
        "{err}"
    );
    raw["schema_version"] = serde_json::json!(SCHEMA_VERSION);
    raw["future_top_level_field"] = serde_json::json!("forward-compatible-ignored");
    let ok_bytes = serde_json::to_vec(&raw).unwrap();
    assert!(decode_state(&ok_bytes).is_ok());
}

#[test]
fn atomic_write_permissions_locking_and_symlink_guards() {
    let tmp = TempPrivateDir::new("kinveil-crypto-perm");
    let state_path = tmp.path.join("state.enc");
    let state = valid_deployable_state();
    let pass = "secret-passphrase";

    write_encrypted_atomic(&state_path, &state, pass).expect("atomic initial write");

    let meta = fs::symlink_metadata(&state_path).expect("stat state");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    let loaded = read_encrypted_file(&state_path, pass).expect("read encrypted file");
    assert_eq!(loaded, state);

    // Concurrent lock contention fails cleanly
    let lock = acquire_state_lock(&state_path).expect("lock");
    assert!(acquire_state_lock(&state_path).is_err());
    drop(lock);

    // with_state_mut updates revision and refuses invalid state mutations
    let (rev, msg) = with_state_mut(&state_path, pass, |s| {
        s.set_config_toml("[subscription]\nupdate_interval_hours = 24\n")?;
        Ok("updated interval".to_owned())
    })
    .expect("with_state_mut");
    assert_eq!(rev, 2);
    assert_eq!(msg, "updated interval");

    let bad_mut = with_state_mut(&state_path, pass, |s| {
        s.next_uid = 1; // <= max user uid (2) -> validate_state must reject
        Ok("bad".to_owned())
    });
    assert!(bad_mut.is_err());
    let still_good = read_encrypted_file(&state_path, pass).expect("re-read untouched vault");
    assert_eq!(still_good.revision, 2);
    assert_eq!(still_good.settings.subscription.update_interval_hours, 24);

    // Symlink state file must be rejected
    let link_path = tmp.path.join("link-state.enc");
    symlink(&state_path, &link_path).expect("symlink");
    assert!(read_encrypted_file(&link_path, pass).is_err());

    // Loose directory permissions rejected
    fs::set_permissions(&tmp.path, Permissions::from_mode(0o755)).expect("chmod 0755");
    assert!(verify_private_dir(&tmp.path).is_err());
    fs::set_permissions(&tmp.path, Permissions::from_mode(0o700)).expect("restore 0700");
}

#[test]
fn committed_state_v1_fixture_round_trips() {
    let fixture_bytes = include_bytes!("fixtures/state-v1.enc");
    assert!(fixture_bytes.starts_with(MAGIC));
    let plaintext =
        decrypt_bytes(fixture_bytes, "correct-horse-battery-staple").expect("decrypt fixture");
    let state = decode_state(&plaintext).expect("decode fixture");
    validate_state(&state).expect("validate fixture");
    validate_for_deploy(&state).expect("fixture deployable");
}

#[test]
fn rolling_backups_retain_newest_twenty_revisions() {
    let tmp = TempPrivateDir::new("kinveil-rolling-backups");
    let state_path = tmp.path.join("state.enc");
    let dummy_enc = encrypt_bytes_with_params(b"{}", "secret-passphrase", 8_192, 1, 1).unwrap();
    fs::write(&state_path, &dummy_enc).unwrap();
    fs::set_permissions(&state_path, Permissions::from_mode(0o600)).unwrap();

    for rev in 1..=25u64 {
        backup_existing_state(&state_path, rev).expect("write rolling backup");
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
    assert_eq!(revs, (6..=25).collect::<Vec<_>>());
    assert_eq!(max_backup_revision(&state_path).unwrap(), 25);

    // Custom vault stems write and track stem-prefixed rolling backups without colliding.
    let custom_path = tmp.path.join("prod-vault.enc");
    fs::write(&custom_path, &dummy_enc).unwrap();
    fs::set_permissions(&custom_path, Permissions::from_mode(0o600)).unwrap();
    backup_existing_state(&custom_path, 42).expect("write custom stem backup");
    assert!(backups_dir.join("prod-vault.42.enc").exists());
    assert_eq!(max_backup_revision(&custom_path).unwrap(), 42);
    assert_eq!(max_backup_revision(&state_path).unwrap(), 25);
}

#[test]
fn serialized_state_omits_derived_public_keys_and_round_trips() {
    let state = valid_deployable_state();
    validate_state(&state).expect("fixture must validate");

    let enc = encrypt_state(&state, "roundtrip-pass").expect("encrypt");
    assert_eq!(&enc[..MAGIC.len()], MAGIC);
    assert!(enc.len() > HEADER_LEN + 16);

    let dec_bytes = decrypt_bytes(&enc, "roundtrip-pass").expect("decrypt");
    let dec = decode_state(&dec_bytes).expect("decode decrypted");
    assert_eq!(state, dec);

    let raw_json = std::str::from_utf8(&dec_bytes).expect("utf-8 JSON");
    let alice = state.user("alice").unwrap();
    let srv = state.server("de1").unwrap();
    let vpn = srv.vpn.as_ref().unwrap();
    let ssh_fwd = &vpn.ssh_forwarding;

    assert!(!raw_json.contains(&alice.amneziawg_public_key().unwrap()));
    assert!(
        !raw_json.contains(
            alice
                .ssh_public_key()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
        )
    );
    assert!(!raw_json.contains(&vpn.vless.public_key().unwrap()));
    assert!(!raw_json.contains(&vpn.amneziawg.public_key().unwrap()));
    assert!(
        !raw_json.contains(
            ssh_fwd
                .host_public_key()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
        )
    );
}

#[test]
fn derived_public_keys_preserve_semantics_and_strip_ssh_comments() {
    let state = valid_deployable_state();
    let alice = state.user("alice").unwrap();
    let srv = state.server("de1").unwrap();
    let vpn = srv.vpn.as_ref().unwrap();
    let ssh_fwd = &vpn.ssh_forwarding;

    let alice_awg_pub = alice.amneziawg_public_key().unwrap();
    assert_eq!(alice_awg_pub.len(), 44);
    assert!(alice_awg_pub.ends_with('='));

    let alice_ssh_pub = alice.ssh_public_key().unwrap();
    assert!(alice_ssh_pub.starts_with("ssh-ed25519 "));
    assert_eq!(alice_ssh_pub.split_whitespace().count(), 2);

    let vless_pub = vpn.vless.public_key().unwrap();
    assert_eq!(vless_pub.len(), 43);

    let srv_awg_pub = vpn.amneziawg.public_key().unwrap();
    assert_eq!(srv_awg_pub.len(), 44);

    let host_pub = ssh_fwd.host_public_key().unwrap();
    assert!(host_pub.starts_with("ssh-ed25519 "));
    assert!(host_pub.ends_with('\n'));
    assert_eq!(host_pub.split_whitespace().count(), 2);
}

#[test]
fn debug_output_redacts_all_secret_strings() {
    let state = valid_deployable_state();
    let debug_str = format!("{state:?}");
    assert!(debug_str.contains("<redacted>"));

    assert!(!debug_str.contains(state.subscription.base_path.as_str()));
    let cf = state.subscription.cloudflare.as_ref().unwrap();
    assert!(!debug_str.contains(cf.api_token.as_str()));

    let srv = &state.servers[0];
    let vpn = srv.vpn.as_ref().unwrap();
    let ssh_fwd = &vpn.ssh_forwarding;
    assert!(!debug_str.contains(vpn.vless.private_key.as_str()));
    assert!(!debug_str.contains(vpn.hysteria2.key_pem.as_str()));
    assert!(!debug_str.contains(vpn.hysteria2.salamander_password.as_str()));
    assert!(!debug_str.contains(vpn.amneziawg.private_key.as_str()));
    assert!(!debug_str.contains(vpn.amneziawg.obfuscation.header_protection_key.as_str()));
    assert!(!debug_str.contains(ssh_fwd.host_private_key.as_str()));

    for user in state.users.values() {
        assert!(!debug_str.contains(user.subscription_token.as_str()));
        assert!(!debug_str.contains(user.vless.uuid.as_str()));
        assert!(!debug_str.contains(user.hysteria2.auth.as_str()));
        assert!(!debug_str.contains(user.amneziawg.private_key.as_str()));
        assert!(!debug_str.contains(user.ssh_forwarding.private_key.as_str()));
    }
}

fn rewrap_openssh_pem(pem: &str, width: usize) -> String {
    let lines: Vec<&str> = pem.trim().lines().collect();
    assert!(lines.len() >= 3);
    let body: String = lines[1..lines.len() - 1].concat();
    let mut out = format!("{}\n", lines[0]);
    for chunk in body.as_bytes().chunks(width) {
        out.push_str(std::str::from_utf8(chunk).expect("ascii base64"));
        out.push('\n');
    }
    out.push_str(lines[lines.len() - 1]);
    out.push('\n');
    out
}

#[test]
fn validation_invariants_and_negative_checks() {
    let base = valid_deployable_state();
    validate_state(&base).expect("base state valid");
    validate_for_deploy(&base).expect("base state deployable");

    // 1. AWG s1 + 56 == s2 collision (148 + s1 == 92 + s2)
    let mut bad_s1_s2 = base.clone();
    let obf = &mut bad_s1_s2.servers[0]
        .vpn
        .as_mut()
        .unwrap()
        .amneziawg
        .obfuscation;
    obf.s1 = 20;
    obf.s2 = 76;
    assert!(validate_state(&bad_s1_s2).is_err());

    // 2. AWG s1 < 12 (minimum for header protection nonce)
    let mut bad_s1_min = base.clone();
    let obf = &mut bad_s1_min.servers[0]
        .vpn
        .as_mut()
        .unwrap()
        .amneziawg
        .obfuscation;
    obf.s1 = 11;
    obf.s2 = 30;
    assert!(validate_state(&bad_s1_min).is_err());

    // 3. AWG h1..h4 overlap
    let mut bad_h = base.clone();
    let obf = &mut bad_h.servers[0].vpn.as_mut().unwrap().amneziawg.obfuscation;
    obf.h1 = IntOrRange::Range("100-200".to_owned());
    obf.h2 = IntOrRange::Range("150-250".to_owned());
    assert!(validate_state(&bad_h).is_err());

    // 4. Corrupted server X25519 private key rejected
    let mut bad_x25519 = base.clone();
    bad_x25519.servers[0]
        .vpn
        .as_mut()
        .unwrap()
        .vless
        .private_key = SecretString::new("not-valid-x25519-key");
    assert!(validate_state(&bad_x25519).is_err());
    // Note: valid 32-byte URL_SAFE_NO_PAD private key derives cleanly
    let (fresh_priv, _) = generate_x25519_reality_keypair();
    let mut good_x25519 = base.clone();
    good_x25519.servers[0]
        .vpn
        .as_mut()
        .unwrap()
        .vless
        .private_key = fresh_priv;
    validate_state(&good_x25519).expect("valid replacement reality key");

    // 5. 76-column OpenSSH PEM acceptance & malformed PEM rejection
    let mut wrapped_76 = base.clone();
    let alice = wrapped_76.user_mut("alice").unwrap();
    alice.ssh_forwarding.private_key =
        SecretString::new(rewrap_openssh_pem(&alice.ssh_forwarding.private_key, 76));
    if let Some(vpn) = wrapped_76.servers[0].vpn.as_mut() {
        vpn.ssh_forwarding.host_private_key =
            SecretString::new(rewrap_openssh_pem(&vpn.ssh_forwarding.host_private_key, 76));
    }
    validate_state(&wrapped_76).expect("76-char OpenSSH PEM lines must validate");

    let mut bad_width_ed = base.clone();
    let alice = bad_width_ed.user_mut("alice").unwrap();
    alice.ssh_forwarding.private_key =
        SecretString::new(rewrap_openssh_pem(&alice.ssh_forwarding.private_key, 77));
    assert!(validate_state(&bad_width_ed).is_err());

    let mut bad_b64_ed = base.clone();
    bad_b64_ed
        .user_mut("alice")
        .unwrap()
        .ssh_forwarding
        .private_key = SecretString::new(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnot!valid!base64\n-----END OPENSSH PRIVATE KEY-----\n",
    );
    assert!(validate_state(&bad_b64_ed).is_err());

    // 6. Hysteria2 wrong cert/IP SAN
    let mut bad_hyst = base.clone();
    let (wrong_cert, wrong_key) =
        generate_hysteria_self_signed_cert("198.51.100.99".parse().unwrap()).unwrap();
    bad_hyst.servers[0].vpn.as_mut().unwrap().hysteria2.cert_pem = wrong_cert;
    bad_hyst.servers[0].vpn.as_mut().unwrap().hysteria2.key_pem = wrong_key;
    assert!(validate_state(&bad_hyst).is_err());

    // 7. Port collision on single server
    let mut bad_port = base.clone();
    bad_port.servers[0].ports.vless = Some(NonZeroU16::new(22).unwrap());
    assert!(validate_state(&bad_port).is_err());

    // 8. Unknown or disabled subscription.server_id
    let mut unknown_sub = base.clone();
    unknown_sub.subscription.server_id = Some("nonexistent".to_owned());
    assert!(validate_state(&unknown_sub).is_err());

    let mut disabled_sub = base.clone();
    disabled_sub.subscription.server_id = Some("fi1".to_owned());
    validate_state(&disabled_sub).expect("disabled subscription server allowed offline");
    assert!(validate_for_deploy(&disabled_sub).is_err());

    // 9. next_uid must be > max existing user uid
    let mut bad_next_uid = base.clone();
    bad_next_uid.next_uid = 2;
    assert!(validate_state(&bad_next_uid).is_err());

    // 10. validate_for_deploy requires >= 1 enabled user, >= 1 enabled vpn, == 1 enabled sub
    let mut no_users = base.clone();
    no_users.user_mut("alice").unwrap().enabled = false;
    validate_state(&no_users).expect("valid offline state even with all disabled");
    assert!(validate_for_deploy(&no_users).is_err());

    let mut no_sub = base;
    no_sub.subscription.server_id = None;
    validate_state(&no_sub).expect("valid offline state without sub server");
    assert!(validate_for_deploy(&no_sub).is_err());
}

#[test]
fn known_hosts_lookup_supports_plaintext_and_hashed_entries() {
    let dir = TempPrivateDir::new("kinveil-kh-test");
    let (_, ed_pub) = generate_openssh_ed25519("kh-test").unwrap();
    let expected = ed_pub
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let kh_path = dir.path.join("known_hosts");

    // 1. Plaintext host entries (both default port 22 and bracketed custom port)
    fs::write(
        &kh_path,
        format!("198.51.100.10 {ed_pub}\n[203.0.113.20]:2222 {ed_pub}\n"),
    )
    .unwrap();
    assert_eq!(
        lookup_known_hosts_key(&kh_path, "198.51.100.10", 22).unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        lookup_known_hosts_key(&kh_path, "203.0.113.20", 2222).unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        lookup_known_hosts_key(&kh_path, "192.0.2.99", 22).unwrap(),
        None
    );

    // 2. Hashed known_hosts via `ssh-keygen -H`
    let status = std::process::Command::new("ssh-keygen")
        .args(["-H", "-f"])
        .arg(&kh_path)
        .output()
        .expect("run ssh-keygen -H");
    assert!(status.status.success());
    let hashed = fs::read_to_string(&kh_path).unwrap();
    assert!(hashed.contains("|1|"));
    assert_eq!(
        lookup_known_hosts_key(&kh_path, "198.51.100.10", 22).unwrap(),
        Some(expected.clone())
    );
    assert_eq!(
        lookup_known_hosts_key(&kh_path, "203.0.113.20", 2222).unwrap(),
        Some(expected)
    );
}

#[test]
fn config_example_toml_defaults_all_uncommented_and_preserves_comments() {
    let parsed_defaults =
        parse_config_toml(DEFAULT_CONFIG_TOML).expect("DEFAULT_CONFIG_TOML parses cleanly");
    assert_eq!(parsed_defaults, Settings::default());

    let uncommented_all = DEFAULT_CONFIG_TOML
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("# ")
                && let Some((lhs, _rhs)) = rest.split_once(" = ")
                && !lhs.is_empty()
                && lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                rest
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let all_settings = parse_config_toml(&uncommented_all)
        .expect("all commented keys in config.example.toml parse");
    assert_eq!(
        all_settings.subscription.happ_routing.as_deref(),
        Some("happ://routing/onadd/example")
    );
    let mut expected = Settings::default();
    expected.subscription.profile_title = Some("Kinveil".to_owned());
    expected.subscription.happ_routing = Some("happ://routing/onadd/example".to_owned());
    expected.artifacts = ArtifactSettings {
        xray_zip_url: Some(
            "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip"
                .to_owned(),
        ),
        xray_zip_sha256: Some(
            "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82".to_owned(),
        ),
        amneziawg_url: Some("https://example.com/amneziawg-go-linux-amd64".to_owned()),
        amneziawg_sha256: Some(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        ),
    };
    assert_eq!(all_settings, expected);

    let mut state = valid_deployable_state();
    state
        .set_config_toml(uncommented_all)
        .expect("apply uncommented config.example.toml");
    validate_state(&state).expect("validate_state passes with all uncommented defaults");

    let tmp = TempPrivateDir::new("kinveil-toml-comments");
    let state_path = tmp.path.join("state.enc");
    let pass = "correct-horse-battery-staple";
    let custom_toml = "\
# Top operator note that must survive intact
[firewall]
block_bittorrent = false

[ssh_forwarding]
# Keep custom SSH forwarding port
port = 2224

[amneziawg]
mtu = 1320 # inline comment
";
    state.set_config_toml(custom_toml).expect("set custom TOML");
    let enc = encrypt_state(&state, pass).expect("encrypt state");
    fs::write(&state_path, enc).expect("write vault");
    fs::set_permissions(&state_path, Permissions::from_mode(0o600)).expect("chmod vault");

    with_state_mut(&state_path, pass, |s| {
        let uid = s.next_uid;
        s.next_uid += 1;
        s.users.insert("charlie".to_owned(), make_user(uid, true));
        Ok(())
    })
    .expect("mutate user list while preserving config_toml");

    let loaded = read_encrypted_file(&state_path, pass).expect("read encrypted vault");
    assert_eq!(loaded.config_toml, custom_toml);
    assert!(!loaded.settings.firewall.block_bittorrent);
    assert_eq!(loaded.settings.ssh_forwarding.port.get(), 2224);
    assert_eq!(loaded.settings.amneziawg.mtu, 1320);

    let raw_json = decrypt_bytes(&fs::read(&state_path).unwrap(), pass).unwrap();
    let decoded = decode_state(&raw_json).unwrap();
    assert_eq!(decoded.config_toml, custom_toml);
}

#[test]
fn ssh_option_injection_and_invalid_sni_rejected() {
    let mut bad_ssh_host = valid_deployable_state();
    bad_ssh_host.servers[0].admin_ssh.host = "-oProxyCommand=id".to_owned();
    assert!(validate_state(&bad_ssh_host).is_err());

    let mut bad_ssh_space = valid_deployable_state();
    bad_ssh_space.servers[0].admin_ssh.host = "bad host".to_owned();
    assert!(validate_state(&bad_ssh_space).is_err());

    let mut bad_ssh_user = valid_deployable_state();
    bad_ssh_user.servers[0].admin_ssh.user = "-baduser".to_owned();
    assert!(validate_state(&bad_ssh_user).is_err());

    let mut bad_sni = valid_deployable_state();
    bad_sni.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .server_name = "-oProxyCommand=x".to_owned();
    assert!(validate_state(&bad_sni).is_err());

    let mut bad_target = valid_deployable_state();
    bad_target.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .target = "-badhost:443".to_owned();
    assert!(validate_state(&bad_target).is_err());

    let mut bad_unbracketed_v6_target = valid_deployable_state();
    bad_unbracketed_v6_target.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .target = "2001:db8::1:443".to_owned();
    assert!(validate_state(&bad_unbracketed_v6_target).is_err());

    let mut bad_xhttp_host = valid_deployable_state();
    bad_xhttp_host.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .xhttp_host = Some("bad host!".to_owned());
    assert!(validate_state(&bad_xhttp_host).is_err());

    let mut self_sni = valid_deployable_state();
    self_sni.servers[0].vpn.as_mut().unwrap().vless.server_name = "sub.example.com".to_owned();
    assert!(validate_state(&self_sni).is_err());

    let mut self_ip_target = valid_deployable_state();
    self_ip_target.servers[0].vpn.as_mut().unwrap().vless.target = "198.51.100.10:443".to_owned();
    assert!(validate_state(&self_ip_target).is_err());

    let mut bad_fp = valid_deployable_state();
    assert!(
        bad_fp
            .set_config_toml("[vless]\nfingerprint = \"not-a-utls-fp\"\n")
            .is_ok()
    );
    assert!(validate_state(&bad_fp).is_err());

    let mut no_vless_modes = valid_deployable_state();
    no_vless_modes
        .set_config_toml("[vless]\nstream = false\npacket = false\n")
        .unwrap();
    assert!(validate_state(&no_vless_modes).is_err());

    let mut ipv6_dns = valid_deployable_state();
    assert!(
        ipv6_dns
            .set_config_toml("[amneziawg]\ndns_servers = [\"2606:4700:4700::1111\"]\n")
            .is_err()
    );

    let mut zero_psk = valid_deployable_state();
    zero_psk.user_mut("alice").unwrap().amneziawg.preshared_key =
        SecretString::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert!(validate_state(&zero_psk).is_err());

    let mut imds_target = valid_deployable_state();
    imds_target.servers[0].vpn.as_mut().unwrap().vless.target = "169.254.169.254:443".to_owned();
    assert!(validate_state(&imds_target).is_err());

    let mut localhost_target = valid_deployable_state();
    localhost_target.servers[0]
        .vpn
        .as_mut()
        .unwrap()
        .vless
        .target = "sub.localhost:443".to_owned();
    assert!(validate_state(&localhost_target).is_err());

    let mut local_masquerade = valid_deployable_state();
    local_masquerade
        .set_config_toml("[hysteria2]\nmasquerade_url = \"https://127.0.0.1:8080\"\n")
        .unwrap();
    assert!(validate_state(&local_masquerade).is_err());

    let mut unpaired_artifact = valid_deployable_state();
    unpaired_artifact
        .set_config_toml("[artifacts]\nxray_zip_url = \"https://example.com/xray.zip\"\n")
        .unwrap();
    assert!(validate_state(&unpaired_artifact).is_err());

    let mut http_artifact = valid_deployable_state();
    http_artifact
        .set_config_toml(
            "[artifacts]\namneziawg_url = \"http://example.com/awg\"\namneziawg_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        )
        .unwrap();
    assert!(validate_state(&http_artifact).is_err());

    let mut short_base = valid_deployable_state();
    short_base.subscription.base_path = SecretString::new("/short/");
    assert!(validate_state(&short_base).is_err());

    let mut bad_title = valid_deployable_state();
    bad_title
        .set_config_toml("[subscription]\nprofile_title = \"Bad\\nTitle\"\n")
        .unwrap();
    assert!(validate_state(&bad_title).is_err());

    let mut arm_srv = valid_deployable_state();
    arm_srv.servers[0].arch = ServerArch::Aarch64;
    validate_state(&arm_srv).expect("non-x86_64 allowed offline in state");
    assert!(validate_for_deploy(&arm_srv).is_err());
}
