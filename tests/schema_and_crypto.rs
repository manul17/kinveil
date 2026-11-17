mod common;

use std::collections::BTreeSet;
use std::fs::{self, Permissions};
use std::num::NonZeroU16;
use std::os::unix::fs::{PermissionsExt, symlink};

use common::{TempPrivateDir, valid_deployable_state};
use kinveil::crypto::{generate_hysteria_self_signed_cert, generate_x25519_reality_keypair};
use kinveil::state::{
    ArtifactSettings, DEFAULT_CONFIG_TOML, IntOrRange, SCHEMA_VERSION, SecretString, Settings,
    State, ValueSource, VpnProtocol, parse_config_toml,
};
use kinveil::store::{
    HEADER_LEN, MAGIC, acquire_state_lock, backup_existing_state, commit_state_mutation,
    decode_state, decrypt_bytes, encrypt_bytes, encrypt_bytes_with_params, max_backup_revision,
    read_encrypted_file, verify_private_dir, write_encrypted_atomic,
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
    raw["unknown_top_level_field"] = serde_json::json!("rejected");
    let bad_extra_bytes = serde_json::to_vec(&raw).unwrap();
    assert!(decode_state(&bad_extra_bytes).is_err());

    let mut nested = serde_json::to_value(valid_deployable_state()).unwrap();
    nested["servers"][0]["vpn"]["unknown_vpn_field"] = serde_json::json!(true);
    assert!(decode_state(&serde_json::to_vec(&nested).unwrap()).is_err());
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

    // commit_state_mutation updates revision and refuses invalid state mutations
    let _lock = acquire_state_lock(&state_path).expect("lock for mutation");
    let mut s = read_encrypted_file(&state_path, pass).expect("read for mutation");
    let old_rev = s.revision;
    s.set_config_toml("[subscription]\nupdate_interval_hours = 24\n")
        .expect("set config");
    let rev =
        commit_state_mutation(&state_path, &mut s, pass, old_rev).expect("commit_state_mutation");
    assert_eq!(rev, 2);

    let mut bad_s = s.clone();
    bad_s.next_uid = 1; // <= max user uid (2) -> validate_state must reject
    let bad_mut = commit_state_mutation(&state_path, &mut bad_s, pass, rev);
    drop(_lock);
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
    assert_eq!(state.config_toml, DEFAULT_CONFIG_TOML);
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

    let raw_json = serde_json::to_string_pretty(&state).expect("serialize JSON");
    let dec = decode_state(raw_json.as_bytes()).expect("decode JSON");
    assert_eq!(state, dec);

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
    bad_port.servers[0].vpn.as_mut().unwrap().vless.port = Some(NonZeroU16::new(22).unwrap());
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
        all_settings.subscription.routing.happ_link.as_deref(),
        Some("happ://routing/onadd/example")
    );
    assert_eq!(
        all_settings.subscription.routing.throne_link.as_deref(),
        Some("throne://route/example")
    );
    let mut expected = Settings::default();
    expected.subscription.profile_title = Some("Kinveil".to_owned());
    expected.subscription.routing.happ_link = Some("happ://routing/onadd/example".to_owned());
    expected.subscription.routing.throne_link = Some("throne://route/example".to_owned());
    expected.vless.sni = Some("www.example.com".to_owned());
    expected.vless.target = Some("www.example.com:443".to_owned());
    expected.vless.xhttp_host = Some("cdn.example.com".to_owned());
    expected.vless.xhttp.path = Some("/edge".to_owned());
    expected.amneziawg.obfuscation.jc = Some(6);
    expected.amneziawg.obfuscation.jmin = Some(64);
    expected.amneziawg.obfuscation.jmax = Some(180);
    expected.amneziawg.obfuscation.s1 = Some(42);
    expected.amneziawg.obfuscation.s2 = Some(88);
    expected.amneziawg.obfuscation.s3 = Some(32);
    expected.amneziawg.obfuscation.s4 = Some(48);
    expected.amneziawg.obfuscation.h1 = Some(IntOrRange::Range("100000000-200000000".to_owned()));
    expected.amneziawg.obfuscation.h2 = Some(IntOrRange::Range("300000000-400000000".to_owned()));
    expected.amneziawg.obfuscation.h3 = Some(IntOrRange::Range("500000000-600000000".to_owned()));
    expected.amneziawg.obfuscation.h4 = Some(IntOrRange::Range("700000000-800000000".to_owned()));
    expected.amneziawg.obfuscation.i1 = Some("<r 48>".to_owned());
    expected.amneziawg.obfuscation.i2 = Some("<c>".to_owned());
    expected.amneziawg.obfuscation.i3 = Some("<t>".to_owned());
    expected.amneziawg.obfuscation.i4 = Some("<r 16>".to_owned());
    expected.amneziawg.obfuscation.i5 = Some("<d>".to_owned());
    expected.amneziawg.obfuscation.content_padding_addition =
        Some(IntOrRange::Range("16-40".to_owned()));
    expected.artifacts = ArtifactSettings {
        xray_zip_url: Some(
            "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip"
                .to_owned(),
        ),
        xray_zip_sha256: Some(
            "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82".to_owned(),
        ),
        geoip_url: Some("https://example.com/geoip.dat".to_owned()),
        geoip_sha256: Some(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        ),
        geosite_url: Some("https://example.com/geosite.dat".to_owned()),
        geosite_sha256: Some(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
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

    let custom_toml = "\
# Top operator note that must survive intact
[firewall.xray]
block_bittorrent = false

[ssh_forwarding]
# Keep custom SSH forwarding port
port = 2224

[amneziawg]
mtu = 1320 # inline comment
";
    state.set_config_toml(custom_toml).expect("set custom TOML");
    let json = serde_json::to_vec(&state).expect("serialize state");
    let decoded = decode_state(&json).expect("decode state");
    assert_eq!(decoded.config_toml, custom_toml);
    assert!(!decoded.settings.firewall.xray.block_bittorrent);
    assert_eq!(decoded.settings.ssh_forwarding.port.get(), 2224);
    assert_eq!(decoded.settings.amneziawg.mtu, 1320);
}

#[test]
fn ssh_option_injection_and_invalid_sni_rejected() {
    let base = valid_deployable_state();

    let mut bad_ssh_host = base.clone();
    bad_ssh_host.servers[0].admin_ssh.host = "-oProxyCommand=id".to_owned();
    assert!(validate_state(&bad_ssh_host).is_err());

    let mut bad_ssh_space = base.clone();
    bad_ssh_space.servers[0].admin_ssh.host = "bad host".to_owned();
    assert!(validate_state(&bad_ssh_space).is_err());

    let mut bad_ssh_bracket = base.clone();
    bad_ssh_bracket.servers[0].admin_ssh.host = "[2001:db8::1]".to_owned();
    assert!(validate_state(&bad_ssh_bracket).is_err());

    let mut good_v6_ssh_host = base.clone();
    good_v6_ssh_host.servers[0].admin_ssh.host = "2001:db8::1".to_owned();
    validate_state(&good_v6_ssh_host).expect("unbracketed IPv6 SSH host passes");

    let mut bad_mapped_v6 = base.clone();
    bad_mapped_v6.servers[0].public_ipv6 = Some("::ffff:198.51.100.20".parse().unwrap());
    assert!(validate_state(&bad_mapped_v6).is_err());

    let mut dup_v6 = base.clone();
    dup_v6.servers[0].public_ipv6 = Some("2001:db8::99".parse().unwrap());
    dup_v6.servers[1].public_ipv6 = Some("2001:db8::99".parse().unwrap());
    assert!(validate_state(&dup_v6).is_err());

    let mut bad_ssh_user = base.clone();
    bad_ssh_user.servers[0].admin_ssh.user = "-baduser".to_owned();
    assert!(validate_state(&bad_ssh_user).is_err());

    let mut bad_ssh_key_opt = base.clone();
    bad_ssh_key_opt.servers[0].admin_ssh.identity_file = Some("-oProxyCommand=id".to_owned());
    assert!(validate_state(&bad_ssh_key_opt).is_err());

    let mut bad_ssh_key_empty = base.clone();
    bad_ssh_key_empty.servers[0].admin_ssh.identity_file = Some("   ".to_owned());
    assert!(validate_state(&bad_ssh_key_empty).is_err());

    let mut bad_ssh_key_ctrl = base.clone();
    bad_ssh_key_ctrl.servers[0].admin_ssh.identity_file = Some("/tmp/key\n".to_owned());
    assert!(validate_state(&bad_ssh_key_ctrl).is_err());

    let mut good_ssh_key = base.clone();
    good_ssh_key.servers[0].admin_ssh.identity_file = Some("/home/ops/.ssh/id_ed25519".to_owned());
    validate_state(&good_ssh_key).expect("valid SSH identity_file passes");

    let mut bad_sni = base.clone();
    bad_sni.servers[0].vpn.as_mut().expect("vpn role").vless.sni =
        Some("-oProxyCommand=x".to_owned());
    assert!(validate_state(&bad_sni).is_err());

    let mut bad_target = base.clone();
    bad_target.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .target = Some("-badhost:443".to_owned());
    assert!(validate_state(&bad_target).is_err());

    let mut bad_unbracketed_v6_target = base.clone();
    bad_unbracketed_v6_target.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .target = Some("2001:db8::1:443".to_owned());
    assert!(validate_state(&bad_unbracketed_v6_target).is_err());

    let mut bad_xhttp_host = base.clone();
    bad_xhttp_host.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .xhttp_host = Some("bad host!".to_owned());
    assert!(validate_state(&bad_xhttp_host).is_err());

    let mut self_xhttp_host = base.clone();
    self_xhttp_host.servers[0]
        .vpn
        .as_mut()
        .expect("vpn role")
        .vless
        .xhttp_host = Some("sub.example.com".to_owned());
    assert!(validate_state(&self_xhttp_host).is_err());

    let mut self_sni = base.clone();
    self_sni.servers[0].vpn.as_mut().unwrap().vless.sni = Some("sub.example.com".to_owned());
    assert!(validate_state(&self_sni).is_err());

    let mut self_ip_target = base.clone();
    self_ip_target.servers[0].vpn.as_mut().unwrap().vless.target =
        Some("198.51.100.10:443".to_owned());
    assert!(validate_state(&self_ip_target).is_err());

    let mut ipv6_dns = base.clone();
    assert!(
        ipv6_dns
            .set_config_toml("[dns]\namneziawg_servers = [\"2606:4700:4700::1111\"]\n")
            .is_err()
    );

    let mut zero_psk = base.clone();
    zero_psk.user_mut("alice").unwrap().amneziawg.preshared_key =
        SecretString::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert!(validate_state(&zero_psk).is_err());

    let mut imds_target = base.clone();
    imds_target.servers[0].vpn.as_mut().unwrap().vless.target =
        Some("169.254.169.254:443".to_owned());
    assert!(validate_state(&imds_target).is_err());

    let mut localhost_target = base.clone();
    localhost_target.servers[0]
        .vpn
        .as_mut()
        .unwrap()
        .vless
        .target = Some("sub.localhost:443".to_owned());
    assert!(validate_state(&localhost_target).is_err());

    let mut short_base = base.clone();
    short_base.subscription.base_path = SecretString::new("/short/");
    assert!(validate_state(&short_base).is_err());

    // [vless], [hysteria2], [subscription], [firewall], [firewall.auto_update], [firewall.xray],
    // [dns], [amneziawg], [artifacts], and [subscription.routing] rejections
    for invalid_toml in [
        "[vless]\nfingerprint = \"not-a-utls-fp\"\n",
        "[vless]\nstream = false\npacket = false\n",
        "[hysteria2]\nmasquerade_url = \"https://127.0.0.1:8080\"\n",
        "[artifacts]\nxray_zip_url = \"https://example.com/xray.zip\"\n",
        "[artifacts]\namneziawg_url = \"http://example.com/awg\"\namneziawg_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        "[subscription]\nprofile_title = \"Bad\\nTitle\"\n",
        "[firewall]\nblock_countries = [\"germany\"]\n",
        "[firewall]\nblock_countries = [\"xx\"]\n",
        "[firewall]\nblock_cidrs = [\"not-an-ip\"]\n",
        "[firewall]\nblock_cidrs = [\"geoip:de\"]\n",
        "[firewall]\nblock_ip_lists = [\"http://example.com/list.txt\"]\n",
        "[firewall]\nblock_ip_lists = [\"https://127.0.0.1/list.txt\"]\n",
        "[firewall]\nblock_ip_lists = [\"https://2001:db8::8888/list.txt\"]\n",
        "[firewall.auto_update]\ninterval_hours = 0\n",
        "[firewall.auto_update]\nipv4_country_url = \"https://example.com/static.txt\"\n",
        "[firewall.auto_update]\nipv6_country_url = \"http://example.com/{cc}.txt\"\n",
        "[firewall.xray]\nblock_domains = [\"bad host!\"]\n",
        "[firewall.xray]\nblock_domain_lists = [\"https://169.254.169.254/domains.txt\"]\n",
        "[firewall]\nblock_cidrs = [\"1.1.1.0/24\"]\n",
        "[dns]\nxray_servers = []\n",
        "[dns]\nxray_servers = [\"https+local://127.0.0.1/dns-query\"]\n",
        "[dns]\nxray_servers = [\"http://1.1.1.1/dns-query\"]\n",
        "[dns]\nxray_servers = [\"169.254.169.254\"]\n",
        "[dns]\namneziawg_servers = []\n",
        "[dns]\namneziawg_servers = [\"127.0.0.1\"]\n",
        "[dns]\namneziawg_servers = [\"10.0.0.1\"]\n",
        "[amneziawg]\nsubnet = \"198.51.100.0/24\"\n[dns]\namneziawg_servers = [\"198.51.100.53\"]\n",
        "[vless.xhttp]\npath = \"no-leading-slash\"\n",
        "[vless.xhttp]\npath = \"/bad?query\"\n",
        "[artifacts]\ngeoip_url = \"https://example.com/geoip.dat\"\n",
        "[artifacts]\ngeosite_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        "[subscription.routing]\nbypass_countries = [\"12\"]\n",
        "[subscription.routing]\nblock_countries = [\"xx\"]\n",
        "[subscription.routing]\nbypass_countries = [\"de\"]\nblock_countries = [\"DE\"]\n",
        "[subscription.routing]\ndomestic_doh = \"http://9.9.9.9/dns-query\"\n",
        "[subscription.routing]\nremote_doh = \"https://10.0.0.1/dns-query\"\n",
        "[subscription.routing]\ndomestic_dns_ip = \"127.0.0.1\"\n",
        "[subscription.routing]\nhapp_link = \"https://example.com\"\n",
        "[subscription.routing]\nthrone_link = \"throne://route/bad{brace}\"\n",
        "[traffic]\nretention_days = 0\n",
        "[traffic]\nretention_days = 3651\n",
    ] {
        let mut s = base.clone();
        s.set_config_toml(invalid_toml)
            .unwrap_or_else(|e| panic!("unexpected TOML parse error for:\n{invalid_toml}\n{e}"));
        assert!(
            validate_state(&s).is_err(),
            "expected validate_state error for:\n{invalid_toml}"
        );
    }
}

#[test]
fn two_layer_effective_config_and_awg_override_validation() {
    let mut base = valid_deployable_state();

    // 1. Default VLESS SNI = None fails when VLESS is enabled and server lacks sni,
    //    but passes when VLESS is disabled on the server or globally.
    base.servers[0].vpn.as_mut().unwrap().vless.sni = None;
    assert!(validate_state(&base).is_err());

    let mut vless_disabled = base.clone();
    vless_disabled.servers[0].vpn.as_mut().unwrap().protocols = Some(BTreeSet::from([
        VpnProtocol::Hysteria2,
        VpnProtocol::AmneziaWg,
    ]));
    validate_state(&vless_disabled).expect("missing SNI is valid when VLESS is disabled");

    let mut empty_protos = base.clone();
    empty_protos.servers[0].vpn.as_mut().unwrap().protocols = Some(BTreeSet::new());
    assert!(validate_state(&empty_protos).is_err());

    let mut no_modes = valid_deployable_state();
    no_modes
        .set_config_toml("[vless]\nenabled = false\nstream = false\npacket = false\n")
        .unwrap();
    no_modes.servers[0].vpn.as_mut().unwrap().protocols =
        Some(BTreeSet::from([VpnProtocol::Vless]));
    assert!(validate_state(&no_modes).is_err());

    // 2. Setting [vless] defaults in config.toml satisfies server without explicit --vless-sni.
    base.set_config_toml(
        "[vless]\nsni = \"cfg.example.com\"\ntarget = \"edge.cfg.example.com:443\"\nxhttp_host = \"cdn.example.com\"\n",
    )
    .unwrap();
    validate_state(&base).expect("[vless].sni satisfies server without override");
    let eff_cfg = base.servers[0].effective_config(&base.settings, true);
    assert_eq!(
        eff_cfg.vless_sni,
        Some(("cfg.example.com".to_owned(), ValueSource::Config))
    );
    assert_eq!(
        eff_cfg.vless_target,
        Some(("edge.cfg.example.com:443".to_owned(), ValueSource::Config))
    );
    assert_eq!(
        eff_cfg.vless_xhttp_host,
        Some(("cdn.example.com".to_owned(), ValueSource::Config))
    );

    // 3. Coupled reset: when server overrides sni to a different domain without overriding
    //    target/xhttp_host, config.toml's target/xhttp_host are NOT inherited.
    let mut sni_override = base.clone();
    sni_override.servers[0].vpn.as_mut().unwrap().vless.sni = Some("srv.example.com".to_owned());
    let eff_srv = sni_override.servers[0].effective_config(&sni_override.settings, true);
    assert_eq!(
        eff_srv.vless_sni,
        Some(("srv.example.com".to_owned(), ValueSource::Server))
    );
    assert_eq!(
        eff_srv.vless_target,
        Some(("srv.example.com:443".to_owned(), ValueSource::Derived))
    );
    assert_eq!(eff_srv.vless_xhttp_host, None);

    // If server explicitly sets the same SNI as config.toml, config target/xhttp_host apply unless overridden.
    let mut same_sni = base.clone();
    same_sni.servers[0].vpn.as_mut().unwrap().vless.sni = Some("CFG.EXAMPLE.COM".to_owned());
    let eff_same = same_sni.servers[0].effective_config(&same_sni.settings, true);
    assert_eq!(
        eff_same.vless_target,
        Some(("edge.cfg.example.com:443".to_owned(), ValueSource::Config))
    );
    assert_eq!(
        eff_same.vless_xhttp_host,
        Some(("cdn.example.com".to_owned(), ValueSource::Config))
    );

    // 4. [amneziawg.obfuscation] obfuscation & CPS overrides merge cleanly and reject collisions.
    let mut awg_ok = valid_deployable_state();
    awg_ok
        .set_config_toml(
            "[amneziawg.obfuscation]\njc = 7\ns1 = 20\ns2 = 40\ni1 = \"<b 0x1122><r 24>\"\ni2 = \"<t>\"\n",
        )
        .unwrap();
    validate_state(&awg_ok).expect("valid AWG config overrides validate");
    let eff_awg = awg_ok.servers[0]
        .effective_config(&awg_ok.settings, true)
        .awg_obfuscation
        .unwrap();
    assert_eq!(eff_awg.jc, 7);
    assert_eq!(eff_awg.s1, 20);
    assert_eq!(eff_awg.s2, 40);
    assert_eq!(eff_awg.i1, "<b 0x1122><r 24>");
    assert_eq!(eff_awg.i2.as_deref(), Some("<t>"));
    assert_eq!(
        eff_awg.header_protection_key,
        awg_ok.servers[0]
            .vpn
            .as_ref()
            .unwrap()
            .amneziawg
            .obfuscation
            .header_protection_key
    );

    // Collision 148 + s1 == 92 + s2 (s1 = 20, s2 = 76) rejected.
    let mut bad_s1_s2 = valid_deployable_state();
    bad_s1_s2
        .set_config_toml("[amneziawg.obfuscation]\ns1 = 20\ns2 = 76\n")
        .unwrap();
    let s1_s2_err = validate_state(&bad_s1_s2).expect_err("s1/s2 collision rejected");
    assert!(
        s1_s2_err.to_string().contains("amneziawg.obfuscation"),
        "{s1_s2_err}"
    );

    // Overlapping h1/h2 rejected in settings.
    let mut bad_h = valid_deployable_state();
    bad_h
        .set_config_toml("[amneziawg.obfuscation]\nh1 = \"100-200\"\nh2 = \"150-250\"\n")
        .unwrap();
    let bad_h_err = validate_state(&bad_h).expect_err("h1/h2 overlap rejected");
    assert!(
        bad_h_err.to_string().contains("amneziawg.obfuscation"),
        "{bad_h_err}"
    );

    // Partial override colliding with server's existing s2 rejected via merged validation.
    let mut merged_collision = valid_deployable_state();
    merged_collision.servers[0]
        .vpn
        .as_mut()
        .unwrap()
        .amneziawg
        .obfuscation
        .s2 = 96;
    merged_collision
        .set_config_toml("[amneziawg.obfuscation]\ns1 = 40\n")
        .unwrap();
    assert!(validate_state(&merged_collision).is_err());

    // 5. Per-server traffic toggle and [traffic].retention_days validation
    let mut tr_state = valid_deployable_state();
    let eff_default = tr_state.servers[0].effective_config(&tr_state.settings, true);
    assert!(!eff_default.has_traffic);

    // [traffic].enabled is no longer a config key (strict deny_unknown_fields)
    assert!(
        tr_state
            .set_config_toml("[traffic]\nenabled = true\n")
            .is_err()
    );

    tr_state
        .set_config_toml("[traffic]\nretention_days = 30\n")
        .unwrap();
    tr_state.servers[0].vpn.as_mut().unwrap().traffic = true;
    validate_state(&tr_state).expect("per-server traffic with retention_days validates");
    let eff_srv_on = tr_state.servers[0].effective_config(&tr_state.settings, true);
    assert!(eff_srv_on.has_traffic);

    // Subscription-only server (vpn = None) never enables traffic accounting
    tr_state.servers[0].vpn = None;
    let eff_sub_only = tr_state.servers[0].effective_config(&tr_state.settings, true);
    assert!(!eff_sub_only.has_traffic);
}
