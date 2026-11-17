mod common;

use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::num::NonZeroU16;
use std::path::Path;
use std::thread;

use common::TempPrivateDir;
use kinveil::crypto::{generate_openssh_ed25519, sha256_hex};
use kinveil::deploy::artifacts::{
    AWG_VERSION, PrebuiltAwgSource, XrayArtifacts, default_awg_cache_pair, default_xray_cache_pair,
    default_xray_geodata_cache_pairs, ensure_awg_bytes_inner, ensure_xray_artifacts_with_geodata,
};
use kinveil::deploy::lists::{
    extract_geoip_country_cidrs, parse_domain_list_text, parse_ip_list_text,
    resolve_firewall_lists_inner,
};
use kinveil::deploy::ssh::{build_ssh_args, lookup_known_hosts_key};
use kinveil::deploy::traffic::{
    ProtoBytes, ServerTrafficStatus, build_traffic_probe_script, parse_traffic_probe_output,
    parse_utc_date,
};
use kinveil::deploy::verify::{
    build_ssh_probe_script, collect_expected_tcp_ports, parse_ssh_probe_output,
    resolve_pinned_https_uri,
};
use kinveil::state::{
    AdminSsh, FirewallAutoUpdateSettings, FirewallSettings, FirewallXraySettings, VpnProtocol,
};

fn ensure_xray_test(
    cache_dir: &Path,
    custom_zip_source: Option<(&str, &str)>,
    need_geodata: bool,
) -> anyhow::Result<XrayArtifacts> {
    ensure_xray_artifacts_with_geodata(
        cache_dir,
        &[],
        None,
        custom_zip_source,
        None,
        None,
        true,
        need_geodata,
        need_geodata,
    )
}

fn spawn_mock_http_server(path: &'static str, body: Vec<u8>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mock server");
    let addr = listener.local_addr().expect("mock local_addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept http request");
        let mut received = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        while !received.windows(4).any(|w| w == b"\r\n\r\n") && received.len() < 8192 {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
            }
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).expect("write header");
        stream.write_all(&body).expect("write body");
        stream.flush().expect("flush response");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.read(&mut chunk);
    });
    (format!("http://{addr}{path}"), handle)
}

fn build_mock_zip_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        for (filename, payload) in entries {
            zw.start_file(*filename, zip::write::SimpleFileOptions::default())
                .expect("start zip entry");
            zw.write_all(payload).expect("write zip entry");
        }
        zw.finish().expect("finish zip");
    }
    cursor.into_inner()
}

fn build_mock_zip(filename: &str, payload: &[u8]) -> Vec<u8> {
    build_mock_zip_entries(&[(filename, payload)])
}

#[test]
fn custom_awg_caches_isolated_from_default_and_checks_sha256() {
    let elf_payload =
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00fake-awg-binary"
            .to_vec();
    let expected_sha = sha256_hex(&elf_payload);
    let cache = TempPrivateDir::new("awg-cache-ok-");

    let (bad_url, bad_handle) = spawn_mock_http_server("/amneziawg-go-bad", elf_payload.clone());
    let mismatch = ensure_awg_bytes_inner(
        &cache.path,
        &[],
        None,
        Some(PrebuiltAwgSource {
            url: bad_url,
            sha256: "0".repeat(64),
            custom_cache: true,
            allow_fallback_to_go_build: false,
        }),
    )
    .expect_err("wrong sha256 must fail");
    bad_handle.join().expect("join server");
    assert!(
        mismatch.to_string().contains("SHA-256 mismatch"),
        "{mismatch}"
    );

    let (url, handle) = spawn_mock_http_server("/amneziawg-go", elf_payload.clone());
    let (got_bytes, got_sha) = ensure_awg_bytes_inner(
        &cache.path,
        &[],
        None,
        Some(PrebuiltAwgSource {
            url,
            sha256: expected_sha.clone(),
            custom_cache: true,
            allow_fallback_to_go_build: false,
        }),
    )
    .expect("verified custom download succeeds");
    handle.join().expect("join server");
    assert_eq!(got_bytes, elf_payload);
    assert_eq!(got_sha, expected_sha);

    let (cached_bytes, cached_sha) = ensure_awg_bytes_inner(
        &cache.path,
        &[],
        None,
        Some(PrebuiltAwgSource {
            url: "http://127.0.0.1:9/unreachable".to_owned(),
            sha256: expected_sha.clone(),
            custom_cache: true,
            allow_fallback_to_go_build: false,
        }),
    )
    .expect("custom cache hit succeeds offline");
    assert_eq!(cached_bytes, elf_payload);
    assert_eq!(cached_sha, expected_sha);

    let (default_bin, _) = default_awg_cache_pair(&cache.path);
    assert!(!default_bin.exists());

    let err = ensure_awg_bytes_inner(
        &cache.path,
        &[],
        None,
        Some(PrebuiltAwgSource {
            url: "http://127.0.0.1:9/unreachable".to_owned(),
            sha256: "f".repeat(64),
            custom_cache: true,
            allow_fallback_to_go_build: false,
        }),
    )
    .expect_err("different SHA must miss cache and fail on unreachable URL");
    assert!(err.to_string().contains("failed to download"), "{err}");
}

#[test]
fn custom_xray_zip_verifies_sha256_extracts_elf_and_caches_isolated() {
    let elf_payload =
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00fake-xray-bin"
            .to_vec();
    let zip_bytes = build_mock_zip("xray", &elf_payload);
    let zip_sha = sha256_hex(&zip_bytes);
    let expected_bin_sha = sha256_hex(&elf_payload);
    let (url, handle) = spawn_mock_http_server("/Xray-linux-64.zip", zip_bytes);
    let cache = TempPrivateDir::new("xray-cache-ok-");

    let got = ensure_xray_test(&cache.path, Some((&url, &zip_sha)), false)
        .expect("custom xray zip succeeds");
    handle.join().expect("join server");
    assert_eq!(got.bin_bytes, elf_payload);
    assert_eq!(got.bin_sha256, expected_bin_sha);

    let (default_bin, _) = default_xray_cache_pair(&cache.path);
    assert!(!default_bin.exists());

    let cached = ensure_xray_test(
        &cache.path,
        Some(("http://127.0.0.1:9/unreachable", &zip_sha)),
        false,
    )
    .expect("custom xray hits disk cache without network");
    assert_eq!(cached.bin_bytes, elf_payload);
    assert_eq!(cached.bin_sha256, expected_bin_sha);

    let err = ensure_xray_test(
        &cache.path,
        Some(("http://127.0.0.1:9/unreachable", &"a".repeat(64))),
        false,
    )
    .expect_err("different custom zip SHA must not hit previous custom cache");
    assert!(err.to_string().contains("failed to download"), "{err}");
}

#[test]
fn xray_zip_extracts_and_caches_geodata_when_requested() {
    let elf_payload =
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00fake-xray-geo"
            .to_vec();
    let geoip_payload = b"fake-geoip-dat-bytes".to_vec();
    let geosite_payload = b"fake-geosite-dat-bytes".to_vec();
    let zip_bytes = build_mock_zip_entries(&[
        ("xray", &elf_payload),
        ("geoip.dat", &geoip_payload),
        ("geosite.dat", &geosite_payload),
    ]);
    let zip_sha = sha256_hex(&zip_bytes);
    let (url, handle) = spawn_mock_http_server("/Xray-linux-64-geo.zip", zip_bytes);
    let cache = TempPrivateDir::new("xray-geodata-cache-");

    let got = ensure_xray_test(&cache.path, Some((&url, &zip_sha)), true)
        .expect("custom xray zip with geodata succeeds");
    handle.join().expect("join server");
    assert_eq!(got.bin_bytes, elf_payload);
    assert_eq!(got.geoip_bytes, geoip_payload);
    assert_eq!(got.geoip_sha256, sha256_hex(&geoip_payload));
    assert_eq!(got.geosite_bytes, geosite_payload);
    assert_eq!(got.geosite_sha256, sha256_hex(&geosite_payload));

    let ((def_geoip, _), _) = default_xray_geodata_cache_pairs(&cache.path);
    assert!(!def_geoip.exists());

    let cached = ensure_xray_test(
        &cache.path,
        Some(("http://127.0.0.1:9/unreachable", &zip_sha)),
        true,
    )
    .expect("custom xray+geodata hits cache without network");
    assert_eq!(cached.geoip_bytes, geoip_payload);
    assert_eq!(cached.geosite_bytes, geosite_payload);
}

#[test]
fn download_verified_awg_rejects_non_elf_even_with_matching_sha256() {
    let html_payload = b"<html>not an elf binary</html>".to_vec();
    let matching_sha = sha256_hex(&html_payload);
    let (url, handle) = spawn_mock_http_server("/amneziawg-go", html_payload);
    let cache = TempPrivateDir::new("awg-cache-badelf-");

    let err = ensure_awg_bytes_inner(
        &cache.path,
        &[],
        None,
        Some(PrebuiltAwgSource {
            url,
            sha256: matching_sha,
            custom_cache: false,
            allow_fallback_to_go_build: true,
        }),
    )
    .expect_err("non-ELF bytes must fail even with matching sha256");
    handle.join().expect("join server");

    assert!(err.to_string().contains("not a valid ELF"), "{err}");
}

#[test]
fn custom_binary_rejects_wrong_arch_elf_and_non_elf() {
    let cache = TempPrivateDir::new("awg-arch-test-");

    let arm64_path = cache.path.join("awg-arm64");
    fs::write(
        &arm64_path,
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00arm64",
    )
    .unwrap();
    let arm_err =
        ensure_awg_bytes_inner(&cache.path, &[], Some(arm64_path.to_str().unwrap()), None)
            .expect_err("aarch64 ELF must fail");
    assert!(arm_err.to_string().contains("x86_64"), "{arm_err}");

    let macho_path = cache.path.join("awg-macos");
    fs::write(&macho_path, b"\xcf\xfa\xed\xfe\x00\x00").unwrap();
    let mac_err =
        ensure_awg_bytes_inner(&cache.path, &[], Some(macho_path.to_str().unwrap()), None)
            .expect_err("Mach-O must fail");
    assert!(mac_err.to_string().contains("not a valid ELF"), "{mac_err}");
}

#[test]
fn bundled_artifacts_hit_offline_and_ignore_tampered_files() {
    let root = TempPrivateDir::new("awg-bundled-test-");
    let cache_dir = root.path.join("cache");
    let bad_dir = root.path.join("bad");
    let good_dir = root.path.join("good");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::create_dir_all(&bad_dir).unwrap();
    fs::create_dir_all(&good_dir).unwrap();

    let elf_payload =
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00bundled-awg-bin"
            .to_vec();
    let valid_sha = sha256_hex(&elf_payload);
    let awg_filename = format!("amneziawg-go-{AWG_VERSION}-linux-amd64");

    fs::write(bad_dir.join(&awg_filename), b"tampered-not-an-elf").unwrap();
    fs::write(good_dir.join(&awg_filename), &elf_payload).unwrap();

    let err = ensure_awg_bytes_inner(
        &cache_dir,
        std::slice::from_ref(&bad_dir),
        None,
        Some(PrebuiltAwgSource {
            url: "http://127.0.0.1:9/unreachable".to_owned(),
            sha256: valid_sha.clone(),
            custom_cache: false,
            allow_fallback_to_go_build: false,
        }),
    )
    .expect_err("tampered bundled artifact must be ignored");
    assert!(err.to_string().contains("failed to download"), "{err}");

    let (got_bytes, got_sha) = ensure_awg_bytes_inner(
        &cache_dir,
        &[bad_dir, good_dir],
        None,
        Some(PrebuiltAwgSource {
            url: "http://127.0.0.1:9/unreachable".to_owned(),
            sha256: valid_sha.clone(),
            custom_cache: false,
            allow_fallback_to_go_build: false,
        }),
    )
    .expect("valid bundled artifact should succeed offline");
    assert_eq!(got_bytes, elf_payload);
    assert_eq!(got_sha, valid_sha);
}

#[test]
fn build_ssh_args_handles_optional_identity_file() {
    let kh = Path::new("/tmp/test-kh");
    let base = AdminSsh {
        host: "203.0.113.10".to_owned(),
        port: NonZeroU16::new(2222).unwrap(),
        user: "ops".to_owned(),
        identity_file: None,
        host_public_key: "ssh-ed25519 AAAA".to_owned(),
    };

    let plain_args = build_ssh_args(&base, kh, "echo ok");
    assert!(
        !plain_args
            .iter()
            .any(|a| a == "-i" || a == "IdentitiesOnly=yes")
    );
    let sep_idx = plain_args.iter().position(|a| a == "--").unwrap();
    assert_eq!(plain_args[sep_idx + 1], "ops@203.0.113.10");
    assert_eq!(plain_args[sep_idx + 2], "echo ok");

    let mut with_key = base;
    with_key.identity_file = Some("/home/ops/.ssh/kinveil_ed25519".to_owned());
    let key_args = build_ssh_args(&with_key, kh, "echo ok");
    let sep_idx_key = key_args.iter().position(|a| a == "--").unwrap();
    let i_idx = key_args.iter().position(|a| a == "-i").unwrap();
    assert!(i_idx < sep_idx_key);
    assert_eq!(key_args[i_idx + 1], "/home/ops/.ssh/kinveil_ed25519");
    assert!(
        key_args[..sep_idx_key]
            .iter()
            .any(|a| a == "IdentitiesOnly=yes")
    );
}

#[test]
fn pinned_ip_resolver_resolves_both_v4_and_v6() {
    let uri = "https://sub.example.com:8443/path";
    assert_eq!(
        resolve_pinned_https_uri("sub.example.com", IpAddr::V4(Ipv4Addr::LOCALHOST), uri).unwrap(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
    );
    assert_eq!(
        resolve_pinned_https_uri("SUB.EXAMPLE.COM", IpAddr::V6(Ipv6Addr::LOCALHOST), uri).unwrap(),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443)
    );
    assert!(
        resolve_pinned_https_uri(
            "SUB.EXAMPLE.COM",
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "https://other.example.com/path"
        )
        .is_err()
    );
}

#[test]
fn known_hosts_lookup_supports_plaintext_and_hashed_entries() {
    let dir = TempPrivateDir::new("kinveil-kh-test-");
    let (_, ed_pub) = generate_openssh_ed25519("kh-test").unwrap();
    let expected = ed_pub
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let kh_path = dir.path.join("known_hosts");

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
fn ssh_probe_script_and_output_parsing() {
    let mut state = common::multi_server_state();

    let v4_ports = collect_expected_tcp_ports(&state, &state.servers[0]);
    assert!(v4_ports.contains(&(8443, "vless")));
    assert!(v4_ports.contains(&(2222, "ssh-fwd")));
    assert!(v4_ports.contains(&(443, "https")));

    let eff = state.servers[0].effective_config(&state.settings, false);
    let hyst_port = eff.hysteria2_port;
    let awg_port = eff.amneziawg_port;
    let script = build_ssh_probe_script(&state, &state.servers[0]);
    assert!(script.contains("kinveil-xray.service"));
    assert!(script.contains("kinveil-awg.service"));
    assert!(script.contains("kinveil-ssh.service"));
    assert!(script.contains("caddy.service"));
    assert!(script.contains("nft list table inet kinveil"));
    assert!(script.contains(&format!(":{hyst_port}([[:space:]]|$)")));
    assert!(script.contains(&format!(":{awg_port}([[:space:]]|$)")));
    assert!(script.contains("-connect 'www.apple.com:443' -servername 'www.apple.com'"));

    let ok_row = parse_ssh_probe_output(
        "srv1",
        &format!(
            "UNIT kinveil-xray.service ok\n\
             UNIT kinveil-awg.service ok\n\
             NFT ok\n\
             UDP {hyst_port} hysteria2 ok\n\
             UDP {awg_port} amneziawg ok\n\
             REALITY ok www.apple.com www.apple.com:443\n"
        ),
    );
    assert!(ok_row.ok);
    assert!(
        ok_row
            .detail
            .contains(&format!("{hyst_port}/udp(hysteria2)"))
    );
    assert!(
        ok_row
            .detail
            .contains("reality(tls1.3+h2 sni=www.apple.com target=www.apple.com:443)")
    );

    let fail_row = parse_ssh_probe_output(
        "srv1",
        &format!(
            "UNIT kinveil-xray.service ok\n\
             UNIT kinveil-awg.service fail\n\
             NFT ok\n\
             UDP {hyst_port} hysteria2 fail\n\
             UDP {awg_port} amneziawg ok\n\
             REALITY fail www.apple.com www.apple.com:443\n"
        ),
    );
    assert!(!fail_row.ok);
    assert!(fail_row.detail.contains("kinveil-awg.service inactive"));
    assert!(
        fail_row
            .detail
            .contains(&format!("{hyst_port}/udp(hysteria2) not listening"))
    );
    assert!(fail_row.detail.contains(
        "reality target TLS 1.3 + H2 probe failed (sni=www.apple.com, target=www.apple.com:443)"
    ));

    state
        .set_config_toml("[firewall]\nblock_countries = [\"de\"]\n")
        .unwrap();
    let fw_script = build_ssh_probe_script(&state, &state.servers[0]);
    assert!(fw_script.contains("kinveil-firewall-update.timer"));
    assert!(!fw_script.contains("kinveil-traffic.timer"));

    state.servers[0].vpn.as_mut().unwrap().traffic = true;
    let tr_script = build_ssh_probe_script(&state, &state.servers[0]);
    assert!(tr_script.contains("kinveil-traffic.timer"));
    assert!(tr_script.contains("kinveil-traffic-flush.service"));
}

#[test]
fn traffic_probe_script_and_output_parsing() {
    let from = parse_utc_date("2026-11-01", "--from").expect("valid from");
    let to = parse_utc_date("2026-11-17", "--to").expect("valid to");
    assert!(parse_utc_date("2024-02-29", "--from").is_ok());
    assert!(parse_utc_date("2026-02-30", "--from").is_err());
    assert!(parse_utc_date("2026-11-7", "--from").is_err());
    assert!(parse_utc_date("2026/11/01", "--from").is_err());

    let script = build_traffic_probe_script(from, to);
    assert!(script.contains("/usr/local/lib/kinveil/traffic/snapshot-traffic.sh"));
    assert!(script.contains("2026-11-01"));
    assert!(script.contains("2026-11-17"));

    let stdout = "\
STATUS ok
DAY\t2026-11-01\tnic\t1000\t2000
DAY\t2026-11-01\tuid\t1\tvless\t300\t700
DAY\t2026-11-01\tuid\t1\tamneziawg\t100\t200
DAY\t2026-11-02\tnic\t3000000000000\t4000000000000
DAY\t2026-11-02\tuid\t1\tvless\t2500000000000\t100
DAY\t2026-11-02\tuid\t2\thysteria2\t50\t60
DAY\t2026-11-02\tuid\t2\tssh-forwarding\t70\t80
";
    let report = parse_traffic_probe_output("md1", stdout, from, to);
    assert_eq!(report.server_id, "md1");
    match report.status {
        ServerTrafficStatus::Ok {
            days_found,
            nic_observed,
            nic_rx,
            nic_tx,
            users,
        } => {
            assert_eq!(days_found, 2);
            assert!(nic_observed);
            assert_eq!(nic_rx, 3_000_000_001_000);
            assert_eq!(nic_tx, 4_000_000_002_000);
            assert_eq!(
                users[&1][&VpnProtocol::Vless],
                ProtoBytes {
                    up: 2_500_000_000_300,
                    down: 800,
                }
            );
            assert_eq!(
                users[&1][&VpnProtocol::AmneziaWg],
                ProtoBytes { up: 100, down: 200 }
            );
            assert_eq!(
                users[&2][&VpnProtocol::Hysteria2],
                ProtoBytes { up: 50, down: 60 }
            );
            assert_eq!(
                users[&2][&VpnProtocol::SshForwarding],
                ProtoBytes { up: 70, down: 80 }
            );
        }
        other => panic!("expected Ok, got {other:?}"),
    }

    assert_eq!(
        parse_traffic_probe_output("md1", "STATUS undeployed\n", from, to).status,
        ServerTrafficStatus::Undeployed
    );
    assert!(matches!(
        parse_traffic_probe_output("md1", "STATUS ok\nDAY\t2026-10-31\tnic\t1\t2\n", from, to)
            .status,
        ServerTrafficStatus::Failed(_)
    ));
    assert!(matches!(
        parse_traffic_probe_output("md1", "", from, to).status,
        ServerTrafficStatus::Failed(_)
    ));
}

fn pb_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

fn pb_len_field(field_num: u64, payload: &[u8], out: &mut Vec<u8>) {
    pb_varint((field_num << 3) | 2, out);
    pb_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn pb_cidr_msg(ip: &[u8], prefix: u64) -> Vec<u8> {
    let mut m = Vec::new();
    pb_len_field(1, ip, &mut m);
    pb_varint(2 << 3, &mut m);
    pb_varint(prefix, &mut m);
    m
}

fn pb_geoip_entry(cc: &str, cidrs: &[(&[u8], u64)], inverse: bool) -> Vec<u8> {
    let mut m = Vec::new();
    pb_len_field(1, cc.as_bytes(), &mut m);
    for (ip, pfx) in cidrs {
        let c = pb_cidr_msg(ip, *pfx);
        pb_len_field(2, &c, &mut m);
    }
    if inverse {
        pb_varint(3 << 3, &mut m);
        pb_varint(1, &mut m);
    }
    m
}

#[test]
fn geoip_protobuf_extraction_and_remote_firewall_lists() {
    let mut geoip_dat = Vec::new();
    let de_entry = pb_geoip_entry(
        "DE",
        &[
            (&[192, 0, 2, 77], 24),
            (
                &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
                48,
            ),
        ],
        false,
    );
    let us_entry = pb_geoip_entry("US", &[(&[198, 51, 100, 0], 24)], false);
    let de_inverse = pb_geoip_entry("DE", &[(&[203, 0, 113, 0], 24)], true);
    pb_len_field(1, &de_entry, &mut geoip_dat);
    pb_len_field(1, &us_entry, &mut geoip_dat);
    pb_len_field(1, &de_inverse, &mut geoip_dat);

    let extracted =
        extract_geoip_country_cidrs(&geoip_dat, &["de".to_owned(), "fr".to_owned()]).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(
        extracted["de"].0,
        vec!["192.0.2.0/24".parse::<ipnet::Ipv4Net>().unwrap()]
    );
    assert_eq!(
        extracted["de"].1,
        vec!["2001:db8:1::/48".parse::<ipnet::Ipv6Net>().unwrap()]
    );

    let (jp_v4_url, jp_v4_h) = spawn_mock_http_server(
        "/jp-v4.txt",
        b"# JP v4\r\n198.51.100.123/25 ; host bits\r\n".to_vec(),
    );
    let (jp_v6_url, jp_v6_h) = spawn_mock_http_server("/jp-v6.txt", b"2001:db8:2::/48\n".to_vec());
    let (ip_list_url, ip_list_h) = spawn_mock_http_server(
        "/custom-ips.txt",
        b"# Extra\n203.0.113.42\n2001:db8:3::1\n".to_vec(),
    );
    let (dom_list_url, dom_list_h) = spawn_mock_http_server(
        "/custom-domains.txt",
        b"# Domains\n.jp\nfull:bad.example.com\ngeosite:category-ads\n".to_vec(),
    );

    let fw = FirewallSettings {
        block_countries: vec!["DE".to_owned(), "jp".to_owned()],
        block_ip_lists: vec![ip_list_url],
        auto_update: FirewallAutoUpdateSettings {
            ipv4_country_url: jp_v4_url,
            ipv6_country_url: jp_v6_url,
            ..Default::default()
        },
        xray: FirewallXraySettings {
            block_domain_lists: vec![dom_list_url],
            ..Default::default()
        },
        ..Default::default()
    };

    let resolved = resolve_firewall_lists_inner(&fw, &geoip_dat, false).unwrap();
    jp_v4_h.join().unwrap();
    jp_v6_h.join().unwrap();
    ip_list_h.join().unwrap();
    dom_list_h.join().unwrap();

    assert!(
        resolved
            .extra_ipv4
            .contains(&"192.0.2.0/24".parse().unwrap())
    );
    assert!(
        resolved
            .extra_ipv4
            .contains(&"198.51.100.0/25".parse().unwrap())
    );
    assert!(
        resolved
            .extra_ipv4
            .contains(&"203.0.113.42/32".parse().unwrap())
    );
    assert!(
        resolved
            .extra_ipv6
            .contains(&"2001:db8:1::/48".parse().unwrap())
    );
    assert!(
        resolved
            .extra_ipv6
            .contains(&"2001:db8:2::/48".parse().unwrap())
    );
    assert!(
        resolved
            .extra_ipv6
            .contains(&"2001:db8:3::1/128".parse().unwrap())
    );
    assert_eq!(
        resolved.extra_xray_domains,
        vec![
            "domain:jp".to_owned(),
            "full:bad.example.com".to_owned(),
            "geosite:category-ads".to_owned()
        ]
    );
    assert_eq!(resolved.missing_geoip_countries, vec!["jp".to_owned()]);

    assert!(parse_ip_list_text("<html>not cidr</html>", "test").is_err());
    assert!(parse_domain_list_text("bad host!", "test").is_err());
    let (bad_url, bad_h) = spawn_mock_http_server("/bad.txt", b"<html>404</html>".to_vec());
    let bad_fw = FirewallSettings {
        block_ip_lists: vec![bad_url],
        ..Default::default()
    };
    assert!(resolve_firewall_lists_inner(&bad_fw, &[], false).is_err());
    bad_h.join().unwrap();
}

#[test]
fn standalone_geodata_overrides_work_without_xray_binary() {
    let custom_geoip = b"custom-geoip-protobuf-bytes".to_vec();
    let geoip_sha = sha256_hex(&custom_geoip);
    let (geoip_url, geoip_h) = spawn_mock_http_server("/geoip.dat", custom_geoip.clone());
    let cache = TempPrivateDir::new("geodata-standalone-");

    let got = ensure_xray_artifacts_with_geodata(
        &cache.path,
        &[],
        None,
        None,
        Some((&geoip_url, &geoip_sha)),
        None,
        false,
        true,
        false,
    )
    .expect("standalone geoip fetch succeeds without xray binary");
    geoip_h.join().unwrap();
    assert!(got.bin_bytes.is_empty());
    assert_eq!(got.geoip_bytes, custom_geoip);
    assert_eq!(got.geoip_sha256, geoip_sha);

    let cached = ensure_xray_artifacts_with_geodata(
        &cache.path,
        &[],
        None,
        None,
        Some(("http://127.0.0.1:9/unreachable", &geoip_sha)),
        None,
        false,
        true,
        false,
    )
    .expect("standalone geoip hits disk cache offline");
    assert_eq!(cached.geoip_bytes, custom_geoip);
}
