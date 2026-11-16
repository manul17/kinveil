use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ureq::Agent;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::deploy::remote::remote_bash_stdin_cmd;
use crate::deploy::ssh::run_ssh;
use crate::render::subscriptions::{SubVariant, render_subscription_body};
use crate::state::{Server, State};

#[derive(Debug, Clone)]
struct PinnedIpResolver {
    domain: String,
    ip: IpAddr,
}

impl PinnedIpResolver {
    fn resolve_pinned_uri(&self, uri: &Uri) -> std::result::Result<SocketAddr, ureq::Error> {
        let host = uri
            .host()
            .ok_or_else(|| ureq::Error::BadUri(format!("missing host in {uri}")))?;
        if !host.eq_ignore_ascii_case(&self.domain) {
            return Err(ureq::Error::HostNotFound);
        }
        let port = uri.port_u16().unwrap_or(443);
        Ok(SocketAddr::new(self.ip, port))
    }
}

impl Resolver for PinnedIpResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> std::result::Result<ResolvedSocketAddrs, ureq::Error> {
        let addr = self.resolve_pinned_uri(uri)?;
        let mut addrs = self.empty();
        addrs.push(addr);
        Ok(addrs)
    }
}

struct HttpResponse {
    status: u16,
    body: String,
}

fn build_pinned_agent(domain: &str, ip: IpAddr, timeout: Duration) -> Agent {
    let config = Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(timeout))
        .build();
    Agent::with_parts(
        config,
        DefaultConnector::default(),
        PinnedIpResolver {
            domain: domain.to_owned(),
            ip,
        },
    )
}

fn direct_ip_https_get(
    agent: &Agent,
    domain: &str,
    request_path: &str,
    user_agent: &str,
) -> Result<HttpResponse> {
    let url = format!("https://{domain}{request_path}");
    let mut resp = agent
        .get(&url)
        .header("User-Agent", user_agent)
        .header("Accept-Encoding", "identity")
        .call()
        .map_err(|e| anyhow!("HTTPS GET to https://{domain}/<redacted> failed: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.body_mut().read_to_string().map_err(|e| {
        anyhow!("non-UTF-8 HTTP response body from https://{domain}/<redacted>: {e}")
    })?;
    Ok(HttpResponse { status, body })
}

/// Probe whether the local host can route UDP packets to a target IPv6 address.
/// Returns `false` only on explicit network-unreachable / addr-not-available errors
/// so unexpected local socket errors still surface during verification.
pub fn has_local_ipv6_route(target: Ipv6Addr) -> bool {
    let Ok(sock) = UdpSocket::bind("[::]:0") else {
        return false;
    };
    match sock.connect(SocketAddr::new(IpAddr::V6(target), 443)) {
        Ok(()) => true,
        Err(err) => !matches!(
            err.kind(),
            ErrorKind::NetworkUnreachable | ErrorKind::AddrNotAvailable
        ),
    }
}

fn verify_https_subscriptions_on_ip(
    state: &State,
    server_id: &str,
    ip: IpAddr,
    max_wait: Duration,
) -> Result<usize> {
    let timeout = Duration::from_secs(10);
    let agent = build_pinned_agent(&state.subscription.domain, ip, timeout);
    let enabled_users = state.enabled_users_by_uid();
    if enabled_users.is_empty() {
        bail!("no enabled users to verify over HTTPS");
    }

    let deadline = Instant::now() + max_wait;
    let (_, first) = enabled_users[0];
    let first_path = format!(
        "{}{}",
        state.subscription.base_path.as_str(),
        first.subscription_token.as_str()
    );

    // Wait/retry for initial TLS/ACME readiness (important immediately after a DNS cutover).
    loop {
        match direct_ip_https_get(&agent, &state.subscription.domain, &first_path, "Happ/1.0") {
            Ok(resp) if resp.status == 200 => break,
            Ok(resp) if Instant::now() < deadline && matches!(resp.status, 404 | 502 | 503) => {
                std::thread::sleep(Duration::from_secs(2));
            }
            Ok(resp) => {
                bail!(
                    "HTTPS subscription probe over {ip} returned unexpected status {} on {server_id}",
                    resp.status
                );
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("HTTPS probe over {ip} on {server_id}"));
            }
        }
    }

    let mut checked = 0usize;
    for (idx, &(name, user)) in enabled_users.iter().enumerate() {
        let path = format!(
            "{}{}",
            state.subscription.base_path.as_str(),
            user.subscription_token.as_str()
        );
        let expected_happ = render_subscription_body(state, name, user, SubVariant::Happ)?;
        let resp_happ = direct_ip_https_get(&agent, &state.subscription.domain, &path, "Happ/1.0")?;
        if resp_happ.status != 200 || resp_happ.body.trim() != expected_happ.trim() {
            bail!(
                "HTTPS Happ subscription payload mismatch over {ip} for user uid {}",
                user.uid
            );
        }

        let expected_throne = render_subscription_body(state, name, user, SubVariant::Throne)?;
        let resp_throne =
            direct_ip_https_get(&agent, &state.subscription.domain, &path, "Throne/1.0")?;
        if resp_throne.status != 200 || resp_throne.body.trim() != expected_throne.trim() {
            bail!(
                "HTTPS Throne subscription payload mismatch over {ip} for user uid {}",
                user.uid
            );
        }

        if idx == 0 {
            let ssh_query_path = format!("{path}?ssh=1");
            let resp_q = direct_ip_https_get(
                &agent,
                &state.subscription.domain,
                &ssh_query_path,
                "Mozilla/5.0",
            )?;
            if resp_q.status != 200 || resp_q.body.trim() != expected_throne.trim() {
                bail!(
                    "HTTPS ?ssh=1 subscription payload mismatch over {ip} for user uid {}",
                    user.uid
                );
            }
        }
        checked += 1;
    }

    let nonexistent = format!(
        "{}__nonexistent_probe__",
        state.subscription.base_path.as_str()
    );
    let resp_404 = direct_ip_https_get(
        &agent,
        &state.subscription.domain,
        &nonexistent,
        "Mozilla/5.0",
    )?;
    if resp_404.status != 404 {
        bail!(
            "expected HTTP 404 over {ip} for unknown subscription token, got {}",
            resp_404.status
        );
    }

    Ok(checked)
}

pub fn verify_https_subscriptions(state: &State, max_wait: Duration) -> Result<usize> {
    let sub_srv = state
        .active_subscription_server()
        .ok_or_else(|| anyhow!("no enabled server holds the 'subscription' role"))?;

    let checked_v4 = verify_https_subscriptions_on_ip(
        state,
        &sub_srv.id,
        IpAddr::V4(sub_srv.public_ipv4),
        max_wait,
    )?;

    if let Some(ipv6) = sub_srv.public_ipv6 {
        if has_local_ipv6_route(ipv6) {
            verify_https_subscriptions_on_ip(state, &sub_srv.id, IpAddr::V6(ipv6), max_wait)?;
        } else {
            eprintln!(
                "warning: subscription server {} has public_ipv6 {ipv6}, but this host lacks a local IPv6 route — skipping IPv6 HTTPS verification",
                sub_srv.id
            );
        }
    }

    Ok(checked_v4)
}

pub fn probe_tcp_port(ip: IpAddr, port: u16, timeout: Duration) -> Result<()> {
    let addr = SocketAddr::new(ip, port);
    TcpStream::connect_timeout(&addr, timeout)?;
    Ok(())
}

fn collect_expected_tcp_ports(state: &State, server: &Server) -> Vec<(u16, &'static str)> {
    let mut ports = Vec::new();
    if server.has_vless(&state.settings) {
        ports.push((server.effective_vless_port(&state.settings), "vless"));
    }
    if server.has_ssh_forwarding(&state.settings) {
        ports.push((server.effective_ssh_port(&state.settings), "ssh"));
    }
    if state.is_subscription_server(&server.id) {
        ports.push((443, "https"));
    }
    ports
}

fn collect_expected_ipv6_tcp_ports(state: &State, server: &Server) -> Vec<(u16, &'static str)> {
    let mut ports = Vec::new();
    if state.is_subscription_server(&server.id) {
        ports.push((443, "https"));
    }
    ports
}

fn probe_addr_ports(
    ip: IpAddr,
    suffix: &str,
    ports: &[(u16, &str)],
    timeout: Duration,
    ok_ports: &mut Vec<String>,
    issues: &mut Vec<String>,
) {
    for &(port, proto) in ports {
        let label = format!("{port}/tcp({proto}{suffix})");
        match probe_tcp_port(ip, port, timeout) {
            Ok(()) => ok_ports.push(label),
            Err(e) => issues.push(format!("{label}: {e}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRow {
    pub target: String,
    pub ok: bool,
    pub detail: String,
}

impl CheckRow {
    fn new(target: impl Into<String>, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            ok,
            detail: detail.into(),
        }
    }
}

pub fn check_external(state: &State, filter_server: Option<&str>) -> Result<Vec<CheckRow>> {
    let mut rows = Vec::new();
    let timeout = Duration::from_secs(5);

    for server in &state.servers {
        if let Some(only) = filter_server
            && server.id != only
        {
            continue;
        }
        if !server.enabled {
            rows.push(CheckRow::new(&server.id, true, "disabled (skipped)"));
            continue;
        }
        let ports_v4 = collect_expected_tcp_ports(state, server);
        let ports_v6 = collect_expected_ipv6_tcp_ports(state, server);
        let mut issues = Vec::new();
        let mut ok_ports = Vec::new();

        probe_addr_ports(
            IpAddr::V4(server.public_ipv4),
            "",
            &ports_v4,
            timeout,
            &mut ok_ports,
            &mut issues,
        );
        if !ports_v6.is_empty()
            && let Some(ipv6) = server.public_ipv6
        {
            if has_local_ipv6_route(ipv6) {
                probe_addr_ports(
                    IpAddr::V6(ipv6),
                    ",v6",
                    &ports_v6,
                    timeout,
                    &mut ok_ports,
                    &mut issues,
                );
            } else {
                ok_ports.push("ipv6-skipped(no local v6 route)".to_owned());
            }
        }

        if issues.is_empty() {
            rows.push(CheckRow::new(
                &server.id,
                true,
                format!("reachable [{}]", ok_ports.join(", ")),
            ));
        } else {
            rows.push(CheckRow::new(
                &server.id,
                false,
                format!(
                    "FAILED [{}] (ok: {})",
                    issues.join("; "),
                    if ok_ports.is_empty() {
                        "none".to_owned()
                    } else {
                        ok_ports.join(", ")
                    }
                ),
            ));
        }
    }

    if filter_server.is_none()
        || state
            .active_subscription_server()
            .is_some_and(|s| Some(s.id.as_str()) == filter_server)
    {
        match verify_https_subscriptions(state, Duration::from_secs(5)) {
            Ok(n) => {
                let v6_note = match state
                    .active_subscription_server()
                    .and_then(|s| s.public_ipv6)
                {
                    Some(v6) if has_local_ipv6_route(v6) => " (IPv4 + IPv6)",
                    Some(_) => " (IPv4; IPv6 skipped locally)",
                    None => "",
                };
                rows.push(CheckRow::new(
                    "https-sub",
                    true,
                    format!("verified {n} subscription(s) + 404 guard{v6_note}"),
                ));
            }
            Err(e) => rows.push(CheckRow::new("https-sub", false, format!("FAILED: {e}"))),
        }
    }

    Ok(rows)
}

fn shell_single_quote(s: &str) -> String {
    let escaped = s.replace('\'', r#"'\''"#);
    format!("'{escaped}'")
}

/// Builds a read-only bash diagnostic probe to execute over SSH on `server`.
pub fn build_ssh_probe_script(state: &State, server: &Server) -> String {
    use std::fmt::Write as _;

    let mut units = Vec::new();
    if server.has_xray(&state.settings) {
        units.push("kinveil-xray.service");
    }
    if server.has_amneziawg(&state.settings) {
        units.push("kinveil-awg.service");
    }
    if server.has_ssh_forwarding(&state.settings) {
        units.push("kinveil-ssh.service");
    }
    if state.is_subscription_server(&server.id) {
        units.push("caddy.service");
    }

    let mut script = String::from("set -u\n");
    for unit in units {
        let _ = writeln!(
            script,
            "if systemctl is-active --quiet {unit}; then echo 'UNIT {unit} ok'; else echo 'UNIT {unit} fail'; fi"
        );
    }
    script.push_str(
        "if nft list table inet kinveil >/dev/null 2>&1; then echo 'NFT ok'; else echo 'NFT fail'; fi\n",
    );

    if server.has_hysteria2(&state.settings) || server.has_amneziawg(&state.settings) {
        script.push_str("UDP_SOCKS=\"$(ss -H -uln 2>/dev/null || true)\"\n");
        if server.has_hysteria2(&state.settings) {
            let hyst_port = server.effective_hysteria2_port(&state.settings);
            let _ = writeln!(
                script,
                "if printf '%s\\n' \"$UDP_SOCKS\" | grep -qE ':{hyst_port}([[:space:]]|$)'; then echo 'UDP {hyst_port} hysteria2 ok'; else echo 'UDP {hyst_port} hysteria2 fail'; fi"
            );
        }
        if server.has_amneziawg(&state.settings) {
            let awg_port = server.effective_amneziawg_port(&state.settings);
            let _ = writeln!(
                script,
                "if printf '%s\\n' \"$UDP_SOCKS\" | grep -qE ':{awg_port}([[:space:]]|$)'; then echo 'UDP {awg_port} amneziawg ok'; else echo 'UDP {awg_port} amneziawg fail'; fi"
            );
        }
    }

    if server.has_vless(&state.settings)
        && let Some(vpn) = server.vpn.as_ref().filter(|v| v.enabled)
    {
        let target_q = shell_single_quote(&vpn.vless.target);
        let sni_q = shell_single_quote(&vpn.vless.server_name);
        let _ = writeln!(
            script,
            "if command -v openssl >/dev/null 2>&1; then\n\
             \x20 REALITY_OUT=\"$(timeout 5 openssl s_client -connect {target_q} -servername {sni_q} -tls1_3 -alpn h2 </dev/null 2>&1 || true)\"\n\
             \x20 if printf '%s' \"$REALITY_OUT\" | grep -q 'TLSv1\\.3' && printf '%s' \"$REALITY_OUT\" | grep -q 'ALPN protocol: h2'; then\n\
             \x20   printf 'REALITY ok %s %s\\n' {sni_q} {target_q}\n\
             \x20 else\n\
             \x20   printf 'REALITY fail %s %s\\n' {sni_q} {target_q}\n\
             \x20 fi\n\
             else\n\
             \x20 printf 'REALITY skipped(no-openssl) %s %s\\n' {sni_q} {target_q}\n\
             fi"
        );
    }

    script
}

/// Parses stdout produced by [`build_ssh_probe_script`] into a structured [`CheckRow`].
pub fn parse_ssh_probe_output(server_id: &str, stdout: &str) -> CheckRow {
    let target = format!("{server_id} (ssh)");
    let mut ok_items = Vec::new();
    let mut failures = Vec::new();

    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["UNIT", unit, "ok"] => ok_items.push((*unit).to_owned()),
            ["UNIT", unit, "fail"] => failures.push(format!("{unit} inactive")),
            ["NFT", "ok"] => ok_items.push("nft:kinveil".to_owned()),
            ["NFT", "fail"] => failures.push("nftables table inet kinveil missing".to_owned()),
            ["UDP", port, proto, "ok"] => ok_items.push(format!("{port}/udp({proto})")),
            ["UDP", port, proto, "fail"] => {
                failures.push(format!("{port}/udp({proto}) not listening"));
            }
            ["REALITY", "ok", sni, target_ep] => {
                ok_items.push(format!("reality(tls1.3+h2 sni={sni} target={target_ep})"));
            }
            ["REALITY", "fail", sni, target_ep] => {
                failures.push(format!(
                    "reality target TLS 1.3 + H2 probe failed (sni={sni}, target={target_ep})"
                ));
            }
            ["REALITY", status, sni, target_ep] if status.starts_with("skipped") => {
                ok_items.push(format!("reality({status} sni={sni} target={target_ep})"));
            }
            ["REALITY", "ok"] => ok_items.push("reality(tls1.3+h2)".to_owned()),
            ["REALITY", "fail"] => {
                failures.push("reality target TLS 1.3 + H2 probe failed".to_owned());
            }
            ["REALITY", status] if status.starts_with("skipped") => {
                ok_items.push(format!("reality({status})"));
            }
            _ => {}
        }
    }

    if ok_items.is_empty() && failures.is_empty() {
        return CheckRow::new(target, false, "empty probe output");
    }
    if failures.is_empty() {
        CheckRow::new(target, true, format!("ok [{}]", ok_items.join(", ")))
    } else {
        CheckRow::new(
            target,
            false,
            format!(
                "FAILED [{}] (ok: {})",
                failures.join("; "),
                if ok_items.is_empty() {
                    "none".to_owned()
                } else {
                    ok_items.join(", ")
                }
            ),
        )
    }
}

/// Runs read-only remote diagnostics over pinned SSH on selected enabled servers.
pub fn check_remote_ssh(state: &State, filter_server: Option<&str>) -> Result<Vec<CheckRow>> {
    let mut rows = Vec::new();
    for server in &state.servers {
        if let Some(only) = filter_server
            && server.id != only
        {
            continue;
        }
        if !server.enabled {
            rows.push(CheckRow::new(
                format!("{} (ssh)", server.id),
                true,
                "disabled (skipped)",
            ));
            continue;
        }
        let script = build_ssh_probe_script(state, server);
        let remote_cmd = remote_bash_stdin_cmd(&server.admin_ssh.user);
        match run_ssh(&server.admin_ssh, remote_cmd, Some(script.as_bytes())) {
            Ok(out) => rows.push(parse_ssh_probe_output(&server.id, &out.stdout)),
            Err(e) => rows.push(CheckRow::new(
                format!("{} (ssh)", server.id),
                false,
                format!("SSH probe failed: {e}"),
            )),
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn pinned_ip_resolver_resolves_both_v4_and_v6() {
        let uri: Uri = "https://sub.example.com:8443/path".parse().unwrap();

        let r4 = PinnedIpResolver {
            domain: "sub.example.com".to_owned(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        assert_eq!(
            r4.resolve_pinned_uri(&uri).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
        );

        let r6 = PinnedIpResolver {
            domain: "SUB.EXAMPLE.COM".to_owned(),
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        assert_eq!(
            r6.resolve_pinned_uri(&uri).unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443)
        );

        let wrong: Uri = "https://other.example.com/path".parse().unwrap();
        assert!(r6.resolve_pinned_uri(&wrong).is_err());
    }

    #[test]
    fn ssh_probe_script_and_output_parsing() {
        let mut state = State::new("sub.example.com".to_owned()).unwrap();
        let (_, host_pub) = crate::crypto::generate_openssh_ed25519("srv1-admin").unwrap();
        let srv = Server {
            id: "srv1".to_owned(),
            label: "DE Germany".to_owned(),
            enabled: true,
            arch: crate::state::ServerArch::X86_64,
            created_at: crate::state::now_utc_seconds(),
            note: None,
            public_ipv4: Ipv4Addr::new(198, 51, 100, 10),
            public_ipv6: None,
            admin_ssh: crate::state::AdminSsh {
                host: "198.51.100.10".to_owned(),
                port: std::num::NonZeroU16::new(22).unwrap(),
                user: "root".to_owned(),
                host_public_key: host_pub,
            },
            ports: crate::state::ServerPortOverrides::default(),
            vpn: Some(
                crate::state::ServerVpn::generate(
                    "srv1",
                    Ipv4Addr::new(198, 51, 100, 10),
                    "www.apple.com",
                    None,
                    None,
                )
                .unwrap(),
            ),
        };
        state.subscription.server_id = Some("srv1".to_owned());
        state.servers.push(srv);

        let hyst_port = state.servers[0].effective_hysteria2_port(&state.settings);
        let awg_port = state.servers[0].effective_amneziawg_port(&state.settings);
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
    }
}
