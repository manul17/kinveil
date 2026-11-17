use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::render::{
    ALWAYS_BLOCKED_IPV4_CIDRS, ALWAYS_BLOCKED_IPV6_CIDRS, PRIVATE_IPV4_CIDRS, PRIVATE_IPV6_CIDRS,
    ResolvedFirewallLists, push_unique,
};
use crate::state::{EffectiveServerConfig, FirewallSettings, Server, State};
use crate::validate::{normalize_country_code, parse_cidr_or_ip};

pub fn render_resolved_conf() -> &'static str {
    "[Resolve]\nLLMNR=no\nMulticastDNS=no\nDNSOverTLS=opportunistic\n"
}

pub fn render_admin_sshd_dropin(port: u16) -> String {
    format!(
        "Port {port}\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
    )
}

pub fn render_sysctl(state: &State, server: &Server) -> String {
    let s = &state.settings.sysctl;
    let eff = server.effective_config(&state.settings, false);
    let ip_forward = u8::from(server.enabled && eff.has_amneziawg);
    format!(
        r#"net.core.rmem_max = {rmem_max}
net.core.wmem_max = {wmem_max}
net.core.rmem_default = {rmem_default}
net.core.wmem_default = {wmem_default}
net.ipv4.ip_forward = {ip_forward}
"#,
        rmem_max = s.udp_rmem_max,
        wmem_max = s.udp_wmem_max,
        rmem_default = s.udp_rmem_default,
        wmem_default = s.udp_wmem_default,
        ip_forward = ip_forward,
    )
}

fn resolved_egress_cidrs(
    fw: &FirewallSettings,
    lists: &ResolvedFirewallLists,
) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>)> {
    let base_v4 = if fw.block_private_networks {
        PRIVATE_IPV4_CIDRS
    } else {
        ALWAYS_BLOCKED_IPV4_CIDRS
    };
    let base_v6 = if fw.block_private_networks {
        PRIVATE_IPV6_CIDRS
    } else {
        ALWAYS_BLOCKED_IPV6_CIDRS
    };

    let mut v4: Vec<Ipv4Net> = base_v4
        .iter()
        .map(|s| s.parse::<Ipv4Net>().expect("valid static IPv4 CIDR"))
        .collect();
    let mut v6: Vec<Ipv6Net> = base_v6
        .iter()
        .map(|s| s.parse::<Ipv6Net>().expect("valid static IPv6 CIDR"))
        .collect();
    v6.push(
        "::ffff:0:0/96"
            .parse::<Ipv6Net>()
            .expect("valid v4-mapped IPv6 CIDR"),
    );

    for raw in &fw.block_cidrs {
        match parse_cidr_or_ip(raw, "firewall.block_cidrs")? {
            IpNet::V4(net) => v4.push(net),
            IpNet::V6(net) => v6.push(net),
        }
    }

    v4.extend(lists.extra_ipv4.iter().map(Ipv4Net::trunc));
    v6.extend(lists.extra_ipv6.iter().map(Ipv6Net::trunc));

    Ok((Ipv4Net::aggregate(&v4), Ipv6Net::aggregate(&v6)))
}

pub fn static_egress_cidrs(fw: &FirewallSettings) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>)> {
    resolved_egress_cidrs(fw, &ResolvedFirewallLists::default())
}

fn write_nft_interval_set<T: std::fmt::Display>(
    out: &mut String,
    name: &str,
    nft_type: &str,
    items: &[T],
) {
    let _ = writeln!(out, "    set {name} {{");
    let _ = writeln!(out, "        type {nft_type}");
    out.push_str("        flags interval\n");
    out.push_str("        auto-merge\n");
    if !items.is_empty() {
        if items.len() <= 8 {
            let elements = items
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "        elements = {{ {elements} }}");
        } else {
            out.push_str("        elements = {\n");
            for (idx, chunk) in items.chunks(8).enumerate() {
                if idx > 0 {
                    out.push_str(",\n");
                }
                out.push_str("            ");
                out.push_str(
                    &chunk
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            out.push_str("\n        }\n");
        }
    }
    out.push_str("    }\n");
}

pub fn render_nft_blocked_sets(
    fw: &FirewallSettings,
    lists: &ResolvedFirewallLists,
) -> Result<String> {
    let (v4, v6) = resolved_egress_cidrs(fw, lists)?;
    let mut out = String::new();
    write_nft_interval_set(&mut out, "egress_blocked_v4", "ipv4_addr", &v4);
    write_nft_interval_set(&mut out, "egress_blocked_v6", "ipv6_addr", &v6);
    Ok(out)
}

fn write_egress_subject_rules(
    out: &mut String,
    subject: &str,
    co_located_sub_ips: Option<(Ipv4Addr, Option<Ipv6Addr>)>,
    dns_resolvers: &[IpAddr],
) {
    for resolver in dns_resolvers {
        let family = if resolver.is_ipv4() { "ip" } else { "ip6" };
        let _ = writeln!(
            out,
            "        {subject} {family} daddr {resolver} meta l4proto {{ tcp, udp }} th dport 53 accept"
        );
    }
    if let Some((ip4, ip6_opt)) = co_located_sub_ips {
        let _ = writeln!(
            out,
            "        {subject} ip daddr {ip4} tcp dport {{ 80, 443 }} accept"
        );
        if let Some(ip6) = ip6_opt {
            let _ = writeln!(
                out,
                "        {subject} ip6 daddr {ip6} tcp dport {{ 80, 443 }} accept"
            );
        }
    }
    let _ = writeln!(out, "        {subject} fib daddr type local reject");
    let _ = writeln!(out, "        {subject} ip daddr @egress_blocked_v4 reject");
    let _ = writeln!(out, "        {subject} ip6 daddr @egress_blocked_v6 reject");
}

pub fn render_nft_egress_fragment(
    xray_uid: Option<u32>,
    co_located_sub_ips: Option<(Ipv4Addr, Option<Ipv6Addr>)>,
    ssh_uids: &[u32],
    dns_resolvers: &[IpAddr],
) -> String {
    let mut sorted_ssh_uids = ssh_uids.to_vec();
    sorted_ssh_uids.sort_unstable();
    sorted_ssh_uids.dedup();

    if xray_uid.is_none() && sorted_ssh_uids.is_empty() {
        return "    # No active Xray or vpnssh egress UIDs\n".to_owned();
    }

    let mut out = String::new();
    if !sorted_ssh_uids.is_empty() {
        let uid_elements = sorted_ssh_uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "    set vpnssh_users {{ type uid; elements = {{ {uid_elements} }}; }}"
        );
    }

    out.push_str("    chain output {\n");
    out.push_str("        type filter hook output priority -10; policy accept;\n");
    // Permit reply packets for already-established inbound VPN/proxy flows owned by Xray or vpnssh.
    out.push_str("        ct direction reply accept\n");

    if let Some(xuid) = xray_uid {
        let subject = format!("meta skuid {xuid}");
        write_egress_subject_rules(&mut out, &subject, co_located_sub_ips, dns_resolvers);
    }

    if !sorted_ssh_uids.is_empty() {
        write_egress_subject_rules(
            &mut out,
            "meta skuid @vpnssh_users",
            co_located_sub_ips,
            dns_resolvers,
        );
    }

    out.push_str("    }\n");
    out
}

pub fn collect_awg_traffic_users(state: &State) -> Result<Vec<(u32, Ipv4Addr)>> {
    let mut users = Vec::new();
    for (_, user) in state.enabled_users_by_uid() {
        let cidr = state.settings.awg_user_cidr(user.uid)?;
        let ip_str = cidr.strip_suffix("/32").unwrap_or(&cidr);
        let ip: Ipv4Addr = ip_str.parse().map_err(|_| {
            anyhow::anyhow!("invalid AmneziaWG address '{ip_str}' for uid {}", user.uid)
        })?;
        users.push((user.uid, ip));
    }
    Ok(users)
}

fn write_nft_map_block(out: &mut String, name: &str, map_type: &str, entries: &[(String, String)]) {
    let _ = writeln!(out, "    map {name} {{");
    let _ = writeln!(out, "        type {map_type}");
    out.push_str("        elements = {\n");
    for (idx, (key, val)) in entries.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        let _ = write!(out, "            {key} : {val}");
    }
    out.push_str("\n        }\n");
    out.push_str("    }\n");
}

pub fn render_nft_traffic_fragment(
    awg_users: &[(u32, Ipv4Addr)],
    ssh_users: &[(u32, u32)],
) -> String {
    let mut awg = awg_users.to_vec();
    awg.sort_unstable_by_key(|&(uid, ip)| (uid, ip));
    awg.dedup_by_key(|(uid, _)| *uid);

    let mut ssh: Vec<(u32, u32)> = ssh_users
        .iter()
        .copied()
        .filter(|&(uid, _)| uid > 0)
        .collect();
    ssh.sort_unstable_by_key(|&(uid, skuid)| (uid, skuid));
    ssh.dedup_by_key(|(uid, _)| *uid);

    if awg.is_empty() && ssh.is_empty() {
        return "    # No active nftables traffic counters\n".to_owned();
    }

    let mut out = String::new();
    for &(uid, _) in &awg {
        let _ = writeln!(out, "    counter awg_up_{uid} {{}}");
        let _ = writeln!(out, "    counter awg_down_{uid} {{}}");
    }
    for &(uid, _) in &ssh {
        let _ = writeln!(out, "    counter ssh_up_{uid} {{}}");
        let _ = writeln!(out, "    counter ssh_down_{uid} {{}}");
    }

    if !awg.is_empty() {
        let up_entries: Vec<(String, String)> = awg
            .iter()
            .map(|(uid, ip)| (ip.to_string(), format!("\"awg_up_{uid}\"")))
            .collect();
        let down_entries: Vec<(String, String)> = awg
            .iter()
            .map(|(uid, ip)| (ip.to_string(), format!("\"awg_down_{uid}\"")))
            .collect();
        write_nft_map_block(&mut out, "awg_up_acct", "ipv4_addr : counter", &up_entries);
        write_nft_map_block(
            &mut out,
            "awg_down_acct",
            "ipv4_addr : counter",
            &down_entries,
        );
        out.push_str("    chain acct_forward {\n");
        out.push_str("        type filter hook forward priority 5; policy accept;\n");
        out.push_str("        iifname \"kv0\" counter name ip saddr map @awg_up_acct\n");
        out.push_str("        oifname \"kv0\" counter name ip daddr map @awg_down_acct\n");
        out.push_str("    }\n");
    }

    if !ssh.is_empty() {
        let uid_mark_entries: Vec<(String, String)> = ssh
            .iter()
            .map(|(uid, skuid)| (skuid.to_string(), format!("0x{uid:x}")))
            .collect();
        let up_entries: Vec<(String, String)> = ssh
            .iter()
            .map(|(uid, _)| (format!("0x{uid:x}"), format!("\"ssh_up_{uid}\"")))
            .collect();
        let down_entries: Vec<(String, String)> = ssh
            .iter()
            .map(|(uid, _)| (format!("0x{uid:x}"), format!("\"ssh_down_{uid}\"")))
            .collect();
        write_nft_map_block(&mut out, "ssh_uid_mark", "uid : mark", &uid_mark_entries);
        write_nft_map_block(&mut out, "ssh_up_acct", "mark : counter", &up_entries);
        write_nft_map_block(&mut out, "ssh_down_acct", "mark : counter", &down_entries);
        out.push_str("    chain acct_output {\n");
        out.push_str("        type filter hook output priority 5; policy accept;\n");
        out.push_str(
            "        ct state new ct direction original ct mark set meta skuid map @ssh_uid_mark\n",
        );
        out.push_str(
            "        ct mark != 0 ct direction original counter name ct mark map @ssh_up_acct\n",
        );
        out.push_str("    }\n");
        out.push_str("    chain acct_input {\n");
        out.push_str("        type filter hook input priority 5; policy accept;\n");
        out.push_str(
            "        ct mark != 0 ct direction reply counter name ct mark map @ssh_down_acct\n",
        );
        out.push_str("    }\n");
    }

    out
}

fn render_nftables_inner(
    state: &State,
    server: &Server,
    eff: &EffectiveServerConfig,
    blocked_sets_block: Option<&str>,
    egress_tail: Option<&str>,
    traffic_tail: Option<&str>,
) -> Result<String> {
    let mut out = String::from("#!/usr/sbin/nft -f\nflush ruleset\n\ntable inet kinveil {\n");
    out.push_str("    chain input {\n");
    out.push_str("        type filter hook input priority filter; policy drop;\n");
    out.push_str("        iifname \"lo\" accept\n");
    out.push_str(
        "        ct state vmap { established : accept, related : accept, invalid : drop }\n",
    );
    out.push_str("        ip protocol icmp accept\n");
    out.push_str("        meta l4proto ipv6-icmp accept\n");
    let _ = writeln!(
        out,
        "        tcp dport {} accept",
        server.admin_ssh.port.get()
    );

    if server.enabled {
        if eff.has_vless {
            let _ = writeln!(out, "        tcp dport {} accept", eff.vless_port);
        }
        if eff.has_hysteria2 {
            let _ = writeln!(out, "        udp dport {} accept", eff.hysteria2_port);
        }
        if eff.has_amneziawg {
            let _ = writeln!(out, "        udp dport {} accept", eff.amneziawg_port);
        }
        if eff.is_subscription {
            out.push_str("        tcp dport { 80, 443 } accept\n");
        }
        if eff.has_ssh_forwarding {
            let _ = writeln!(out, "        tcp dport {} accept", eff.ssh_forwarding_port);
        }
    }
    out.push_str("    }\n");

    if let Some(sets_block) = blocked_sets_block {
        out.push_str(sets_block);
    }

    if server.enabled && eff.has_amneziawg {
        let awg_net = state.settings.validated_awg_subnet()?;
        out.push_str("    chain forward {\n");
        out.push_str("        type filter hook forward priority filter; policy drop;\n");
        out.push_str(
            "        ct state vmap { established : accept, related : accept, invalid : drop }\n",
        );
        out.push_str(
            "        iifname \"kv0\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n",
        );
        out.push_str(
            "        oifname \"kv0\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n",
        );
        out.push_str("        iifname \"kv0\" oifname \"kv0\" reject\n");
        out.push_str("        iifname \"kv0\" meta nfproto ipv6 reject\n");
        out.push_str("        iifname \"kv0\" ip daddr @egress_blocked_v4 reject\n");
        out.push_str("        iifname \"kv0\" accept\n");
        out.push_str("    }\n");

        out.push_str("    chain postrouting {\n");
        out.push_str("        type nat hook postrouting priority srcnat; policy accept;\n");
        let _ = writeln!(
            out,
            "        iifname \"kv0\" oifname != \"kv0\" ip saddr {awg_net} masquerade"
        );
        out.push_str("    }\n");
    }

    if let Some(tail) = egress_tail {
        out.push_str(tail);
    }

    if let Some(traffic) = traffic_tail {
        out.push_str(traffic);
    }

    out.push_str("}\n");
    Ok(out)
}

/// Render a standalone `/etc/nftables.conf` with explicit Xray/vpnssh UIDs, resolvers, and
/// resolved firewall sets (used for local verification and unit testing).
pub fn render_nftables(
    state: &State,
    server: &Server,
    xray_uid: Option<u32>,
    ssh_uids: &[u32],
    dns_resolvers: &[IpAddr],
    lists: &ResolvedFirewallLists,
) -> Result<String> {
    let eff = server.effective_config(&state.settings, state.is_subscription_server(&server.id));
    let blocked_sets = if server.enabled && eff.has_any_vpn_protocol {
        Some(render_nft_blocked_sets(&state.settings.firewall, lists)?)
    } else {
        None
    };
    let eff_xray_uid = if server.enabled && eff.has_xray {
        xray_uid
    } else {
        None
    };
    let eff_ssh_uids: &[u32] = if server.enabled && eff.has_ssh_forwarding {
        ssh_uids
    } else {
        &[]
    };
    let co_located_sub_ips = if eff.is_subscription {
        Some((server.public_ipv4, server.public_ipv6))
    } else {
        None
    };
    let tail = if eff_xray_uid.is_some() || !eff_ssh_uids.is_empty() {
        Some(render_nft_egress_fragment(
            eff_xray_uid,
            co_located_sub_ips,
            eff_ssh_uids,
            dns_resolvers,
        ))
    } else {
        None
    };
    let traffic_tail = if server.enabled && eff.has_traffic {
        let awg_users = if eff.has_amneziawg {
            collect_awg_traffic_users(state)?
        } else {
            Vec::new()
        };
        let ssh_users = if eff.has_ssh_forwarding && !eff_ssh_uids.is_empty() {
            state
                .enabled_users_by_uid()
                .into_iter()
                .zip(eff_ssh_uids.iter().copied())
                .map(|((_, u), skuid)| (u.uid, skuid))
                .collect()
        } else {
            Vec::new()
        };
        Some(render_nft_traffic_fragment(&awg_users, &ssh_users))
    } else {
        None
    };
    render_nftables_inner(
        state,
        server,
        &eff,
        blocked_sets.as_deref(),
        tail.as_deref(),
        traffic_tail.as_deref(),
    )
}

/// Render `/etc/nftables.conf` for target Debian hosts where `/etc/kinveil/nft-blocked.nft`,
/// `/etc/kinveil/nft-egress.nft`, and optional `/etc/kinveil/nft-traffic.nft` are included.
pub fn render_nftables_for_host(state: &State, server: &Server) -> Result<String> {
    let eff = server.effective_config(&state.settings, state.is_subscription_server(&server.id));
    let blocked_sets = (server.enabled && eff.has_any_vpn_protocol)
        .then_some("    include \"/etc/kinveil/nft-blocked.nft\"\n");
    let need_egress = server.enabled && (eff.has_xray || eff.has_ssh_forwarding);
    let tail = need_egress.then_some("    include \"/etc/kinveil/nft-egress.nft\"\n");
    let traffic_tail = (server.enabled && eff.has_traffic)
        .then_some("    include \"/etc/kinveil/nft-traffic.nft\"\n");
    render_nftables_inner(state, server, &eff, blocked_sets, tail, traffic_tail)
}

pub fn render_firewall_update_urls(fw: &FirewallSettings) -> Result<String> {
    let mut urls = Vec::new();
    let mut seen_countries = Vec::new();
    for raw_cc in &fw.block_countries {
        let cc = normalize_country_code(raw_cc, "firewall.block_countries")?;
        if !seen_countries.contains(&cc) {
            seen_countries.push(cc.clone());
            urls.push(fw.auto_update.ipv4_country_url.replace("{cc}", &cc));
            urls.push(fw.auto_update.ipv6_country_url.replace("{cc}", &cc));
        }
    }
    for raw_url in &fw.block_ip_lists {
        push_unique(&mut urls, raw_url.trim().to_owned());
    }
    let mut out = urls.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

pub fn render_firewall_update_service() -> String {
    r#"[Unit]
Description=Kinveil firewall blocklist update
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/kinveil/firewall/update-firewall.sh
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/kinveil
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
"#
    .to_owned()
}

pub fn render_firewall_update_timer(interval_hours: u32) -> String {
    format!(
        r#"[Unit]
Description=Periodic Kinveil firewall blocklist refresh

[Timer]
OnActiveSec={interval_hours}h
OnUnitActiveSec={interval_hours}h
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
"#
    )
}
