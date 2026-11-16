use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;

use crate::render::{
    ALWAYS_BLOCKED_IPV4_CIDRS, ALWAYS_BLOCKED_IPV6_CIDRS, PRIVATE_IPV4_CIDRS, PRIVATE_IPV6_CIDRS,
};
use crate::state::{Server, State};

pub fn render_sysctl(state: &State, server: &Server) -> String {
    let s = &state.settings.sysctl;
    let ip_forward = u8::from(server.enabled && server.has_amneziawg(&state.settings));
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

pub fn egress_blocked_ipv4_list(block_private_networks: bool) -> String {
    if block_private_networks {
        PRIVATE_IPV4_CIDRS.join(", ")
    } else {
        ALWAYS_BLOCKED_IPV4_CIDRS.join(", ")
    }
}

pub fn egress_blocked_ipv6_list(block_private_networks: bool) -> String {
    let base = if block_private_networks {
        PRIVATE_IPV6_CIDRS
    } else {
        ALWAYS_BLOCKED_IPV6_CIDRS
    };
    let mut cidrs = Vec::with_capacity(base.len() + 1);
    cidrs.extend_from_slice(&base[..2]);
    cidrs.push("::ffff:0:0/96");
    cidrs.extend_from_slice(&base[2..]);
    cidrs.join(", ")
}

pub fn render_nft_egress_fragment(
    xray_uid: Option<u32>,
    co_located_sub_ips: Option<(Ipv4Addr, Option<Ipv6Addr>)>,
    ssh_uids: &[u32],
    dns_resolvers: &[IpAddr],
    block_private_networks: bool,
) -> String {
    let mut sorted_ssh_uids = ssh_uids.to_vec();
    sorted_ssh_uids.sort_unstable();
    sorted_ssh_uids.dedup();

    if xray_uid.is_none() && sorted_ssh_uids.is_empty() {
        return "    # No active Xray or vpnssh egress UIDs\n".to_owned();
    }

    let ipv4_list = egress_blocked_ipv4_list(block_private_networks);
    let ipv6_list = egress_blocked_ipv6_list(block_private_networks);

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
    // Permit reply packets for already-established inbound VPN/proxy flows owned by Xray.
    out.push_str("        ct direction reply accept\n");

    if let Some(xuid) = xray_uid {
        for resolver in dns_resolvers {
            let family = if resolver.is_ipv4() { "ip" } else { "ip6" };
            let _ = writeln!(
                out,
                "        meta skuid {xuid} {family} daddr {resolver} meta l4proto {{ tcp, udp }} th dport 53 accept"
            );
        }
        if let Some((ip4, ip6_opt)) = co_located_sub_ips {
            let _ = writeln!(
                out,
                "        meta skuid {xuid} ip daddr {ip4} tcp dport {{ 80, 443 }} accept"
            );
            if let Some(ip6) = ip6_opt {
                let _ = writeln!(
                    out,
                    "        meta skuid {xuid} ip6 daddr {ip6} tcp dport {{ 80, 443 }} accept"
                );
            }
        }
        let _ = writeln!(out, "        meta skuid {xuid} fib daddr type local reject");
        let _ = writeln!(
            out,
            "        meta skuid {xuid} ip daddr {{ {ipv4_list} }} reject"
        );
        let _ = writeln!(
            out,
            "        meta skuid {xuid} ip6 daddr {{ {ipv6_list} }} reject"
        );
    }

    if !sorted_ssh_uids.is_empty() {
        for resolver in dns_resolvers {
            let family = if resolver.is_ipv4() { "ip" } else { "ip6" };
            let _ = writeln!(
                out,
                "        meta skuid @vpnssh_users {family} daddr {resolver} meta l4proto {{ tcp, udp }} th dport 53 accept"
            );
        }
        out.push_str("        meta skuid @vpnssh_users fib daddr type local reject\n");
        let _ = writeln!(
            out,
            "        meta skuid @vpnssh_users ip daddr {{ {ipv4_list} }} reject"
        );
        let _ = writeln!(
            out,
            "        meta skuid @vpnssh_users ip6 daddr {{ {ipv6_list} }} reject"
        );
    }

    out.push_str("    }\n");
    out
}

fn render_nftables_inner(
    state: &State,
    server: &Server,
    egress_tail: Option<&str>,
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
        if server.has_vless(&state.settings) {
            let _ = writeln!(
                out,
                "        tcp dport {} accept",
                server.effective_vless_port(&state.settings)
            );
        }
        if server.has_hysteria2(&state.settings) {
            let _ = writeln!(
                out,
                "        udp dport {} accept",
                server.effective_hysteria2_port(&state.settings)
            );
        }
        if server.has_amneziawg(&state.settings) {
            let _ = writeln!(
                out,
                "        udp dport {} accept",
                server.effective_amneziawg_port(&state.settings)
            );
        }
        if state.is_subscription_server(&server.id) {
            out.push_str("        tcp dport { 80, 443 } accept\n");
        }
        if server.has_ssh_forwarding(&state.settings) {
            let _ = writeln!(
                out,
                "        tcp dport {} accept",
                server.effective_ssh_port(&state.settings)
            );
        }
    }
    out.push_str("    }\n");

    if server.enabled && server.has_amneziawg(&state.settings) {
        let awg_net = state.settings.validated_awg_subnet()?;
        let awg_blocked_ipv4 =
            egress_blocked_ipv4_list(state.settings.firewall.block_private_networks);
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
        let _ = writeln!(
            out,
            "        iifname \"kv0\" ip daddr {{ {awg_blocked_ipv4} }} reject"
        );
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

    out.push_str("}\n");
    Ok(out)
}

/// Render a standalone `/etc/nftables.conf` with explicit Xray/vpnssh UIDs and resolvers
/// (used for local verification and unit testing).
pub fn render_nftables(
    state: &State,
    server: &Server,
    xray_uid: Option<u32>,
    ssh_uids: &[u32],
    dns_resolvers: &[IpAddr],
) -> Result<String> {
    let eff_xray_uid = if server.enabled && server.has_xray(&state.settings) {
        xray_uid
    } else {
        None
    };
    let eff_ssh_uids: &[u32] = if server.enabled && server.has_ssh_forwarding(&state.settings) {
        ssh_uids
    } else {
        &[]
    };
    let co_located_sub_ips = if state.is_subscription_server(&server.id) {
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
            state.settings.firewall.block_private_networks,
        ))
    } else {
        None
    };
    render_nftables_inner(state, server, tail.as_deref())
}

/// Render `/etc/nftables.conf` for target Debian hosts where `/etc/kinveil/nft-egress.nft`
/// is generated after provisioning `kinveil` + `vpnssh*` Linux UIDs and reading `/etc/resolv.conf`.
pub fn render_nftables_for_host(state: &State, server: &Server) -> Result<String> {
    let need_egress = server.enabled
        && (server.has_xray(&state.settings) || server.has_ssh_forwarding(&state.settings));
    let tail = if need_egress {
        Some("    include \"/etc/kinveil/nft-egress.nft\"\n")
    } else {
        None
    };
    render_nftables_inner(state, server, tail)
}
