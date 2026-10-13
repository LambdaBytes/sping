//! Network context detection. Best-effort: undetected values fall back to
//! `"unknown"`, `0.0.0.0`, or `None`.

#[cfg(any(target_os = "windows", test))]
mod adapters_windows;
pub mod classify;
pub mod dns;
pub mod gateway;
pub mod iface;
pub mod route;

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

use crate::context::classify::TargetClass;

/// Network context snapshot, re-detected periodically for hot interface/gateway changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkContext {
    /// `"unknown"` if detection failed.
    pub interface: String,
    /// Source IP for the target; `0.0.0.0` if detection failed.
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    pub local_ip: IpAddr,
    /// `0` when unknown.
    pub prefix_len: u8,
    /// `None` when no default route was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    pub target_class: TargetClass,
}

/// Detect full network context for a target address.
pub fn detect(target: dns::ResolvedAddr) -> NetworkContext {
    context_for(
        target,
        iface::detect_local_ip(target),
        gateway::detect(),
        iface::interface_for_ip,
    )
}

/// Detect the network context of each target, in order: every target has
/// its own source address, interface and classification. The default
/// gateway is detected once for all of them and the interface once per
/// distinct source address — on macOS and Windows each of those runs an
/// external tool or a system call.
pub fn detect_all(targets: &[dns::ResolvedAddr]) -> Vec<NetworkContext> {
    let gw = gateway::detect();
    let mut interfaces = std::collections::HashMap::new();
    targets
        .iter()
        .map(|&target| {
            context_for(
                target,
                iface::detect_local_ip(target),
                gw,
                |local_ip, scope_id| {
                    interfaces
                        .entry((local_ip, scope_id))
                        .or_insert_with(|| iface::interface_for_ip(local_ip, scope_id))
                        .clone()
                },
            )
        })
        .collect()
}

/// The context of one target, given its source address (`None`: the system
/// has none for it, e.g. no route of its family), the default gateway and a
/// way to find the interface that holds a source address (in a zone).
fn context_for(
    target: dns::ResolvedAddr,
    source: Option<IpAddr>,
    gw: Option<Ipv4Addr>,
    mut interface_for: impl FnMut(IpAddr, u32) -> Option<iface::InterfaceInfo>,
) -> NetworkContext {
    let local_ip = source.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    // Without a source address there is no interface to look up: asking for
    // 0.0.0.0 would find whichever interface a route happens to cover it
    // with (the default route's, or a VPN's 0.0.0.0/1), and its prefix.
    let iface_info = source.and_then(|ip| interface_for(ip, target.scope_id));
    let interface = iface_info
        .as_ref()
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "unknown".into());
    let prefix_len = iface_info.as_ref().map(|i| i.prefix_len).unwrap_or(0);

    let target_class = classify::classify(target.ip, local_ip, prefix_len, gw);

    NetworkContext {
        interface,
        local_ip,
        prefix_len,
        gateway: gw.map(|ip| ip.to_string()),
        target_class,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> dns::ResolvedAddr {
        dns::ResolvedAddr::unscoped(s.parse().unwrap())
    }

    fn info(name: &str, ip: &str, prefix_len: u8) -> iface::InterfaceInfo {
        iface::InterfaceInfo {
            name: name.into(),
            ip: ip.parse().unwrap(),
            prefix_len,
        }
    }

    /// The interface found for a target's source address — and nothing
    /// carried over from another target — decides its context. The source
    /// address itself is whatever this host gives (`0.0.0.0` where sockets
    /// are denied): the test holds either way.
    #[test]
    fn context_follows_the_targets_own_interface() {
        let target = addr("127.0.0.1");
        let local_ip = iface::detect_local_ip(target).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let gw = Some(Ipv4Addr::new(192, 168, 1, 1));

        let ctx = context_for(target, Some(local_ip), gw, |ip, scope_id| {
            assert_eq!((ip, scope_id), (local_ip, 0));
            Some(info("lo", "127.0.0.1", 8))
        });
        assert_eq!((ctx.interface.as_str(), ctx.prefix_len), ("lo", 8));
        assert_eq!(ctx.local_ip, local_ip);
        assert_eq!(ctx.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(
            ctx.target_class,
            classify::classify(target.ip, local_ip, 8, gw)
        );

        // No interface found: the documented fallbacks.
        let ctx = context_for(target, Some(local_ip), None, |_, _| None);
        assert_eq!((ctx.interface.as_str(), ctx.prefix_len), ("unknown", 0));
        assert_eq!(ctx.gateway, None);
        assert_eq!(ctx.target_class, TargetClass::Loopback);
    }

    /// No source address for the target: no interface is looked up, so no
    /// route that happens to cover 0.0.0.0 (here a VPN's 0.0.0.0/1) lends
    /// its interface and prefix, and the target is not put in that subnet.
    #[test]
    fn no_source_looks_up_no_interface() {
        let ctx = context_for(addr("8.8.8.8"), None, None, |_, _| {
            Some(info("tun0", "0.0.0.0", 1))
        });
        assert_eq!((ctx.interface.as_str(), ctx.prefix_len), ("unknown", 0));
        assert_eq!(ctx.local_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(ctx.target_class, TargetClass::PublicNetwork);

        let ctx = context_for(addr("2001:db8::1"), None, None, |_, _| {
            Some(info("eth0", "0.0.0.0", 0))
        });
        assert_eq!(ctx.interface, "unknown");
        assert_eq!(ctx.local_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    /// `detect_all` is `detect` for each target, in order.
    #[test]
    fn detect_all_matches_detect_per_target() {
        let targets = [addr("127.0.0.1"), addr("::1"), addr("127.0.0.1")];
        let all = detect_all(&targets);
        assert_eq!(all.len(), targets.len());
        for (target, ctx) in targets.iter().zip(&all) {
            assert_eq!(ctx, &detect(*target));
        }
        assert!(detect_all(&[]).is_empty());
    }
}
