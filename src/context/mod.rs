//! Network context detection. Best-effort: undetected values fall back to
//! `"unknown"`, `0.0.0.0`, or `None`.

#[cfg(any(target_os = "windows", test))]
mod adapters_windows;
pub mod classify;
pub mod dns;
pub mod gateway;
pub mod iface;
pub mod route;

use std::fmt;
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

/// A context and the target it was detected for: a detection for the
/// address probed before a DNS failover may still arrive after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub target: dns::ResolvedAddr,
    pub context: NetworkContext,
}

/// One field of the context that changed (added in 1.7.0), named and
/// valued in JSON as in `net_ctx`; `None` is unknown (no interface or
/// source, no prefix, no default gateway).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextChange {
    pub what: ContextField,
    pub from: Option<ContextValue>,
    pub to: Option<ContextValue>,
}

/// What sping observes of the context: the `net_ctx` fields. Not the next
/// hop of routes other than the default one, nor IPv6's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextField {
    Interface,
    LocalIp,
    PrefixLen,
    Gateway,
    TargetClass,
}

/// A field's value: serialized as in `net_ctx`, shown as the views show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ContextValue {
    Text(String),
    Prefix(u8),
    Class(TargetClass),
}

impl fmt::Display for ContextValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextValue::Text(text) => f.write_str(text),
            ContextValue::Prefix(len) => write!(f, "{len}"),
            ContextValue::Class(class) => write!(f, "{class}"),
        }
    }
}

/// What differs between two contexts of one target, field by field, in the
/// order above; empty when they are the same.
pub fn changes(old: &NetworkContext, new: &NetworkContext) -> Vec<ContextChange> {
    let fields = |ctx: &NetworkContext| {
        [
            (
                ContextField::Interface,
                (ctx.interface != "unknown").then(|| ContextValue::Text(ctx.interface.clone())),
            ),
            (
                ContextField::LocalIp,
                (!ctx.local_ip.is_unspecified())
                    .then(|| ContextValue::Text(ctx.local_ip.to_string())),
            ),
            (
                ContextField::PrefixLen,
                (ctx.prefix_len != 0).then_some(ContextValue::Prefix(ctx.prefix_len)),
            ),
            (
                ContextField::Gateway,
                ctx.gateway.clone().map(ContextValue::Text),
            ),
            (
                ContextField::TargetClass,
                Some(ContextValue::Class(ctx.target_class)),
            ),
        ]
    };
    fields(old)
        .into_iter()
        .zip(fields(new))
        .filter(|((_, from), (_, to))| from != to)
        .map(|((what, from), (_, to))| ContextChange { what, from, to })
        .collect()
}

/// Detect full network context for a target address.
pub fn detect(target: dns::ResolvedAddr) -> NetworkContext {
    context_for(
        target,
        source_for(target),
        gateway::detect(),
        iface::interface_for_ip,
    )
}

/// The source address the system would send from to `target`: none when it
/// has no route or no address of the family, or offers only `::1`/`0.0.0.0`
/// through an interface with no address (which would otherwise show the
/// loopback interface, or whichever interface a route covering `0.0.0.0`
/// names), and none when it cannot tell.
fn source_for(target: dns::ResolvedAddr) -> Option<IpAddr> {
    iface::usable_source(target).ok().flatten()
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
            context_for(target, source_for(target), gw, |local_ip, scope_id| {
                interfaces
                    .entry((local_ip, scope_id))
                    .or_insert_with(|| iface::interface_for_ip(local_ip, scope_id))
                    .clone()
            })
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

    /// Both families of a name and the source of each, against the real
    /// resolver and kernel: run by `scripts/family-bench.sh`, one network
    /// namespace per case, with a hosts file of its own (`*.test` names) and
    /// no DNS server.
    #[tokio::test]
    #[ignore = "run by scripts/family-bench.sh inside its namespaces"]
    async fn family_bench() {
        let case = std::env::var("SPING_FAMILY_CASE").expect("SPING_FAMILY_CASE is not set");
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let source = |s: &str| iface::usable_source(addr(s));
        match case.as_str() {
            // Only `lo`: the lookup still gives both families (no
            // address-based filtering); no source but the loopback ones.
            "bare" => {
                let both = dns::resolve_both("both.test").await.unwrap();
                assert_eq!(both.v4, Some(addr("192.0.2.20")));
                assert_eq!(both.v6, Some(addr("2001:db8::20")));
                assert!(both.time.is_some());
                let v4 = dns::resolve_both("v4only.test").await.unwrap();
                assert_eq!((v4.v4, v4.v6), (Some(addr("192.0.2.10")), None));
                let v6 = dns::resolve_both("v6only.test").await.unwrap();
                assert_eq!((v6.v4, v6.v6), (None, Some(addr("2001:db8::10"))));

                // `resolve` keeps its choice: the IPv4 address although the
                // answer lists the IPv6 one first.
                use dns::Family;
                for (family, expected) in [
                    (None, "192.0.2.20"),
                    (Some(Family::V4), "192.0.2.20"),
                    (Some(Family::V6), "2001:db8::20"),
                ] {
                    let (got, time) = dns::resolve("both.test", family).await.unwrap();
                    assert_eq!(got, addr(expected), "{family:?}");
                    assert!(time.is_some());
                }

                // Failures read as `resolve`'s.
                for target in ["nothere.test", "fe80::1%nosuchif0"] {
                    let both = dns::resolve_both(target).await.unwrap_err().to_string();
                    let one = dns::resolve(target, None).await.unwrap_err().to_string();
                    assert_eq!(both, one);
                }
                assert_eq!(
                    dns::resolve_both("fe80::1%nosuchif0")
                        .await
                        .unwrap_err()
                        .to_string(),
                    "unknown zone in 'fe80::1%nosuchif0' (use an interface name or index)"
                );

                assert_eq!(source("2001:db8::1").unwrap(), None);
                assert_eq!(source("198.51.100.1").unwrap(), None);
                assert_eq!(source("::1").unwrap(), Some(ip("::1")));
                assert_eq!(source("127.0.0.1").unwrap(), Some(ip("127.0.0.1")));

                // Re-resolution with the real resolver: the answer, not its
                // order, moves the probe.
                use dns::Resolution;
                let both = addr("192.0.2.20");
                assert_eq!(
                    dns::re_resolve("both.test", both).await,
                    Resolution::Unchanged
                );
                // The record changes between two lookups.
                let hosts = std::fs::read_to_string("/etc/hosts").unwrap();
                let moved = hosts.replace("192.0.2.20 both.test", "192.0.2.21 both.test");
                assert_ne!(moved, hosts);
                std::fs::write("/etc/hosts", &moved).unwrap();
                let changed = dns::re_resolve("both.test", both).await;
                std::fs::write("/etc/hosts", &hosts).unwrap();
                assert_eq!(changed, Resolution::Changed(addr("192.0.2.21")));
                assert_eq!(
                    dns::re_resolve("v6only.test", addr("192.0.2.10")).await,
                    Resolution::NoAddressOfFamily
                );
                assert_eq!(
                    dns::re_resolve("nothere.test", both).await,
                    Resolution::Failed { timed_out: false }
                );
            }
            // Default routes through an interface with no address: the
            // kernel picks `::1` and `0.0.0.0`, which are no source.
            "no-address" => {
                assert_eq!(iface::detect_local_ip(addr("2001:db8::1")), Some(ip("::1")));
                assert_eq!(source("2001:db8::1").unwrap(), None);
                assert_eq!(
                    iface::detect_local_ip(addr("198.51.100.1")),
                    Some(ip("0.0.0.0"))
                );
                assert_eq!(source("198.51.100.1").unwrap(), None);

                // The context says there is no source: not `lo ::1/128`, nor
                // the interface a route covering 0.0.0.0 names.
                let targets = [addr("2001:db8::1"), addr("198.51.100.1")];
                for (target, ctx) in targets.iter().zip(detect_all(&targets)) {
                    for ctx in [detect(*target), ctx] {
                        assert_eq!(ctx.local_ip, ip("0.0.0.0"), "{target:?}");
                        assert_eq!((ctx.interface.as_str(), ctx.prefix_len), ("unknown", 0));
                    }
                }
            }
            // Only link-local IPv6 addresses and a default route through a
            // router: the link-local one is the source, as it is.
            "link-local-only" => {
                let v6 = source("2001:db8::1").unwrap();
                assert!(
                    matches!(v6, Some(IpAddr::V6(v6)) if v6.is_unicast_link_local()),
                    "{v6:?}"
                );
                assert_eq!(iface::detect_local_ip(addr("2001:db8::1")), v6);
                assert_eq!(source("198.51.100.1").unwrap(), None);
            }
            // A link-local source reaches the destinations on its link.
            "on-link" => {
                assert_eq!(source("10.9.0.1").unwrap(), Some(ip("169.254.1.2")));
                let v6 = source("fd00:9::1").unwrap();
                assert!(
                    matches!(v6, Some(IpAddr::V6(v6)) if v6.is_unicast_link_local()),
                    "{v6:?}"
                );
            }
            "global" => {
                assert_eq!(source("198.51.100.1").unwrap(), Some(ip("10.0.5.2")));
                assert_eq!(source("2001:db8::1").unwrap(), Some(ip("2001:db8:5::2")));
                // A usable source: the context of always.
                for (target, local, prefix) in [
                    ("198.51.100.1", "10.0.5.2", 24),
                    ("2001:db8::1", "2001:db8:5::2", 64),
                ] {
                    let ctx = detect(addr(target));
                    assert_eq!(ctx.local_ip, ip(local));
                    assert_eq!((ctx.interface.as_str(), ctx.prefix_len), ("v0", prefix));
                }
            }
            // `unreachable`: no route; `prohibit` and `blackhole`: unknown.
            "routes" => {
                for (unreachable, prohibit, blackhole) in [
                    ("198.51.100.1", "198.51.100.65", "198.51.100.129"),
                    ("2001:db8:1::1", "2001:db8:2::1", "2001:db8:3::1"),
                ] {
                    assert_eq!(source(unreachable).unwrap(), None);
                    assert!(source(prohibit).is_err(), "{prohibit}");
                    assert!(source(blackhole).is_err(), "{blackhole}");
                }
            }
            "no-ipv6" => {
                assert_eq!(source("2001:db8::1").unwrap(), None);
                assert_eq!(source("::1").unwrap(), None);
            }
            // A name server that never answers (the bench sends its queries
            // to a neighbour that drops them): the lookup times out at 5 s,
            // while the system's resolver would wait 10.
            "dns-timeout" => {
                let start = std::time::Instant::now();
                let found = dns::re_resolve("slow.test", addr("192.0.2.20")).await;
                let took = start.elapsed();
                assert_eq!(found, dns::Resolution::Failed { timed_out: true });
                assert!(
                    (std::time::Duration::from_secs(5)..std::time::Duration::from_secs(7))
                        .contains(&took),
                    "{took:?}"
                );
            }
            other => panic!("unknown case {other}"),
        }
    }

    /// What differs between two contexts, field by field; unknown values
    /// are `None`.
    #[test]
    fn changes_between_two_contexts() {
        use ContextValue::{Class, Prefix, Text};
        let base = NetworkContext {
            interface: "eth0".into(),
            local_ip: "192.168.1.100".parse().unwrap(),
            prefix_len: 24,
            gateway: Some("192.168.1.1".into()),
            target_class: TargetClass::PublicNetwork,
        };
        assert!(changes(&base, &base.clone()).is_empty());
        let text = |s: &str| Some(Text(s.into()));
        let change = |what, from, to| ContextChange { what, from, to };

        let wifi = NetworkContext {
            interface: "wlan0".into(),
            local_ip: "10.0.0.7".parse().unwrap(),
            prefix_len: 16,
            gateway: Some("10.0.0.1".into()),
            ..base.clone()
        };
        assert_eq!(
            changes(&base, &wifi),
            [
                change(ContextField::Interface, text("eth0"), text("wlan0")),
                change(
                    ContextField::LocalIp,
                    text("192.168.1.100"),
                    text("10.0.0.7")
                ),
                change(ContextField::PrefixLen, Some(Prefix(24)), Some(Prefix(16))),
                change(ContextField::Gateway, text("192.168.1.1"), text("10.0.0.1")),
            ]
        );

        // The source lost: known → unknown, and back.
        let lost = NetworkContext {
            interface: "unknown".into(),
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_len: 0,
            gateway: None,
            target_class: TargetClass::RoutedInternal,
        };
        assert_eq!(
            changes(&base, &lost),
            [
                change(ContextField::Interface, text("eth0"), None),
                change(ContextField::LocalIp, text("192.168.1.100"), None),
                change(ContextField::PrefixLen, Some(Prefix(24)), None),
                change(ContextField::Gateway, text("192.168.1.1"), None),
                change(
                    ContextField::TargetClass,
                    Some(Class(TargetClass::PublicNetwork)),
                    Some(Class(TargetClass::RoutedInternal))
                ),
            ]
        );
        assert_eq!(changes(&lost, &base).len(), 5);

        let lan = NetworkContext {
            target_class: TargetClass::SameLan,
            ..base.clone()
        };
        assert_eq!(
            changes(&base, &lan),
            [change(
                ContextField::TargetClass,
                Some(Class(TargetClass::PublicNetwork)),
                Some(Class(TargetClass::SameLan))
            )]
        );
    }
}
