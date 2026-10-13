//! Target classification relative to local network topology.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TargetClass {
    /// Inside the local subnet (`local_ip`/`prefix_len`).
    SameLan,
    /// Private (RFC 1918, IPv6 unique local) address outside the local subnet.
    RoutedInternal,
    PublicNetwork,
    DefaultGateway,
    /// `169.254.0.0/16` or IPv6 `fe80::/10`.
    LinkLocal,
    /// `127.0.0.0/8` or `::1`. JSON contract v1 lists five `target_class`
    /// values and loopback targets reported `"RoutedInternal"` (or, wrongly,
    /// `"SameLan"` when a route such as a VPN's `0.0.0.0/1` covered them):
    /// it stays `"RoutedInternal"`, only the text shown is new.
    #[serde(rename = "RoutedInternal")]
    Loopback,
}

impl std::fmt::Display for TargetClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetClass::SameLan => write!(f, "same LAN"),
            TargetClass::RoutedInternal => write!(f, "routed internal"),
            TargetClass::PublicNetwork => write!(f, "public"),
            TargetClass::DefaultGateway => write!(f, "default gateway"),
            TargetClass::LinkLocal => write!(f, "link-local"),
            TargetClass::Loopback => write!(f, "loopback"),
        }
    }
}

/// Classify a target IP. Default-gateway match takes precedence over subnet
/// matching; a loopback target is loopback whatever the local subnet (a route
/// such as a VPN's `0.0.0.0/1` would otherwise put 127.0.0.1 in it).
pub fn classify(
    target: IpAddr,
    local_ip: IpAddr,
    prefix_len: u8,
    gateway: Option<Ipv4Addr>,
) -> TargetClass {
    if let (IpAddr::V4(t), Some(gw)) = (target, gateway)
        && t == gw
    {
        return TargetClass::DefaultGateway;
    }

    if target.is_loopback() {
        return TargetClass::Loopback;
    }

    match target {
        IpAddr::V4(t) => classify_v4(t, local_ip, prefix_len),
        IpAddr::V6(t) => classify_v6(t, local_ip, prefix_len),
    }
}

fn classify_v6(target: Ipv6Addr, local_ip: IpAddr, prefix_len: u8) -> TargetClass {
    // Link-local: fe80::/10
    if (target.segments()[0] & 0xffc0) == 0xfe80 {
        return TargetClass::LinkLocal;
    }

    if let IpAddr::V6(local) = local_ip
        && prefix_len > 0
        && prefix_len <= 128
    {
        let mask = if prefix_len == 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - prefix_len)
        };
        if (target.to_bits() & mask) == (local.to_bits() & mask) {
            return TargetClass::SameLan;
        }
    }

    // Unique local: fc00::/7
    if (target.segments()[0] & 0xfe00) == 0xfc00 {
        return TargetClass::RoutedInternal;
    }

    TargetClass::PublicNetwork
}

fn classify_v4(target: Ipv4Addr, local_ip: IpAddr, prefix_len: u8) -> TargetClass {
    let t = target.octets();

    // Link-local: 169.254.0.0/16
    if t[0] == 169 && t[1] == 254 {
        return TargetClass::LinkLocal;
    }

    if let IpAddr::V4(local) = local_ip
        && prefix_len > 0
        && prefix_len <= 32
    {
        let mask = if prefix_len == 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let t_bits = u32::from_be_bytes(target.octets());
        let l_bits = u32::from_be_bytes(local.octets());
        if (t_bits & mask) == (l_bits & mask) {
            return TargetClass::SameLan;
        }
    }

    // Private ranges: 10/8, 172.16/12, 192.168/16
    if is_private(target) {
        return TargetClass::RoutedInternal;
    }

    TargetClass::PublicNetwork
}

fn is_private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (o[1] & 0xf0) == 16) || (o[0] == 192 && o[1] == 168)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_classify_same_lan() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(classify(target, local, 24, None), TargetClass::SameLan);
    }

    #[test]
    fn test_classify_public() {
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(
            classify(target, local, 24, None),
            TargetClass::PublicNetwork
        );
    }

    #[test]
    fn test_classify_gateway() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let gw = Some(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(classify(target, local, 24, gw), TargetClass::DefaultGateway);
    }

    #[test]
    fn test_classify_routed_internal() {
        let target = IpAddr::V4(Ipv4Addr::new(10, 20, 8, 15));
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(
            classify(target, local, 24, None),
            TargetClass::RoutedInternal
        );
    }

    /// Loopback whatever subnet the source seems to be in: unknown (0), a
    /// VPN's `0.0.0.0/1` (1) or the loopback interface's own /8.
    #[test]
    fn test_classify_loopback() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for prefix_len in [0, 1, 8] {
            assert_eq!(
                classify(ip("127.0.0.1"), ip("127.0.0.1"), prefix_len, None),
                TargetClass::Loopback
            );
        }
        assert_eq!(
            classify(ip("127.0.0.2"), ip("192.168.1.100"), 24, None),
            TargetClass::Loopback
        );
        assert_eq!(
            classify(ip("::1"), ip("::1"), 128, None),
            TargetClass::Loopback
        );
        // A private address is still routed internal.
        assert_eq!(
            classify(ip("10.0.0.1"), ip("192.168.1.100"), 24, None),
            TargetClass::RoutedInternal
        );
    }

    /// Shown as `loopback`; in JSON the value loopback targets always had.
    #[test]
    fn loopback_is_shown_but_keeps_its_json_value() {
        assert_eq!(TargetClass::Loopback.to_string(), "loopback");
        assert_eq!(
            serde_json::to_string(&TargetClass::Loopback).unwrap(),
            "\"RoutedInternal\""
        );
    }

    #[test]
    fn test_classify_link_local() {
        let target = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(classify(target, local, 24, None), TargetClass::LinkLocal);
    }

    #[test]
    fn test_classify_v6() {
        let v6 = |s: &str| s.parse::<IpAddr>().unwrap();
        let local = v6("2001:db8:1::10");
        assert_eq!(
            classify(v6("fe80::1"), local, 64, None),
            TargetClass::LinkLocal
        );
        assert_eq!(
            classify(v6("2001:db8:1::5"), local, 64, None),
            TargetClass::SameLan
        );
        assert_eq!(
            classify(v6("2001:db8:2::5"), local, 64, None),
            TargetClass::PublicNetwork
        );
        // Unique local outside the prefix; the same prefix wins over the range.
        assert_eq!(
            classify(v6("fd00::1"), local, 64, None),
            TargetClass::RoutedInternal
        );
        assert_eq!(
            classify(v6("fd12:3456::1"), v6("fd12:3456::2"), 64, None),
            TargetClass::SameLan
        );
        // Unknown prefix: never "same LAN".
        assert_eq!(
            classify(v6("2001:db8:1::5"), local, 0, None),
            TargetClass::PublicNetwork
        );
        // An IPv4 local address says nothing about an IPv6 target.
        let local_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(
            classify(v6("fd00::1"), local_v4, 24, None),
            TargetClass::RoutedInternal
        );
    }
}
