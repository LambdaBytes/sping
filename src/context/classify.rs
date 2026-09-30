//! Target classification relative to local network topology.

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TargetClass {
    /// Inside the local subnet (`local_ip`/`prefix_len`).
    SameLan,
    /// Private (RFC 1918) or loopback address outside the local subnet.
    RoutedInternal,
    PublicNetwork,
    DefaultGateway,
    /// `169.254.0.0/16` or IPv6 `fe80::/10`.
    LinkLocal,
}

impl std::fmt::Display for TargetClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetClass::SameLan => write!(f, "same LAN"),
            TargetClass::RoutedInternal => write!(f, "routed internal"),
            TargetClass::PublicNetwork => write!(f, "public"),
            TargetClass::DefaultGateway => write!(f, "default gateway"),
            TargetClass::LinkLocal => write!(f, "link-local"),
        }
    }
}

/// Classify a target IP. Default-gateway match takes precedence over subnet matching.
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

    match target {
        IpAddr::V4(t) => classify_v4(t, local_ip, prefix_len),
        IpAddr::V6(t) => {
            if (t.segments()[0] & 0xffc0) == 0xfe80 {
                TargetClass::LinkLocal
            } else {
                TargetClass::PublicNetwork
            }
        }
    }
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
    o[0] == 10
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 168)
        || o[0] == 127
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

    #[test]
    fn test_classify_link_local() {
        let target = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(classify(target, local, 24, None), TargetClass::LinkLocal);
    }
}
