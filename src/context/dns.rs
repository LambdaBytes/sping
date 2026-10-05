//! Hostname resolution with a hard 5s timeout. Prefers IPv4 unless restricted
//! via `-4`/`-6`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Address family restriction (-4 / -6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn matches(self, ip: IpAddr) -> bool {
        match self {
            Family::V4 => ip.is_ipv4(),
            Family::V6 => ip.is_ipv6(),
        }
    }
}

/// A resolved probe address. An IPv6 link-local address only identifies a
/// host together with its zone (`fe80::1%eth0`), so the zone index travels
/// with the address down to the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedAddr {
    pub ip: IpAddr,
    /// IPv6 zone index; `0` when the address has none (IPv4, global IPv6).
    pub scope_id: u32,
}

impl ResolvedAddr {
    /// An address without a zone.
    pub fn unscoped(ip: IpAddr) -> Self {
        Self { ip, scope_id: 0 }
    }

    /// Socket address for this endpoint; the zone is carried for IPv6.
    pub fn socket_addr(self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V6(ip) => {
                SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, self.scope_id))
            }
            ip => SocketAddr::new(ip, port),
        }
    }
}

impl From<SocketAddr> for ResolvedAddr {
    fn from(addr: SocketAddr) -> Self {
        let scope_id = match addr {
            SocketAddr::V6(v6) => v6.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        Self {
            ip: addr.ip(),
            scope_id,
        }
    }
}

/// Whether `target` is an address rather than a name: an IP, or an IPv6
/// address with a zone (`fe80::1%eth0`), which only the system resolver can
/// turn into a zone index.
pub fn is_literal(target: &str) -> bool {
    target.parse::<IpAddr>().is_ok()
        || target
            .split_once('%')
            .is_some_and(|(ip, zone)| !zone.is_empty() && ip.parse::<Ipv6Addr>().is_ok())
}

/// Whether the resolver dropped the zone of a link-local literal
/// (`fe80::1%en0`). macOS accepts a zone it cannot map (`%en0 `, with a
/// trailing space) and returns the address without one, which would only fail
/// at send time; a global address does not need its zone. A zone written as
/// `0` (or `000`) is the default zone (RFC 4007, 11.2), not a lost one; only
/// digits make an index, so `+0` is not one.
fn zone_lost(target: &str, addr: ResolvedAddr) -> bool {
    let IpAddr::V6(ip) = addr.ip else {
        return false;
    };
    let Some((_, zone)) = target.split_once('%') else {
        return false;
    };
    let default_zone = !zone.is_empty() && zone.bytes().all(|b| b == b'0');
    !default_zone && ip.is_unicast_link_local() && addr.scope_id == 0
}

/// Resolve a hostname to an address, with timing. A literal address returns
/// a `None` resolution time.
///
/// # Errors
///
/// Fails on family mismatch, timeout/lookup failure, or no matching address.
pub async fn resolve(
    target: &str,
    family: Option<Family>,
) -> Result<(ResolvedAddr, Option<Duration>)> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        if let Some(f) = family
            && !f.matches(ip)
        {
            bail!("'{target}' does not match the requested address family");
        }
        return Ok((ResolvedAddr::unscoped(ip), None));
    }

    let host = format!("{target}:0");
    let start = Instant::now();

    let addrs = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(&host))
        .await
        .map_err(|_| anyhow::anyhow!("DNS resolution for '{target}' timed out after 5s"))?
        .with_context(|| {
            if is_literal(target) {
                format!("unknown zone in '{target}' (use an interface name or index)")
            } else {
                format!("DNS resolution failed for '{target}'")
            }
        })?;

    let all: Vec<ResolvedAddr> = addrs.map(ResolvedAddr::from).collect();

    let chosen = match family {
        Some(f) => all.iter().copied().find(|a| f.matches(a.ip)),
        None => all
            .iter()
            .copied()
            .find(|a| a.ip.is_ipv4())
            .or_else(|| all.first().copied()),
    };

    let Some(addr) = chosen else {
        match family {
            Some(Family::V4) => bail!("no IPv4 address found for '{target}'"),
            Some(Family::V6) => bail!("no IPv6 address found for '{target}'"),
            None => bail!("no address found for '{target}'"),
        }
    };

    if zone_lost(target, addr) {
        bail!("unknown zone in '{target}' (use an interface name or index)");
    }

    // A zoned literal went through the resolver for its zone index only.
    let elapsed = (!is_literal(target)).then(|| start.elapsed());
    Ok((addr, elapsed))
}

/// Re-resolve a hostname, returning `Some(new)` only when `current` dropped
/// out of the answer set (`None` for literal addresses, failure, timeout).
/// Restricted to `current`'s family: the ICMP backend socket is family-bound.
pub async fn re_resolve(target: &str, current: ResolvedAddr) -> Option<ResolvedAddr> {
    if is_literal(target) {
        return None;
    }

    let host = format!("{target}:0");
    let result = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(&host))
        .await
        .ok()?
        .ok()?;

    let candidates: Vec<ResolvedAddr> = result
        .map(ResolvedAddr::from)
        .filter(|a| a.ip.is_ipv4() == current.ip.is_ipv4())
        .collect();

    // Round-robin DNS rotates record order between queries; only retarget
    // when the current address disappeared from the answer set entirely.
    if candidates.is_empty() || candidates.contains(&current) {
        return None;
    }
    candidates.first().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_detection() {
        for t in ["8.8.8.8", "::1", "fe80::1", "fe80::1%eth0", "fe80::1%12"] {
            assert!(is_literal(t), "{t}");
        }
        for t in ["example.com", "fe80::1%", "host%eth0", "8.8.8.8%eth0", ""] {
            assert!(!is_literal(t), "{t}");
        }
    }

    #[test]
    fn resolved_addr_keeps_the_zone() {
        let v6: SocketAddr = "[fe80::1%7]:0".parse().unwrap();
        let addr = ResolvedAddr::from(v6);
        assert_eq!((addr.ip, addr.scope_id), ("fe80::1".parse().unwrap(), 7));
        assert_eq!(addr.socket_addr(80), "[fe80::1%7]:80".parse().unwrap());

        let v4 = ResolvedAddr::from("192.0.2.1:0".parse::<SocketAddr>().unwrap());
        assert_eq!(v4, ResolvedAddr::unscoped("192.0.2.1".parse().unwrap()));
        assert_eq!(v4.socket_addr(80), "192.0.2.1:80".parse().unwrap());
    }

    /// The same link-local address in two zones is two different endpoints.
    #[test]
    fn zone_is_part_of_the_identity() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        let a = ResolvedAddr { ip, scope_id: 2 };
        let b = ResolvedAddr { ip, scope_id: 3 };
        assert_ne!(a, b);
        let set: std::collections::HashSet<_> = [a, b, a].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn link_local_without_its_zone_is_a_lost_zone() {
        let link_local = ResolvedAddr::unscoped("fe80::1".parse().unwrap());
        let zoned = ResolvedAddr {
            scope_id: 7,
            ..link_local
        };
        let global = ResolvedAddr::unscoped("2001:db8::1".parse().unwrap());
        assert!(zone_lost("fe80::1%en0 ", link_local));
        assert!(!zone_lost("fe80::1%en0", zoned));
        // Zone 0 is the default zone, written out.
        assert!(!zone_lost("fe80::1%0", link_local));
        assert!(!zone_lost("fe80::1%000", link_local));
        // A signed zero is not an index: macOS takes it for an interface name.
        assert!(zone_lost("fe80::1%+0", link_local));
        // A global address works without its zone; a name carries none.
        assert!(!zone_lost("2001:db8::1%en0", global));
        assert!(!zone_lost("printer.local", link_local));
    }

    /// The macOS resolver accepts a zone it cannot map and drops it; the
    /// probe would then fail at send time with "No route to host".
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn unmappable_zone_is_reported() {
        let target = "fe80::1%en0 ";
        // The case guarded against: the resolver hands the address back
        // without its zone instead of rejecting it.
        let mut addrs = tokio::net::lookup_host(format!("{target}:0"))
            .await
            .unwrap();
        let first = addrs.next().map(ResolvedAddr::from);
        assert_eq!(
            first,
            Some(ResolvedAddr::unscoped("fe80::1".parse().unwrap()))
        );

        let err = resolve(target, None).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("unknown zone in '{target}' (use an interface name or index)")
        );
    }

    #[tokio::test]
    async fn literal_ip_resolves_without_lookup() {
        let (addr, time) = resolve("::1", None).await.unwrap();
        assert_eq!(addr, ResolvedAddr::unscoped("::1".parse().unwrap()));
        assert!(time.is_none());
        assert!(resolve("::1", Some(Family::V4)).await.is_err());
    }
}
