//! Hostname resolution with a hard 5s timeout. Prefers IPv4 unless restricted
//! via `-4`/`-6`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;

pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Address family restriction (-4 / -6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Family {
    #[serde(rename = "ipv4")]
    V4,
    #[serde(rename = "ipv6")]
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

    let start = Instant::now();
    let all = lookup(target).await?;

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

/// Look `target` up with the 5s timeout: a name, or a zoned literal whose
/// zone only the system resolver can turn into an index.
async fn lookup(target: &str) -> Result<Vec<ResolvedAddr>> {
    let host = format!("{target}:0");
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
    Ok(addrs.map(ResolvedAddr::from).collect())
}

/// The first address of each family from one lookup, for comparing IPv4
/// with IPv6. A missing family means the lookup gave none, not that the
/// name has no record of it: some resolvers leave out what the host cannot
/// reach. This lookup is not the probe's: the address the probe uses is the
/// scheduler's (round-robin answers, DNS failover), not this one's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Families {
    pub v4: Option<ResolvedAddr>,
    pub v6: Option<ResolvedAddr>,
    /// `None` for a literal address, as in `resolve`.
    pub time: Option<Duration>,
}

/// Resolve `target` to the first address of each family, with timing. A
/// literal address gives its own family only, with no lookup.
///
/// # Errors
///
/// As `resolve` without a family: timeout or lookup failure, an unknown
/// zone, or no address at all. One family missing is not an error.
pub async fn resolve_both(target: &str) -> Result<Families> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        let (v4, v6) = first_of_each(&[ResolvedAddr::unscoped(ip)]);
        return Ok(Families { v4, v6, time: None });
    }

    let start = Instant::now();
    let all = lookup(target).await?;
    let (v4, v6) = first_of_each(&all);
    if v4.is_none() && v6.is_none() {
        bail!("no address found for '{target}'");
    }
    if let Some(v6) = v6
        && zone_lost(target, v6)
    {
        bail!("unknown zone in '{target}' (use an interface name or index)");
    }

    let time = (!is_literal(target)).then(|| start.elapsed());
    Ok(Families { v4, v6, time })
}

/// The first IPv4 and the first IPv6 address of `all`, in its order.
fn first_of_each(all: &[ResolvedAddr]) -> (Option<ResolvedAddr>, Option<ResolvedAddr>) {
    let first = |family: Family| all.iter().copied().find(|a| family.matches(a.ip));
    (first(Family::V4), first(Family::V6))
}

/// What a re-resolution of the target's name found, for the address being
/// probed (`current`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// `current` is still among the answers (round-robin reorders them).
    Unchanged,
    /// `current` dropped out: the first answer of its family instead.
    Changed(ResolvedAddr),
    /// The answer has no address of `current`'s family. Not that the name
    /// has none: a resolver may leave out what the host cannot reach.
    NoAddressOfFamily,
    /// The lookup failed: no answer within the timeout, or an error.
    Failed { timed_out: bool },
}

/// Re-resolve a hostname for the address being probed. The answer is
/// restricted to `current`'s family: the probe's socket is bound to it. A
/// literal address is `Unchanged`.
pub async fn re_resolve(target: &str, current: ResolvedAddr) -> Resolution {
    if is_literal(target) {
        return Resolution::Unchanged;
    }

    let host = format!("{target}:0");
    match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(&host)).await {
        Err(_) => Resolution::Failed { timed_out: true },
        Ok(Err(_)) => Resolution::Failed { timed_out: false },
        Ok(Ok(addrs)) => resolution(&addrs.map(ResolvedAddr::from).collect::<Vec<_>>(), current),
    }
}

/// What `answer` means for `current`. Round-robin DNS rotates the order of
/// the records between queries: only an answer without `current` moves the
/// probe, to its first address of the family.
fn resolution(answer: &[ResolvedAddr], current: ResolvedAddr) -> Resolution {
    let mut candidates = answer
        .iter()
        .copied()
        .filter(|a| a.ip.is_ipv4() == current.ip.is_ipv4())
        .peekable();
    match candidates.peek() {
        None => Resolution::NoAddressOfFamily,
        Some(_) if answer.contains(&current) => Resolution::Unchanged,
        Some(&first) => Resolution::Changed(first),
    }
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

    fn addr(s: &str) -> ResolvedAddr {
        ResolvedAddr::unscoped(s.parse().unwrap())
    }

    #[test]
    fn first_of_each_takes_the_first_of_each_family() {
        let (a4, b4) = (addr("192.0.2.1"), addr("192.0.2.2"));
        let (a6, b6) = (addr("2001:db8::1"), addr("2001:db8::2"));
        assert_eq!(first_of_each(&[a4, b4]), (Some(a4), None));
        assert_eq!(first_of_each(&[a6, b6]), (None, Some(a6)));
        // Each family in the answer's order, whichever family comes first.
        assert_eq!(first_of_each(&[b6, a6, b4, a4]), (Some(b4), Some(b6)));
        assert_eq!(first_of_each(&[a4, a6, b4]), (Some(a4), Some(a6)));
        assert_eq!(first_of_each(&[]), (None, None));
        // The zone travels with the address.
        let zoned = ResolvedAddr {
            ip: "fe80::1".parse().unwrap(),
            scope_id: 7,
        };
        assert_eq!(first_of_each(&[zoned, a6]), (None, Some(zoned)));
    }

    #[tokio::test]
    async fn literal_gives_its_own_family_only() {
        let v4 = resolve_both("192.0.2.1").await.unwrap();
        assert_eq!(
            (v4.v4, v4.v6, v4.time),
            (Some(addr("192.0.2.1")), None, None)
        );
        let v6 = resolve_both("2001:db8::1").await.unwrap();
        assert_eq!(
            (v6.v4, v6.v6, v6.time),
            (None, Some(addr("2001:db8::1")), None)
        );
    }

    /// A zoned literal goes through the resolver for its zone only: the zone
    /// is kept and there is no resolution time.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn literal_keeps_its_zone() {
        // SAFETY: a NUL-terminated name; the call only reads it.
        let lo = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(lo, 0);
        let both = resolve_both("fe80::1%lo").await.unwrap();
        let zoned = ResolvedAddr {
            ip: "fe80::1".parse().unwrap(),
            scope_id: lo,
        };
        assert_eq!((both.v4, both.v6, both.time), (None, Some(zoned), None));
    }

    /// What an answer means for the address probed: only an answer without
    /// it moves the probe; one without its family is said apart.
    #[test]
    fn a_re_resolution_by_its_answer() {
        let a = |s: &str| ResolvedAddr::unscoped(s.parse().unwrap());
        let current = a("192.0.2.1");
        for (answer, expected) in [
            (vec![a("192.0.2.1")], Resolution::Unchanged),
            // Round-robin: the same records, another order.
            (vec![a("192.0.2.2"), a("192.0.2.1")], Resolution::Unchanged),
            (
                vec![a("2001:db8::1"), a("192.0.2.1")],
                Resolution::Unchanged,
            ),
            (
                vec![a("2001:db8::1"), a("192.0.2.7"), a("192.0.2.8")],
                Resolution::Changed(a("192.0.2.7")),
            ),
            (vec![a("2001:db8::1")], Resolution::NoAddressOfFamily),
            (vec![], Resolution::NoAddressOfFamily),
        ] {
            assert_eq!(resolution(&answer, current), expected, "{answer:?}");
        }
        let v6 = a("2001:db8::1");
        assert_eq!(
            resolution(&[a("192.0.2.1")], v6),
            Resolution::NoAddressOfFamily
        );
        assert_eq!(
            resolution(&[a("192.0.2.1"), a("2001:db8::9")], v6),
            Resolution::Changed(a("2001:db8::9"))
        );
    }

    #[tokio::test]
    async fn a_literal_is_never_re_resolved() {
        let current = ResolvedAddr::unscoped("192.0.2.1".parse().unwrap());
        assert_eq!(
            re_resolve("192.0.2.1", current).await,
            Resolution::Unchanged
        );
        assert_eq!(
            re_resolve("fe80::1%1", current).await,
            Resolution::Unchanged
        );
    }
}
