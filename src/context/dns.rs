//! Hostname resolution with a hard 5s timeout. Prefers IPv4 unless restricted
//! via `-4`/`-6`.

use std::net::IpAddr;
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

/// Resolve a hostname to an IP, with timing. A literal IP returns immediately
/// with a `None` resolution time.
///
/// # Errors
///
/// Fails on family mismatch, timeout/lookup failure, or no matching address.
pub async fn resolve(target: &str, family: Option<Family>) -> Result<(IpAddr, Option<Duration>)> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        if let Some(f) = family
            && !f.matches(ip)
        {
            bail!("'{target}' does not match the requested address family");
        }
        return Ok((ip, None));
    }

    let host = format!("{target}:0");
    let start = Instant::now();

    let addrs = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(&host))
        .await
        .map_err(|_| anyhow::anyhow!("DNS resolution for '{target}' timed out after 5s"))?
        .with_context(|| format!("DNS resolution failed for '{target}'"))?;

    let all: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();

    let chosen = match family {
        Some(f) => all.iter().copied().find(|ip| f.matches(*ip)),
        None => all
            .iter()
            .copied()
            .find(|ip| ip.is_ipv4())
            .or_else(|| all.first().copied()),
    };

    let Some(ip) = chosen else {
        match family {
            Some(Family::V4) => bail!("no IPv4 address found for '{target}'"),
            Some(Family::V6) => bail!("no IPv6 address found for '{target}'"),
            None => bail!("no address found for '{target}'"),
        }
    };

    let elapsed = start.elapsed();
    Ok((ip, Some(elapsed)))
}

/// Re-resolve a hostname, returning `Some(new_ip)` only when `current_ip`
/// dropped out of the answer set (`None` for literal IPs, failure, timeout).
/// Restricted to `current_ip`'s family: the ICMP backend socket is family-bound.
pub async fn re_resolve(target: &str, current_ip: IpAddr) -> Option<IpAddr> {
    if target.parse::<IpAddr>().is_ok() {
        return None;
    }

    let host = format!("{target}:0");
    let result = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(&host))
        .await
        .ok()?
        .ok()?;

    let candidates: Vec<IpAddr> = result
        .map(|a| a.ip())
        .filter(|ip| ip.is_ipv4() == current_ip.is_ipv4())
        .collect();

    // Round-robin DNS rotates record order between queries; only retarget
    // when the current IP disappeared from the answer set entirely.
    if candidates.is_empty() || candidates.contains(&current_ip) {
        return None;
    }
    candidates.first().copied()
}
