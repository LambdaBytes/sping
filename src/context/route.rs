//! Routing-table access. Linux parses `/proc/net/route`; macOS shells out
//! to `route -n get default`; Windows parses `route print 0.0.0.0`. When
//! multiple default routes exist on Linux, the lowest metric wins.

use std::net::Ipv4Addr;

/// Entry from the kernel routing table.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RouteEntry {
    pub iface: String,
    pub destination: Ipv4Addr,
    /// `0.0.0.0` for on-link routes.
    pub gateway: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// `u32::MAX` when the field is unparsable.
    pub metric: u32,
}

/// Parse the kernel routing table. Linux only; empty on macOS/Windows, where
/// only [`default_gateway`] is available.
pub fn read_routes() -> Vec<RouteEntry> {
    #[cfg(target_os = "linux")]
    {
        read_routes_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new() // macOS/Windows: use default_gateway() directly
    }
}

/// Get the default gateway and interface; `None` when no default route exists.
/// On Windows the second element is the interface IP, not its name (`route
/// print` exposes no name).
pub fn default_gateway() -> Option<(Ipv4Addr, String)> {
    #[cfg(target_os = "linux")]
    {
        if let Some(result) = default_gateway_linux() {
            return Some(result);
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(result) = default_gateway_macos() {
            return Some(result);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(result) = default_gateway_windows() {
            return Some(result);
        }
    }
    None
}

// ── Windows ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn default_gateway_windows() -> Option<(Ipv4Addr, String)> {
    // `route print 0.0.0.0` outputs lines like:
    //   0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
    // Fields: Network, Netmask, Gateway, Interface, Metric
    let output = std::process::Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            let gw = parts[2].parse::<Ipv4Addr>().ok()?;
            let iface_ip = parts[3].to_string();
            return Some((gw, iface_ip));
        }
    }
    None
}

// ── Linux ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn read_routes_linux() -> Vec<RouteEntry> {
    let Ok(content) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };

    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 8 {
                return None;
            }
            let iface = cols[0].to_string();
            let destination = parse_hex_ip(cols[1])?;
            let gateway = parse_hex_ip(cols[2])?;
            let metric = cols[6].parse::<u32>().unwrap_or(u32::MAX);
            let mask = parse_hex_ip(cols[7])?;
            Some(RouteEntry {
                iface,
                destination,
                gateway,
                mask,
                metric,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn default_gateway_linux() -> Option<(Ipv4Addr, String)> {
    // Multiple default routes (WiFi + Ethernet, VPN): pick the lowest metric,
    // which is what the kernel actually uses.
    read_routes_linux()
        .into_iter()
        .filter(|r| r.destination == Ipv4Addr::UNSPECIFIED && r.mask == Ipv4Addr::UNSPECIFIED)
        .min_by_key(|r| r.metric)
        .map(|r| (r.gateway, r.iface))
}

#[cfg(target_os = "linux")]
fn parse_hex_ip(hex: &str) -> Option<Ipv4Addr> {
    // `/proc/net/route` encodes addresses as host-byte-order hex; convert
    // to network order before constructing the address.
    let val = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(val.to_be()))
}

// ── macOS ────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn default_gateway_macos() -> Option<(Ipv4Addr, String)> {
    // `route -n get default` outputs:
    //    route to: default
    //    gateway: 192.168.1.1
    //    interface: en0
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let mut gateway = None;
    let mut iface = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(gw) = line.strip_prefix("gateway:") {
            gateway = gw.trim().parse::<Ipv4Addr>().ok();
        }
        if let Some(ifn) = line.strip_prefix("interface:") {
            iface = Some(ifn.trim().to_string());
        }
    }

    Some((gateway?, iface.unwrap_or_else(|| "unknown".into())))
}

/// Convert a netmask to prefix length. Assumes a contiguous mask: counts
/// leading one bits only.
pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from_be_bytes(mask.octets());
    bits.leading_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_hex_ip() {
        let ip = parse_hex_ip("0100007F").unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_mask_to_prefix() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }
}
