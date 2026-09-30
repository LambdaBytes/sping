//! Local interface discovery: Linux via the routing table, macOS via
//! `ifconfig`, Windows via `ipconfig` (locale-tolerant). Best-effort.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use crate::context::route::{self, mask_to_prefix, read_routes};

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: IpAddr,
    /// `0` when the netmask could not be determined.
    pub prefix_len: u8,
}

/// Detect the local IP used to reach `target` (UDP connect trick: no packet
/// is sent, the kernel only selects a source address). `None` if no route.
pub fn detect_local_ip(target: IpAddr) -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::new(target, 80)).ok()?;
    let local = sock.local_addr().ok()?;
    Some(local.ip())
}

/// Find the interface name and prefix for `local_ip`. `None` for IPv6 and
/// when no data source (routing table, gateway, platform tool) matches.
pub fn interface_for_ip(local_ip: IpAddr) -> Option<InterfaceInfo> {
    let IpAddr::V4(_v4) = local_ip else {
        return None;
    };

    // Routing table is empty off Linux, so this loop is a no-op there.
    let routes = read_routes();
    for r in &routes {
        let mask_bits = u32::from_be_bytes(r.mask.octets());
        let dest_bits = u32::from_be_bytes(r.destination.octets());
        let ip_bits = u32::from_be_bytes(_v4.octets());

        if (ip_bits & mask_bits) == dest_bits && mask_bits != 0 {
            return Some(InterfaceInfo {
                name: r.iface.clone(),
                ip: local_ip,
                prefix_len: mask_to_prefix(r.mask),
            });
        }
    }

    // Fallback: use default gateway for interface name, platform tool for prefix
    if let Some((_, iface_name)) = route::default_gateway() {
        #[cfg(target_os = "macos")]
        if let Some(info) = interface_from_ifconfig(local_ip) {
            return Some(info);
        }
        #[cfg(target_os = "windows")]
        if let Some(info) = interface_from_ipconfig(local_ip) {
            return Some(info);
        }
        return Some(InterfaceInfo {
            name: iface_name,
            ip: local_ip,
            prefix_len: 0,
        });
    }

    // Last resort: platform-specific parsing
    #[cfg(target_os = "macos")]
    if let Some(info) = interface_from_ifconfig(local_ip) {
        return Some(info);
    }
    #[cfg(target_os = "windows")]
    if let Some(info) = interface_from_ipconfig(local_ip) {
        return Some(info);
    }

    None
}

/// List all interfaces with their IPs.
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    // Linux: probe each routed subnet with the UDP connect trick to learn
    // the per-interface local address.
    let routes = read_routes();
    if !routes.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for r in &routes {
            if r.mask == Ipv4Addr::UNSPECIFIED || !seen.insert(r.iface.clone()) {
                continue;
            }
            let dest_bits = u32::from_be_bytes(r.destination.octets());
            if dest_bits == 0 {
                continue;
            }
            let probe_ip = Ipv4Addr::from((dest_bits | 1).to_be_bytes());
            if let Some(local_ip) = detect_local_ip(IpAddr::V4(probe_ip)) {
                result.push(InterfaceInfo {
                    name: r.iface.clone(),
                    ip: local_ip,
                    prefix_len: mask_to_prefix(r.mask),
                });
            }
        }
        if !result.is_empty() {
            return result;
        }
    }

    #[cfg(target_os = "macos")]
    {
        list_interfaces_ifconfig()
    }
    #[cfg(target_os = "windows")]
    {
        list_interfaces_ipconfig()
    }
    #[cfg(target_os = "linux")]
    Vec::new()
}

// ── macOS: ifconfig parsing ──────────────────────────────────────────

#[cfg(target_os = "macos")]
fn interface_from_ifconfig(local_ip: IpAddr) -> Option<InterfaceInfo> {
    list_interfaces_ifconfig()
        .into_iter()
        .find(|i| i.ip == local_ip)
}

#[cfg(target_os = "macos")]
fn list_interfaces_ifconfig() -> Vec<InterfaceInfo> {
    let output = std::process::Command::new("ifconfig").output().ok();
    let Some(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_ifconfig(&text)
}

#[cfg(target_os = "macos")]
fn parse_ifconfig(text: &str) -> Vec<InterfaceInfo> {
    let mut result = Vec::new();
    let mut current_iface = String::new();

    for line in text.lines() {
        if !line.starts_with('\t')
            && !line.starts_with(' ')
            && let Some(name) = line.split(':').next()
        {
            current_iface = name.to_string();
        }
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") && !trimmed.starts_with("inet6") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 4
                && let Ok(ip) = parts[1].parse::<Ipv4Addr>()
            {
                if ip.is_loopback() {
                    continue;
                }
                let prefix = if parts[2] == "netmask" {
                    parse_hex_netmask(parts[3])
                } else {
                    0
                };
                result.push(InterfaceInfo {
                    name: current_iface.clone(),
                    ip: IpAddr::V4(ip),
                    prefix_len: prefix,
                });
            }
        }
    }
    result
}

#[cfg(target_os = "macos")]
fn parse_hex_netmask(hex: &str) -> u8 {
    let hex = hex.trim_start_matches("0x");
    let val = u32::from_str_radix(hex, 16).unwrap_or(0);
    val.count_ones() as u8
}

// ── Windows: ipconfig parsing ────────────────────────────────────────

#[cfg(target_os = "windows")]
fn interface_from_ipconfig(local_ip: IpAddr) -> Option<InterfaceInfo> {
    list_interfaces_ipconfig()
        .into_iter()
        .find(|i| i.ip == local_ip)
}

#[cfg(target_os = "windows")]
fn list_interfaces_ipconfig() -> Vec<InterfaceInfo> {
    // `ipconfig` outputs blocks like:
    //   Ethernet adapter Ethernet:
    //      IPv4 Address. . . . . . . . . . . : 192.168.1.100
    //      Subnet Mask . . . . . . . . . . . : 255.255.255.0
    let output = std::process::Command::new("ipconfig").output().ok();
    let Some(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_ipconfig(&text)
}

#[cfg(target_os = "windows")]
fn parse_ipconfig(text: &str) -> Vec<InterfaceInfo> {
    let mut result = Vec::new();
    let mut current_iface = String::new();
    let mut current_ip: Option<Ipv4Addr> = None;

    for line in text.lines() {
        let trimmed = line.trim();

        // Adapter header: "Ethernet adapter Ethernet:" or "Wireless LAN adapter Wi-Fi:"
        if !line.starts_with(' ') && line.ends_with(':') {
            if let Some(ip) = current_ip.take()
                && !ip.is_loopback()
                && !ip.is_unspecified()
            {
                result.push(InterfaceInfo {
                    name: current_iface.clone(),
                    ip: IpAddr::V4(ip),
                    prefix_len: 0,
                });
            }
            // Extract adapter name: "Ethernet adapter Ethernet:" → "Ethernet".
            // Localized Windows ("Adaptador de Ethernet Ethernet:") has no
            // " adapter " marker; fall back to the full header text.
            let name = line.trim_end_matches(':');
            let name = match name.rfind(" adapter ") {
                Some(pos) => &name[pos + " adapter ".len()..],
                None => name,
            };
            current_iface = name.to_string();
        }

        // IPv4 line: "   IPv4 Address. . . . . . . . . . . : 192.168.1.100"
        if trimmed.contains("IPv4")
            && trimmed.contains(':')
            && let Some(ip_str) = trimmed.rsplit(':').next()
        {
            current_ip = ip_str.trim().parse::<Ipv4Addr>().ok();
        }

        // Subnet mask: "   Subnet Mask . . . . . . . . . . . : 255.255.255.0"
        // Localized: "Máscara de subred" — match the accent-safe "scara" stem
        // ("á" survives neither OEM codepages nor from_utf8_lossy intact).
        // Detail lines are always indented; adapter headers are not.
        if line.starts_with(' ')
            && (trimmed.contains("Subnet Mask") || trimmed.contains("scara"))
            && trimmed.contains(':')
            && let Some(mask_str) = trimmed.rsplit(':').next()
            && let Ok(mask) = mask_str.trim().parse::<Ipv4Addr>()
            && let Some(ip) = current_ip.take()
            && !ip.is_loopback()
            && !ip.is_unspecified()
        {
            result.push(InterfaceInfo {
                name: current_iface.clone(),
                ip: IpAddr::V4(ip),
                prefix_len: mask_to_prefix(mask),
            });
        }
    }

    // Flush last adapter.
    if let Some(ip) = current_ip
        && !ip.is_loopback()
        && !ip.is_unspecified()
    {
        result.push(InterfaceInfo {
            name: current_iface,
            ip: IpAddr::V4(ip),
            prefix_len: 0,
        });
    }

    result
}
