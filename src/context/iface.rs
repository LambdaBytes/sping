//! Local interface discovery: Linux via the routing table and the kernel's
//! IPv6 address table, macOS via `ifconfig`, Windows via the adapter API
//! (`ipconfig` text as a fallback). Best-effort.

use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use crate::context::dns::ResolvedAddr;
use crate::context::route::{self, mask_to_prefix, read_routes};

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: IpAddr,
    /// `0` when the netmask could not be determined.
    pub prefix_len: u8,
}

/// Detect the local IP used to reach `target`. `None` if no route.
pub fn detect_local_ip(target: ResolvedAddr) -> Option<IpAddr> {
    route_source(target).ok()
}

/// The source address the system picks to reach `target` (UDP connect
/// trick: no packet is sent, the kernel only selects a source address).
fn route_source(target: ResolvedAddr) -> io::Result<IpAddr> {
    let bind = if target.ip.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(target.socket_addr(80))?;
    Ok(sock.local_addr()?.ip())
}

/// The address the system would send from to reach `target`, for comparing
/// IPv4 with IPv6.
///
/// - `Ok(Some)`: that address. A link-local one reaches only the
///   destinations on its link: routers do not forward link-local sources,
///   so the caller cannot take it for a working source to anything else.
/// - `Ok(None)`: no address it could send from — no route, no address of
///   the family, or none that leaves the host. With no address on the
///   route's interface, Linux hands out `::1` for IPv6 (also while the
///   link-local address is tentative) and `0.0.0.0` for IPv4.
/// - `Err`: it could not tell (a local error: a denied socket, a
///   `prohibit` or `blackhole` route).
pub fn usable_source(target: ResolvedAddr) -> io::Result<Option<IpAddr>> {
    source_state(route_source(target), target.ip)
}

/// What `route_source` found for `target`, as `usable_source` reports it.
fn source_state(found: io::Result<IpAddr>, target: IpAddr) -> io::Result<Option<IpAddr>> {
    match found {
        // No address, or a loopback one, which never leaves the host.
        Ok(source) if source.is_unspecified() || source.is_loopback() && !target.is_loopback() => {
            Ok(None)
        }
        Ok(source) => Ok(Some(source)),
        // No route (or an `unreachable` one) and no address to send from.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
                    | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Find the interface name and prefix for `local_ip`. `None` when no data
/// source (routing table, address table, gateway, platform tool) matches.
/// `scope_id` is the target's IPv6 zone (0 = none): the same link-local
/// address can exist on several interfaces, and the zone says which one.
pub fn interface_for_ip(local_ip: IpAddr, scope_id: u32) -> Option<InterfaceInfo> {
    let IpAddr::V4(_v4) = local_ip else {
        return pick_in_zone(ipv6_entries(), local_ip, scope_id);
    };

    // Linux keeps 127.0.0.0/8 in its local routing table, which
    // /proc/net/route does not show; it is on the kernel's loopback device.
    #[cfg(target_os = "linux")]
    if _v4.is_loopback() {
        return Some(InterfaceInfo {
            name: "lo".into(),
            ip: local_ip,
            prefix_len: 8,
        });
    }

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

    // Fallback: use default gateway for interface name, platform tool for
    // prefix. A loopback address is never on the default route's interface.
    if !_v4.is_loopback()
        && let Some((_, iface_name)) = route::default_gateway()
    {
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
            if let Some(local_ip) = detect_local_ip(ResolvedAddr::unscoped(IpAddr::V4(probe_ip))) {
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

    // IPv4 only and no loopback, like the Linux listing above.
    #[cfg(target_os = "macos")]
    {
        list_interfaces_ifconfig()
            .into_iter()
            .filter(|i| i.ip.is_ipv4() && !i.ip.is_loopback())
            .collect()
    }
    #[cfg(target_os = "windows")]
    {
        windows_entries(true)
            .into_iter()
            .map(|(_, info)| info)
            .filter(|i| i.ip.is_ipv4() && !i.ip.is_loopback())
            .collect()
    }
    #[cfg(target_os = "linux")]
    Vec::new()
}

/// Every local IPv6 address with its interface index (0 when the source
/// does not tell): the kernel's address table on Linux, the platform tool
/// or API elsewhere.
fn ipv6_entries() -> Vec<(u32, InterfaceInfo)> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/net/if_inet6")
            .map(|text| parse_if_inet6(&text))
            .unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        list_interfaces_ifconfig()
            .into_iter()
            .map(|info| (interface_index(&info.name), info))
            .collect()
    }
    #[cfg(target_os = "windows")]
    {
        windows_entries(false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// The entry holding `local_ip`. With a zone, the entry on that interface
/// wins and one on another interface is not it; entries whose index is
/// unknown (0) still qualify.
fn pick_in_zone(
    entries: Vec<(u32, InterfaceInfo)>,
    local_ip: IpAddr,
    scope_id: u32,
) -> Option<InterfaceInfo> {
    let mut unknown_zone = None;
    for (index, info) in entries.into_iter().filter(|(_, i)| i.ip == local_ip) {
        if scope_id == 0 || index == scope_id {
            return Some(info);
        }
        if index == 0 && unknown_zone.is_none() {
            unknown_zone = Some(info);
        }
    }
    unknown_zone
}

/// Parse `/proc/net/if_inet6`: one address per line, `<32 hex digits>
/// <ifindex, hex> <prefix len, hex> <scope> <flags> <name>`.
#[cfg(any(target_os = "linux", test))]
fn parse_if_inet6(text: &str) -> Vec<(u32, InterfaceInfo)> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let (addr, index, prefix, _scope, _flags, name) = (
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
                f.next()?,
            );
            let bits = u128::from_str_radix(addr, 16).ok()?;
            let index = u32::from_str_radix(index, 16).ok()?;
            let prefix_len = u8::from_str_radix(prefix, 16).ok()?;
            Some((
                index,
                InterfaceInfo {
                    name: name.to_string(),
                    ip: IpAddr::V6(std::net::Ipv6Addr::from(bits)),
                    prefix_len,
                },
            ))
        })
        .collect()
}

// ── macOS: ifconfig parsing ──────────────────────────────────────────

#[cfg(target_os = "macos")]
fn interface_from_ifconfig(local_ip: IpAddr) -> Option<InterfaceInfo> {
    list_interfaces_ifconfig()
        .into_iter()
        .find(|i| i.ip == local_ip)
}

/// Interface index of `name` (`if_nametoindex`); 0 when there is none.
#[cfg(target_os = "macos")]
fn interface_index(name: &str) -> u32 {
    let Ok(name) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: `name` is a live NUL-terminated C string; the call only reads
    // it and returns 0 for an unknown interface.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

#[cfg(target_os = "macos")]
fn list_interfaces_ifconfig() -> Vec<InterfaceInfo> {
    // By absolute path, like route (`route::default_gateway_macos`): cron's
    // PATH, /usr/bin:/bin, does not reach /sbin.
    let output = std::process::Command::new("/sbin/ifconfig").output().ok();
    let Some(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_ifconfig(&text)
}

#[cfg(any(target_os = "macos", test))]
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
        // "inet6 fe80::1%en0 prefixlen 64 secured scopeid 0x4": the zone
        // suffix is not part of the address.
        if trimmed.starts_with("inet6 ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 4
                && parts[2] == "prefixlen"
                && let Ok(ip) = parts[1]
                    .split('%')
                    .next()
                    .unwrap_or("")
                    .parse::<std::net::Ipv6Addr>()
                && let Ok(prefix) = parts[3].parse::<u8>()
            {
                result.push(InterfaceInfo {
                    name: current_iface.clone(),
                    ip: IpAddr::V6(ip),
                    prefix_len: prefix,
                });
            }
        }
    }
    result
}

#[cfg(any(target_os = "macos", test))]
fn parse_hex_netmask(hex: &str) -> u8 {
    let hex = hex.trim_start_matches("0x");
    let val = u32::from_str_radix(hex, 16).unwrap_or(0);
    val.count_ones() as u8
}

// ── Windows: ipconfig parsing ────────────────────────────────────────

#[cfg(target_os = "windows")]
fn interface_from_ipconfig(local_ip: IpAddr) -> Option<InterfaceInfo> {
    pick_in_zone(windows_entries(false), local_ip, 0)
}

/// Addresses with their interface index: from the adapter API, whose names
/// and prefixes do not depend on the display language; from `ipconfig` text
/// (index unknown) only if the API gives nothing.
#[cfg(target_os = "windows")]
fn windows_entries(only_up: bool) -> Vec<(u32, InterfaceInfo)> {
    match crate::context::adapters_windows::adapters(only_up) {
        Some(list) if !list.is_empty() => list,
        _ => list_interfaces_ipconfig()
            .into_iter()
            .map(|info| (0, info))
            .collect(),
    }
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

#[cfg(any(target_os = "windows", test))]
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

        // IPv6 line: "   IPv6 Address. . . . . . . . . . . : 2001:db8::1"
        // (localized labels still contain "IPv6", and may contain ": "
        // themselves: "Vínculo: dirección IPv6 local. . . : fe80::1%12"). The
        // value follows the last ": "; a "%zone" suffix is dropped. ipconfig
        // gives no prefix.
        if line.starts_with(' ')
            && trimmed.contains("IPv6")
            && let Some((_, value)) = trimmed.rsplit_once(": ")
            && let Ok(ip) = value
                .trim()
                .split('%')
                .next()
                .unwrap_or("")
                .parse::<std::net::Ipv6Addr>()
            && !ip.is_loopback()
            && !ip.is_unspecified()
        {
            result.push(InterfaceInfo {
                name: current_iface.clone(),
                ip: IpAddr::V6(ip),
                prefix_len: 0,
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(list: &'a [InterfaceInfo], ip: &str) -> &'a InterfaceInfo {
        let ip: IpAddr = ip.parse().unwrap();
        list.iter()
            .find(|i| i.ip == ip)
            .unwrap_or_else(|| panic!("{ip} not parsed"))
    }

    #[test]
    fn if_inet6_gives_name_and_prefix() {
        let text = "\
fe800000000000005054ff0000005ae2 02 40 20 80    ens18
20010db8000000010000000000000010 02 40 00 80    ens18
00000000000000000000000000000001 01 80 10 80       lo
garbage line
";
        let parsed = parse_if_inet6(text);
        assert_eq!(
            parsed.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            [2, 2, 1]
        );
        let list: Vec<InterfaceInfo> = parsed.into_iter().map(|(_, info)| info).collect();
        let e = entry(&list, "2001:db8:0:1::10");
        assert_eq!((e.name.as_str(), e.prefix_len), ("ens18", 64));
        let e = entry(&list, "::1");
        assert_eq!((e.name.as_str(), e.prefix_len), ("lo", 128));
        assert_eq!(entry(&list, "fe80::5054:ff00:0:5ae2").name, "ens18");
    }

    /// The index column is hexadecimal: interface 26 is written `1a`.
    #[test]
    fn if_inet6_index_is_hex() {
        let parsed = parse_if_inet6("fe800000000000000000000000000001 1a 40 20 80 veth0\n");
        assert_eq!(parsed[0].0, 26);
    }

    #[test]
    fn zone_selects_among_equal_addresses() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        let entries = || {
            ["eth0", "eth1", "tun0"]
                .into_iter()
                .zip([2u32, 3, 0])
                .map(|(name, index)| {
                    (
                        index,
                        InterfaceInfo {
                            name: name.into(),
                            ip,
                            prefix_len: 64,
                        },
                    )
                })
                .collect::<Vec<_>>()
        };
        let name = |scope| pick_in_zone(entries(), ip, scope).map(|i| i.name);
        // No zone: the first entry with that address, as before.
        assert_eq!(name(0).as_deref(), Some("eth0"));
        assert_eq!(name(3).as_deref(), Some("eth1"));
        // A zone no entry carries: only one of unknown index can be it.
        assert_eq!(name(9).as_deref(), Some("tun0"));
        assert_eq!(
            pick_in_zone(entries(), "fe80::2".parse().unwrap(), 2).map(|i| i.name),
            None
        );
        let known_only: Vec<_> = entries().into_iter().filter(|(i, _)| *i != 0).collect();
        assert!(pick_in_zone(known_only, ip, 9).is_none());
    }

    /// A 127.0.0.1 source is on the loopback interface with its /8, never
    /// on the default route's interface (which Windows named by its
    /// address). Exact on Linux; on macOS and Windows it comes from the
    /// system's list, which holds the loopback interface on every host.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn loopback_source_is_on_the_loopback_interface() {
        let info =
            interface_for_ip("127.0.0.1".parse().unwrap(), 0).expect("no interface for 127.0.0.1");
        #[cfg(target_os = "linux")]
        assert_eq!(info.name, "lo");
        assert!(info.name.parse::<IpAddr>().is_err(), "{info:?}");
        assert_eq!(info.prefix_len, 8, "{info:?}");
    }

    #[test]
    fn ifconfig_gives_both_families() {
        let text = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::1c2b:3d4e:5f60:7182%en0 prefixlen 64 secured scopeid 0xb
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8:1::20 prefixlen 64 autoconf secured
";
        let list = parse_ifconfig(text);
        let e = entry(&list, "192.168.1.20");
        assert_eq!((e.name.as_str(), e.prefix_len), ("en0", 24));
        let e = entry(&list, "2001:db8:1::20");
        assert_eq!((e.name.as_str(), e.prefix_len), ("en0", 64));
        // The zone suffix is not part of the address.
        let e = entry(&list, "fe80::1c2b:3d4e:5f60:7182");
        assert_eq!((e.name.as_str(), e.prefix_len), ("en0", 64));
        assert_eq!(entry(&list, "::1").name, "lo0");
        // Loopback too: a 127.0.0.1 source is looked up here.
        let e = entry(&list, "127.0.0.1");
        assert_eq!((e.name.as_str(), e.prefix_len), ("lo0", 8));
    }

    #[test]
    fn ipconfig_gives_both_families() {
        let text = "\
Windows IP Configuration


Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : lan
   IPv6 Address. . . . . . . . . . . : 2001:db8:1::31
   Temporary IPv6 Address. . . . . . : 2001:db8:1:0:1234:5678:9abc:def0
   Link-local IPv6 Address . . . . . : fe80::9d2e:4bfb:a4a2:eb3%12
   IPv4 Address. . . . . . . . . . . : 192.168.1.31
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
";
        let list = parse_ipconfig(text);
        let e = entry(&list, "192.168.1.31");
        assert_eq!((e.name.as_str(), e.prefix_len), ("Ethernet 3", 24));
        for ip in [
            "2001:db8:1::31",
            "2001:db8:1:0:1234:5678:9abc:def0",
            "fe80::9d2e:4bfb:a4a2:eb3",
        ] {
            let e = entry(&list, ip);
            assert_eq!((e.name.as_str(), e.prefix_len), ("Ethernet 3", 0));
        }
    }

    /// Spanish Windows: no " adapter " marker, and the link-local label has
    /// a ": " of its own.
    #[test]
    fn ipconfig_localized_labels() {
        let text = "\
Configuración IP de Windows


Adaptador de Ethernet Ethernet 3:

   Sufijo DNS específico para la conexión. . : lan
   Dirección IPv6 . . . . . . . . . . : 2001:db8:1::31
   Dirección IPv6 temporal. . . . . . : 2001:db8:1:0:1234:5678:9abc:def0
   Vínculo: dirección IPv6 local. . . : fe80::9d2e:4bfb:a4a2:eb3%12
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.1.31
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0
   Puerta de enlace predeterminada . . . . . : 192.168.1.1
";
        let list = parse_ipconfig(text);
        let e = entry(&list, "192.168.1.31");
        assert_eq!(
            (e.name.as_str(), e.prefix_len),
            ("Adaptador de Ethernet Ethernet 3", 24)
        );
        for ip in [
            "2001:db8:1::31",
            "2001:db8:1:0:1234:5678:9abc:def0",
            "fe80::9d2e:4bfb:a4a2:eb3",
        ] {
            assert_eq!(entry(&list, ip).name, "Adaptador de Ethernet Ethernet 3");
        }
    }

    /// A source that cannot leave the host is no source; a link-local one
    /// reaches its link, whatever the destination's prefix.
    #[test]
    fn a_loopback_source_serves_only_a_loopback_target() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let state = |source, target| source_state(Ok(ip(source)), ip(target)).unwrap();
        for (source, target) in [
            ("2001:db8:5::2", "2001:db8::1"),
            ("fd00:1::2", "2001:db8::1"),
            ("10.0.5.2", "198.51.100.1"),
            ("::1", "::1"),
            ("127.0.0.1", "127.0.0.1"),
            ("127.0.0.1", "127.0.0.2"),
            // Link-local sources, to destinations on their link.
            ("fe80::1", "fd00:9::1"),
            ("fe80::1", "fe80::2"),
            ("fe80::1", "ff02::1"),
            ("169.254.1.2", "10.9.0.1"),
        ] {
            assert_eq!(
                state(source, target),
                Some(ip(source)),
                "{source} -> {target}"
            );
        }
        for (source, target) in [
            ("::1", "2001:db8::1"),
            ("::1", "fe80::2"),
            ("127.0.0.1", "198.51.100.1"),
            ("::", "2001:db8::1"),
            ("0.0.0.0", "198.51.100.1"),
        ] {
            assert_eq!(state(source, target), None, "{source} -> {target}");
        }
    }

    /// No route and no address to send from are no source; any other local
    /// error leaves the source unknown.
    #[test]
    fn other_local_errors_leave_the_source_unknown() {
        use io::ErrorKind;
        let target: IpAddr = "2001:db8::1".parse().unwrap();
        for kind in [
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::AddrNotAvailable,
        ] {
            assert_eq!(
                source_state(Err(kind.into()), target).unwrap(),
                None,
                "{kind:?}"
            );
        }
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            let err = source_state(Err(kind.into()), target).unwrap_err();
            assert_eq!(err.kind(), kind);
        }

        // The system's own codes, as std maps them.
        #[cfg(unix)]
        let (none, unknown) = (
            [libc::ENETUNREACH, libc::EHOSTUNREACH, libc::EADDRNOTAVAIL],
            // A denied socket, a `prohibit` route, a `blackhole` route or a
            // link-local address without its zone, a kernel without IPv6.
            [libc::EPERM, libc::EACCES, libc::EINVAL, libc::EAFNOSUPPORT],
        );
        // WSAENETUNREACH, WSAEHOSTUNREACH, WSAEADDRNOTAVAIL; WSAEACCES,
        // WSAEINVAL, WSAEAFNOSUPPORT.
        #[cfg(windows)]
        let (none, unknown) = ([10051, 10065, 10049], [10013, 10022, 10047]);
        #[cfg(any(unix, windows))]
        {
            for code in none {
                let err = io::Error::from_raw_os_error(code);
                assert_eq!(source_state(Err(err), target).unwrap(), None, "code {code}");
            }
            for code in unknown {
                let err = io::Error::from_raw_os_error(code);
                assert!(source_state(Err(err), target).is_err(), "code {code}");
            }
        }
    }
}
