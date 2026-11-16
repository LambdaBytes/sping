//! Routing-table access. Linux parses `/proc/net/route`; macOS shells out
//! to `route -n get default`; Windows parses `route print 0.0.0.0`. When
//! multiple default routes exist on Linux, the lowest metric wins.

use std::net::Ipv4Addr;

/// Entry from the kernel routing table.
#[derive(Debug, Clone)]
// Off Linux only a test builds a route and nothing reads `gateway` or `metric`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

/// Get the default gateway and interface; `None` when no default route exists
/// or the routes could not be read.
/// On Windows the second element is the interface IP, not its name (`route
/// print` exposes no name).
pub fn default_gateway() -> Option<(Ipv4Addr, String)> {
    default_gateway_checked().ok().flatten()
}

/// The default gateway as [`default_gateway`] finds it, telling a missing
/// default route (`Ok(None)`) from routes that could not be read (`Err`,
/// with the reason): `sping --ip` says which.
pub fn default_gateway_checked() -> Result<Option<(Ipv4Addr, String)>, String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/net/route")
            .map(|content| default_route(parse_routes(&content)))
            .map_err(|e| format!("cannot read /proc/net/route: {e}"))
    }
    #[cfg(target_os = "macos")]
    {
        default_gateway_macos()
    }
    #[cfg(target_os = "windows")]
    {
        default_gateway_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(None)
    }
}

// ── Windows ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn default_gateway_windows() -> Result<Option<(Ipv4Addr, String)>, String> {
    // `route print 0.0.0.0` outputs lines like:
    //   0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
    // Fields: Network, Netmask, Gateway, Interface, Metric
    let route = system_program("route.exe")
        .ok_or_else(|| "cannot run route: the system directory is unknown".to_string())?;
    let output = std::process::Command::new(route)
        .args(["print", "0.0.0.0"])
        .output()
        .map_err(|e| format!("cannot run route: {e}"))?;
    windows_gateway(
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
    )
}

/// A program of Windows' own by its full path, in the system directory
/// (`C:\Windows\System32`). By its bare name `Command` looks first in the
/// directory sping.exe was started from, so a `route.exe` saved beside it (a
/// downloads folder) would run instead: seen with v1.9.0-rc1 on the Windows
/// runner (2026-11-13). `None` when the system does not say where that
/// directory is.
#[cfg(target_os = "windows")]
pub(crate) fn system_program(name: &str) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    // MAX_PATH: the system directory is a short path.
    let mut buffer = [0u16; 260];
    // SAFETY: `buffer` is a live array of `buffer.len()` u16s, which the call
    // writes at most (its NUL included). It returns the length written
    // without the NUL, the size it would need (more than the buffer) or 0.
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    let dir = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len]));
    Some(dir.join(name))
}

/// The default gateway in `route print 0.0.0.0`'s output: the first
/// active default route's, `None` when there is none or its gateway is not
/// an address ("On-link"). Without one, a failed `route` could not tell.
#[cfg(any(target_os = "windows", test))]
fn windows_gateway(succeeded: bool, stdout: &str) -> Result<Option<(Ipv4Addr, String)>, String> {
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            let Ok(gw) = parts[2].parse::<Ipv4Addr>() else {
                return Ok(None);
            };
            // A persistent route ("Network Address  Netmask  Gateway
            // Address  Metric") has its metric where an active one has the
            // address of its interface, and may not be in use.
            if parts[3].parse::<Ipv4Addr>().is_err() {
                continue;
            }
            let iface_ip = parts[3].to_string();
            return Ok(Some((gw, iface_ip)));
        }
    }
    if succeeded {
        Ok(None)
    } else {
        Err("route print failed".into())
    }
}

// ── Linux ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn read_routes_linux() -> Vec<RouteEntry> {
    let Ok(content) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    parse_routes(&content)
}

/// The entries of `/proc/net/route`'s text.
#[cfg(target_os = "linux")]
fn parse_routes(content: &str) -> Vec<RouteEntry> {
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

/// The default route's gateway and interface among `routes`. Multiple
/// default routes (WiFi + Ethernet, VPN): the lowest metric, which is what
/// the kernel actually uses. `None` as well when that route has no gateway
/// (`default dev ppp0`): its 0.0.0.0 is no address.
#[cfg(target_os = "linux")]
fn default_route(routes: Vec<RouteEntry>) -> Option<(Ipv4Addr, String)> {
    routes
        .into_iter()
        .filter(|r| r.destination == Ipv4Addr::UNSPECIFIED && r.mask == Ipv4Addr::UNSPECIFIED)
        .min_by_key(|r| r.metric)
        .filter(|r| !r.gateway.is_unspecified())
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
fn default_gateway_macos() -> Result<Option<(Ipv4Addr, String)>, String> {
    // `route -n get default` outputs:
    //    route to: default
    //    gateway: 192.168.1.1
    //    interface: en0
    // By absolute path: cron runs us with PATH=/usr/bin:/bin, without
    // /sbin, where macOS installs route (13 to 27, at least).
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("cannot run /sbin/route: {e}"))?;
    macos_gateway(
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}

/// The default gateway in `route -n get default`'s output (Apple's
/// `route.c`). `route get` exits 0 even when the lookup fails, and says why
/// on stderr: `writing to routing socket: not in table` (`ESRCH`) is no
/// default route; any other complaint, or a failed `route`, could not tell.
#[cfg(any(target_os = "macos", test))]
fn macos_gateway(
    succeeded: bool,
    stdout: &str,
    stderr: &str,
) -> Result<Option<(Ipv4Addr, String)>, String> {
    let mut gateway = None;
    let mut iface = None;

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(gw) = line.strip_prefix("gateway:") {
            gateway = gw.trim().parse::<Ipv4Addr>().ok();
        }
        if let Some(ifn) = line.strip_prefix("interface:") {
            iface = Some(ifn.trim().to_string());
        }
    }

    if let Some(gateway) = gateway {
        return Ok(Some((gateway, iface.unwrap_or_else(|| "unknown".into()))));
    }
    let complaint = stderr.lines().map(str::trim).find(|l| !l.is_empty());
    match (succeeded, complaint) {
        (true, None) => Ok(None),
        (true, Some(line)) if line.ends_with("not in table") => Ok(None),
        (_, Some(line)) => Err(line.to_string()),
        (false, None) => Err("/sbin/route failed".into()),
    }
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

    /// An address as `/proc/net/route` prints it: the kernel's `__be32` in
    /// `%08X`, that is, the address's bytes read as a host-order `u32`.
    #[cfg(target_os = "linux")]
    fn route_hex(ip: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_ne_bytes(ip.octets()))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_hex_ip() {
        let hex = route_hex(Ipv4Addr::new(127, 0, 0, 1));
        #[cfg(target_endian = "little")]
        assert_eq!(hex, "0100007F");
        #[cfg(target_endian = "big")]
        assert_eq!(hex, "7F000001");
        assert_eq!(parse_hex_ip(&hex), Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    /// The default route of `/proc/net/route`'s text: the lowest metric of
    /// several (Wi-Fi and Ethernet), none without one.
    #[cfg(target_os = "linux")]
    #[test]
    fn default_route_of_the_table() {
        let header =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        let any = route_hex(Ipv4Addr::UNSPECIFIED);
        let wifi_gw = route_hex(Ipv4Addr::new(192, 168, 1, 1));
        let eth_gw = route_hex(Ipv4Addr::new(10, 0, 0, 1));
        let net = route_hex(Ipv4Addr::new(10, 0, 0, 0));
        let mask = route_hex(Ipv4Addr::new(255, 255, 255, 0));
        let table = format!(
            "{header}\
wlan0\t{any}\t{wifi_gw}\t0003\t0\t0\t600\t{any}\t0\t0\t0\n\
eth0\t{any}\t{eth_gw}\t0003\t0\t0\t100\t{any}\t0\t0\t0\n\
eth0\t{net}\t{any}\t0001\t0\t0\t100\t{mask}\t0\t0\t0\n"
        );
        assert_eq!(
            default_route(parse_routes(&table)),
            Some((Ipv4Addr::new(10, 0, 0, 1), "eth0".into()))
        );
        let no_default = format!("{header}eth0\t{net}\t{any}\t0001\t0\t0\t100\t{mask}\t0\t0\t0\n");
        assert_eq!(default_route(parse_routes(&no_default)), None);
        assert_eq!(default_route(parse_routes(header)), None);
    }

    /// A default route with no gateway (`default dev ppp0`: a point-to-point
    /// link, a VPN) is no default gateway, as on macOS and Windows: its
    /// gateway column is 0.0.0.0, no address to show or to probe. With the
    /// lowest metric it is the route the kernel uses, whatever gateway a
    /// default route of a higher metric has.
    #[cfg(target_os = "linux")]
    #[test]
    fn default_route_with_no_gateway() {
        let header =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        let any = route_hex(Ipv4Addr::UNSPECIFIED);
        let eth_gw = route_hex(Ipv4Addr::new(192, 168, 50, 1));
        let on_link =
            |metric: u32| format!("ppp0\t{any}\t{any}\t0001\t0\t0\t{metric}\t{any}\t0\t0\t0\n");
        let through =
            |metric: u32| format!("eth0\t{any}\t{eth_gw}\t0003\t0\t0\t{metric}\t{any}\t0\t0\t0\n");

        let alone = format!("{header}{}", on_link(0));
        assert_eq!(default_route(parse_routes(&alone)), None);
        let preferred = format!("{header}{}{}", on_link(50), through(600));
        assert_eq!(default_route(parse_routes(&preferred)), None);
        let backup = format!("{header}{}{}", on_link(600), through(100));
        assert_eq!(
            default_route(parse_routes(&backup)),
            Some((Ipv4Addr::new(192, 168, 50, 1), "eth0".into()))
        );
    }

    /// macOS: a gateway when `route` gives one; "not in table" is no
    /// default route; another complaint or a failure could not tell.
    #[test]
    fn macos_route_get_outputs() {
        let found = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(
            macos_gateway(true, found, ""),
            Ok(Some((Ipv4Addr::new(192, 168, 1, 1), "en0".into())))
        );
        assert_eq!(
            macos_gateway(true, "", "route: writing to routing socket: not in table\n"),
            Ok(None)
        );
        assert_eq!(macos_gateway(true, "", ""), Ok(None));
        assert_eq!(
            macos_gateway(
                true,
                "",
                "route: writing to routing socket: Operation not permitted\n"
            ),
            Err("route: writing to routing socket: Operation not permitted".into())
        );
        assert_eq!(
            macos_gateway(false, "", ""),
            Err("/sbin/route failed".into())
        );
        // A default route through an interface, with no gateway address.
        assert_eq!(
            macos_gateway(true, "   route to: default\n  interface: utun3\n", ""),
            Ok(None)
        );
    }

    /// Windows: the first default route; none, or "On-link"; a failed
    /// `route` without one could not tell.
    #[test]
    fn windows_route_print_outputs() {
        let table = "===========================================================================\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25\n";
        assert_eq!(
            windows_gateway(true, table),
            Ok(Some((
                Ipv4Addr::new(192, 168, 1, 1),
                "192.168.1.100".into()
            )))
        );
        assert_eq!(windows_gateway(true, "Active Routes:\n  None\n"), Ok(None));
        assert_eq!(
            windows_gateway(
                true,
                "          0.0.0.0          0.0.0.0         On-link     10.8.0.6    257\n"
            ),
            Ok(None)
        );
        assert_eq!(windows_gateway(false, ""), Err("route print failed".into()));
    }

    /// Windows: `route` and `ipconfig` are the system's, by their full path
    /// in the system directory, never a program of that name found first
    /// beside sping.exe.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_programs_come_from_the_system_directory() {
        for name in ["route.exe", "ipconfig.exe"] {
            let path = system_program(name).expect("the system directory");
            assert!(path.is_absolute(), "{}", path.display());
            assert!(path.is_file(), "{}", path.display());
            let dir = path
                .parent()
                .and_then(|d| d.file_name())
                .expect("a directory");
            assert!(dir.eq_ignore_ascii_case("System32"), "{}", path.display());
        }
    }

    /// Windows: a persistent route is not a route in use. Its line has the
    /// metric where an active route's has the address of its interface.
    #[test]
    fn windows_persistent_routes_are_not_the_gateway() {
        let persistent = "\
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0         10.0.0.1  Default
          0.0.0.0          0.0.0.0      192.168.0.1       1
===========================================================================
";
        let none = format!("Active Routes:\n  None\n{persistent}");
        assert_eq!(windows_gateway(true, &none), Ok(None));
        assert_eq!(
            windows_gateway(false, &none),
            Err("route print failed".into())
        );

        let active = "\
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
";
        assert_eq!(
            windows_gateway(true, &format!("{active}{persistent}")),
            Ok(Some((
                Ipv4Addr::new(192, 168, 1, 1),
                "192.168.1.100".into()
            )))
        );
    }

    #[test]
    fn test_mask_to_prefix() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }
}
