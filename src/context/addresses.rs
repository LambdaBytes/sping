//! The host's addresses as `sping --ip` shows them (1.8):
//! - every address of every interface, with its prefix, kind and, for IPv6,
//!   its state;
//! - the source each family uses towards a reference address;
//! - the IPv4 default gateway.
//!
//! Only what the system already knows: nothing is sent (the source comes from
//! a UDP connect, which sends no packet) and no privilege is asked for. What a
//! source does not say is unknown (`None`, or `Unknown` with the reason),
//! never guessed.
//!
//! Sources:
//! - Linux: `getifaddrs` (every address and netmask) and `/proc/net/if_inet6`
//!   (the IPv6 states).
//! - macOS: `ifconfig`.
//! - Windows: `GetAdaptersAddresses`, with no fallback (`ipconfig` would leave
//!   the loopback out).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::context::dns::ResolvedAddr;

/// The addresses whose route gives each family's source: global ones (the
/// default WAN reference and its IPv6 sibling). With a more specific route to
/// them (a split-tunnel VPN), the source is that route's, so the views name
/// the address.
pub const SOURCE_REFERENCE_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
pub const SOURCE_REFERENCE_V6: IpAddr =
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

/// What an address is, from the address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Loopback,
    LinkLocal,
    /// RFC 1918 (IPv4) or a unique local address, `fc00::/7` (IPv6).
    Private,
    /// The shared address space of carrier-grade NAT, `100.64.0.0/10`.
    Shared,
    Global,
}

/// The kind of `ip`.
pub fn kind(ip: IpAddr) -> Kind {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_loopback() {
                Kind::Loopback
            } else if v4.is_link_local() {
                Kind::LinkLocal
            } else if v4.is_private() {
                Kind::Private
            } else if a == 100 && (b & 0xc0) == 64 {
                Kind::Shared
            } else {
                Kind::Global
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            if v6.is_loopback() {
                Kind::Loopback
            } else if first & 0xffc0 == 0xfe80 {
                Kind::LinkLocal
            } else if first & 0xfe00 == 0xfc00 {
                Kind::Private
            } else {
                Kind::Global
            }
        }
    }
}

/// The state of an IPv6 address; each `None` where the system does not say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct States {
    /// A temporary (privacy) address (RFC 8981).
    pub temporary: Option<bool>,
    /// Past its preferred lifetime: kept, no longer chosen as a source.
    pub deprecated: Option<bool>,
    /// Duplicate address detection still running: not usable yet.
    pub tentative: Option<bool>,
    /// Duplicate address detection found another host with it.
    pub duplicate: Option<bool>,
}

/// One address of one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    pub interface: String,
    pub ip: IpAddr,
    /// `None` when the system gives no prefix; a real `/0` is `Some(0)`.
    pub prefix_len: Option<u8>,
    /// IPv6 only; `None` for IPv4.
    pub states: Option<States>,
}

/// The source the system picks towards a reference address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// That address, and its interface when exactly one interface holds it.
    Found {
        ip: IpAddr,
        interface: Option<String>,
    },
    /// No route or no address of the family to send from.
    None,
    /// It could not be told (a local error), with the reason.
    Unknown(String),
}

/// The IPv4 default gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gateway {
    Found {
        ip: Ipv4Addr,
        interface: Option<String>,
    },
    /// No default route.
    None,
    /// The routes could not be read, with the reason.
    Unknown(String),
}

/// What `sping --ip` shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostView {
    /// In the order the system lists them, grouped by interface (its first
    /// appearance), IPv4 before IPv6 within each.
    pub addresses: Vec<HostAddress>,
    pub source_v4: Source,
    pub source_v6: Source,
    pub gateway: Gateway,
}

/// Read everything `sping --ip` shows.
///
/// # Errors
///
/// The addresses could not be read at all (the reason). A missing source or
/// gateway is not an error: it is said in the view.
pub fn read() -> Result<HostView, String> {
    let addresses = read_addresses()?;
    let source = |to| {
        source_of(
            crate::context::iface::usable_source(ResolvedAddr::unscoped(to)),
            &addresses,
        )
    };
    let (source_v4, source_v6) = (source(SOURCE_REFERENCE_V4), source(SOURCE_REFERENCE_V6));
    let gateway = gateway_of(
        crate::context::route::default_gateway_checked(),
        cfg!(target_os = "windows"),
        &addresses,
    );
    Ok(HostView {
        addresses: grouped(addresses),
        source_v4,
        source_v6,
        gateway,
    })
}

/// The addresses grouped by interface, in the order each interface first
/// appears, IPv4 before IPv6 within each; otherwise as listed.
fn grouped(addresses: Vec<HostAddress>) -> Vec<HostAddress> {
    let mut order: Vec<String> = Vec::new();
    for a in &addresses {
        if !order.contains(&a.interface) {
            order.push(a.interface.clone());
        }
    }
    let mut sorted = addresses;
    sorted.sort_by_key(|a| {
        (
            order.iter().position(|name| *name == a.interface),
            a.ip.is_ipv6(),
        )
    });
    sorted
}

/// The interface holding `ip`, when exactly one does (a link-local address
/// may be on several).
fn interface_of(ip: IpAddr, addresses: &[HostAddress]) -> Option<String> {
    let mut holders = addresses
        .iter()
        .filter(|a| a.ip == ip)
        .map(|a| &a.interface);
    match (holders.next(), holders.next()) {
        (Some(name), None) => Some(name.clone()),
        _ => None,
    }
}

/// The source as `iface::usable_source` found it.
fn source_of(found: std::io::Result<Option<IpAddr>>, addresses: &[HostAddress]) -> Source {
    match found {
        Ok(Some(ip)) => Source::Found {
            ip,
            interface: interface_of(ip, addresses),
        },
        Ok(None) => Source::None,
        Err(e) => Source::Unknown(e.to_string()),
    }
}

/// The gateway as `route::default_gateway_checked` found it. Its interface
/// is a name on Linux and macOS (`unknown` when `route` gave none; a Linux
/// interface may well be called `192.168.1.100`) and, when
/// `interface_is_address` (Windows), the interface's address, looked up
/// among the addresses.
fn gateway_of(
    found: Result<Option<(Ipv4Addr, String)>, String>,
    interface_is_address: bool,
    addresses: &[HostAddress],
) -> Gateway {
    match found {
        Ok(Some((ip, interface))) => Gateway::Found {
            ip,
            interface: if interface_is_address {
                interface
                    .parse::<IpAddr>()
                    .ok()
                    .and_then(|address| interface_of(address, addresses))
            } else if interface == "unknown" {
                None
            } else {
                Some(interface)
            },
        },
        Ok(None) => Gateway::None,
        Err(reason) => Gateway::Unknown(reason),
    }
}

/// Every address of every interface.
fn read_addresses() -> Result<Vec<HostAddress>, String> {
    #[cfg(target_os = "linux")]
    {
        let raw = getifaddrs_list()?;
        Ok(with_linux_states(
            raw,
            std::fs::read_to_string("/proc/net/if_inet6"),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        // The path the context uses, the one nixpkgs' recipe replaces.
        use crate::context::iface::IFCONFIG;
        let output = std::process::Command::new(IFCONFIG)
            .output()
            .map_err(|e| format!("cannot run {IFCONFIG}: {e}"))?;
        if !output.status.success() {
            return Err(format!("{IFCONFIG} failed ({})", output.status));
        }
        Ok(parse_ifconfig_addresses(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(crate::context::adapters_windows::addresses()?
            .into_iter()
            .map(|a| HostAddress {
                states: a.ip.is_ipv6().then(|| windows_states(a.dad_state)),
                interface: a.name,
                ip: a.ip,
                prefix_len: a.prefix_len,
            })
            .collect())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("not supported on this system".into())
    }
}

/// `getifaddrs` addresses (interface, IP, prefix from the netmask), with the
/// IPv6 states of `/proc/net/if_inet6`'s text, matched by interface and
/// address. If that text could not be read, or has no line for an address,
/// that address's states are unknown; its prefix, when the netmask was
/// missing, is taken from there too.
#[cfg(any(target_os = "linux", test))]
fn with_linux_states(
    raw: Vec<(String, IpAddr, Option<u8>)>,
    if_inet6: std::io::Result<String>,
) -> Vec<HostAddress> {
    use crate::context::iface::if_inet6_lines;
    let text = if_inet6.ok();
    raw.into_iter()
        .map(|(interface, ip, prefix_len)| {
            let IpAddr::V6(v6) = ip else {
                return HostAddress {
                    interface,
                    ip,
                    prefix_len,
                    states: None,
                };
            };
            let line = text
                .as_deref()
                .and_then(|t| if_inet6_lines(t).find(|l| l.ip == v6 && l.name == interface));
            HostAddress {
                prefix_len: prefix_len.or(line.as_ref().map(|l| l.prefix_len)),
                states: Some(
                    line.and_then(|l| l.flags)
                        .map(linux_states)
                        .unwrap_or_default(),
                ),
                interface,
                ip,
            }
        })
        .collect()
}

/// IPv6 states from `IFA_F_*` (`linux/if_addr.h`).
#[cfg(any(target_os = "linux", test))]
fn linux_states(flags: u32) -> States {
    const TEMPORARY: u32 = 0x01;
    const DADFAILED: u32 = 0x08;
    const DEPRECATED: u32 = 0x20;
    const TENTATIVE: u32 = 0x40;
    States {
        temporary: Some(flags & TEMPORARY != 0),
        deprecated: Some(flags & DEPRECATED != 0),
        tentative: Some(flags & TENTATIVE != 0),
        duplicate: Some(flags & DADFAILED != 0),
    }
}

/// Every IPv4 and IPv6 address `getifaddrs` gives, with its interface and
/// the prefix length of its netmask (`None` without one).
#[cfg(target_os = "linux")]
fn getifaddrs_list() -> Result<Vec<(String, IpAddr, Option<u8>)>, String> {
    use std::ffi::CStr;

    /// Frees the list on every way out.
    struct List(*mut libc::ifaddrs);
    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: the pointer came from a successful `getifaddrs` and is
            // freed once, here.
            unsafe { libc::freeifaddrs(self.0) }
        }
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a live out-pointer; on success the call stores a list
    // that `freeifaddrs` releases, on failure it stores nothing.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(format!(
            "getifaddrs failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if head.is_null() {
        return Ok(Vec::new());
    }
    let list = List(head);

    let mut result = Vec::new();
    let mut entry = list.0;
    while !entry.is_null() {
        // SAFETY: a node of the list `getifaddrs` built, alive until `list`
        // is dropped at the end of this function.
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is non-null (checked) and points to a sockaddr
        // whose family says which struct it is; `read_unaligned` asks
        // nothing of its alignment.
        let family =
            i32::from(unsafe { std::ptr::addr_of!((*ifa.ifa_addr).sa_family).read_unaligned() });
        // The netmask, when there is one of the address's family, read the
        // same way; none otherwise.
        let mask = (!ifa.ifa_netmask.is_null()
            // SAFETY: as above.
            && i32::from(unsafe {
                std::ptr::addr_of!((*ifa.ifa_netmask).sa_family).read_unaligned()
            }) == family)
            .then_some(ifa.ifa_netmask);
        // SAFETY: the address, and the mask when kept, are sockaddrs of
        // `family` (checked).
        let (ip, prefix_len) = unsafe {
            match family {
                libc::AF_INET => (
                    IpAddr::V4(sockaddr_in_ip(ifa.ifa_addr)),
                    mask.map(|m| crate::context::route::mask_to_prefix(sockaddr_in_ip(m))),
                ),
                libc::AF_INET6 => (
                    IpAddr::V6(sockaddr_in6_ip(ifa.ifa_addr)),
                    mask.map(|m| u128::from(sockaddr_in6_ip(m)).leading_ones() as u8),
                ),
                _ => continue,
            }
        };
        // SAFETY: a non-null (checked), NUL-terminated interface name in the
        // same list; copied out before the list is freed.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        result.push((name, ip, prefix_len));
    }
    Ok(result)
}

/// The address of a `sockaddr_in`.
///
/// # Safety
///
/// `sa` points to a readable `sockaddr_in`.
#[cfg(target_os = "linux")]
unsafe fn sockaddr_in_ip(sa: *const libc::sockaddr) -> Ipv4Addr {
    // SAFETY: the caller's contract; `read_unaligned` asks nothing of the
    // pointer's alignment.
    let sin = unsafe { sa.cast::<libc::sockaddr_in>().read_unaligned() };
    Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))
}

/// The address of a `sockaddr_in6`.
///
/// # Safety
///
/// `sa` points to a readable `sockaddr_in6`.
#[cfg(target_os = "linux")]
unsafe fn sockaddr_in6_ip(sa: *const libc::sockaddr) -> Ipv6Addr {
    // SAFETY: as for `sockaddr_in_ip`.
    let sin6 = unsafe { sa.cast::<libc::sockaddr_in6>().read_unaligned() };
    Ipv6Addr::from(sin6.sin6_addr.s6_addr)
}

/// IPv6 states from a Windows `NL_DAD_STATE` (nldef.h). Windows also
/// randomizes the public address's suffix, so `IpSuffixOriginRandom` does
/// not tell a temporary address apart: `temporary` stays unknown (not
/// measured on Windows yet).
#[cfg(any(target_os = "windows", test))]
fn windows_states(dad_state: i32) -> States {
    const TENTATIVE: i32 = 1;
    const DUPLICATE: i32 = 2;
    const DEPRECATED: i32 = 3;
    const PREFERRED: i32 = 4;
    match dad_state {
        TENTATIVE | DUPLICATE | DEPRECATED | PREFERRED => States {
            temporary: None,
            deprecated: Some(dad_state == DEPRECATED),
            tentative: Some(dad_state == TENTATIVE),
            duplicate: Some(dad_state == DUPLICATE),
        },
        // IpDadStateInvalid, or a value this table does not know.
        _ => States::default(),
    }
}

/// The addresses of `ifconfig`'s text (macOS), read by keyword, not by
/// position:
/// - `inet A [--> B] netmask 0xHEX …`
/// - `inet6 A[%zone] [--> B] prefixlen N [state words] [scopeid …]`
///
/// The IPv6 state words `ifconfig` prints for the address flags it finds
/// (`temporary`, `deprecated`, `tentative`, `duplicated`) are states; any
/// other word (`autoconf`, `secured`, `detached`…) is not. A state word that
/// is absent is a flag `ifconfig` would have printed, so it is false.
#[cfg(any(target_os = "macos", test))]
fn parse_ifconfig_addresses(text: &str) -> Vec<HostAddress> {
    let mut result = Vec::new();
    let mut interface = String::new();
    for line in text.lines() {
        if !line.starts_with(['\t', ' '])
            && let Some((name, _)) = line.split_once(':')
        {
            interface = name.to_string();
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let after = |key: &str| {
            words
                .iter()
                .position(|w| *w == key)
                .and_then(|i| words.get(i + 1).copied())
        };
        match words.first() {
            Some(&"inet") => {
                let Some(ip) = words.get(1).and_then(|w| w.parse::<Ipv4Addr>().ok()) else {
                    continue;
                };
                let prefix_len = after("netmask").and_then(|mask| {
                    u32::from_str_radix(mask.trim_start_matches("0x"), 16)
                        .ok()
                        .map(|m| m.leading_ones() as u8)
                });
                result.push(HostAddress {
                    interface: interface.clone(),
                    ip: IpAddr::V4(ip),
                    prefix_len,
                    states: None,
                });
            }
            Some(&"inet6") => {
                let Some(ip) = words
                    .get(1)
                    .and_then(|w| w.split('%').next())
                    .and_then(|w| w.parse::<Ipv6Addr>().ok())
                else {
                    continue;
                };
                let has = |word: &str| Some(words.contains(&word));
                result.push(HostAddress {
                    interface: interface.clone(),
                    ip: IpAddr::V6(ip),
                    prefix_len: after("prefixlen").and_then(|p| p.parse().ok()),
                    states: Some(States {
                        temporary: has("temporary"),
                        deprecated: has("deprecated"),
                        tentative: has("tentative"),
                        duplicate: has("duplicated"),
                    }),
                });
            }
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn kinds_by_range() {
        for (address, expected) in [
            ("127.0.0.1", Kind::Loopback),
            ("127.255.0.9", Kind::Loopback),
            ("169.254.10.1", Kind::LinkLocal),
            ("10.1.2.3", Kind::Private),
            ("172.16.0.1", Kind::Private),
            ("172.31.255.1", Kind::Private),
            ("192.168.1.100", Kind::Private),
            ("100.64.0.1", Kind::Shared),
            ("100.127.255.1", Kind::Shared),
            ("100.128.0.1", Kind::Global),
            ("172.32.0.1", Kind::Global),
            ("192.0.2.10", Kind::Global),
            ("::1", Kind::Loopback),
            ("fe80::1", Kind::LinkLocal),
            ("febf::1", Kind::LinkLocal),
            ("fec0::1", Kind::Global),
            ("fd00:3::2", Kind::Private),
            ("fc00::1", Kind::Private),
            ("2001:db8::5", Kind::Global),
        ] {
            assert_eq!(kind(ip(address)), expected, "{address}");
        }
    }

    const IF_INET6: &str = "\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000000000fffe000001 02 40 20 80     eth0
20010db8000000000000000000000005 02 40 00 01     eth0
20010db8000000000000000000000006 02 40 00 20     eth0
20010db8000000000000000000000007 02 40 00 c8     eth0
20010db8000000000000000000000008 02 40 00 zz     eth0
";

    /// The kernel's flags, one by one and together; unreadable text, a
    /// missing line or an unreadable flags field leave the states unknown.
    #[test]
    fn linux_states_from_if_inet6() {
        let raw = |list: &[(&str, &str, Option<u8>)]| -> Vec<(String, IpAddr, Option<u8>)> {
            list.iter()
                .map(|(n, a, p)| (n.to_string(), ip(a), *p))
                .collect()
        };
        let input = raw(&[
            ("lo", "127.0.0.1", Some(8)),
            ("lo", "::1", Some(128)),
            ("eth0", "2001:db8::5", Some(64)),
            ("eth0", "2001:db8::6", None),
            ("eth0", "2001:db8::7", Some(64)),
            ("eth0", "2001:db8::8", Some(64)),
            ("eth0", "2001:db8::9", Some(64)),
            // The same address on another interface is not its line.
            ("eth1", "2001:db8::5", Some(64)),
        ]);
        let got = with_linux_states(input.clone(), Ok(IF_INET6.into()));
        let states = |i: usize| got[i].states;
        let known = |t, d, n, u| {
            Some(States {
                temporary: Some(t),
                deprecated: Some(d),
                tentative: Some(n),
                duplicate: Some(u),
            })
        };
        assert_eq!(states(0), None, "IPv4 has none");
        assert_eq!(states(1), known(false, false, false, false));
        assert_eq!(states(2), known(true, false, false, false));
        assert_eq!(states(3), known(false, true, false, false));
        // 0xc8: tentative, dadfailed and permanent.
        assert_eq!(states(4), known(false, false, true, true));
        assert_eq!(states(5), Some(States::default()), "unreadable flags");
        assert_eq!(states(6), Some(States::default()), "no line");
        assert_eq!(states(7), Some(States::default()), "another interface's");
        // No netmask: the prefix of the kernel's table.
        assert_eq!(got[3].prefix_len, Some(64));

        let unreadable = with_linux_states(
            input,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        );
        assert!(
            unreadable
                .iter()
                .filter(|a| a.ip.is_ipv6())
                .all(|a| a.states == Some(States::default())),
            "{unreadable:?}"
        );
        assert_eq!(unreadable[3].prefix_len, None, "no netmask, no table");
    }

    #[test]
    fn windows_dad_states() {
        let s = |t: Option<bool>, d, n, u| States {
            temporary: t,
            deprecated: Some(d),
            tentative: Some(n),
            duplicate: Some(u),
        };
        assert_eq!(windows_states(4), s(None, false, false, false));
        assert_eq!(windows_states(3), s(None, true, false, false));
        assert_eq!(windows_states(1), s(None, false, true, false));
        assert_eq!(windows_states(2), s(None, false, false, true));
        assert_eq!(windows_states(0), States::default());
        assert_eq!(windows_states(9), States::default());
    }

    /// `ifconfig` as macOS prints it (`af_inet.c`, `af_inet6.c`): the
    /// prefix by keyword, also on a point-to-point line (`-->`), the zone
    /// off the address, the state words as states and nothing else.
    #[test]
    fn ifconfig_addresses_by_keyword() {
        let text = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:00:00:01
\tinet6 fe80::c4e:1b5c:1f2:aa01%en0 prefixlen 64 secured scopeid 0xe
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8::1c2:3ff:fe45:6789 prefixlen 64 autoconf secured
\tinet6 2001:db8::5b1:c2ff:1 prefixlen 64 autoconf temporary
\tinet6 2001:db8::dead prefixlen 64 deprecated autoconf temporary
\tinet6 2001:db8::beef prefixlen 64 tentative
\tinet6 2001:db8::babe prefixlen 64 duplicated
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.8.0.6 --> 10.8.0.5 netmask 0xffffffff
\tinet6 fd00:8::6 --> fd00:8::5 prefixlen 128
en1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tstatus: inactive
";
        let got = parse_ifconfig_addresses(text);
        let summary: Vec<(String, String, Option<u8>)> = got
            .iter()
            .map(|a| (a.interface.clone(), a.ip.to_string(), a.prefix_len))
            .collect();
        let row = |n: &str, a: &str, p| (n.to_string(), a.to_string(), Some(p));
        assert_eq!(
            summary,
            [
                row("lo0", "127.0.0.1", 8),
                row("lo0", "::1", 128),
                row("lo0", "fe80::1", 64),
                row("en0", "fe80::c4e:1b5c:1f2:aa01", 64),
                row("en0", "192.168.1.20", 24),
                row("en0", "2001:db8::1c2:3ff:fe45:6789", 64),
                row("en0", "2001:db8::5b1:c2ff:1", 64),
                row("en0", "2001:db8::dead", 64),
                row("en0", "2001:db8::beef", 64),
                row("en0", "2001:db8::babe", 64),
                row("utun3", "10.8.0.6", 32),
                row("utun3", "fd00:8::6", 128),
            ]
        );
        let states = |a: &str| got.iter().find(|x| x.ip == ip(a)).unwrap().states;
        let s = |t, d, n, u| {
            Some(States {
                temporary: Some(t),
                deprecated: Some(d),
                tentative: Some(n),
                duplicate: Some(u),
            })
        };
        assert_eq!(states("192.168.1.20"), None);
        assert_eq!(
            states("2001:db8::1c2:3ff:fe45:6789"),
            s(false, false, false, false)
        );
        assert_eq!(states("2001:db8::5b1:c2ff:1"), s(true, false, false, false));
        assert_eq!(states("2001:db8::dead"), s(true, true, false, false));
        assert_eq!(states("2001:db8::beef"), s(false, false, true, false));
        assert_eq!(states("2001:db8::babe"), s(false, false, false, true));
    }

    fn address(interface: &str, a: &str) -> HostAddress {
        HostAddress {
            interface: interface.into(),
            ip: ip(a),
            prefix_len: Some(24),
            states: None,
        }
    }

    /// The source's interface is the one holding it, when only one does;
    /// no source and an unknown one are said as such.
    #[test]
    fn sources_and_their_interfaces() {
        let list = [
            address("eth0", "192.168.1.100"),
            address("eth0", "fe80::1"),
            address("wlan0", "fe80::1"),
        ];
        assert_eq!(
            source_of(Ok(Some(ip("192.168.1.100"))), &list),
            Source::Found {
                ip: ip("192.168.1.100"),
                interface: Some("eth0".into())
            }
        );
        assert_eq!(
            source_of(Ok(Some(ip("fe80::1"))), &list),
            Source::Found {
                ip: ip("fe80::1"),
                interface: None
            },
            "on two interfaces"
        );
        assert_eq!(
            source_of(Ok(Some(ip("10.0.0.9"))), &list),
            Source::Found {
                ip: ip("10.0.0.9"),
                interface: None
            },
            "on none"
        );
        assert_eq!(source_of(Ok(None), &list), Source::None);
        assert_eq!(
            source_of(Err(std::io::Error::other("permission denied")), &list),
            Source::Unknown("permission denied".into())
        );
    }

    /// A name stays a name, even one that reads as an address (Linux allows
    /// it); on Windows the address `route` gives is looked up; `unknown`
    /// (macOS, no interface line) and an address on no interface are not
    /// invented; a failed read is said.
    #[test]
    fn gateways_and_their_interfaces() {
        let list = [
            address("Ethernet", "192.168.1.100"),
            address("192.168.1.100", "10.0.0.2"),
        ];
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        let found = |interface: Option<&str>| Gateway::Found {
            ip: gw,
            interface: interface.map(String::from),
        };
        for (route, windows, expected) in [
            ("eth0", false, found(Some("eth0"))),
            ("192.168.1.100", false, found(Some("192.168.1.100"))),
            ("unknown", false, found(None)),
            ("192.168.1.100", true, found(Some("Ethernet"))),
            ("192.168.1.101", true, found(None)),
            ("Ethernet", true, found(None)),
        ] {
            assert_eq!(
                gateway_of(Ok(Some((gw, route.into()))), windows, &list),
                expected,
                "{route} windows={windows}"
            );
        }
        assert_eq!(gateway_of(Ok(None), false, &list), Gateway::None);
        assert_eq!(
            gateway_of(Err("cannot read /proc/net/route".into()), false, &list),
            Gateway::Unknown("cannot read /proc/net/route".into())
        );
    }

    #[test]
    fn grouped_by_interface_ipv4_first() {
        let list = vec![
            address("eth0", "fe80::1"),
            address("lo", "127.0.0.1"),
            address("eth0", "192.168.1.100"),
            address("lo", "::1"),
            address("eth0", "192.168.1.101"),
        ];
        let order: Vec<String> = grouped(list)
            .iter()
            .map(|a| format!("{} {}", a.interface, a.ip))
            .collect();
        assert_eq!(
            order,
            [
                "eth0 192.168.1.100",
                "eth0 192.168.1.101",
                "eth0 fe80::1",
                "lo 127.0.0.1",
                "lo ::1",
            ]
        );
    }

    /// The system's own list (Linux): the loopback's IPv4 address always,
    /// its IPv6 one when IPv6 is on.
    #[cfg(target_os = "linux")]
    #[test]
    fn getifaddrs_lists_the_loopback() {
        let list = getifaddrs_list().expect("getifaddrs");
        assert!(
            list.iter()
                .any(|(n, a, p)| n == "lo" && *a == ip("127.0.0.1") && *p == Some(8)),
            "{list:?}"
        );
        let ipv6_on = std::fs::read_to_string("/proc/sys/net/ipv6/conf/lo/disable_ipv6")
            .is_ok_and(|v| v.trim() == "0");
        if ipv6_on {
            assert!(
                list.iter()
                    .any(|(n, a, p)| n == "lo" && *a == ip("::1") && *p == Some(128)),
                "{list:?}"
            );
        }
    }
}
