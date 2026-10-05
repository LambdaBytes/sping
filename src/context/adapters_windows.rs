//! Windows interface enumeration through `GetAdaptersAddresses`
//! (iphlpapi.dll): adapter names, addresses and prefix lengths straight from
//! the system, independent of the display language `ipconfig` prints in.

use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::context::iface::InterfaceInfo;

/// Winsock address families (`AF_INET6` is 23 on Windows, not the Unix value).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
/// `sizeof(sockaddr_in)` / `sizeof(sockaddr_in6)`.
const SOCKADDR_IN_LEN: i32 = 16;
const SOCKADDR_IN6_LEN: i32 = 28;
/// `IfOperStatusUp`.
const IF_OPER_STATUS_UP: i32 = 1;

/// Bounds on the walk: a corrupt list must not loop forever or read a name
/// without end. `IF_MAX_STRING_SIZE` is 256.
const MAX_ADAPTERS: usize = 1024;
const MAX_ADDRESSES: usize = 1024;
const MAX_NAME_UNITS: usize = 256;

/// Leading fields of `IP_ADAPTER_ADDRESSES_LH` (iptypes.h), up to
/// `Ipv6IfIndex`. The system writes these records; they are only read
/// through a pointer, never built or copied by size, so the rest of the
/// record is left undeclared. `align(8)`: the record starts with a union
/// holding a `ULONGLONG`.
#[repr(C, align(8))]
#[allow(dead_code)] // undeclared-by-use fields fix the layout of the others
struct IpAdapterAddresses {
    length: u32,
    if_index: u32,
    next: *const IpAdapterAddresses,
    adapter_name: *const u8,
    first_unicast_address: *const IpAdapterUnicastAddress,
    first_anycast_address: *const c_void,
    first_multicast_address: *const c_void,
    first_dns_server_address: *const c_void,
    dns_suffix: *const u16,
    description: *const u16,
    friendly_name: *const u16,
    physical_address: [u8; 8],
    physical_address_length: u32,
    flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: i32,
    ipv6_if_index: u32,
}

/// `SOCKET_ADDRESS` (ws2def.h).
#[repr(C)]
struct SocketAddress {
    sockaddr: *const u8,
    sockaddr_length: i32,
}

/// `IP_ADAPTER_UNICAST_ADDRESS_LH` (iptypes.h), whole record.
#[repr(C, align(8))]
#[allow(dead_code)] // see IpAdapterAddresses
struct IpAdapterUnicastAddress {
    length: u32,
    flags: u32,
    next: *const IpAdapterUnicastAddress,
    address: SocketAddress,
    prefix_origin: i32,
    suffix_origin: i32,
    dad_state: i32,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    lease_lifetime: u32,
    on_link_prefix_length: u8,
}

// Field offsets of the Windows SDK layout (checked against windows-sys and a
// C compiler for x64, ARM64 and x86). A mismatch here is a build error, not
// a wrong read at run time.
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(offset_of!(IpAdapterAddresses, first_unicast_address) == 24);
    assert!(offset_of!(IpAdapterAddresses, friendly_name) == 72);
    assert!(offset_of!(IpAdapterAddresses, oper_status) == 104);
    assert!(offset_of!(IpAdapterAddresses, ipv6_if_index) == 108);
    assert!(size_of::<IpAdapterAddresses>() == 112);
    assert!(offset_of!(IpAdapterUnicastAddress, address) == 16);
    assert!(offset_of!(IpAdapterUnicastAddress, on_link_prefix_length) == 56);
    assert!(size_of::<IpAdapterUnicastAddress>() == 64);
};
#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(offset_of!(IpAdapterAddresses, friendly_name) == 40);
    assert!(offset_of!(IpAdapterAddresses, oper_status) == 68);
    assert!(offset_of!(IpAdapterUnicastAddress, address) == 12);
    assert!(offset_of!(IpAdapterUnicastAddress, on_link_prefix_length) == 44);
    assert!(size_of::<IpAdapterUnicastAddress>() == 48);
};

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *mut c_void,
        adapter_addresses: *mut IpAdapterAddresses,
        size_pointer: *mut u32,
    ) -> u32;
}

/// Every unicast address of every adapter (only adapters that are up when
/// `only_up`), each with its interface index: `IfIndex` for IPv4,
/// `Ipv6IfIndex` — the zone index — for IPv6. `None` when the system call
/// fails, so the caller can fall back to another source.
#[cfg(target_os = "windows")]
pub fn adapters(only_up: bool) -> Option<Vec<(u32, InterfaceInfo)>> {
    const AF_UNSPEC: u32 = 0;
    // GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    const FLAGS: u32 = 0x2 | 0x4 | 0x8;
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    /// More than any real adapter list; refuses a nonsensical size request.
    const MAX_BUFFER: u32 = 16 * 1024 * 1024;

    // The documented starting size; the call reports the size it needs.
    let mut size: u32 = 16 * 1024;
    for _ in 0..3 {
        if size > MAX_BUFFER {
            return None;
        }
        // u64 words: the records need 8-byte alignment, which `Vec<u8>`
        // does not promise.
        let words = (size as usize).div_ceil(8);
        let mut buf = vec![0u64; words];
        let mut len = (words * 8) as u32;
        // SAFETY: `buf` is a live, writable, 8-aligned buffer of `len` bytes
        // and `len` a live u32; the call writes at most `len` bytes and
        // stores the size it needs back in `len`.
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                FLAGS,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        match ret {
            ERROR_SUCCESS => {
                // SAFETY: on success the list starts at `buf` and every
                // pointer in it points into `buf`, which is alive and not
                // written to until `collect` returns.
                return Some(unsafe { collect(buf.as_ptr().cast(), only_up) });
            }
            ERROR_BUFFER_OVERFLOW => size = len,
            // ERROR_NO_DATA and real failures alike: nothing to report.
            _ => return None,
        }
    }
    None
}

/// Walk an adapter list.
///
/// # Safety
///
/// `first` is null or points to a list as `GetAdaptersAddresses` writes it:
/// each record starts with its own byte length, is 8-aligned, and its
/// `Next`, name and socket-address pointers are null or point to memory that
/// is valid — for `sockaddr_length` bytes, or up to a NUL for names — and
/// not written to during the call.
unsafe fn collect(first: *const IpAdapterAddresses, only_up: bool) -> Vec<(u32, InterfaceInfo)> {
    let mut result = Vec::new();
    let mut adapter_ptr = first;
    for _ in 0..MAX_ADAPTERS {
        if adapter_ptr.is_null() {
            break;
        }
        // SAFETY: every record starts with its `Length` (caller contract).
        let length = unsafe { adapter_ptr.cast::<u32>().read() } as usize;
        // A record shorter than the declared fields cannot be read, and its
        // `Next` cannot be trusted either.
        if length < size_of::<IpAdapterAddresses>() {
            break;
        }
        // SAFETY: the record covers every declared field (checked above) and
        // is aligned and not mutated (caller contract).
        let adapter = unsafe { &*adapter_ptr };
        adapter_ptr = adapter.next;

        if only_up && adapter.oper_status != IF_OPER_STATUS_UP {
            continue;
        }
        // SAFETY: null or a NUL-terminated UTF-16 string (caller contract).
        let name = unsafe { wide_string(adapter.friendly_name) };

        let mut unicast_ptr = adapter.first_unicast_address;
        for _ in 0..MAX_ADDRESSES {
            if unicast_ptr.is_null() {
                break;
            }
            // SAFETY: as for the adapter record.
            let length = unsafe { unicast_ptr.cast::<u32>().read() } as usize;
            if length < size_of::<IpAdapterUnicastAddress>() {
                break;
            }
            // SAFETY: as for the adapter record.
            let unicast = unsafe { &*unicast_ptr };
            unicast_ptr = unicast.next;

            // SAFETY: null or valid for `sockaddr_length` bytes (caller
            // contract).
            let Some(ip) = (unsafe { socket_address_ip(&unicast.address) }) else {
                continue;
            };
            let (index, max_prefix) = match ip {
                // Like the other platforms' sources, IPv4 loopback is not
                // an interface address worth reporting.
                IpAddr::V4(v4) if v4.is_loopback() => continue,
                IpAddr::V4(_) => (adapter.if_index, 32),
                IpAddr::V6(_) => (adapter.ipv6_if_index, 128),
            };
            // Out of range (255 marks "unknown") reads as no prefix.
            let prefix_len = match unicast.on_link_prefix_length {
                p if p <= max_prefix => p,
                _ => 0,
            };
            result.push((
                index,
                InterfaceInfo {
                    name: name.clone(),
                    ip,
                    prefix_len,
                },
            ));
        }
    }
    result
}

/// Read a NUL-terminated UTF-16 string of at most [`MAX_NAME_UNITS`] units.
///
/// # Safety
///
/// `ptr` is null or points to UTF-16 units valid up to and including a NUL.
unsafe fn wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return "unknown".into();
    }
    let mut units = Vec::new();
    for i in 0..MAX_NAME_UNITS {
        // SAFETY: all units before the NUL are readable (caller contract);
        // `read_unaligned` asks nothing of the pointer's alignment.
        let unit = unsafe { ptr.add(i).read_unaligned() };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

/// The IP of a `sockaddr_in` / `sockaddr_in6`; `None` for other families or
/// a length too short for the family.
///
/// # Safety
///
/// `address.sockaddr` is null or valid for `address.sockaddr_length` bytes.
unsafe fn socket_address_ip(address: &SocketAddress) -> Option<IpAddr> {
    let ptr = address.sockaddr;
    if ptr.is_null() || address.sockaddr_length < 2 {
        return None;
    }
    // SAFETY: at least 2 bytes are readable (checked above).
    let family = unsafe { ptr.cast::<u16>().read_unaligned() };
    match family {
        // sockaddr_in: family, port, then 4 address bytes at offset 4.
        AF_INET if address.sockaddr_length >= SOCKADDR_IN_LEN => {
            let mut octets = [0u8; 4];
            // SAFETY: bytes 4..8 lie within the checked length.
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(4), octets.as_mut_ptr(), 4) };
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        // sockaddr_in6: family, port, flowinfo, then 16 address bytes at
        // offset 8.
        AF_INET6 if address.sockaddr_length >= SOCKADDR_IN6_LEN => {
            let mut octets = [0u8; 16];
            // SAFETY: bytes 8..24 lie within the checked length.
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(8), octets.as_mut_ptr(), 16) };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr_in(ip: [u8; 4]) -> Vec<u8> {
        let mut sa = vec![0u8; SOCKADDR_IN_LEN as usize];
        sa[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        sa[4..8].copy_from_slice(&ip);
        sa
    }

    fn sockaddr_in6(ip: &str) -> Vec<u8> {
        let mut sa = vec![0u8; SOCKADDR_IN6_LEN as usize];
        sa[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        sa[8..24].copy_from_slice(&ip.parse::<Ipv6Addr>().unwrap().octets());
        sa
    }

    fn unicast(sockaddr: &[u8], prefix: u8) -> Box<IpAdapterUnicastAddress> {
        Box::new(IpAdapterUnicastAddress {
            length: size_of::<IpAdapterUnicastAddress>() as u32,
            flags: 0,
            next: std::ptr::null(),
            address: SocketAddress {
                sockaddr: sockaddr.as_ptr(),
                sockaddr_length: sockaddr.len() as i32,
            },
            prefix_origin: 0,
            suffix_origin: 0,
            dad_state: 0,
            valid_lifetime: 0,
            preferred_lifetime: 0,
            lease_lifetime: 0,
            on_link_prefix_length: prefix,
        })
    }

    fn adapter(
        name: &[u16],
        first_unicast: *const IpAdapterUnicastAddress,
        oper_status: i32,
    ) -> Box<IpAdapterAddresses> {
        Box::new(IpAdapterAddresses {
            // The real record is longer than the declared fields.
            length: 448,
            if_index: 12,
            next: std::ptr::null(),
            adapter_name: std::ptr::null(),
            first_unicast_address: first_unicast,
            first_anycast_address: std::ptr::null(),
            first_multicast_address: std::ptr::null(),
            first_dns_server_address: std::ptr::null(),
            dns_suffix: std::ptr::null(),
            description: std::ptr::null(),
            friendly_name: name.as_ptr(),
            physical_address: [0; 8],
            physical_address_length: 6,
            flags: 0,
            mtu: 1500,
            if_type: 6,
            oper_status,
            ipv6_if_index: 7,
        })
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn summary(list: &[(u32, InterfaceInfo)]) -> Vec<(u32, &str, String, u8)> {
        list.iter()
            .map(|(idx, i)| (*idx, i.name.as_str(), i.ip.to_string(), i.prefix_len))
            .collect()
    }

    #[test]
    fn walks_adapters_and_addresses() {
        let eth_name = wide("Ethernet 3");
        let wifi_name = wide("Conexión de red inalámbrica");
        let (v4, v6, ll) = (
            sockaddr_in([192, 168, 1, 31]),
            sockaddr_in6("2001:db8:1::31"),
            sockaddr_in6("fe80::9d2e:4bfb:a4a2:eb3"),
        );
        let wifi_v4 = sockaddr_in([10, 0, 0, 5]);

        let eth_ll = unicast(&ll, 64);
        let mut eth_v6 = unicast(&v6, 64);
        let mut eth_v4 = unicast(&v4, 24);
        eth_v6.next = &*eth_ll;
        eth_v4.next = &*eth_v6;
        let wifi_addr = unicast(&wifi_v4, 8);

        let wifi = adapter(&wifi_name, &*wifi_addr, 2); // IfOperStatusDown
        let mut eth = adapter(&eth_name, &*eth_v4, IF_OPER_STATUS_UP);
        eth.next = &*wifi;

        // SAFETY: the list is built from live boxes and vectors above.
        let all = unsafe { collect(&*eth, false) };
        assert_eq!(
            summary(&all),
            vec![
                (12, "Ethernet 3", "192.168.1.31".to_string(), 24),
                (7, "Ethernet 3", "2001:db8:1::31".to_string(), 64),
                (7, "Ethernet 3", "fe80::9d2e:4bfb:a4a2:eb3".to_string(), 64),
                (12, "Conexión de red inalámbrica", "10.0.0.5".to_string(), 8),
            ]
        );

        // SAFETY: as above.
        let up = unsafe { collect(&*eth, true) };
        assert_eq!(up.len(), 3);
        assert!(up.iter().all(|(_, i)| i.name == "Ethernet 3"));
    }

    #[test]
    fn skips_what_it_cannot_read() {
        let name = wide("Ethernet");
        let loopback = sockaddr_in([127, 0, 0, 1]);
        let short = vec![2u8, 0, 0, 0]; // AF_INET, but only 4 bytes
        let other_family = vec![0u8; 28]; // family 0
        let good = sockaddr_in6("::1");

        let a_good = unicast(&good, 255); // 255: unknown prefix
        let mut a_other = unicast(&other_family, 64);
        let mut a_short = unicast(&short, 24);
        let mut a_loop = unicast(&loopback, 8);
        a_other.next = &*a_good;
        a_short.next = &*a_other;
        a_loop.next = &*a_short;

        let eth = adapter(&name, &*a_loop, IF_OPER_STATUS_UP);
        // SAFETY: the list is built from live boxes and vectors above.
        let list = unsafe { collect(&*eth, false) };
        assert_eq!(summary(&list), vec![(7, "Ethernet", "::1".to_string(), 0)]);

        // SAFETY: null is an empty list.
        assert!(unsafe { collect(std::ptr::null(), false) }.is_empty());
    }

    #[test]
    fn stops_at_a_record_too_short_to_read() {
        let name = wide("Ethernet");
        let v4 = sockaddr_in([192, 168, 1, 31]);
        let addr = unicast(&v4, 24);
        let mut second = adapter(&name, &*addr, IF_OPER_STATUS_UP);
        second.length = 16; // older, shorter record: fields beyond are not there
        let mut first = adapter(&name, &*addr, IF_OPER_STATUS_UP);
        first.next = &*second;

        // SAFETY: the list is built from live boxes and vectors above.
        let list = unsafe { collect(&*first, false) };
        assert_eq!(list.len(), 1);

        // The same for an address record.
        let mut short_addr = unicast(&v4, 24);
        short_addr.length -= 8;
        let eth = adapter(&name, &*short_addr, IF_OPER_STATUS_UP);
        // SAFETY: as above.
        assert!(unsafe { collect(&*eth, false) }.is_empty());
    }

    /// The real call, on the real system: every Windows host has at least
    /// the loopback pseudo-interface with `::1`, and every adapter a name.
    #[cfg(target_os = "windows")]
    #[test]
    fn system_adapter_list_is_readable() {
        let list = adapters(false).expect("GetAdaptersAddresses failed");
        assert!(!list.is_empty());
        assert!(list.iter().all(|(_, i)| !i.name.is_empty()));
        for (_, info) in &list {
            let max = if info.ip.is_ipv4() { 32 } else { 128 };
            assert!(info.prefix_len <= max, "{info:?}");
        }
        // Only adapters that are up: a subset of the full list.
        let up = adapters(true).expect("GetAdaptersAddresses failed");
        assert!(up.len() <= list.len());
    }

    #[test]
    fn names_are_bounded_and_null_safe() {
        // SAFETY: null is allowed.
        assert_eq!(unsafe { wide_string(std::ptr::null()) }, "unknown");
        // No terminator within the bound: the read stops at the bound.
        let endless = vec![b'a' as u16; MAX_NAME_UNITS + 8];
        // SAFETY: MAX_NAME_UNITS units are readable.
        assert_eq!(
            unsafe { wide_string(endless.as_ptr()) }.len(),
            MAX_NAME_UNITS
        );
    }
}
