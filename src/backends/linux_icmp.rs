//! ICMP echo backend for Linux and macOS. Prefers unprivileged `SOCK_DGRAM`
//! and falls back to `SOCK_RAW` (needs `CAP_NET_RAW`/root). On Linux, TTL and
//! the kernel receive timestamp come from `recvmsg(2)` ancillary data; on
//! macOS the IPv4 TTL is parsed from the IP header the BSD stack prepends and
//! the IPv6 hop limit comes from `recvmsg(2)` ancillary data.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::AsRawFd;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::probe::types::{ProbeOptions, ProbeResult};

/// Internet checksum (RFC 1071): one's-complement sum of 16-bit big-endian
/// words, with an odd trailing byte padded on the right.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an ICMP Echo Request (type 8) with the canonical 0..255 byte-pattern
/// payload and a precomputed checksum.
fn build_echo_request_v4(seq: u16, identifier: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut pkt = vec![0u8; total];
    pkt[0] = 8; // Type: Echo Request
    pkt[1] = 0; // Code
    pkt[4..6].copy_from_slice(&identifier.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    for i in 0..payload_size {
        pkt[8 + i] = (i & 0xff) as u8;
    }
    let cksum = checksum(&pkt);
    pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

/// Build an ICMPv6 Echo Request (type 128). The checksum is left at zero:
/// ICMPv6 checksums cover an IPv6 pseudo-header and are filled in by the
/// kernel for both DGRAM and RAW ICMPv6 sockets.
fn build_echo_request_v6(seq: u16, identifier: u16, payload_size: usize) -> Vec<u8> {
    let total = 8 + payload_size;
    let mut pkt = vec![0u8; total];
    pkt[0] = 128; // Type: ICMPv6 Echo Request
    pkt[1] = 0; // Code
    pkt[4..6].copy_from_slice(&identifier.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    for i in 0..payload_size {
        pkt[8 + i] = (i & 0xff) as u8;
    }
    pkt
}

/// Parse an ICMP Echo Reply, returning `(matched, ttl)` where `ttl > 0` only
/// when an IP header was present in the datagram.
///
/// `expected_source` filters by source IP — critical on RAW sockets, which
/// receive every ICMP packet on the host (multi-target cross-talk).
/// `expected_id` is `Some(id)` for RAW sockets (the kernel preserves our
/// identifier); for DGRAM pass `None`: Linux rewrites and demuxes it, and on
/// macOS the sender check above tells the replies apart.
fn parse_echo_reply_v4(
    data: &[u8],
    expected_seq: u16,
    expected_source: std::net::Ipv4Addr,
    expected_id: Option<u16>,
) -> (bool, u8) {
    // On RAW sockets (and macOS DGRAM) the IP header is included.
    // On Linux DGRAM the kernel strips it. Detect and skip.
    let (icmp, ip_ttl, source_ok) = if data.len() >= 28 && (data[0] >> 4) == 4 {
        let ihl = (data[0] & 0x0F) as usize * 4;
        // IHL must cover the fixed header and leave room for the ICMP header.
        if ihl < 20 || ihl + 8 > data.len() {
            return (false, 0);
        }
        let ttl = data[8];
        let src = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let ok = src == expected_source;
        (&data[ihl..], ttl, ok)
    } else {
        // No IP header (Linux DGRAM) — can't verify source, assume OK
        (data, 0u8, true)
    };

    if !source_ok {
        return (false, 0);
    }
    if icmp.len() < 8 {
        return (false, 0);
    }
    let id_ok = match expected_id {
        Some(id) => u16::from_be_bytes([icmp[4], icmp[5]]) == id,
        None => true,
    };
    // RAW sockets bypass kernel checksum validation; reject corrupted replies.
    let checksum_ok = expected_id.is_none() || checksum(icmp) == 0;
    let matched = icmp[0] == 0
        && icmp[1] == 0
        && u16::from_be_bytes([icmp[6], icmp[7]]) == expected_seq
        && id_ok
        && checksum_ok;
    (matched, ip_ttl)
}

/// Parse an ICMPv6 Echo Reply (type 129). The IPv6 header is never delivered
/// to ICMPv6 sockets, so there is no source/hop-limit extraction here.
///
/// `expected_id` is `Some(id)` where the socket also receives replies meant
/// for other sockets and the kernel leaves the identifier alone (RAW; macOS
/// DGRAM); `None` on Linux DGRAM, where the kernel rewrites the identifier
/// and demuxes by it.
fn parse_echo_reply_v6(data: &[u8], expected_seq: u16, expected_id: Option<u16>) -> bool {
    if data.len() < 8 {
        return false;
    }
    let id_ok = match expected_id {
        Some(id) => u16::from_be_bytes([data[4], data[5]]) == id,
        None => true,
    };
    data[0] == 129
        && data[1] == 0
        && u16::from_be_bytes([data[6], data[7]]) == expected_seq
        && id_ok
}

/// Whether an ICMPv6 reply received from `source` may be attributed to
/// `target`. A RAW ICMPv6 socket receives every echo reply on the host: the
/// identifier tells this backend's replies from those of the others in the
/// process, and the sender from those of another process that happens to
/// probe with the same identifier and sequence number. DGRAM sockets are not
/// checked here (Linux demuxes them; macOS relies on the identifier, since a
/// reply to an anycast target comes from another address).
///
/// A link-local target is one host per zone: when both the target and the
/// sender carry a zone index, they must agree. A sender reported without one
/// is matched by address alone.
fn v6_source_ok(is_raw: bool, source: Option<SocketAddr>, target: IpAddr, scope_id: u32) -> bool {
    if !is_raw {
        return true;
    }
    let Some(source) = source else {
        return false;
    };
    let source_scope = match source {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    source.ip() == target && (scope_id == 0 || source_scope == 0 || source_scope == scope_id)
}

/// `CLOCK_REALTIME` now, in nanoseconds since the epoch (Linux only). Paired
/// with the `SO_TIMESTAMPNS` receive stamp so the RTT excludes receive-side
/// scheduling latency.
#[cfg(target_os = "linux")]
fn realtime_nanos() -> Option<i128> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable `timespec` and `CLOCK_REALTIME` is a
    // valid clock id; `clock_gettime` writes the struct and returns 0 or -1.
    let r = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if r == 0 {
        Some(ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn realtime_nanos() -> Option<i128> {
    None
}

/// Prefer the kernel-stamped RTT (rx kernel time - tx wall time) when it is
/// plausible; fall back to the userspace measurement otherwise (missing
/// stamps, or a wall-clock step between send and receive).
fn refine_rtt(
    tx_ns: Option<i128>,
    rx_ns: Option<i128>,
    fallback: std::time::Duration,
) -> std::time::Duration {
    if let (Some(tx), Some(rx)) = (tx_ns, rx_ns) {
        let delta = rx - tx;
        if delta > 0
            && let Ok(nanos) = u64::try_from(delta)
        {
            let kernel = std::time::Duration::from_nanos(nanos);
            // The kernel stamp is taken before userspace wakes up, so it can
            // never legitimately exceed the userspace elapsed time.
            if kernel <= fallback {
                return kernel;
            }
        }
    }
    fallback
}

/// Receive with TTL / hop limit, kernel receive-timestamp (Linux) and sender
/// extraction via recvmsg. Returns `(len, ttl, rx_nanos_since_epoch, source)`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn recv_with_ttl(
    fd: i32,
    buf: &mut [u8],
) -> io::Result<(usize, u8, Option<i128>, Option<SocketAddr>)> {
    use std::ptr;

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // 8-byte alignment so CMSG_FIRSTHDR's cast to `*cmsghdr` is well-aligned;
    // a plain `[u8; N]` would not guarantee it. Holds IP_TTL (or
    // IPV6_HOPLIMIT) + SCM_TIMESTAMPNS.
    #[repr(align(8))]
    struct CmsgBuf([u8; 128]);
    let mut cmsg_buf = CmsgBuf([0u8; 128]);

    // SAFETY: all-zero bytes are a valid (empty) `msghdr`.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut libc::c_void;
    // `as _`: the field is a `size_t` on Linux and a `socklen_t` on macOS.
    msg.msg_controllen = cmsg_buf.0.len() as _;

    // SAFETY: `msg` points to a live iovec, control buffer and (inside
    // `try_init`) a zeroed `sockaddr_storage` of `*len` bytes that all outlive
    // the call; the kernel writes at most `iov_len`/`msg_controllen`/
    // `msg_namelen` bytes and stores the sender's real address length back
    // in `msg_namelen`, which is what `try_init` requires of `len`.
    let (n, sender) = unsafe {
        SockAddr::try_init(|storage, len| {
            msg.msg_name = storage.cast();
            msg.msg_namelen = *len;
            let n = libc::recvmsg(fd, &mut msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            *len = msg.msg_namelen;
            Ok(n)
        })
    }?;

    let mut ttl: u8 = 0;
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut rx_ns: Option<i128> = None;
    // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR walk the kernel-written control
    // buffer and yield either null or a pointer to a valid, aligned cmsghdr
    // within it. Payloads behind CMSG_DATA are read with `read_unaligned`
    // because the data region carries no alignment guarantee, and only when
    // the header announces a payload of at least the size read (control data
    // cut short by `MSG_CTRUNC` is skipped, not read).
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        // `size_t` on Linux, `socklen_t` on macOS.
        #[allow(clippy::unnecessary_cast)]
        let cmsg_len = hdr.cmsg_len as usize;
        let holds = |payload: usize| cmsg_len >= unsafe { libc::CMSG_LEN(payload as u32) } as usize;
        if ((hdr.cmsg_level == libc::IPPROTO_IP && hdr.cmsg_type == libc::IP_TTL)
            || (hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_HOPLIMIT))
            && holds(std::mem::size_of::<i32>())
        {
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            let val = unsafe { ptr::read_unaligned(data as *const i32) };
            ttl = val as u8;
        }
        #[cfg(target_os = "linux")]
        {
            if hdr.cmsg_level == libc::SOL_SOCKET
                && hdr.cmsg_type == libc::SCM_TIMESTAMPNS
                && holds(std::mem::size_of::<libc::timespec>())
            {
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                let ts = unsafe { ptr::read_unaligned(data as *const libc::timespec) };
                rx_ns = Some(ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128);
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    Ok((n as usize, ttl, rx_ns, sender.as_socket()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn recv_with_ttl(
    _fd: i32,
    _buf: &mut [u8],
) -> io::Result<(usize, u8, Option<i128>, Option<SocketAddr>)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "recvmsg not available on this platform",
    ))
}

/// Echo identifier of the `n`-th backend created by process `pid`: the pid
/// for the first one, like `ping`, and a different value for each of the
/// next 65535 (an odd multiplier is a bijection on `u16`).
fn identifier_for(pid: u16, n: u16) -> u16 {
    pid ^ n.wrapping_mul(0x9E37)
}

/// Identifier for a new backend, unique among the backends of this process:
/// a socket that also receives the replies of the others (RAW; macOS DGRAM)
/// recognizes its own by it. Their sequence numbers advance in lockstep, so
/// the sequence number alone cannot.
fn next_identifier() -> u16 {
    static CREATED: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let n = CREATED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    identifier_for(std::process::id() as u16, n)
}

/// A value drawn once per process from the operating system's random source
/// (the keys of the standard library's hasher).
fn process_salt() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    static SALT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SALT.get_or_init(|| {
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    })
}

/// Sequence number sent on the wire for the probe `seq`. Sixteen bits of
/// identifier cannot be unique across processes: two of them may hold the
/// same one. Each process therefore counts from its own random offset, so
/// that their sequence numbers are unlikely to line up as well. This makes
/// a mix-up between processes improbable; it cannot rule it out.
fn seq_on_wire(seq: u16, offset: u16) -> u16 {
    seq.wrapping_add(offset)
}

/// Linux/macOS ICMP backend (DGRAM, with RAW fallback when DGRAM is denied).
pub struct LinuxIcmpBackend {
    socket: Socket,
    identifier: u16,
    /// See [`seq_on_wire`].
    seq_offset: u16,
    is_v6: bool,
    is_raw: bool,
}

/// Enable SO_TIMESTAMPNS kernel receive timestamps (Linux only, best-effort).
#[cfg(target_os = "linux")]
fn enable_rx_timestamps(socket: &Socket) {
    // SAFETY: passes a pointer to a live c_int and its exact size to
    // setsockopt on a valid fd. Best-effort: without kernel stamps,
    // `refine_rtt` falls back to the userspace measurement.
    unsafe {
        let val: libc::c_int = 1;
        let _ = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_rx_timestamps(_socket: &Socket) {}

/// Try DGRAM first; on `PermissionDenied`, fall back to RAW. Returns
/// `(socket, is_raw)`.
fn open_icmp_socket(domain: Domain, proto: Protocol) -> io::Result<(Socket, bool)> {
    match Socket::new(domain, Type::DGRAM, Some(proto)) {
        Ok(s) => Ok((s, false)),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            // RAW socket — kernel does not rewrite the ICMP identifier, so
            // replies must be filtered by id (see `is_raw` in `parse_echo_reply_v4`).
            // SOCK_RAW is hidden behind socket2's "all" feature; access it
            // directly via libc to avoid an extra cargo feature.
            let raw = Socket::new(domain, Type::from(libc::SOCK_RAW), Some(proto))?;
            Ok((raw, true))
        }
        Err(e) => Err(e),
    }
}

impl LinuxIcmpBackend {
    /// Create an IPv4 ICMP backend.
    ///
    /// # Errors
    ///
    /// Fails when no ICMP socket can be opened (no `ping_group_range`
    /// membership and no `CAP_NET_RAW`).
    pub fn new() -> io::Result<Self> {
        let (socket, is_raw) = open_icmp_socket(Domain::IPV4, Protocol::ICMPV4)?;
        socket.set_nonblocking(false)?;
        // Request IP_TTL ancillary data on received datagrams (Linux only).
        // SAFETY: passes a pointer to a live c_int and its exact size to
        // setsockopt on a valid fd.
        #[cfg(target_os = "linux")]
        unsafe {
            let val: libc::c_int = 1;
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        enable_rx_timestamps(&socket);
        let identifier = next_identifier();
        Ok(Self {
            socket,
            identifier,
            seq_offset: process_salt() as u16,
            is_v6: false,
            is_raw,
        })
    }

    /// Create an IPv6 ICMPv6 backend (DGRAM with RAW fallback).
    ///
    /// # Errors
    ///
    /// Fails when no ICMPv6 socket can be opened (no `ping_group_range`
    /// membership and no `CAP_NET_RAW`).
    pub fn new_v6() -> io::Result<Self> {
        let (socket, is_raw) = open_icmp_socket(Domain::IPV6, Protocol::ICMPV6)?;
        socket.set_nonblocking(false)?;
        // Request IPV6_HOPLIMIT ancillary data on received datagrams:
        // neither socket type delivers the IPv6 header in the payload.
        // Best-effort: without it the reply simply carries no hop limit.
        // SAFETY: passes a pointer to a live c_int and its exact size to
        // setsockopt on a valid fd.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        unsafe {
            let val: libc::c_int = 1;
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVHOPLIMIT,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        enable_rx_timestamps(&socket);
        let identifier = next_identifier();
        Ok(Self {
            socket,
            identifier,
            seq_offset: process_salt() as u16,
            is_v6: true,
            is_raw,
        })
    }

    /// Bind to a network interface (`SO_BINDTODEVICE`, Linux only; no-op
    /// elsewhere).
    ///
    /// # Errors
    ///
    /// `InvalidInput` on a NUL byte in the name; `PermissionDenied` without
    /// `CAP_NET_RAW`/root.
    pub fn bind_interface(&self, iface: &str) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            let name = CString::new(iface).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name")
            })?;
            // SAFETY: `name` is a live NUL-terminated C string; the length
            // passed includes the terminator, as SO_BINDTODEVICE expects.
            unsafe {
                let ret = libc::setsockopt(
                    self.socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name.as_ptr() as *const libc::c_void,
                    name.to_bytes_with_nul().len() as libc::socklen_t,
                );
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::PermissionDenied {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "permission denied binding to interface '{iface}'. \
                                 SO_BINDTODEVICE requires CAP_NET_RAW or root."
                            ),
                        ));
                    }
                    return Err(err);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = iface;
        }
        Ok(())
    }

    /// Bind to a specific source address. `scope_id` is the target's IPv6
    /// zone: a link-local source lives in the same zone as the target it
    /// talks to, and the kernel refuses to bind one without it.
    ///
    /// # Errors
    ///
    /// OS error if the address is not local or its family mismatches.
    pub fn bind_source(&self, addr: IpAddr, scope_id: u32) -> io::Result<()> {
        let sa = match addr {
            IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
                SocketAddr::V6(std::net::SocketAddrV6::new(v6, 0, 0, scope_id))
            }
            _ => SocketAddr::new(addr, 0),
        };
        self.socket.bind(&SockAddr::from(sa))
    }

    /// The identifier a reply must carry, where that can be checked. A RAW
    /// socket receives every echo reply on the host with its identifier
    /// intact. So does a macOS DGRAM ICMPv6 socket: the kernel hands every
    /// ICMPv6 socket every echo reply and does not rewrite the identifier.
    /// (macOS DGRAM IPv4 keeps matching by sender, from the IP header.)
    /// Linux DGRAM sockets get their own replies only, under an identifier
    /// the kernel chose: nothing to check.
    fn expected_id(&self) -> Option<u16> {
        (self.is_raw || (cfg!(target_os = "macos") && self.is_v6)).then_some(self.identifier)
    }

    /// Whether replies are read with `recvmsg` (ancillary data) instead of
    /// socket2's plain receive: always on Linux; on macOS only for IPv6,
    /// whose hop limit travels in ancillary data (the IPv4 TTL there comes
    /// from the IP header in the datagram).
    fn reads_ancillary_data(&self) -> bool {
        cfg!(target_os = "linux") || (cfg!(target_os = "macos") && self.is_v6)
    }

    /// Set the outgoing TTL (IPv4) or unicast hop limit (IPv6).
    ///
    /// # Errors
    ///
    /// OS error if the socket option cannot be applied.
    pub fn set_ttl(&self, ttl: u8) -> io::Result<()> {
        if self.is_v6 {
            self.socket.set_unicast_hops_v6(ttl as u32)
        } else {
            self.socket.set_ttl(ttl as u32)
        }
    }

    /// Send one ICMP echo and wait for reply. Blocking — call from spawn_blocking.
    pub fn ping(&self, opts: &ProbeOptions, seq: u16) -> ProbeResult {
        if self.socket.set_read_timeout(Some(opts.timeout)).is_err() {
            return ProbeResult::Error {
                seq: seq as u64,
                message: "failed to set socket timeout".into(),
            };
        }

        let expected_v4 = match opts.target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
        };
        let dest = SockAddr::from(match opts.target {
            IpAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(v6, 0, 0, opts.scope_id)),
            ip => SocketAddr::new(ip, 0),
        });
        // `seq` names the probe to the caller; the packets carry `wire_seq`.
        let wire_seq = seq_on_wire(seq, self.seq_offset);
        let packet = if self.is_v6 {
            build_echo_request_v6(wire_seq, self.identifier, opts.payload_size)
        } else {
            build_echo_request_v4(wire_seq, self.identifier, opts.payload_size)
        };
        // `start` first: the plausibility guard in `refine_rtt` compares the
        // kernel-stamped RTT against `start.elapsed()`, so the wall stamp must
        // not predate the monotonic one.
        let start = Instant::now();
        let tx_ns = realtime_nanos();

        if let Err(e) = self.socket.send_to(&packet, &dest) {
            return ProbeResult::Error {
                seq: seq as u64,
                message: format!("send failed: {e}"),
            };
        }

        let expected_id = self.expected_id();
        // Full reply size: payload + 8-byte ICMP header + up to 60 bytes of
        // IPv4 header on RAW. Truncation would fail the RAW checksum check and
        // turn every large-payload probe into a timeout.
        let buf_len = (opts.payload_size + 68).max(2048);
        let mut buf = vec![0u8; buf_len];
        let mut fallback_buf: Option<Vec<MaybeUninit<u8>>> = None;
        let fd = self.as_raw_fd();
        loop {
            let result = if self.reads_ancillary_data() {
                recv_with_ttl(fd, &mut buf)
            } else {
                Err(io::ErrorKind::Unsupported.into())
            };
            match result {
                Ok((n, ttl, rx_ns, source)) => {
                    let rtt = refine_rtt(tx_ns, rx_ns, start.elapsed());
                    let (ok, ip_ttl) = if self.is_v6 {
                        (
                            v6_source_ok(self.is_raw, source, opts.target, opts.scope_id)
                                && parse_echo_reply_v6(&buf[..n], wire_seq, expected_id),
                            0,
                        )
                    } else {
                        parse_echo_reply_v4(&buf[..n], wire_seq, expected_v4, expected_id)
                    };
                    if ok {
                        // Use TTL from IP header (macOS) if recvmsg TTL is 0
                        let final_ttl = if ttl > 0 { ttl } else { ip_ttl };
                        return ProbeResult::Reply {
                            seq: seq as u64,
                            rtt,
                            ttl: final_ttl,
                        };
                    }
                    if self.rearm_timeout(start, opts.timeout).is_none() {
                        return ProbeResult::Timeout { seq: seq as u64 };
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    if self.rearm_timeout(start, opts.timeout).is_none() {
                        return ProbeResult::Timeout { seq: seq as u64 };
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return ProbeResult::Timeout { seq: seq as u64 };
                }
                // macOS IPv6: recvmsg is the receive path itself, so its
                // errors are final, as those of the plain receive below are.
                // Receiving again would wait a second time for a datagram
                // that may already have been consumed.
                Err(e) if cfg!(target_os = "macos") && self.is_v6 => {
                    return ProbeResult::Error {
                        seq: seq as u64,
                        message: format!("recv failed: {e}"),
                    };
                }
                Err(_) => {
                    // Fall back to socket2's recv when recvmsg is unavailable
                    // (macOS IPv4) or failed; TTL then comes from the IP header.
                    let mbuf = fallback_buf
                        .get_or_insert_with(|| vec![MaybeUninit::<u8>::uninit(); buf_len]);
                    match self.socket.recv_from(mbuf) {
                        Ok((n, sender)) => {
                            let rtt = start.elapsed();
                            // SAFETY: recv_from initialized the first `n` bytes.
                            let data = unsafe {
                                std::slice::from_raw_parts(mbuf.as_ptr().cast::<u8>(), n)
                            };
                            let source = sender.as_socket();
                            let (ok, ip_ttl) = if self.is_v6 {
                                (
                                    v6_source_ok(self.is_raw, source, opts.target, opts.scope_id)
                                        && parse_echo_reply_v6(data, wire_seq, expected_id),
                                    0,
                                )
                            } else {
                                parse_echo_reply_v4(data, wire_seq, expected_v4, expected_id)
                            };
                            if ok {
                                return ProbeResult::Reply {
                                    seq: seq as u64,
                                    rtt,
                                    ttl: ip_ttl,
                                };
                            }
                            if self.rearm_timeout(start, opts.timeout).is_none() {
                                return ProbeResult::Timeout { seq: seq as u64 };
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                            if self.rearm_timeout(start, opts.timeout).is_none() {
                                return ProbeResult::Timeout { seq: seq as u64 };
                            }
                        }
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::TimedOut =>
                        {
                            return ProbeResult::Timeout { seq: seq as u64 };
                        }
                        Err(e) => {
                            return ProbeResult::Error {
                                seq: seq as u64,
                                message: format!("recv failed: {e}"),
                            };
                        }
                    }
                }
            }
        }
    }

    /// Shrink the socket read timeout to the remaining probe budget.
    /// Returns `None` when the budget is exhausted.
    fn rearm_timeout(&self, start: Instant, timeout: std::time::Duration) -> Option<()> {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return None;
        }
        let remaining = (timeout - elapsed).max(std::time::Duration::from_millis(1));
        let _ = self.socket.set_read_timeout(Some(remaining));
        Some(())
    }

    fn as_raw_fd(&self) -> i32 {
        use std::os::unix::io::AsRawFd;
        self.socket.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic RAW-style echo reply: 20-byte IP header + ICMP (8 hdr + 4 payload).
    fn echo_reply_raw(seq: u16, id: u16, src: [u8; 4], first_byte: u8) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = first_byte;
        ip[8] = 57; // TTL
        ip[12..16].copy_from_slice(&src);
        let mut icmp = vec![0u8; 12];
        icmp[0] = 0; // Type: Echo Reply
        icmp[1] = 0; // Code
        icmp[4..6].copy_from_slice(&id.to_be_bytes());
        icmp[6..8].copy_from_slice(&seq.to_be_bytes());
        let ck = checksum(&icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());
        ip.extend_from_slice(&icmp);
        ip
    }

    const SRC: [u8; 4] = [8, 8, 8, 8];

    fn src_ip() -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(8, 8, 8, 8)
    }

    #[test]
    fn raw_reply_matches() {
        let pkt = echo_reply_raw(7, 42, SRC, 0x45);
        assert_eq!(parse_echo_reply_v4(&pkt, 7, src_ip(), Some(42)), (true, 57));
    }

    #[test]
    fn raw_reply_wrong_source_rejected() {
        let pkt = echo_reply_raw(7, 42, [9, 9, 9, 9], 0x45);
        assert_eq!(parse_echo_reply_v4(&pkt, 7, src_ip(), Some(42)), (false, 0));
    }

    #[test]
    fn raw_reply_wrong_id_rejected() {
        let pkt = echo_reply_raw(7, 42, SRC, 0x45);
        assert!(!parse_echo_reply_v4(&pkt, 7, src_ip(), Some(43)).0);
    }

    #[test]
    fn malformed_ihl_too_large_no_panic() {
        // IHL=15 claims a 60-byte header but the packet is only 32 bytes.
        let pkt = echo_reply_raw(7, 42, SRC, 0x4F);
        assert_eq!(parse_echo_reply_v4(&pkt, 7, src_ip(), Some(42)), (false, 0));
    }

    #[test]
    fn malformed_ihl_too_small_rejected() {
        // IHL=4 (16 bytes) is below the minimum IPv4 header size.
        let pkt = echo_reply_raw(7, 42, SRC, 0x44);
        assert_eq!(parse_echo_reply_v4(&pkt, 7, src_ip(), Some(42)), (false, 0));
    }

    #[test]
    fn corrupted_checksum_rejected_on_raw() {
        let mut pkt = echo_reply_raw(7, 42, SRC, 0x45);
        let last = pkt.len() - 1;
        pkt[last] ^= 0xFF; // corrupt payload without touching the checksum
        assert!(!parse_echo_reply_v4(&pkt, 7, src_ip(), Some(42)).0);
    }

    #[test]
    fn nonzero_code_rejected() {
        let mut pkt = echo_reply_raw(7, 42, SRC, 0x45);
        pkt[21] = 3; // ICMP code
        // Recompute checksum so only the code check can reject it.
        pkt[22] = 0;
        pkt[23] = 0;
        let ck = checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&ck.to_be_bytes());
        assert!(!parse_echo_reply_v4(&pkt, 7, src_ip(), Some(42)).0);
    }

    #[test]
    fn dgram_reply_without_ip_header_matches() {
        // Linux DGRAM: kernel strips the IP header and rewrites the identifier.
        let mut icmp = vec![0u8; 12];
        icmp[6..8].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(parse_echo_reply_v4(&icmp, 7, src_ip(), None), (true, 0));
    }

    #[test]
    fn refine_rtt_prefers_plausible_kernel_stamp() {
        use std::time::Duration;
        let fallback = Duration::from_millis(10);
        // Kernel says 4 ms, userspace says 10 ms → kernel wins.
        let rtt = refine_rtt(Some(1_000_000_000), Some(1_004_000_000), fallback);
        assert_eq!(rtt, Duration::from_millis(4));
        // Kernel stamp exceeds userspace elapsed (clock step) → fallback.
        let rtt = refine_rtt(Some(1_000_000_000), Some(1_020_000_000), fallback);
        assert_eq!(rtt, fallback);
        // Negative delta (clock step backwards) → fallback.
        let rtt = refine_rtt(Some(2_000_000_000), Some(1_000_000_000), fallback);
        assert_eq!(rtt, fallback);
        // Missing stamps → fallback.
        assert_eq!(refine_rtt(None, Some(1), fallback), fallback);
        assert_eq!(refine_rtt(Some(1), None, fallback), fallback);
    }

    #[test]
    fn v6_reply_id_filter() {
        let mut pkt = vec![0u8; 12];
        pkt[0] = 129;
        pkt[1] = 0;
        pkt[4..6].copy_from_slice(&42u16.to_be_bytes());
        pkt[6..8].copy_from_slice(&7u16.to_be_bytes());
        assert!(parse_echo_reply_v6(&pkt, 7, Some(42)));
        assert!(!parse_echo_reply_v6(&pkt, 7, Some(43)));
        assert!(parse_echo_reply_v6(&pkt, 7, None));
        pkt[1] = 1; // non-zero code
        assert!(!parse_echo_reply_v6(&pkt, 7, None));
    }

    /// Every backend of a process gets an identifier of its own.
    #[test]
    fn identifiers_are_unique_per_backend() {
        for pid in [0u16, 1, 4242, u16::MAX] {
            assert_eq!(identifier_for(pid, 0), pid);
            let mut seen = vec![false; 1 << 16];
            for n in 0..=u16::MAX {
                let id = identifier_for(pid, n) as usize;
                assert!(
                    !seen[id],
                    "pid {pid}: identifier {id} repeats at backend {n}"
                );
                seen[id] = true;
            }
        }
        assert_ne!(next_identifier(), next_identifier());
    }

    /// Two processes may hold the same identifier; with different offsets
    /// their sequence numbers differ for every probe, and the caller's
    /// numbering is untouched by the offset.
    #[test]
    fn wire_sequence_starts_from_the_process_offset() {
        assert_eq!(seq_on_wire(1, 0), 1);
        assert_eq!(seq_on_wire(1, 41_000), 41_001);
        assert_eq!(seq_on_wire(u16::MAX, 2), 1); // wraps
        for seq in [0u16, 1, 500, u16::MAX] {
            assert_ne!(seq_on_wire(seq, 7), seq_on_wire(seq, 8));
        }
        // One offset per process: every backend created here shares it.
        assert_eq!(process_salt(), process_salt());
    }

    /// macOS hands every ICMPv6 socket every echo reply, identifier intact:
    /// a backend must not take the reply to another backend's probe for its
    /// own, even with the same sequence number.
    #[cfg(target_os = "macos")]
    #[test]
    fn v6_reply_to_another_backend_is_not_ours() {
        let target = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let (Ok(ours), Ok(other)) = (LinuxIcmpBackend::new_v6(), LinuxIcmpBackend::new_v6()) else {
            return; // no ICMPv6 socket permission in this environment
        };
        assert_ne!(ours.identifier, other.identifier);
        let seq = 9;
        let packet = build_echo_request_v6(seq, other.identifier, 8);
        let dest = SockAddr::from(SocketAddr::new(target, 0));
        if other.socket.send_to(&packet, &dest).is_err() {
            return; // no IPv6 loopback in this environment
        }
        // Read what reaches `ours` for a while: the other backend's reply
        // may be among it, and must not pass as a reply to `ours`.
        let start = Instant::now();
        let budget = std::time::Duration::from_millis(500);
        let mut buf = [0u8; 128];
        while ours.rearm_timeout(start, budget).is_some() {
            let Ok((n, ..)) = recv_with_ttl(ours.as_raw_fd(), &mut buf) else {
                break;
            };
            assert!(
                !parse_echo_reply_v6(&buf[..n], seq, ours.expected_id()),
                "took another backend's reply for our own"
            );
        }
    }

    fn sender(ip: IpAddr, scope_id: u32) -> SocketAddr {
        match ip {
            IpAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(v6, 0, 0, scope_id)),
            ip => SocketAddr::new(ip, 0),
        }
    }

    #[test]
    fn v6_raw_reply_from_other_target_rejected() {
        let target: IpAddr = "fd00::1".parse().unwrap();
        let other: IpAddr = "fd00::2".parse().unwrap();
        assert!(v6_source_ok(true, Some(sender(target, 0)), target, 0));
        assert!(!v6_source_ok(true, Some(sender(other, 0)), target, 0));
        assert!(!v6_source_ok(true, None, target, 0));
    }

    /// The same link-local address in another zone is another host.
    #[test]
    fn v6_raw_reply_from_other_zone_rejected() {
        let target: IpAddr = "fe80::1".parse().unwrap();
        assert!(v6_source_ok(true, Some(sender(target, 2)), target, 2));
        assert!(!v6_source_ok(true, Some(sender(target, 3)), target, 2));
        // A sender reported without a zone, or a target probed without one,
        // is matched by address alone.
        assert!(v6_source_ok(true, Some(sender(target, 0)), target, 2));
        assert!(v6_source_ok(true, Some(sender(target, 3)), target, 0));
    }

    #[test]
    fn v6_dgram_reply_source_not_checked() {
        let target: IpAddr = "fd00::1".parse().unwrap();
        let other: IpAddr = "fd00::2".parse().unwrap();
        assert!(v6_source_ok(false, Some(sender(other, 0)), target, 0));
        assert!(v6_source_ok(false, None, target, 0));
    }

    /// The RAW ICMPv6 source filter depends on recvmsg reporting the sender,
    /// and the TTL column on it reporting the hop limit.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn recv_reports_sender_and_hop_limit_on_loopback() {
        let target = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let Ok(backend) = LinuxIcmpBackend::new_v6() else {
            return; // no ICMPv6 socket permission in this environment
        };
        let packet = build_echo_request_v6(1, backend.identifier, 8);
        let dest = SockAddr::from(SocketAddr::new(target, 0));
        if backend.socket.send_to(&packet, &dest).is_err() {
            return; // no IPv6 loopback in this environment
        }
        let expected_id = backend.expected_id();
        let start = Instant::now();
        let budget = std::time::Duration::from_secs(2);
        let mut buf = [0u8; 128];
        // A RAW socket also delivers unrelated ICMPv6 (our own request, NDP,
        // router advertisements): read until our reply shows up.
        loop {
            assert!(
                backend.rearm_timeout(start, budget).is_some(),
                "no echo reply from ::1 within {budget:?}"
            );
            let (n, hop_limit, _, source) =
                recv_with_ttl(backend.as_raw_fd(), &mut buf).expect("echo reply from ::1");
            if parse_echo_reply_v6(&buf[..n], 1, expected_id) {
                assert_eq!(source.map(|s| s.ip()), Some(target));
                assert!(hop_limit > 0, "IPV6_HOPLIMIT missing from the reply");
                return;
            }
        }
    }
}
