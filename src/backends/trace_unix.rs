//! Trace prober for Linux and macOS (`probe::trace`): ICMP echo requests with
//! a TTL (IPv6 hop limit) per round, on a socket and identifier of its own.
//!
//! Linux: a DGRAM ICMP socket (RAW when DGRAM is denied) with `IP_RECVERR` /
//! `IPV6_RECVERR`. The ICMP errors about our probes (time exceeded,
//! unreachable) arrive on the socket's error queue with the router's address
//! and the probe as it was sent; echo replies arrive on the normal queue. An
//! error queued with `IP_RECVERR` also leaves its errno pending on the
//! socket: a DGRAM socket fails its next send with it, a RAW one its next
//! receive (measured on Linux 6.12). Reading the error queue clears it, so
//! the queue is read before every send and whenever an operation fails with
//! such an errno.
//!
//! macOS, IPv4 only: a DGRAM ICMP socket (RAW when DGRAM is denied), which
//! needs no root and gets every ICMP message of the host, errors included,
//! on its normal queue, with the IPv4 header in front and the identifier as
//! sent (measured on macOS 27, step 1b of 1.7: E1 and E2). BSD hands `ip_len`
//! over in host byte order, the outer one without its header, so no IP length
//! is read and no error's checksum is checked. IPv6 was not measured there:
//! such a trace is `Unavailable(Platform)`.
//!
//! A probe is ours when the echo quoted back (in an error) or echoed (in a
//! reply) carries a sequence number of the round in progress, our identifier
//! where the kernel leaves it alone (RAW, macOS), and the trace's nonce, which
//! opens the payload; on macOS also when the quoted packet is ICMP to the
//! target, and the echo reply comes from it. Main probes, other traces and
//! late answers do not pass. Where the kernel does not demux (RAW, macOS),
//! another process's trace to the same target can pass only with our
//! identifier and sequence number, quoted by a router that cites 8 bytes of
//! ICMP (no nonce): improbable, not ruled out.

// Each platform leaves the other's parsers unused (the error queue's on
// macOS, `macos_answer` on Linux, where the tests use it); `is_raw` is for
// the tests.
#![allow(dead_code)]
#![cfg_attr(not(target_os = "linux"), allow(unused_imports))]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use socket2::{SockAddr, Socket};

use crate::context::dns::ResolvedAddr;
use crate::probe::trace::{
    HopProbe, HopProber, Interrupted, OpenError, OtherReply, ReplyKind, Round, TraceOptions,
    UnreachableKind,
};

/// `sock_extended_err.ee_origin` values (`linux/errqueue.h`).
const SO_EE_ORIGIN_ICMP: u8 = 2;
const SO_EE_ORIGIN_ICMP6: u8 = 3;

/// Longest a wait goes without looking at the cancel flag.
const CANCEL_CHECK: Duration = Duration::from_millis(100);

/// Most entries read from a queue in one go. A RAW socket receives every
/// ICMP message of the host, so a busy host could keep a queue from ever
/// emptying: the wait loop looks at the cancel flag and the deadline between
/// batches.
const DRAIN_BATCH: usize = 64;

/// The trace prober of Linux and macOS.
pub struct UnixHopProber {
    socket: Socket,
    target: IpAddr,
    scope_id: u32,
    dest: SockAddr,
    is_v6: bool,
    is_raw: bool,
    identifier: u16,
    nonce: [u8; 8],
    payload_size: usize,
}

impl UnixHopProber {
    /// Open the trace socket for `target`: DGRAM, RAW when DGRAM is denied,
    /// bound like the probe (`-I` where the platform binds one, `-S`).
    ///
    /// # Errors
    ///
    /// `Unavailable(Permission)` when no ICMP socket may be opened,
    /// `Unavailable(Platform)` for an IPv6 target on macOS (not measured
    /// there), `Local` for anything else that keeps the socket from being
    /// prepared.
    pub fn open(target: ResolvedAddr, opts: &TraceOptions) -> Result<Self, OpenError> {
        use socket2::{Domain, Protocol};

        let local = |what: &str, e: io::Error| OpenError::Local(format!("{what}: {e}"));
        let is_v6 = target.ip.is_ipv6();
        if cfg!(target_os = "macos") && is_v6 {
            return Err(OpenError::Unavailable(
                crate::probe::trace::Unavailable::Platform,
            ));
        }
        let (domain, proto) = if is_v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let (socket, is_raw) = super::linux_icmp::open_icmp_socket(domain, proto).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                OpenError::Unavailable(crate::probe::trace::Unavailable::Permission)
            } else {
                local("cannot open an ICMP socket", e)
            }
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|e| local("cannot make the ICMP socket non-blocking", e))?;
        // macOS hands the errors over on the normal queue (module docs).
        #[cfg(target_os = "linux")]
        {
            let (level, name) = if is_v6 {
                (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
            } else {
                (libc::IPPROTO_IP, libc::IP_RECVERR)
            };
            set_int_option(&socket, level, name, 1)
                .map_err(|e| local("cannot ask for ICMP errors on the socket", e))?;
        }
        if let Some(iface) = &opts.interface {
            // As for the probe, which warns: a failure leaves it unbound.
            let _ = super::linux_icmp::bind_device(&socket, iface);
        }
        if let Some(source) = opts.source {
            super::linux_icmp::bind_source_addr(&socket, source, target.scope_id)
                .map_err(|e| local(&format!("cannot bind the trace to {source}"), e))?;
        }
        Ok(Self {
            socket,
            target: target.ip,
            scope_id: target.scope_id,
            dest: SockAddr::from(target.socket_addr(0)),
            is_v6,
            is_raw,
            identifier: super::linux_icmp::trace_identifier(),
            nonce: fresh_nonce(),
            payload_size: opts.payload_size,
        })
    }

    /// Whether the socket is RAW (DGRAM was denied).
    pub fn is_raw(&self) -> bool {
        self.is_raw
    }
}

/// Eight bytes that tell this trace's probes from any other's: drawn from
/// the standard library's per-instance random hasher keys.
fn fresh_nonce() -> [u8; 8] {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
        .to_be_bytes()
}

#[cfg(target_os = "linux")]
fn set_int_option(
    socket: &Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: passes a pointer to a live c_int and its exact size to
    // setsockopt on a valid fd.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl HopProber for UnixHopProber {
    fn probe_round(
        &mut self,
        ttl: u8,
        seqs: &[u16],
        probe_timeout: Duration,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Round {
        let mut state = RoundState::new(seqs, probe_timeout);
        let set = if self.is_v6 {
            self.socket.set_unicast_hops_v6(ttl as u32)
        } else {
            self.socket.set_ttl(ttl as u32)
        };
        if let Err(e) = set {
            for i in 0..seqs.len() {
                state.not_sent(i, format!("cannot set the TTL: {e}"));
            }
            return state.into_round(None);
        }

        for (i, &seq) in seqs.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return state.into_round(Some(Interrupted::Cancel));
            }
            if Instant::now() >= deadline {
                return state.into_round(Some(Interrupted::Budget));
            }
            self.send_probe(&mut state, i, seq);
        }
        let interrupted = self.wait(&mut state, deadline, cancel);
        state.into_round(interrupted)
    }
}

impl UnixHopProber {
    fn fd(&self) -> libc::c_int {
        use std::os::unix::io::AsRawFd;
        self.socket.as_raw_fd()
    }

    /// Send probe `i` of the round. On Linux the error queue is read first:
    /// an error still queued from an earlier probe would fail this send.
    fn send_probe(&self, state: &mut RoundState, i: usize, seq: u16) {
        let packet = echo_request(
            self.is_v6,
            self.identifier,
            seq,
            &self.nonce,
            self.payload_size,
        );
        #[cfg(target_os = "linux")]
        {
            self.read_errors(state);
            match self.socket.send_to(&packet, &self.dest) {
                Ok(_) => state.sent(i, Instant::now()),
                Err(first) => {
                    // An error that arrived between the read and the send:
                    // read it (clearing the errno) and send once more.
                    if self.read_errors(state) > 0 {
                        match self.socket.send_to(&packet, &self.dest) {
                            Ok(_) => state.sent(i, Instant::now()),
                            Err(e) => state.not_sent(i, format!("send failed: {e}")),
                        }
                    } else {
                        state.not_sent(i, format!("send failed: {first}"));
                    }
                }
            }
        }
        #[cfg(target_os = "macos")]
        match self.socket.send_to(&packet, &self.dest) {
            Ok(_) => state.sent(i, Instant::now()),
            Err(e) => state.not_sent(i, format!("send failed: {e}")),
        }
    }

    /// Wait for the round's answers until every sent probe is settled, or
    /// the cancel flag or the deadline cuts it short.
    fn wait(
        &self,
        state: &mut RoundState,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Option<Interrupted> {
        loop {
            let now = Instant::now();
            state.expire(now);
            if state.done() {
                return None;
            }
            if cancel.load(Ordering::Relaxed) {
                return Some(Interrupted::Cancel);
            }
            if now >= deadline {
                return Some(Interrupted::Budget);
            }
            let until = state.next_expiry().map_or(deadline, |at| at.min(deadline));
            let wait = until.saturating_duration_since(now).min(CANCEL_CHECK);
            // Round up: a 0 ms poll would spin until the expiry.
            let ms = wait.as_micros().div_ceil(1000).max(1) as libc::c_int;
            let mut pfd = libc::pollfd {
                fd: self.fd(),
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            };
            // SAFETY: one live `pollfd` on a valid fd, count 1.
            let ready = unsafe { libc::poll(&mut pfd, 1, ms) };
            if ready < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                state.fail_pending(&format!("poll failed: {e}"));
                return None;
            }
            if pfd.revents & libc::POLLERR != 0 {
                #[cfg(target_os = "linux")]
                self.read_errors(state);
                // No error queue: take the pending socket error, or poll
                // would keep returning at once.
                #[cfg(target_os = "macos")]
                let _ = self.socket.take_error();
            }
            if pfd.revents & libc::POLLIN != 0
                && let Err(e) = self.read_replies(state)
            {
                state.fail_pending(&format!("recv failed: {e}"));
                return None;
            }
        }
    }

    /// Read the error queue, up to [`DRAIN_BATCH`] entries, settling the
    /// probes it speaks of. Returns how many entries were read.
    #[cfg(target_os = "linux")]
    fn read_errors(&self, state: &mut RoundState) -> usize {
        let mut buf = [0u8; 512];
        let mut count = 0;
        while count < DRAIN_BATCH {
            match recv_queued_error(self.fd(), &mut buf) {
                Ok(Some((n, err))) => {
                    count += 1;
                    if let Some(err) = err {
                        self.take_error(state, &buf[..n], err, Instant::now());
                    }
                }
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        count
    }

    #[cfg(target_os = "linux")]
    fn take_error(&self, state: &mut RoundState, quoted: &[u8], err: QueuedError, at: Instant) {
        let expected_id = self.is_raw.then_some(self.identifier);
        let Some(seq) = quoted_probe(
            quoted,
            self.is_v6,
            expected_id,
            &self.nonce,
            self.payload_size,
        ) else {
            return;
        };
        match (err.origin, err.offender) {
            (SO_EE_ORIGIN_ICMP | SO_EE_ORIGIN_ICMP6, Some(from)) => {
                let kind = reply_kind(self.is_v6, err.icmp_type, err.code);
                state.settle_reply(seq, from, at, kind);
            }
            // A local error about the probe after it was handed over.
            _ => {
                let e = io::Error::from_raw_os_error(err.errno as i32);
                state.settle(seq, HopProbe::Failed(format!("probe failed: {e}")));
            }
        }
    }

    /// Read the normal queue, up to [`DRAIN_BATCH`] datagrams, settling our
    /// echo replies, and on macOS the errors too.
    fn read_replies(&self, state: &mut RoundState) -> io::Result<()> {
        use std::mem::MaybeUninit;
        let mut buf = vec![MaybeUninit::<u8>::uninit(); (self.payload_size + 68).max(2048)];
        for _ in 0..DRAIN_BATCH {
            match self.socket.recv_from(&mut buf) {
                Ok((n, sender)) => {
                    // SAFETY: recv_from initialized the first `n` bytes.
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                    self.take_reply(state, data, sender.as_socket(), Instant::now());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // The errno of a queued ICMP error (RAW): read the queue.
                #[cfg(target_os = "linux")]
                Err(e) if is_icmp_errno(&e) => {
                    self.read_errors(state);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn take_reply(
        &self,
        state: &mut RoundState,
        data: &[u8],
        sender: Option<SocketAddr>,
        at: Instant,
    ) {
        let expected_id = self.is_raw.then_some(self.identifier);
        let seq = match self.target {
            IpAddr::V4(target) => {
                echo_reply_seq_v4(data, target, expected_id, &self.nonce, self.payload_size)
            }
            IpAddr::V6(_) => {
                if !super::linux_icmp::v6_source_ok(self.is_raw, sender, self.target, self.scope_id)
                {
                    return;
                }
                echo_reply_seq_v6(data, expected_id, &self.nonce, self.payload_size)
            }
        };
        if let Some(seq) = seq {
            let from = sender.map_or(self.target, |s| s.ip());
            state.settle_reply(seq, from, at, ReplyKind::EchoReply);
        }
    }

    /// Settle what a datagram says about our probes: an echo reply or an
    /// ICMP error, both on the normal queue on macOS.
    #[cfg(target_os = "macos")]
    fn take_reply(
        &self,
        state: &mut RoundState,
        data: &[u8],
        _sender: Option<SocketAddr>,
        at: Instant,
    ) {
        // `open` takes IPv4 targets only on macOS.
        let IpAddr::V4(target) = self.target else {
            return;
        };
        if let Some((seq, from, kind)) = macos_answer(
            data,
            target,
            self.identifier,
            &self.nonce,
            self.payload_size,
        ) {
            state.settle_reply(seq, from, at, kind);
        }
    }
}

/// Whether `e` is an errno an ICMP error can leave pending on the socket
/// (`icmp_err_convert`, `icmpv6_err_convert`).
#[cfg(target_os = "linux")]
fn is_icmp_errno(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::EACCES
                | libc::EPROTO
                | libc::EMSGSIZE
                | libc::ECONNREFUSED
                | libc::ENOPROTOOPT
                | libc::EOPNOTSUPP
                | libc::EHOSTDOWN
                | libc::ENONET
        )
    )
}

/// One entry of the error queue: `None` when it carried no extended error.
#[cfg(target_os = "linux")]
fn recv_queued_error(
    fd: libc::c_int,
    buf: &mut [u8],
) -> io::Result<Option<(usize, Option<QueuedError>)>> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // 8-byte alignment so CMSG_FIRSTHDR's cast to `*cmsghdr` is well-aligned.
    #[repr(align(8))]
    struct CmsgBuf([u8; 256]);
    let mut cmsg_buf = CmsgBuf([0u8; 256]);
    // SAFETY: all-zero bytes are a valid (empty) `msghdr`.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.0.len() as _;

    // SAFETY: `msg` points to a live iovec and control buffer that outlive
    // the call; the kernel writes at most `iov_len` and `msg_controllen`
    // bytes into them.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
    if n < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(e)
        };
    }

    let mut err = None;
    // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR walk the kernel-written control
    // buffer and yield null or a valid, aligned cmsghdr within it; the data
    // behind CMSG_DATA is read as bytes, only up to the length its header
    // announces.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if (hdr.cmsg_level == libc::IPPROTO_IP && hdr.cmsg_type == libc::IP_RECVERR)
            || (hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_RECVERR)
        {
            let header = unsafe { libc::CMSG_LEN(0) } as usize;
            // `cmsg_len` is a `size_t` with glibc, a `socklen_t` with musl.
            let len = (hdr.cmsg_len as usize).saturating_sub(header);
            let data = unsafe { std::slice::from_raw_parts(libc::CMSG_DATA(cmsg), len) };
            err = parse_extended_err(data);
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok(Some((n as usize, err)))
}

/// The echo request of a trace probe: our identifier and `seq`, and the
/// trace's nonce at the start of the payload (as much of it as fits), then
/// the usual 0..255 pattern. ICMPv6 checksums are the kernel's.
fn echo_request(
    is_v6: bool,
    identifier: u16,
    seq: u16,
    nonce: &[u8; 8],
    payload_size: usize,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 8 + payload_size];
    pkt[0] = if is_v6 { 128 } else { 8 };
    pkt[4..6].copy_from_slice(&identifier.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    for i in 0..payload_size {
        pkt[8 + i] = nonce.get(i).copied().unwrap_or((i & 0xff) as u8);
    }
    if !is_v6 {
        let sum = super::linux_icmp::checksum(&pkt);
        pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    pkt
}

/// A `sock_extended_err` from the error queue, with its offender address.
#[derive(Debug, Clone, Copy, PartialEq)]
struct QueuedError {
    errno: u32,
    origin: u8,
    icmp_type: u8,
    code: u8,
    /// Who sent the ICMP message (`SO_EE_OFFENDER`), when one is given.
    offender: Option<IpAddr>,
}

/// Parse `struct sock_extended_err` (`linux/errqueue.h`: `ee_errno` u32,
/// `ee_origin`, `ee_type`, `ee_code`, `ee_pad` u8, `ee_info`, `ee_data` u32,
/// host byte order) and the `sockaddr_in`/`sockaddr_in6` that follows it.
fn parse_extended_err(data: &[u8]) -> Option<QueuedError> {
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    if data.len() < 16 {
        return None;
    }
    let offender = data.get(16..).and_then(|sa| {
        let family = u16::from_ne_bytes(sa.get(0..2)?.try_into().ok()?);
        match family {
            AF_INET => {
                let octets: [u8; 4] = sa.get(4..8)?.try_into().ok()?;
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            AF_INET6 => {
                let octets: [u8; 16] = sa.get(8..24)?.try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    });
    Some(QueuedError {
        errno: u32::from_ne_bytes(data[0..4].try_into().ok()?),
        origin: data[4],
        icmp_type: data[5],
        code: data[6],
        offender,
    })
}

/// The sequence number of the probe an ICMP error quotes back, if the probe
/// is ours: an echo request with our identifier (where it can be checked)
/// and, in whatever part of the payload was quoted, the trace's nonce.
fn quoted_probe(
    quoted: &[u8],
    is_v6: bool,
    expected_id: Option<u16>,
    nonce: &[u8; 8],
    payload_size: usize,
) -> Option<u16> {
    let request = if is_v6 { 128 } else { 8 };
    if quoted.len() < 8 || quoted[0] != request || quoted[1] != 0 {
        return None;
    }
    probe_of(quoted, expected_id, nonce, payload_size)
}

/// Identifier, nonce and sequence number of an echo request or reply
/// (`icmp` starts at the ICMP header).
fn probe_of(
    icmp: &[u8],
    expected_id: Option<u16>,
    nonce: &[u8; 8],
    payload_size: usize,
) -> Option<u16> {
    if let Some(id) = expected_id
        && u16::from_be_bytes([icmp[4], icmp[5]]) != id
    {
        return None;
    }
    let present = icmp
        .len()
        .saturating_sub(8)
        .min(payload_size)
        .min(nonce.len());
    if icmp[8..8 + present] != nonce[..present] {
        return None;
    }
    Some(u16::from_be_bytes([icmp[6], icmp[7]]))
}

/// Our echo reply over IPv4: with the IP header (RAW, macOS), from `target`.
fn echo_reply_seq_v4(
    data: &[u8],
    target: Ipv4Addr,
    expected_id: Option<u16>,
    nonce: &[u8; 8],
    payload_size: usize,
) -> Option<u16> {
    let icmp = if data.first().is_some_and(|b| b >> 4 == 4) {
        let ihl = (data[0] & 0x0f) as usize * 4;
        if ihl < 20 || data.len() < ihl {
            return None;
        }
        if data[12..16] != target.octets() {
            return None;
        }
        &data[ihl..]
    } else {
        data
    };
    if icmp.len() < 8 || icmp[0] != 0 || icmp[1] != 0 {
        return None;
    }
    probe_of(icmp, expected_id, nonce, payload_size)
}

/// Our echo reply over IPv6 (no IP header on either socket type).
fn echo_reply_seq_v6(
    data: &[u8],
    expected_id: Option<u16>,
    nonce: &[u8; 8],
    payload_size: usize,
) -> Option<u16> {
    if data.len() < 8 || data[0] != 129 || data[1] != 0 {
        return None;
    }
    probe_of(data, expected_id, nonce, payload_size)
}

/// What a datagram read on a macOS ICMP socket (DGRAM or RAW, IPv4) says
/// about our probes: the sequence number, who answered and how. The socket
/// gets every ICMP message of the host, so the datagram is ours only as an
/// echo reply from `target`, or as an error (time exceeded, unreachable)
/// quoting ICMP to `target`, each carrying our probe (`identifier`, nonce).
/// Whether `seq` belongs to the round in progress is the caller's check. No
/// IP length is read: BSD rewrites them (module docs).
fn macos_answer(
    data: &[u8],
    target: Ipv4Addr,
    identifier: u16,
    nonce: &[u8; 8],
    payload_size: usize,
) -> Option<(u16, IpAddr, ReplyKind)> {
    let (header, icmp) = ipv4_icmp(data)?;
    let from = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
    let (seq, kind) = match (icmp[0], icmp[1]) {
        (0, 0) if from == target => (
            probe_of(icmp, Some(identifier), nonce, payload_size)?,
            ReplyKind::EchoReply,
        ),
        (3 | 11, code) => {
            let (quoted_header, quoted) = ipv4_icmp(&icmp[8..])?;
            if quoted_header[16..20] != target.octets() {
                return None;
            }
            (
                quoted_probe(quoted, false, Some(identifier), nonce, payload_size)?,
                reply_kind(false, icmp[0], code),
            )
        }
        _ => return None,
    };
    Some((seq, IpAddr::V4(from), kind))
}

/// An IPv4 packet carrying ICMP, split into its header and at least the 8
/// bytes of an ICMP header; `None` when it is not one, or is cut short.
fn ipv4_icmp(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *data.first()?;
    let ihl = (first & 0x0f) as usize * 4;
    if first >> 4 != 4 || ihl < 20 || data.len() < ihl + 8 || data[9] != libc::IPPROTO_ICMP as u8 {
        return None;
    }
    Some(data.split_at(ihl))
}

/// What an ICMP error says about a probe.
fn reply_kind(is_v6: bool, icmp_type: u8, code: u8) -> ReplyKind {
    let other = ReplyKind::Other(OtherReply::Icmp { icmp_type, code });
    match (is_v6, icmp_type, code) {
        (false, 11, 0) | (true, 3, 0) => ReplyKind::TimeExceeded,
        // Fragmentation needed: the IPv4 "packet too big" (RFC 1191), not a
        // dead end.
        (false, 3, 4) => other,
        (false, 3, code) => ReplyKind::Unreachable(match code {
            0 | 6 | 11 => UnreachableKind::Net,
            1 | 7 | 12 => UnreachableKind::Host,
            2 => UnreachableKind::Protocol,
            3 => UnreachableKind::Port,
            9 | 10 | 13 => UnreachableKind::AdminProhibited,
            _ => UnreachableKind::Other,
        }),
        (true, 1, code) => ReplyKind::Unreachable(match code {
            0 => UnreachableKind::Net,
            1 | 5 | 6 => UnreachableKind::AdminProhibited,
            3 => UnreachableKind::Host,
            4 => UnreachableKind::Port,
            _ => UnreachableKind::Other,
        }),
        _ => other,
    }
}

/// The probes of one round and what became of them.
struct RoundState {
    seqs: Vec<u16>,
    sent_at: Vec<Option<Instant>>,
    outcome: Vec<Option<HopProbe>>,
    /// How long each probe waits for its answer.
    probe_timeout: Duration,
}

impl RoundState {
    fn new(seqs: &[u16], probe_timeout: Duration) -> Self {
        Self {
            seqs: seqs.to_vec(),
            sent_at: vec![None; seqs.len()],
            outcome: vec![None; seqs.len()],
            probe_timeout,
        }
    }

    fn sent(&mut self, i: usize, at: Instant) {
        self.sent_at[i] = Some(at);
    }

    fn not_sent(&mut self, i: usize, message: String) {
        self.outcome[i] = Some(HopProbe::NotSent(message));
    }

    /// Settle the sent probe `seq`. An answer for a probe that is not of
    /// this round (late, or someone else's), not sent, or already settled
    /// is ignored. Returns whether it was taken.
    fn settle(&mut self, seq: u16, probe: HopProbe) -> bool {
        let Some(i) = self.seqs.iter().position(|&s| s == seq) else {
            return false;
        };
        if self.sent_at[i].is_none() || self.outcome[i].is_some() {
            return false;
        }
        self.outcome[i] = Some(probe);
        true
    }

    /// Settle the sent probe `seq` with an answer read at `at`. An answer
    /// read after the probe's wait was over is late: the probe stays to be
    /// marked silent.
    fn settle_reply(&mut self, seq: u16, from: IpAddr, at: Instant, kind: ReplyKind) -> bool {
        let Some(sent) = self
            .seqs
            .iter()
            .position(|&s| s == seq)
            .and_then(|i| self.sent_at[i])
        else {
            return false;
        };
        let rtt = at.saturating_duration_since(sent);
        if rtt > self.probe_timeout {
            return false;
        }
        self.settle(seq, HopProbe::Reply { from, rtt, kind })
    }

    /// Mark silent every sent probe whose wait is over.
    fn expire(&mut self, now: Instant) {
        for i in 0..self.seqs.len() {
            if self.outcome[i].is_none()
                && let Some(sent) = self.sent_at[i]
                && now >= sent + self.probe_timeout
            {
                self.outcome[i] = Some(HopProbe::Silent);
            }
        }
    }

    /// When the next sent probe's wait ends.
    fn next_expiry(&self) -> Option<Instant> {
        (0..self.seqs.len())
            .filter(|&i| self.outcome[i].is_none())
            .filter_map(|i| self.sent_at[i])
            .min()
            .map(|sent| sent + self.probe_timeout)
    }

    /// Every probe has an outcome (sent probes settled, the others not sent).
    fn done(&self) -> bool {
        self.outcome.iter().all(Option::is_some)
    }

    /// Fail every sent probe still waiting.
    fn fail_pending(&mut self, message: &str) {
        for i in 0..self.seqs.len() {
            if self.outcome[i].is_none() && self.sent_at[i].is_some() {
                self.outcome[i] = Some(HopProbe::Failed(message.to_string()));
            }
        }
    }

    /// The finished probes, in sending order.
    fn into_round(self, interrupted: Option<Interrupted>) -> Round {
        Round {
            probes: self.outcome.into_iter().flatten().collect(),
            interrupted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];

    #[test]
    fn echo_request_carries_the_nonce_then_the_pattern() {
        let pkt = echo_request(false, 0x5150, 7, &NONCE, 56);
        assert_eq!(pkt.len(), 64);
        assert_eq!(&pkt[0..2], &[8, 0]);
        assert_eq!(&pkt[4..8], &[0x51, 0x50, 0, 7]);
        assert_eq!(&pkt[8..16], &NONCE);
        assert_eq!(pkt[16], 8);
        assert_eq!(pkt[63], 55);
        assert_eq!(super::super::linux_icmp::checksum(&pkt), 0);

        let v6 = echo_request(true, 1, 2, &NONCE, 4);
        assert_eq!(v6, [128, 0, 0, 0, 0, 1, 0, 2, 0xA1, 0xB2, 0xC3, 0xD4]);
        assert_eq!(echo_request(true, 1, 2, &NONCE, 0).len(), 8);
    }

    fn extended_err(origin: u8, icmp_type: u8, code: u8, offender: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&113u32.to_ne_bytes());
        data.extend_from_slice(&[origin, icmp_type, code, 0]);
        data.extend_from_slice(&0u32.to_ne_bytes());
        data.extend_from_slice(&0u32.to_ne_bytes());
        data.extend_from_slice(offender);
        data
    }

    fn sockaddr_in(octets: [u8; 4]) -> Vec<u8> {
        let mut sa = 2u16.to_ne_bytes().to_vec();
        sa.extend_from_slice(&[0, 0]);
        sa.extend_from_slice(&octets);
        sa.extend_from_slice(&[0; 8]);
        sa
    }

    fn sockaddr_in6(addr: Ipv6Addr) -> Vec<u8> {
        let mut sa = 10u16.to_ne_bytes().to_vec();
        sa.extend_from_slice(&[0; 6]);
        sa.extend_from_slice(&addr.octets());
        sa.extend_from_slice(&[0; 4]);
        sa
    }

    /// The entries the bench saw: time exceeded from the router, IPv4 and
    /// IPv6 (origin 2 / 3), with its address.
    #[test]
    fn extended_errors_with_the_routers_address() {
        let v4 = parse_extended_err(&extended_err(2, 11, 0, &sockaddr_in([10, 0, 1, 1]))).unwrap();
        assert_eq!(
            v4,
            QueuedError {
                errno: 113,
                origin: 2,
                icmp_type: 11,
                code: 0,
                offender: Some("10.0.1.1".parse().unwrap()),
            }
        );
        let router: Ipv6Addr = "fd00:1::1".parse().unwrap();
        let v6 = parse_extended_err(&extended_err(3, 3, 0, &sockaddr_in6(router))).unwrap();
        assert_eq!(v6.offender, Some(IpAddr::V6(router)));
        assert_eq!((v6.origin, v6.icmp_type), (3, 3));

        // No offender (AF_UNSPEC), or no room for one.
        let none = parse_extended_err(&extended_err(1, 0, 0, &[0u8; 16])).unwrap();
        assert_eq!(none.offender, None);
        assert_eq!(
            parse_extended_err(&extended_err(2, 11, 0, &[]))
                .unwrap()
                .offender,
            None
        );
        assert_eq!(parse_extended_err(&[0u8; 15]), None);
    }

    /// The probe as the kernel quoted it in the bench: DGRAM rewrote the
    /// identifier (0x048f), RAW kept ours (0x5150).
    #[test]
    fn quoted_probes_are_ours_only_with_our_nonce_and_identifier() {
        let quote = |id: u16| {
            let mut q = echo_request(false, id, 7, &NONCE, 44);
            q[2] = 0x4e; // whatever checksum the kernel left
            q
        };
        assert_eq!(
            quoted_probe(&quote(0x048f), false, None, &NONCE, 44),
            Some(7)
        );
        assert_eq!(
            quoted_probe(&quote(0x5150), false, Some(0x5150), &NONCE, 44),
            Some(7)
        );
        assert_eq!(
            quoted_probe(&quote(0x5151), false, Some(0x5150), &NONCE, 44),
            None
        );

        let mut other_trace = quote(0x048f);
        other_trace[9] ^= 0xff;
        assert_eq!(quoted_probe(&other_trace, false, None, &NONCE, 44), None);

        // A main probe (pattern payload) is not ours.
        let mut main_probe = quote(0x048f);
        for (i, b) in main_probe[8..].iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(quoted_probe(&main_probe, false, None, &NONCE, 44), None);

        // A router that quotes only the ICMP header: identifier and seq.
        assert_eq!(
            quoted_probe(&quote(0x5150)[..8], false, Some(0x5150), &NONCE, 44),
            Some(7)
        );
        // Not an echo request, or not this family's.
        assert_eq!(quoted_probe(&quote(0x048f), true, None, &NONCE, 44), None);
        let v6 = echo_request(true, 9, 3, &NONCE, 16);
        assert_eq!(quoted_probe(&v6, true, None, &NONCE, 16), Some(3));
        // With `-s 0` there is no nonce to check.
        let bare = echo_request(false, 9, 4, &NONCE, 0);
        assert_eq!(quoted_probe(&bare, false, None, &NONCE, 0), Some(4));
    }

    fn reply_v4(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0, 0, 0, 0];
        icmp.extend_from_slice(&id.to_be_bytes());
        icmp.extend_from_slice(&seq.to_be_bytes());
        icmp.extend_from_slice(payload);
        icmp
    }

    fn with_ip_header(src: [u8; 4], icmp: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&[10, 0, 1, 2]);
        ip.extend_from_slice(icmp);
        ip
    }

    #[test]
    fn echo_replies_are_ours_by_nonce_identifier_and_source() {
        let target = Ipv4Addr::new(10, 0, 3, 2);
        let mut payload = NONCE.to_vec();
        payload.extend_from_slice(&[8, 9, 10]);
        // Linux DGRAM: no IP header, identifier rewritten.
        let dgram = reply_v4(0x048f, 21, &payload);
        assert_eq!(
            echo_reply_seq_v4(&dgram, target, None, &NONCE, 11),
            Some(21)
        );
        // RAW: header, our identifier, from the target.
        let raw = with_ip_header([10, 0, 3, 2], &reply_v4(0x5150, 21, &payload));
        assert_eq!(
            echo_reply_seq_v4(&raw, target, Some(0x5150), &NONCE, 11),
            Some(21)
        );
        // From someone else, with another identifier, or another nonce.
        let elsewhere = with_ip_header([10, 0, 9, 9], &reply_v4(0x5150, 21, &payload));
        assert_eq!(
            echo_reply_seq_v4(&elsewhere, target, Some(0x5150), &NONCE, 11),
            None
        );
        assert_eq!(
            echo_reply_seq_v4(&raw, target, Some(0x5151), &NONCE, 11),
            None
        );
        let mut main_reply = dgram.clone();
        main_reply[8..].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(
            echo_reply_seq_v4(&main_reply, target, None, &NONCE, 11),
            None
        );
        // A time exceeded on the normal queue (RAW) is not an echo reply.
        let mut te = raw.clone();
        te[20] = 11;
        assert_eq!(
            echo_reply_seq_v4(&te, target, Some(0x5150), &NONCE, 11),
            None
        );

        let mut v6 = reply_v4(0x5150, 22, &payload);
        v6[0] = 129;
        assert_eq!(echo_reply_seq_v6(&v6, Some(0x5150), &NONCE, 11), Some(22));
        assert_eq!(echo_reply_seq_v6(&dgram, None, &NONCE, 11), None);
    }

    #[test]
    fn icmp_errors_by_family() {
        use UnreachableKind::*;
        let cases = [
            (false, 11, 0, ReplyKind::TimeExceeded),
            (false, 3, 0, ReplyKind::Unreachable(Net)),
            (false, 3, 1, ReplyKind::Unreachable(Host)),
            (false, 3, 2, ReplyKind::Unreachable(Protocol)),
            (false, 3, 3, ReplyKind::Unreachable(Port)),
            (false, 3, 13, ReplyKind::Unreachable(AdminProhibited)),
            (false, 3, 5, ReplyKind::Unreachable(Other)),
            (true, 3, 0, ReplyKind::TimeExceeded),
            (true, 1, 0, ReplyKind::Unreachable(Net)),
            (true, 1, 1, ReplyKind::Unreachable(AdminProhibited)),
            (true, 1, 3, ReplyKind::Unreachable(Host)),
            (true, 1, 4, ReplyKind::Unreachable(Port)),
            (true, 1, 2, ReplyKind::Unreachable(Other)),
        ];
        for (v6, t, c, kind) in cases {
            assert_eq!(reply_kind(v6, t, c), kind, "v6={v6} type={t} code={c}");
        }
        // Fragment reassembly time exceeded, packet too big (IPv4: fragmentation
        // needed), parameter problem.
        for (v6, t, c) in [
            (false, 11, 1),
            (false, 3, 4),
            (true, 3, 1),
            (true, 2, 0),
            (false, 12, 0),
        ] {
            assert_eq!(
                reply_kind(v6, t, c),
                ReplyKind::Other(OtherReply::Icmp {
                    icmp_type: t,
                    code: c
                })
            );
        }
    }

    #[test]
    fn a_round_settles_only_its_own_sent_probes_once() {
        let t0 = Instant::now();
        let mut state = RoundState::new(&[10, 11, 12], Duration::from_secs(1));
        state.sent(0, t0);
        state.not_sent(1, "send failed".into());
        state.sent(2, t0);
        let from: IpAddr = "10.0.1.1".parse().unwrap();
        let at = t0 + Duration::from_millis(5);
        // A late answer from an earlier round, an unsent probe, a duplicate.
        assert!(!state.settle_reply(9, from, at, ReplyKind::TimeExceeded));
        assert!(!state.settle_reply(11, from, at, ReplyKind::TimeExceeded));
        assert!(state.settle_reply(10, from, at, ReplyKind::TimeExceeded));
        assert!(!state.settle_reply(10, from, at, ReplyKind::EchoReply));
        assert!(!state.done());
        assert_eq!(state.next_expiry(), Some(t0 + Duration::from_secs(1)));
        // The answer to probe 12 read after its wait was over is late.
        let late = t0 + Duration::from_millis(1001);
        assert!(!state.settle_reply(12, from, late, ReplyKind::TimeExceeded));
        state.expire(t0 + Duration::from_secs(1));
        assert!(state.done());
        let round = state.into_round(None);
        assert_eq!(
            round.probes,
            [
                HopProbe::Reply {
                    from,
                    rtt: Duration::from_millis(5),
                    kind: ReplyKind::TimeExceeded
                },
                HopProbe::NotSent("send failed".into()),
                HopProbe::Silent,
            ]
        );
    }

    /// An interrupted round keeps what finished, in order, and drops the
    /// probes still waiting.
    #[test]
    fn an_interrupted_round_drops_the_probes_still_waiting() {
        let t0 = Instant::now();
        let mut state = RoundState::new(&[1, 2, 3], Duration::from_secs(1));
        state.sent(0, t0);
        state.sent(1, t0);
        state.settle_reply(2, "10.0.1.1".parse().unwrap(), t0, ReplyKind::TimeExceeded);
        let round = state.into_round(Some(Interrupted::Budget));
        assert_eq!(round.probes.len(), 1);
        assert_eq!(round.interrupted, Some(Interrupted::Budget));
    }

    /// Datagrams as a macOS 27 ICMP DGRAM socket read them (step 1b of 1.7,
    /// E2): echo requests to 1.1.1.1 with identifier 19942, the nonce above
    /// and 56 bytes of payload. The host's and the routers' private
    /// addresses are replaced by documentation ones (the IP checksums, not
    /// read, are left as they were). BSD's `ip_len` is as it arrived: host
    /// byte order, the outer one without its header.
    mod macos {
        use super::*;

        pub const ID: u16 = 19942;
        pub const TARGET: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
        const PAYLOAD: &str = "a1b2c3d4e5f6071808090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                               202122232425262728292a2b2c2d2e2f3031323334353637";
        /// Time exceeded for seq 1..4, from hops 1..4.
        const TIME_EXCEEDED: [(&str, [u8; 4]); 4] = [
            (
                "45c05c00314600004001bad0c6336401c000020a0b00f4ff00000000\
                 45005400e036000001011064c000020a0101010108006c7f4de60001",
                [198, 51, 100, 1],
            ),
            (
                "45c05c00db3d00003f010fd9c6336402c000020a0b00f4ff00000000\
                 45005400f5af00000101faeac000020a0101010108006c7e4de60002",
                [198, 51, 100, 2],
            ),
            (
                "45c05c0059eb00003e01932bc6336403c000020a0b00f4ff00000000\
                 450054005c5a000001019440c000020a0101010108006c7d4de60003",
                [198, 51, 100, 3],
            ),
            (
                "45205c0059e600003d01f805cb007104c000020a0b00f4ff00000000\
                 45005400e088000001011012c000020a0101010108006c7c4de60004",
                [203, 0, 113, 4],
            ),
        ];
        /// The echo reply to seq 6, from 1.1.1.1.
        const REPLY: &str = "45004000aa6400003401133601010101c000020a0000747a4de60006";

        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        pub fn time_exceeded(hop: usize) -> (Vec<u8>, IpAddr) {
            let (head, from) = TIME_EXCEEDED[hop];
            (hex(&format!("{head}{PAYLOAD}")), IpAddr::from(from))
        }

        pub fn reply() -> Vec<u8> {
            hex(&format!("{REPLY}{PAYLOAD}"))
        }

        pub fn answer(data: &[u8]) -> Option<(u16, IpAddr, ReplyKind)> {
            macos_answer(data, TARGET, ID, &NONCE, 56)
        }
    }

    /// What a macOS socket read: each hop's time exceeded for its probe, and
    /// the target's echo reply; the real bytes parse as ours.
    #[test]
    fn macos_answers_as_read_on_macos() {
        for hop in 0..4 {
            let (data, from) = macos::time_exceeded(hop);
            assert_eq!(
                macos::answer(&data),
                Some((hop as u16 + 1, from, ReplyKind::TimeExceeded)),
                "hop {}",
                hop + 1
            );
        }
        assert_eq!(
            macos::answer(&macos::reply()),
            Some((6, IpAddr::V4(macos::TARGET), ReplyKind::EchoReply))
        );
        // An unreachable quoting our probe, and fragmentation needed, which
        // is no dead end.
        let (mut data, from) = macos::time_exceeded(0);
        data[20..22].copy_from_slice(&[3, 1]);
        assert_eq!(
            macos::answer(&data),
            Some((1, from, ReplyKind::Unreachable(UnreachableKind::Host)))
        );
        data[21] = 4;
        assert_eq!(
            macos::answer(&data),
            Some((
                1,
                from,
                ReplyKind::Other(OtherReply::Icmp {
                    icmp_type: 3,
                    code: 4
                })
            ))
        );
        // No IP length is read: BSD's are not the wire's anyway.
        let (mut data, from) = macos::time_exceeded(1);
        data[2..4].copy_from_slice(&[0xff, 0xff]);
        data[30..32].copy_from_slice(&[0, 0]);
        assert_eq!(
            macos::answer(&data),
            Some((2, from, ReplyKind::TimeExceeded))
        );
    }

    /// A macOS socket gets every ICMP message of the host: another socket's
    /// (E2: what socket B read), another target's or another payload's are
    /// not ours, nor anything cut short or not ICMP.
    #[test]
    fn macos_answers_of_others_are_not_ours() {
        let (te, _) = macos::time_exceeded(2);
        let reply = macos::reply();
        for data in [&te, &reply] {
            // Another identifier: what B read.
            assert_eq!(macos_answer(data, macos::TARGET, 36326, &NONCE, 56), None);
            // Another target.
            let other = Ipv4Addr::new(1, 0, 0, 1);
            assert_eq!(macos_answer(data, other, macos::ID, &NONCE, 56), None);
            // Another nonce.
            let nonce = [0u8; 8];
            assert_eq!(
                macos_answer(data, macos::TARGET, macos::ID, &nonce, 56),
                None
            );
            // Not an IPv4 header with ICMP, or one cut short.
            let mut bad = data.clone();
            bad[0] = 0x44;
            assert_eq!(macos::answer(&bad), None, "IHL under 20");
            let mut bad = data.clone();
            bad[9] = 17;
            assert_eq!(macos::answer(&bad), None, "not ICMP");
            assert_eq!(macos::answer(&data[..27]), None, "ICMP header cut");
        }
        // The quoted packet: not ICMP, its header too short or cut short.
        let mut bad = te.clone();
        bad[37] = 17;
        assert_eq!(macos::answer(&bad), None);
        let mut bad = te.clone();
        bad[28] = 0x44;
        assert_eq!(macos::answer(&bad), None);
        assert_eq!(macos::answer(&te[..55]), None);
        // An echo reply from someone else, or not a plain one.
        let mut bad = reply.clone();
        bad[12..16].copy_from_slice(&[198, 51, 100, 1]);
        assert_eq!(macos::answer(&bad), None);
        let mut bad = reply.clone();
        bad[21] = 1;
        assert_eq!(macos::answer(&bad), None);
        // An echo request quoted back is ours; anything else quoted is not.
        let mut bad = te.clone();
        bad[48] = 0;
        assert_eq!(macos::answer(&bad), None);
    }

    /// A router that quotes 8 bytes of ICMP leaves no nonce to check: the
    /// probe is ours by identifier, sequence number and target, and another
    /// process with the same three would pass (module docs). Part of the
    /// nonce is checked as far as it goes.
    #[test]
    fn a_short_quote_is_ours_by_identifier_sequence_and_target() {
        let (te, from) = macos::time_exceeded(3);
        let eight = &te[..56];
        assert_eq!(
            macos::answer(eight),
            Some((4, from, ReplyKind::TimeExceeded))
        );
        assert_eq!(macos_answer(eight, macos::TARGET, 1, &NONCE, 56), None);
        let other = Ipv4Addr::new(1, 0, 0, 1);
        assert_eq!(macos_answer(eight, other, macos::ID, &NONCE, 56), None);
        let three = &te[..59];
        assert!(macos::answer(three).is_some());
        let mut wrong = three.to_vec();
        wrong[58] ^= 0xff;
        assert_eq!(macos::answer(&wrong), None);
    }
}
