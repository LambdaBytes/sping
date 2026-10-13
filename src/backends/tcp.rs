//! TCP connect probe (`--tcp PORT`): times the TCP handshake with the target's
//! port. Needs no ICMP permission and reaches hosts behind ICMP filters. One
//! new socket per probe, closed normally once the outcome is known.

use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Once;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::probe::types::{ProbeOptions, ProbeResult};

/// Connects to `opts.target:opts.tcp_port` for each probe.
pub struct TcpProber {
    /// Interface to bind each socket to (`-I`); Linux only, and only when the
    /// first attempt worked.
    interface: Option<String>,
}

impl TcpProber {
    /// Prepare a socket once with the options, so a local error (no socket,
    /// a source address that cannot be bound, a TTL that cannot be set) is
    /// reported before probing starts. `-I` follows the ICMP probe: bound on
    /// Linux, a warning (once) if that fails; accepted without effect on
    /// macOS; a warning (once) on Windows.
    ///
    /// # Errors
    ///
    /// The socket cannot be created or configured.
    pub fn new(opts: &ProbeOptions) -> io::Result<Self> {
        let mut prober = Self { interface: None };
        if let Some(iface) = &opts.interface {
            match bind_interface(&stream_socket(opts)?, iface) {
                Ok(true) => prober.interface = Some(iface.clone()),
                Ok(false) => {}
                Err(e) => warn_once(&format!(
                    "warning: could not bind to interface {iface}: {e}"
                )),
            }
        }
        prober.socket(opts)?;
        Ok(prober)
    }

    /// A new socket for one connect, with the options applied in the ICMP
    /// probe's order: the interface before the source, since Linux binds a
    /// link-local source without a zone only on a socket bound to a device.
    fn socket(&self, opts: &ProbeOptions) -> io::Result<Socket> {
        let socket = stream_socket(opts)?;
        if let Some(iface) = &self.interface {
            bind_interface(&socket, iface)?;
        }
        if let Some(source) = opts.source {
            socket.bind(&SockAddr::from(with_port(source, 0, opts.scope_id)))?;
        }
        if let Some(ttl) = opts.ttl {
            match opts.target {
                IpAddr::V4(_) => socket.set_ttl(u32::from(ttl))?,
                IpAddr::V6(_) => socket.set_unicast_hops_v6(u32::from(ttl))?,
            }
        }
        #[cfg(target_os = "windows")]
        no_syn_retransmissions(&socket, opts.timeout);
        Ok(socket)
    }

    /// Connect once and classify the outcome; `seq` only tags the result.
    pub fn ping(&self, opts: &ProbeOptions, seq: u16) -> ProbeResult {
        let seq = u64::from(seq);
        let socket = match self.socket(opts) {
            Ok(socket) => socket,
            Err(e) => {
                return ProbeResult::Error {
                    seq,
                    message: format!("socket setup failed: {e}"),
                };
            }
        };
        let start = Instant::now();
        let outcome = socket.connect_timeout(&SockAddr::from(target_addr(opts)), opts.timeout);
        classify(outcome, start.elapsed(), seq)
        // `socket` is dropped here: a normal close, whatever the outcome.
    }
}

/// A TCP socket of the target's family, no option applied yet.
fn stream_socket(opts: &ProbeOptions) -> io::Result<Socket> {
    Socket::new(
        Domain::for_address(target_addr(opts)),
        Type::STREAM,
        Some(Protocol::TCP),
    )
}

/// The probed endpoint: the target with its port and, for IPv6, its zone.
fn target_addr(opts: &ProbeOptions) -> SocketAddr {
    with_port(opts.target, opts.tcp_port.unwrap_or(0), opts.scope_id)
}

fn with_port(ip: IpAddr, port: u16, scope_id: u32) -> SocketAddr {
    match ip {
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope_id)),
        ip => SocketAddr::new(ip, port),
    }
}

/// What a connect attempt means for the probe. A refusal is an answer (a
/// reset, or an ICMP port-unreachable from the target or a device on the
/// way); silence until the timeout is a loss; anything else (no route, no
/// usable address) is an error, as a failed ICMP send is.
pub(crate) fn classify(outcome: io::Result<()>, elapsed: Duration, seq: u64) -> ProbeResult {
    match outcome {
        Ok(()) => ProbeResult::Connected { seq, rtt: elapsed },
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            ProbeResult::Refused { seq, rtt: elapsed }
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            ProbeResult::Timeout { seq }
        }
        Err(e) => ProbeResult::Error {
            seq,
            message: format!("connect failed: {e}"),
        },
    }
}

/// Bind `socket` to `iface`: `Ok(true)` when bound, `Ok(false)` where the
/// platform does not bind (macOS accepts the flag without effect; Windows
/// warns once).
#[cfg(target_os = "linux")]
fn bind_interface(socket: &Socket, iface: &str) -> io::Result<bool> {
    socket.bind_device(Some(iface.as_bytes()))?;
    Ok(true)
}

#[cfg(target_os = "macos")]
fn bind_interface(_socket: &Socket, _iface: &str) -> io::Result<bool> {
    Ok(false)
}

#[cfg(target_os = "windows")]
fn bind_interface(_socket: &Socket, _iface: &str) -> io::Result<bool> {
    warn_once("warning: interface binding not supported on Windows. Use -S <source-ip> instead.");
    Ok(false)
}

/// Windows sends the SYN again after a reset, so a refused connect fails only
/// after about 2 s (measured on Windows, loopback and LAN): past the default
/// `-W`, it read as a loss. With no SYN retransmission the reset ends the
/// connect at once, and each probe is a single SYN, as each ICMP probe is a
/// single echo request. That single SYN is given up after the initial
/// retransmission timeout, about 1 s with the system's RTT estimate (measured
/// with `-W 5`): the estimate is `timeout` instead, so that the wait is the
/// probe's `-W`, up to a limit of the system's: about 3 s (measured: `-W 2`
/// waits 2 s, `-W 5` about 3 s). If the system refuses the setting, a warning
/// (once): refusals then come late.
#[cfg(target_os = "windows")]
fn no_syn_retransmissions(socket: &Socket, timeout: Duration) {
    use std::os::windows::io::AsRawSocket;

    /// `TCP_INITIAL_RTO_PARAMETERS` (mstcpip.h), its padding byte explicit
    /// so that every byte handed to the system is initialised.
    #[repr(C)]
    struct TcpInitialRtoParameters {
        rtt: u16,
        max_syn_retransmissions: u8,
        padding: u8,
    }
    const _: () = assert!(size_of::<TcpInitialRtoParameters>() == 4);
    /// `SIO_TCP_INITIAL_RTO`: `_WSAIOW(IOC_VENDOR, 17)`, that is
    /// `0x80000000 | 0x18000000 | 17`.
    const SIO_TCP_INITIAL_RTO: u32 = 0x9800_0011;
    /// `TCP_INITIAL_RTO_UNSPECIFIED_RTT` (`(USHORT) -1`) and
    /// `TCP_INITIAL_RTO_DEFAULT_RTT` (0) are not RTTs: an estimate is kept
    /// between them, in milliseconds.
    const MAX_RTT_MS: u16 = u16::MAX - 1;
    /// `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS`: `(UCHAR) -2`.
    const NO_SYN_RETRANSMISSIONS: u8 = 0xFE;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            socket: usize,
            control_code: u32,
            in_buffer: *const std::ffi::c_void,
            in_size: u32,
            out_buffer: *mut std::ffi::c_void,
            out_size: u32,
            bytes_returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
            completion_routine: *mut std::ffi::c_void,
        ) -> i32;
    }

    let params = TcpInitialRtoParameters {
        rtt: u16::try_from(timeout.as_millis())
            .unwrap_or(MAX_RTT_MS)
            .clamp(1, MAX_RTT_MS),
        max_syn_retransmissions: NO_SYN_RETRANSMISSIONS,
        padding: 0,
    };
    let mut returned: u32 = 0;
    // SAFETY: `socket` stays open for the call; the input is a live
    // `TCP_INITIAL_RTO_PARAMETERS` of the size passed; no output buffer, no
    // overlapped I/O, no completion routine.
    let status = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_TCP_INITIAL_RTO,
            (&raw const params).cast(),
            size_of::<TcpInitialRtoParameters>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        let e = io::Error::last_os_error();
        static WARNED: Once = Once::new();
        WARNED.call_once(|| {
            eprintln!(
                "warning: cannot turn off SYN retries ({e}): a refused port may show as a timeout"
            );
        });
    }
}

/// Print one warning per process: probes run once per interval, and each
/// target's prober is built twice (precheck and scheduler).
fn warn_once(message: &str) {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| eprintln!("{message}"));
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

    use super::*;

    fn kind(k: io::ErrorKind) -> io::Result<()> {
        Err(io::Error::from(k))
    }

    fn opts(target: IpAddr, port: u16) -> ProbeOptions {
        ProbeOptions {
            target,
            tcp_port: Some(port),
            // A refusal comes at once, also on Windows (no SYN retries):
            // later than this is a regression.
            timeout: Duration::from_secs(1),
            ..ProbeOptions::default()
        }
    }

    /// A port nobody listens on: bound, then released.
    fn closed_port(ip: IpAddr) -> u16 {
        TcpListener::bind((ip, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn listening_port_connects_and_closed_port_refuses() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = TcpListener::bind((ip, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut o = opts(ip, port);
        o.ttl = Some(64);
        let prober = TcpProber::new(&o).unwrap();
        assert!(matches!(
            prober.ping(&o, 1),
            ProbeResult::Connected { seq: 1, .. }
        ));
        // The handshake reached this listener.
        let (_, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), ip);

        let o = opts(ip, closed_port(ip));
        assert!(matches!(
            prober.ping(&o, 2),
            ProbeResult::Refused { seq: 2, .. }
        ));
    }

    #[test]
    fn ipv6_loopback() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let Ok(listener) = TcpListener::bind((ip, 0)) else {
            eprintln!("no IPv6 loopback here: ipv6_loopback not run");
            return;
        };
        let o = opts(ip, listener.local_addr().unwrap().port());
        let prober = TcpProber::new(&o).unwrap();
        assert!(matches!(prober.ping(&o, 1), ProbeResult::Connected { .. }));
        let o = opts(ip, closed_port(ip));
        assert!(matches!(prober.ping(&o, 2), ProbeResult::Refused { .. }));
    }

    #[test]
    fn source_that_is_not_local_fails_setup() {
        let mut o = opts(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
        o.source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
        assert!(TcpProber::new(&o).is_err());
    }

    /// `-S` is the source of the connect: 127.0.0.2 is local on Linux only.
    #[cfg(target_os = "linux")]
    #[test]
    fn source_address_is_the_connect_source() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = TcpListener::bind((ip, 0)).unwrap();
        let mut o = opts(ip, listener.local_addr().unwrap().port());
        let source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        o.source = Some(source);
        let prober = TcpProber::new(&o).unwrap();
        assert!(matches!(prober.ping(&o, 1), ProbeResult::Connected { .. }));
        let (_, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), source);
    }

    /// `-I` is applied before `-S`: Linux binds a link-local source given
    /// without a zone only on a socket already bound to a device.
    #[cfg(target_os = "linux")]
    #[test]
    fn interface_is_bound_before_a_link_local_source() {
        // A link-local address (scope 20) of a real interface:
        // "<address> <index> <prefix> <scope> <flags> <name>".
        let found = std::fs::read_to_string("/proc/net/if_inet6")
            .unwrap_or_default()
            .lines()
            .find_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() != 6 || f[3] != "20" || f[5] == "lo" {
                    return None;
                }
                let ip = Ipv6Addr::from(u128::from_str_radix(f[0], 16).ok()?);
                Some((ip, u32::from_str_radix(f[1], 16).ok()?, f[5].to_string()))
            });
        let Some((ip, index, iface)) = found else {
            eprintln!("no link-local IPv6 address here: test not run");
            return;
        };
        let listener = TcpListener::bind(SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, index)));
        let bindable = Socket::new(Domain::IPV6, Type::STREAM, None)
            .and_then(|s| s.bind_device(Some(iface.as_bytes())));
        let (Ok(listener), Ok(())) = (listener, bindable) else {
            eprintln!("{iface}: cannot listen on {ip} or bind to the device: test not run");
            return;
        };

        // The target and the source carry no zone; `-I` supplies it.
        let mut o = opts(IpAddr::V6(ip), listener.local_addr().unwrap().port());
        o.source = Some(IpAddr::V6(ip));
        o.interface = Some(iface);
        let prober = TcpProber::new(&o).unwrap();
        assert!(matches!(prober.ping(&o, 1), ProbeResult::Connected { .. }));
    }

    /// A listener whose queue is full drops new SYNs (Linux): the connect
    /// gets no answer and must give up at `-W`, not later.
    #[cfg(target_os = "linux")]
    #[test]
    fn silence_is_a_timeout_at_the_limit() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        listener
            .bind(&SockAddr::from(SocketAddr::new(ip, 0)))
            .unwrap();
        listener.listen(0).unwrap();
        let port = listener.local_addr().unwrap().as_socket().unwrap().port();
        // Fills the queue (one pending connection for a backlog of 0).
        let _queued = std::net::TcpStream::connect((ip, port)).unwrap();

        let mut o = opts(ip, port);
        o.timeout = Duration::from_millis(300);
        let prober = TcpProber::new(&o).unwrap();
        let start = Instant::now();
        let result = prober.ping(&o, 1);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, ProbeResult::Timeout { seq: 1 }),
            "{result:?}"
        );
        // poll(2) works in whole milliseconds: the wait may end a fraction
        // of one before the limit.
        assert!(
            elapsed >= Duration::from_millis(290) && elapsed < Duration::from_secs(2),
            "{elapsed:?}"
        );
    }

    #[test]
    fn outcomes_map_to_answers_losses_and_errors() {
        let rtt = Duration::from_millis(3);
        assert!(
            matches!(classify(Ok(()), rtt, 1), ProbeResult::Connected { seq: 1, rtt: r } if r == rtt)
        );
        assert!(matches!(
            classify(kind(io::ErrorKind::ConnectionRefused), rtt, 2),
            ProbeResult::Refused { seq: 2, rtt: r } if r == rtt
        ));
        assert!(matches!(
            classify(kind(io::ErrorKind::TimedOut), rtt, 3),
            ProbeResult::Timeout { seq: 3 }
        ));
        assert!(matches!(
            classify(kind(io::ErrorKind::WouldBlock), rtt, 4),
            ProbeResult::Timeout { seq: 4 }
        ));
        for k in [
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::PermissionDenied,
        ] {
            assert!(
                matches!(classify(kind(k), rtt, 5), ProbeResult::Error { seq: 5, .. }),
                "{k:?}"
            );
        }
    }
}
