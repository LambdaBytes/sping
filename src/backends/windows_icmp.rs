//! Windows ICMP backend using `IcmpSendEcho` / `Icmp6SendEcho2` from
//! `iphlpapi.dll`. Works without administrator rights and reports RTT for
//! IPv4 and IPv6 (TTL is only available on IPv4 replies).

#[cfg(target_os = "windows")]
mod imp {
    use std::io;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    use crate::probe::types::{ProbeOptions, ProbeResult};

    // FFI types and functions from iphlpapi.dll. `HANDLE` keeps the Win32
    // spelling on purpose to mirror the platform headers.
    #[allow(clippy::upper_case_acronyms)]
    type HANDLE = isize;

    const AF_INET6: u16 = 23;
    /// IP_REQ_TIMED_OUT — a plain timeout; any other non-zero status
    /// (unreachable, TTL expired, ...) is a distinct error condition.
    const IP_REQ_TIMED_OUT: u32 = 11010;

    /// `IO_STATUS_BLOCK` (a pointer-sized status union plus a `ULONG_PTR`):
    /// `Icmp6SendEcho2` needs room for one after the reply in its buffer.
    const IO_STATUS_BLOCK_SIZE: usize = 2 * std::mem::size_of::<usize>();

    #[repr(C)]
    struct IpOptionInformation {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        /// The alignment gap before the pointer, declared as a field so its
        /// bytes are part of the value: implicit padding is not preserved
        /// when a struct is moved, and the FFI reads these bytes (see
        /// `options`).
        #[cfg(target_pointer_width = "64")]
        _pad: [u8; 4],
        options_data: *mut u8,
    }

    // The explicit gap must not change the C layout (4 option bytes, then a
    // pointer at pointer alignment); with it, no implicit padding is left.
    const _: () =
        assert!(std::mem::size_of::<IpOptionInformation>() == 2 * std::mem::size_of::<usize>());

    #[repr(C)]
    struct IcmpEchoReply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut std::ffi::c_void,
        options: IpOptionInformation,
    }

    /// Winsock sockaddr_in6 (28 bytes).
    #[repr(C)]
    struct SockAddrIn6 {
        sin6_family: u16,
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: [u8; 16],
        sin6_scope_id: u32,
    }

    /// ipexport.h IPV6_ADDRESS_EX — packed(1), matches windows-sys.
    #[repr(C, packed(1))]
    struct Ipv6AddressEx {
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: [u16; 8],
        sin6_scope_id: u32,
    }

    /// ICMPV6_ECHO_REPLY_LH. No TTL/options field exists for IPv6 replies.
    #[repr(C)]
    struct Icmpv6EchoReply {
        address: Ipv6AddressEx,
        status: u32,
        round_trip_time: u32,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> HANDLE;
        fn Icmp6CreateFile() -> HANDLE;
        fn IcmpCloseHandle(handle: HANDLE) -> i32;
        fn IcmpSendEcho(
            handle: HANDLE,
            destination: u32,
            request_data: *mut std::ffi::c_void,
            request_size: u16,
            request_options: *mut IpOptionInformation,
            reply_buffer: *mut std::ffi::c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
        fn Icmp6SendEcho2(
            handle: HANDLE,
            event: HANDLE,
            apc_routine: *mut std::ffi::c_void,
            apc_context: *mut std::ffi::c_void,
            source_address: *mut SockAddrIn6,
            destination_address: *mut SockAddrIn6,
            request_data: *mut std::ffi::c_void,
            request_size: u16,
            request_options: *mut IpOptionInformation,
            reply_buffer: *mut std::ffi::c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }

    pub struct WindowsIcmpBackend {
        handle: HANDLE,
        is_v6: bool,
        /// Outgoing TTL; 0 means OS default.
        ttl: std::sync::atomic::AtomicU8,
    }

    // SAFETY: the handle is an opaque kernel object usable from any thread
    // (per iphlpapi); the only mutable state, `ttl`, is atomic.
    unsafe impl Send for WindowsIcmpBackend {}
    unsafe impl Sync for WindowsIcmpBackend {}

    impl WindowsIcmpBackend {
        /// Create an IPv4 ICMP backend.
        ///
        /// # Errors
        ///
        /// Returns the OS error when the ICMP handle cannot be created.
        pub fn new() -> io::Result<Self> {
            // SAFETY: FFI call with no arguments; failure is reported via
            // INVALID_HANDLE_VALUE (-1), checked below.
            let handle = unsafe { IcmpCreateFile() };
            if handle == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                handle,
                is_v6: false,
                ttl: std::sync::atomic::AtomicU8::new(0),
            })
        }

        /// Create an IPv6 ICMPv6 backend.
        ///
        /// # Errors
        ///
        /// Returns the OS error when the ICMPv6 handle cannot be created.
        pub fn new_v6() -> io::Result<Self> {
            // SAFETY: FFI call with no arguments; failure is reported via
            // INVALID_HANDLE_VALUE (-1), checked below.
            let handle = unsafe { Icmp6CreateFile() };
            if handle == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                handle,
                is_v6: true,
                ttl: std::sync::atomic::AtomicU8::new(0),
            })
        }

        /// Interface binding is unavailable through `IcmpSendEcho`; always
        /// returns `Unsupported`.
        pub fn bind_interface(&self, _iface: &str) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "interface binding not supported on Windows. Use -S <source-ip> instead.",
            ))
        }

        /// Source binding is unavailable through `IcmpSendEcho`; warns on
        /// stderr instead of silently ignoring `-S`.
        pub fn bind_source(&self, _addr: IpAddr, _scope_id: u32) -> io::Result<()> {
            eprintln!("warning: -S/--source is ignored on Windows (OS picks the route)");
            Ok(())
        }

        /// Set the outgoing TTL for subsequent probes (0 = OS default).
        pub fn set_ttl(&self, ttl: u8) -> io::Result<()> {
            self.ttl.store(ttl, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }

        /// Per-probe `IP_OPTION_INFORMATION`; the bool is whether to pass it
        /// (`ttl > 0`). Zeroed in full — including `_pad` — because on 64-bit
        /// the API reads it as the 8-byte `IP_OPTION_INFORMATION32`, where
        /// those bytes are the `OptionsData` pointer. The same bytes are a
        /// valid native `IP_OPTION_INFORMATION` with a null `options_data`.
        fn options(&self) -> (IpOptionInformation, bool) {
            let ttl = self.ttl.load(std::sync::atomic::Ordering::Relaxed);
            // SAFETY: all-zero is a valid `IpOptionInformation` (u8 fields + a
            // null `options_data` pointer).
            let mut opts: IpOptionInformation = unsafe { std::mem::zeroed() };
            opts.ttl = ttl;
            (opts, ttl > 0)
        }

        /// `IcmpSendEcho`/`Icmp6SendEcho2` return 0 both on timeout and on API
        /// failure; disambiguate via GetLastError.
        fn api_failure(seq: u16) -> ProbeResult {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(IP_REQ_TIMED_OUT as i32) {
                ProbeResult::Timeout { seq: seq as u64 }
            } else {
                ProbeResult::Error {
                    seq: seq as u64,
                    message: format!("ICMP call failed: {err}"),
                }
            }
        }

        /// Send one ICMP echo and wait for the reply. Blocking — call from
        /// `spawn_blocking`.
        pub fn ping(&self, opts: &ProbeOptions, seq: u16) -> ProbeResult {
            match (opts.target, self.is_v6) {
                // `IcmpSendEcho` takes an in_addr, which keeps its bytes in
                // network order in memory: reinterpret natively, do not swap.
                (IpAddr::V4(v4), false) => self.ping_v4(opts, seq, u32::from_ne_bytes(v4.octets())),
                (IpAddr::V6(v6), true) => self.ping_v6(opts, seq, v6.octets()),
                _ => ProbeResult::Error {
                    seq: seq as u64,
                    message: "target address family does not match the ICMP backend".into(),
                },
            }
        }

        fn ping_v4(&self, opts: &ProbeOptions, seq: u16, ip: u32) -> ProbeResult {
            let timeout_ms = u32::try_from(opts.timeout.as_millis()).unwrap_or(u32::MAX);
            let mut payload = build_payload(opts.payload_size);

            let reply_size = std::mem::size_of::<IcmpEchoReply>() + opts.payload_size + 8;
            let mut reply_buf = vec![0u8; reply_size];

            let (mut options, use_options) = self.options();
            let options_ptr = if use_options {
                &mut options as *mut IpOptionInformation
            } else {
                std::ptr::null_mut()
            };

            let start = Instant::now();

            // SAFETY: every pointer is a live, frame-owned buffer passed with
            // its exact length; the synchronous call outlives none of them.
            let ret = unsafe {
                IcmpSendEcho(
                    self.handle,
                    ip,
                    payload.as_mut_ptr() as *mut std::ffi::c_void,
                    payload.len() as u16,
                    options_ptr,
                    reply_buf.as_mut_ptr() as *mut std::ffi::c_void,
                    reply_size as u32,
                    timeout_ms,
                )
            };

            if ret == 0 {
                return Self::api_failure(seq);
            }

            // SAFETY: `ret != 0` means a reply was written at the start of
            // `reply_buf`. `read_unaligned` because a `Vec<u8>` is not aligned
            // for `IcmpEchoReply`.
            let reply =
                unsafe { std::ptr::read_unaligned(reply_buf.as_ptr() as *const IcmpEchoReply) };

            match reply.status {
                0 => ProbeResult::Reply {
                    seq: seq as u64,
                    rtt: rtt_from_ms(reply.round_trip_time, start),
                    ttl: reply.options.ttl,
                },
                IP_REQ_TIMED_OUT => ProbeResult::Timeout { seq: seq as u64 },
                status => ProbeResult::Error {
                    seq: seq as u64,
                    message: format!("ICMP error status {status}"),
                },
            }
        }

        fn ping_v6(&self, opts: &ProbeOptions, seq: u16, addr: [u8; 16]) -> ProbeResult {
            let timeout_ms = u32::try_from(opts.timeout.as_millis()).unwrap_or(u32::MAX);
            let mut payload = build_payload(opts.payload_size);

            // Reply + echoed payload + 8 bytes for an ICMP error message + an
            // IO_STATUS_BLOCK, as the Icmp6SendEcho2 ReplyBuffer contract asks.
            let reply_size = std::mem::size_of::<Icmpv6EchoReply>()
                + opts.payload_size
                + 8
                + IO_STATUS_BLOCK_SIZE;
            let mut reply_buf = vec![0u8; reply_size];

            // Unspecified source: the stack picks the route.
            let mut src = SockAddrIn6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: [0u8; 16],
                sin6_scope_id: 0,
            };
            // The zone index of a link-local target (`fe80::1%12`) selects
            // the interface; 0 for every other address.
            let mut dst = SockAddrIn6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: addr,
                sin6_scope_id: opts.scope_id,
            };

            // `Ttl` is the IPv6 hop limit here (see `options`).
            let (mut options, use_options) = self.options();
            let options_ptr = if use_options {
                &mut options as *mut IpOptionInformation
            } else {
                std::ptr::null_mut()
            };

            let start = Instant::now();

            // SAFETY: null event/APC make the call synchronous; every pointer
            // is a live, frame-owned buffer passed with its exact length, so
            // they all outlive the call.
            let ret = unsafe {
                Icmp6SendEcho2(
                    self.handle,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut src,
                    &mut dst,
                    payload.as_mut_ptr() as *mut std::ffi::c_void,
                    payload.len() as u16,
                    options_ptr,
                    reply_buf.as_mut_ptr() as *mut std::ffi::c_void,
                    reply_size as u32,
                    timeout_ms,
                )
            };

            if ret == 0 {
                return Self::api_failure(seq);
            }

            // SAFETY: `ret != 0` means a reply was written at the start of
            // `reply_buf`. `read_unaligned` because a `Vec<u8>` is not aligned
            // for `Icmpv6EchoReply`.
            let reply =
                unsafe { std::ptr::read_unaligned(reply_buf.as_ptr() as *const Icmpv6EchoReply) };

            match reply.status {
                0 => ProbeResult::Reply {
                    seq: seq as u64,
                    rtt: rtt_from_ms(reply.round_trip_time, start),
                    // Icmp6SendEcho2 replies carry no hop-limit information.
                    ttl: 0,
                },
                IP_REQ_TIMED_OUT => ProbeResult::Timeout { seq: seq as u64 },
                status => ProbeResult::Error {
                    seq: seq as u64,
                    message: format!("ICMPv6 error status {status}"),
                },
            }
        }
    }

    /// Echo payload with the canonical 0..255 byte pattern.
    fn build_payload(size: usize) -> Vec<u8> {
        let mut payload = vec![0u8; size];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        payload
    }

    /// IcmpSendEcho reports RTT with 1 ms resolution; below that, fall back
    /// to the userspace measurement.
    fn rtt_from_ms(ms: u32, start: Instant) -> Duration {
        if ms == 0 {
            start.elapsed()
        } else {
            Duration::from_millis(ms as u64)
        }
    }

    impl Drop for WindowsIcmpBackend {
        fn drop(&mut self) {
            // SAFETY: `handle` was created by Icmp*CreateFile and is closed
            // exactly once.
            unsafe {
                IcmpCloseHandle(self.handle);
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub use imp::WindowsIcmpBackend;
