//! Platform ICMP backends selected at compile time via `cfg`, re-exported
//! under the common alias [`IcmpBackend`]. All backends share one API.

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod linux_icmp;

#[cfg(target_os = "windows")]
pub mod windows_icmp;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use linux_icmp::LinuxIcmpBackend as IcmpBackend;

#[cfg(target_os = "windows")]
pub use windows_icmp::WindowsIcmpBackend as IcmpBackend;

/// Print a hint after an ICMP socket creation failure.
/// No-op on Windows: `IcmpSendEcho` works without admin.
pub fn eprint_icmp_hint() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        eprintln!("hint: try one of:");
        eprintln!(
            "   sudo sysctl net.ipv4.ping_group_range='0 2147483647'   (allow unprivileged DGRAM)"
        );
        eprintln!(
            "   sudo setcap cap_net_raw+ep <path-to-sping>             (grant raw-socket cap)"
        );
        eprintln!(
            "   sudo sping ...                                         (run as root, RAW fallback)"
        );
    }
}
