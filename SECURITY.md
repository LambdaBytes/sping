# Security Policy

## Reporting a vulnerability

Please report security issues privately to **acf981@protonmail.com** rather
than opening a public issue. Include steps to reproduce and the affected
version (`sping --version`). You can expect an acknowledgement within a
reasonable time; please allow a fix to ship before public disclosure.

## Privileges and the network model

sping sends ICMP Echo requests. How it obtains that capability depends on the
platform; the goal is to run **unprivileged** in the common case.

### Linux and macOS

The backend opens an unprivileged datagram ICMP socket first
(`SOCK_DGRAM`/`IPPROTO_ICMP`), governed on Linux by the
`net.ipv4.ping_group_range` sysctl, which covers all users by default on Debian
and most distributions. Only if that is denied does it fall back to a raw socket
(`SOCK_RAW`), which requires `CAP_NET_RAW` or root.

Two things always need `CAP_NET_RAW`:

- the raw-socket fallback itself, and
- binding to an interface with `-I`/`--interface` (`SO_BINDTODEVICE`, Linux).

Preferred way to grant just that capability, without setuid or running as root:

```sh
sudo setcap cap_net_raw+ep /usr/bin/sping
```

Packagers should **not** ship sping setuid-root or set the capability in a
maintainer script by default — datagram ICMP is enough for the common case, and
the user can opt in with `setcap` if they need the raw path or `-I`.

### Windows

sping uses `IcmpSendEcho`/`Icmp6SendEcho2` from `iphlpapi.dll`. These work
without administrator rights and do not open raw sockets.

## Memory safety

The only `unsafe` code lives in the two ICMP backends: the socket and clock
calls on Linux/macOS (`recvmsg`, `setsockopt`, `clock_gettime`, cmsg parsing
and the view over a received buffer) and the `iphlpapi` calls on Windows. Each
`unsafe` block carries a `// SAFETY:` justification. The build is checked with
`cargo clippy --all-targets -- -D warnings` on Linux, macOS and Windows targets,
and dependencies are scanned with `cargo audit` and `cargo deny`.
