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
`net.ipv4.ping_group_range` sysctl, which most distributions open to every user
by default (Debian from Debian 13 on, through its `linux-sysctl-defaults`
package; not Debian 12). Only if that is denied does it fall back to a raw socket
(`SOCK_RAW`), which requires `CAP_NET_RAW` or root.

Two things always need `CAP_NET_RAW`:

- the raw-socket fallback itself, and
- binding to an interface with `-I`/`--interface` (`SO_BINDTODEVICE`, Linux).

The traceroute of `--diagnose` opens its own ICMP socket the same way,
datagram first and raw only if that is denied, and reads the routers' ICMP
errors from it (on Linux from its error queue, `IP_RECVERR`); it needs nothing
more. On macOS it covers IPv4 targets.

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

### `--ip` and `--external`

`sping --ip` sends nothing and needs no privilege: the source of each family
comes from a UDP connect, which sends no packet. Only with `--external` does it
send: one lookup of the server's name through the system resolver, then, over
UDP, at most three STUN Binding requests per family (RFC 8489) to that server,
`stun.cloudflare.com:3478` by default, which then sees this host's public
address.

## Memory safety

The `unsafe` code is confined to calls into the operating system: in the ICMP
backends, the socket and clock calls on Linux/macOS (`recvmsg`, `setsockopt`,
`clock_gettime`, cmsg parsing and the view over a received buffer) and the
`iphlpapi` calls on Windows; in the TCP backend on Windows, the call that
keeps the SYN from being retransmitted (`WSAIoctl`); in the network context,
the Linux address list (`getifaddrs`), the Windows adapter list
(`GetAdaptersAddresses`) and the interface index of an IPv6 zone
(`if_nametoindex`). Each `unsafe` block carries a `// SAFETY:` justification. The build is checked with
`cargo clippy --all-targets -- -D warnings` on Linux, macOS and Windows targets,
and dependencies are scanned with `cargo audit` and `cargo deny`.
