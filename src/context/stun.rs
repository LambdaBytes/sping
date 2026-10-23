//! STUN Binding over UDP (RFC 8489) for `sping --ip --external` (1.8): the
//! address and port a STUN server saw a request of this host come from, one
//! address family at a time. A third party is asked, so it never runs on its
//! own: only when `--external` is given.
//!
//! One query:
//! - is a UDP socket connected to the server, so the kernel drops datagrams
//!   from anyone else;
//! - sends a Binding request at most three times, at fixed instants;
//! - has a fixed budget, which nothing that arrives extends.
//!
//! An answer counts only with this request's transaction ID and the magic
//! cookie; its fields are read inside what was received, never past it.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::context::dns;

/// STUN's port (RFC 8489). The server asked when `--external` names none is
/// clap's default in `cli.rs` (the owner's choice, 1.8: Cloudflare's, which
/// documents it, both families).
pub const DEFAULT_PORT: u16 = 3478;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ERROR_CODE: u16 = 0x0009;
const HEADER_LEN: usize = 20;

/// When the request is sent, from the start of a query: RFC 8489's
/// retransmission timeout of 500 ms, doubling, cut to three sends.
const SENDS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(500),
    Duration::from_millis(1500),
];
/// How long a query waits in all, from its first send.
pub const BUDGET: Duration = Duration::from_secs(3);

/// A transaction ID: 96 bits from the standard library's hasher keys, which
/// it draws from the system's random source. SipHash keyed with them works
/// as a PRF: whoever does not know the keys cannot predict the output. (On
/// Linux the keys come from `getrandom` with `GRND_INSECURE`, so very early
/// in boot they may not be cryptographic; matching a diagnostic query's
/// answer asks no more.)
pub fn transaction_id() -> [u8; 12] {
    use std::hash::{BuildHasher, Hasher};
    let draw = || {
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
            .to_be_bytes()
    };
    let (a, b) = (draw(), draw());
    let mut id = [0u8; 12];
    id[..8].copy_from_slice(&a);
    id[8..].copy_from_slice(&b[..4]);
    id
}

/// A Binding request: the 20-byte header, no attributes.
pub fn request(txid: &[u8; 12]) -> [u8; 20] {
    let mut msg = [0u8; 20];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length 0: no attributes.
    msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(txid);
    msg
}

/// What a server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The address and port it saw the request come from.
    Mapped(SocketAddr),
    /// An error response: its code and reason.
    Error { code: u16, reason: String },
}

/// What a received datagram is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parse {
    /// Not an answer to this request (not STUN, not a response, another
    /// transaction): skipped.
    NotOurs,
    /// This request's answer, but it does not read.
    Malformed(&'static str),
    Answer(Answer),
}

/// Read `data` as the answer to the request with `txid`.
///
/// Rules, all checked before anything is taken:
/// - 20 bytes at least, the two top bits of the type 0, the magic cookie and
///   this transaction ID (otherwise not ours);
/// - a declared length that is a multiple of 4 and fits in what arrived;
/// - every attribute (4 bytes of type and length), its value and its padding
///   to 4 inside the declared length;
/// - a (XOR-)MAPPED-ADDRESS value of 8 bytes (family 1, IPv4) or 20 (family
///   2, IPv6); XOR-MAPPED-ADDRESS wins over MAPPED-ADDRESS;
/// - an ERROR-CODE of 4 bytes at least, class 3 to 6, number 0 to 99.
///
/// Unknown attributes are skipped.
pub fn parse_response(data: &[u8], txid: &[u8; 12]) -> Parse {
    if data.len() < HEADER_LEN
        || data[0] & 0xc0 != 0
        || data[4..8] != MAGIC_COOKIE.to_be_bytes()
        || data[8..20] != txid[..]
    {
        return Parse::NotOurs;
    }
    let kind = u16::from_be_bytes([data[0], data[1]]);
    if kind != BINDING_SUCCESS && kind != BINDING_ERROR {
        return Parse::NotOurs;
    }
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if length % 4 != 0 {
        return Parse::Malformed("length not a multiple of 4");
    }
    let Some(end) = HEADER_LEN
        .checked_add(length)
        .filter(|&end| end <= data.len())
    else {
        return Parse::Malformed("cut short");
    };
    let mut mapped = None;
    let mut xor_mapped = None;
    let mut error = None;
    let mut offset = HEADER_LEN;
    while offset < end {
        if end - offset < 4 {
            return Parse::Malformed("attribute header cut short");
        }
        let attr = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
        let value_start = offset + 4;
        let padded = len.div_ceil(4) * 4;
        if end - value_start < padded {
            return Parse::Malformed("attribute past the message");
        }
        let value = &data[value_start..value_start + len];
        match attr {
            XOR_MAPPED_ADDRESS if xor_mapped.is_none() => match address(value, Some(txid)) {
                Ok(a) => xor_mapped = Some(a),
                Err(why) => return Parse::Malformed(why),
            },
            MAPPED_ADDRESS if mapped.is_none() => match address(value, None) {
                Ok(a) => mapped = Some(a),
                Err(why) => return Parse::Malformed(why),
            },
            ERROR_CODE if error.is_none() => match error_code(value) {
                Ok(e) => error = Some(e),
                Err(why) => return Parse::Malformed(why),
            },
            _ => {}
        }
        offset = value_start + padded;
    }
    if kind == BINDING_ERROR {
        return match error {
            Some(error) => Parse::Answer(error),
            None => Parse::Malformed("error response without ERROR-CODE"),
        };
    }
    match xor_mapped.or(mapped) {
        Some(a) => Parse::Answer(Answer::Mapped(a)),
        None => Parse::Malformed("no mapped address"),
    }
}

/// A (XOR-)MAPPED-ADDRESS value: reserved byte, family, port, address. With
/// `txid`, XOR'd: the port with the cookie's top 16 bits, an IPv4 address
/// with the cookie, an IPv6 address with the cookie and then the ID.
fn address(value: &[u8], txid: Option<&[u8; 12]>) -> Result<SocketAddr, &'static str> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let (family, port) = match value {
        [_, family, p0, p1, ..] => (*family, u16::from_be_bytes([*p0, *p1])),
        _ => return Err("address cut short"),
    };
    let port = match txid {
        Some(_) => port ^ (MAGIC_COOKIE >> 16) as u16,
        None => port,
    };
    match (family, value.len()) {
        (1, 8) => {
            let mut octets = [value[4], value[5], value[6], value[7]];
            if txid.is_some() {
                for (o, c) in octets.iter_mut().zip(cookie) {
                    *o ^= c;
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        (2, 20) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if let Some(txid) = txid {
                let key = cookie.iter().chain(txid.iter());
                for (o, k) in octets.iter_mut().zip(key) {
                    *o ^= k;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        (1 | 2, _) => Err("address of the wrong length"),
        _ => Err("address of an unknown family"),
    }
}

/// An ERROR-CODE value: two reserved bytes, the class (hundreds), the
/// number, then a UTF-8 reason. The reason is the server's text and is
/// printed: its control characters (a terminal's escape sequences) become
/// U+FFFD, and it is cut to RFC 8489's 128 characters.
fn error_code(value: &[u8]) -> Result<Answer, &'static str> {
    let [_, _, class, number, reason @ ..] = value else {
        return Err("ERROR-CODE cut short");
    };
    let class = class & 0x07;
    if !(3..=6).contains(&class) || *number > 99 {
        return Err("ERROR-CODE out of range");
    }
    Ok(Answer::Error {
        code: u16::from(class) * 100 + u16::from(*number),
        reason: String::from_utf8_lossy(reason)
            .chars()
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .take(128)
            .collect(),
    })
}

/// What one query came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Answer(Answer),
    /// Nothing that answered this request within the budget.
    NoAnswer,
    /// Only answers of ours that did not read (the last reason).
    Malformed(&'static str),
    /// It could not be asked, or the system refused it (the reason).
    Failed(String),
}

/// One query's sends and wait, on a clock and a wire given as closures (the
/// real socket, or a test's). `recv` waits at most what it is given and
/// says `Ok(None)` when nothing came. The sends go out at `SENDS` from the
/// start and the query ends at `BUDGET`: these are absolute instants, so
/// nothing that arrives and is skipped moves them. A port unreachable says
/// there is no server there and ends the query at once: the connected socket
/// reports it as `ConnectionRefused` (Unix) or `ConnectionReset` (Windows,
/// WSAECONNRESET on a datagram socket). An interrupted send or receive
/// (`EINTR`) is tried again.
pub fn exchange(
    txid: &[u8; 12],
    mut now: impl FnMut() -> Instant,
    mut send: impl FnMut() -> io::Result<()>,
    mut recv: impl FnMut(Duration) -> io::Result<Option<Vec<u8>>>,
) -> Outcome {
    let start = now();
    let mut sent = 0;
    let mut malformed = None;
    loop {
        let elapsed = now().saturating_duration_since(start);
        if elapsed >= BUDGET {
            return match malformed {
                Some(why) => Outcome::Malformed(why),
                None => Outcome::NoAnswer,
            };
        }
        if sent < SENDS.len() && elapsed >= SENDS[sent] {
            match send() {
                Ok(()) => sent += 1,
                // Not sent: tried again, at the same instants.
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Outcome::Failed(format!("send failed: {e}")),
            }
            continue;
        }
        let until = SENDS.get(sent).copied().unwrap_or(BUDGET).min(BUDGET);
        match recv(until - elapsed) {
            Ok(None) => {}
            Ok(Some(data)) => match parse_response(&data, txid) {
                Parse::Answer(answer) => return Outcome::Answer(answer),
                Parse::Malformed(why) => malformed = Some(why),
                Parse::NotOurs => {}
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Outcome::Failed("port unreachable: no STUN server there".into());
            }
            Err(e) => return Outcome::Failed(format!("receive failed: {e}")),
        }
    }
}

/// The external address of one family, as one server saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum External {
    /// `mapped` is what the server saw; `local`, the socket it came from.
    Seen {
        mapped: SocketAddr,
        local: Option<SocketAddr>,
        asked: IpAddr,
    },
    /// It could not be told (the reason); `asked` when there was an address
    /// to ask.
    Unknown {
        asked: Option<IpAddr>,
        reason: String,
    },
}

/// What `--external` found: the server as asked, and each family (`None`:
/// the server's name gave no address of that family).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalView {
    pub server: String,
    pub v4: Option<External>,
    pub v6: Option<External>,
}

/// `SERVER[:PORT]`: a name or an address, with STUN's port by default. An
/// IPv6 address with a port is written `[address]:port`; one without a port
/// may be written bare. Either way it must be one (a zone, `%eth0` or `%2`,
/// allowed): a mistyped address is a usage error, not a name to look up.
///
/// # Errors
///
/// An empty host, a port that is not 1 to 65535, or a host written as an
/// IPv6 address that is not one.
pub fn parse_server(server: &str) -> Result<(String, u16), String> {
    let port_of = |p: &str| match p.parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(format!("{server}: not a port: {p}")),
    };
    let (host, port, ipv6) = if let Some(rest) = server.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("{server}: no closing ]"));
        };
        let port = match after {
            "" => DEFAULT_PORT,
            _ => match after.strip_prefix(':') {
                Some(p) => port_of(p)?,
                None => return Err(format!("{server}: expected :PORT after ]")),
            },
        };
        (host, port, true)
    } else {
        match server.split_once(':') {
            // More than one colon: a bare IPv6 address.
            Some((_, rest)) if rest.contains(':') => (server, DEFAULT_PORT, true),
            Some((host, p)) => (host, port_of(p)?, false),
            None => (server, DEFAULT_PORT, false),
        }
    };
    if host.is_empty() {
        return Err(format!("{server}: no host"));
    }
    if ipv6 {
        let (address, zone) = match host.split_once('%') {
            Some((address, zone)) => (address, Some(zone)),
            None => (host, None),
        };
        if address.parse::<Ipv6Addr>().is_err() || zone == Some("") {
            return Err(format!("{server}: not an IPv6 address: {host}"));
        }
    }
    Ok((host.to_string(), port))
}

/// Ask the server at `host` and `port` (from [`parse_server`]) for each
/// family's external address: one resolution of its name (the system
/// resolver decides its packets; none for an address), then one query per
/// family it has an address of, both at once.
pub async fn external(host: &str, port: u16) -> ExternalView {
    let shown = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let families = match dns::resolve_both(host).await {
        Ok(families) => families,
        Err(e) => {
            let unknown = || {
                Some(External::Unknown {
                    asked: None,
                    reason: format!("{e:#}"),
                })
            };
            return ExternalView {
                server: shown,
                v4: unknown(),
                v6: unknown(),
            };
        }
    };
    let ask = |target: Option<dns::ResolvedAddr>| {
        target.map(|t| tokio::task::spawn_blocking(move || query(t.socket_addr(port))))
    };
    let (v4, v6) = (ask(families.v4), ask(families.v6));
    let joined = |handle: Option<tokio::task::JoinHandle<External>>| async move {
        match handle {
            Some(h) => Some(h.await.unwrap_or_else(|e| External::Unknown {
                asked: None,
                reason: format!("the query stopped: {e}"),
            })),
            None => None,
        }
    };
    ExternalView {
        server: shown,
        v4: joined(v4).await,
        v6: joined(v6).await,
    }
}

/// One query to `server` on a socket of its own.
fn query(server: SocketAddr) -> External {
    let asked = server.ip();
    let unknown = |reason: String| External::Unknown {
        asked: Some(asked),
        reason,
    };
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => return unknown(format!("cannot open a UDP socket: {e}")),
    };
    if let Err(e) = socket.connect(server) {
        return unknown(match e.kind() {
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                "no route to the server".into()
            }
            _ => format!("cannot reach the server: {e}"),
        });
    }
    let local = socket.local_addr().ok();
    let txid = transaction_id();
    let message = request(&txid);
    let mut buf = [0u8; 1500];
    let outcome = exchange(
        &txid,
        Instant::now,
        || socket.send(&message).map(drop),
        |wait| {
            socket.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
            match socket.recv(&mut buf) {
                Ok(n) => Ok(Some(buf[..n].to_vec())),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        },
    );
    match outcome {
        Outcome::Answer(Answer::Mapped(mapped)) => External::Seen {
            mapped,
            local,
            asked,
        },
        Outcome::Answer(Answer::Error { code, reason }) => unknown(
            format!("the server answered error {code} {reason}")
                .trim_end()
                .into(),
        ),
        Outcome::NoAnswer => unknown(format!("no answer within {} s", BUDGET.as_secs())),
        Outcome::Malformed(why) => unknown(format!("the answer did not read: {why}")),
        Outcome::Failed(why) => unknown(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5769, 2.2 and 2.3.
    const TXID: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];
    fn rfc5769_v4() -> Vec<u8> {
        hex("0101003c 2112a442 b7e7a701 bc34d686 fa87dfae
             8022000b 74657374 20766563 746f7220
             00200008 0001a147 e112a643
             00080014 2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7
             80280004 c07d4c96")
    }
    fn rfc5769_v6() -> Vec<u8> {
        hex("01010048 2112a442 b7e7a701 bc34d686 fa87dfae
             8022000b 74657374 20766563 746f7220
             00200014 0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9
             00080014 a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41
             80280004 c8fb0b4c")
    }

    #[test]
    fn the_rfc_5769_responses() {
        assert_eq!(
            parse_response(&rfc5769_v4(), &TXID),
            Parse::Answer(Answer::Mapped("192.0.2.1:32853".parse().unwrap()))
        );
        assert_eq!(
            parse_response(&rfc5769_v6(), &TXID),
            Parse::Answer(Answer::Mapped(
                "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                    .parse()
                    .unwrap()
            ))
        );
    }

    /// Cut anywhere, neither vector gives an address or panics.
    #[test]
    fn a_response_cut_anywhere_gives_no_address() {
        for full in [rfc5769_v4(), rfc5769_v6()] {
            for len in 0..full.len() {
                let got = parse_response(&full[..len], &TXID);
                assert!(!matches!(got, Parse::Answer(_)), "{len}: {got:?}");
            }
        }
    }

    #[test]
    fn the_request() {
        let req = request(&TXID);
        assert_eq!(&req[..8], &[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(&req[8..], &TXID);
        assert_ne!(transaction_id(), transaction_id());
    }

    /// A message with the given type and attributes, for `TXID`.
    fn message(kind: u16, attrs: &[u8]) -> Vec<u8> {
        let mut m = kind.to_be_bytes().to_vec();
        m.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(&TXID);
        m.extend_from_slice(attrs);
        m
    }

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut a = kind.to_be_bytes().to_vec();
        a.extend_from_slice(&(value.len() as u16).to_be_bytes());
        a.extend_from_slice(value);
        a.resize(a.len().div_ceil(4) * 4, 0);
        a
    }

    #[test]
    fn mapped_address_and_errors() {
        // An old server's MAPPED-ADDRESS, not XOR'd.
        let plain = attr(MAPPED_ADDRESS, &[0, 1, 0x9c, 0x40, 198, 51, 100, 7]);
        assert_eq!(
            parse_response(&message(BINDING_SUCCESS, &plain), &TXID),
            Parse::Answer(Answer::Mapped("198.51.100.7:40000".parse().unwrap()))
        );
        // XOR-MAPPED-ADDRESS wins over MAPPED-ADDRESS, in either order.
        let xor = rfc5769_v4()[36..48].to_vec();
        for attrs in [[plain.clone(), xor.clone()].concat(), [xor, plain].concat()] {
            assert_eq!(
                parse_response(&message(BINDING_SUCCESS, &attrs), &TXID),
                Parse::Answer(Answer::Mapped("192.0.2.1:32853".parse().unwrap()))
            );
        }
        let unauthorized = attr(
            ERROR_CODE,
            &[0, 0, 4, 1, b'U', b'n', b'a', b'u', b't', b'h'],
        );
        assert_eq!(
            parse_response(&message(BINDING_ERROR, &unauthorized), &TXID),
            Parse::Answer(Answer::Error {
                code: 401,
                reason: "Unauth".into()
            })
        );
        // The server's reason never reaches the terminal as an escape
        // sequence, and is cut to 128 characters.
        let mut hostile = vec![0, 0, 5, 0];
        hostile.extend_from_slice(b"\x1b[2J\x07ok");
        hostile.extend_from_slice(&[b'x'; 200]);
        let Parse::Answer(Answer::Error { code, reason }) =
            parse_response(&message(BINDING_ERROR, &attr(ERROR_CODE, &hostile)), &TXID)
        else {
            panic!("not an error answer");
        };
        assert_eq!(code, 500);
        assert!(reason.starts_with("\u{fffd}[2J\u{fffd}ok"), "{reason:?}");
        assert_eq!(reason.chars().count(), 128);
    }

    #[test]
    fn what_is_not_ours_or_does_not_read() {
        let good = rfc5769_v4();
        let mut other_id = good.clone();
        other_id[19] ^= 1;
        let mut other_cookie = good.clone();
        other_cookie[4] ^= 1;
        let mut not_response = good.clone();
        not_response[0] = 0x00; // a success response turned into a request
        let mut top_bits = good.clone();
        top_bits[0] |= 0x80;
        for data in [other_id, other_cookie, not_response, top_bits, vec![0; 19]] {
            assert_eq!(parse_response(&data, &TXID), Parse::NotOurs);
        }
        let malformed = |attrs: &[u8], length: Option<u16>| {
            let mut m = message(BINDING_SUCCESS, attrs);
            if let Some(len) = length {
                m[2..4].copy_from_slice(&len.to_be_bytes());
            }
            parse_response(&m, &TXID)
        };
        let v4 = |value: &[u8]| attr(XOR_MAPPED_ADDRESS, value);
        for (attrs, length, why) in [
            (vec![], Some(2), "length not a multiple of 4"),
            (vec![], Some(8), "cut short"),
            (vec![0, 0x20, 0, 8], None, "attribute past the message"),
            (
                v4(&[0, 1, 0, 0, 1, 2, 3]),
                None,
                "address of the wrong length",
            ),
            (
                v4(&[0, 3, 0, 0, 1, 2, 3, 4]),
                None,
                "address of an unknown family",
            ),
            (
                v4(&[0, 2, 0, 0, 1, 2, 3, 4]),
                None,
                "address of the wrong length",
            ),
            (attr(0x8022, b"x"), None, "no mapped address"),
        ] {
            assert_eq!(malformed(&attrs, length), Parse::Malformed(why), "{why}");
        }
        let short_error = message(BINDING_ERROR, &attr(ERROR_CODE, &[0, 0, 4]));
        assert_eq!(
            parse_response(&short_error, &TXID),
            Parse::Malformed("ERROR-CODE cut short")
        );
        let bad_class = message(BINDING_ERROR, &attr(ERROR_CODE, &[0, 0, 7, 1]));
        assert_eq!(
            parse_response(&bad_class, &TXID),
            Parse::Malformed("ERROR-CODE out of range")
        );
    }

    #[test]
    fn servers_as_written() {
        let ok = |s: &str| parse_server(s).unwrap();
        assert_eq!(ok("stun.example.com"), ("stun.example.com".into(), 3478));
        assert_eq!(
            ok("stun.example.com:19302"),
            ("stun.example.com".into(), 19302)
        );
        assert_eq!(ok("192.0.2.5:3479"), ("192.0.2.5".into(), 3479));
        assert_eq!(ok("2001:db8::5"), ("2001:db8::5".into(), 3478));
        assert_eq!(ok("[2001:db8::5]"), ("2001:db8::5".into(), 3478));
        assert_eq!(ok("[2001:db8::5]:3479"), ("2001:db8::5".into(), 3479));
        assert_eq!(ok("fe80::1%eth0"), ("fe80::1%eth0".into(), 3478));
        assert_eq!(ok("[fe80::1%2]:3479"), ("fe80::1%2".into(), 3479));
        for bad in [
            "",
            ":3478",
            "host:0",
            "host:70000",
            "host:x",
            "[2001:db8::5",
            "[::1]x",
            "[]:1",
            // Written as IPv6 addresses, and not ones.
            ":::1",
            "1:2:3",
            "[::g]",
            "[::g]:3478",
            "[192.0.2.1]:3478",
            "fe80::1%",
        ] {
            assert!(parse_server(bad).is_err(), "{bad}");
        }
    }

    /// `--external` alone asks Cloudflare's server; it needs `--ip`.
    #[test]
    fn the_default_server() {
        use clap::Parser;
        let args = crate::cli::Args::try_parse_from(["sping", "--ip", "--external"]).unwrap();
        let server = args.external.expect("asked");
        assert_eq!(
            parse_server(&server).unwrap(),
            ("stun.cloudflare.com".into(), 3478)
        );
        let named = crate::cli::Args::try_parse_from(["sping", "--ip", "--external", "192.0.2.5"]);
        assert_eq!(named.unwrap().external.as_deref(), Some("192.0.2.5"));
        let err = crate::cli::Args::try_parse_from(["sping", "--external"]).expect_err("refused");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// A simulated wire: what each receive gets, how long it takes; the
    /// clock moves only as the wire says.
    struct Wire {
        now: Cell<Instant>,
        sends: RefCell<Vec<Duration>>,
        start: Instant,
    }

    impl Wire {
        fn new() -> Self {
            let start = Instant::now();
            Self {
                now: Cell::new(start),
                sends: RefCell::new(Vec::new()),
                start,
            }
        }
        fn elapsed(&self) -> Duration {
            self.now.get() - self.start
        }
        fn run(
            &self,
            mut answer: impl FnMut(Duration, Duration) -> (Duration, Option<Vec<u8>>),
        ) -> Outcome {
            exchange(
                &TXID,
                || self.now.get(),
                || {
                    self.sends.borrow_mut().push(self.elapsed());
                    Ok(())
                },
                |wait| {
                    let (took, data) = answer(self.elapsed(), wait);
                    assert!(took <= wait, "a receive took {took:?} of {wait:?}");
                    self.now.set(self.now.get() + took);
                    Ok(data)
                },
            )
        }
    }

    /// Silence: three sends, at 0, 0.5 and 1.5 s, and the end at 3 s.
    #[test]
    fn three_sends_then_the_end() {
        let wire = Wire::new();
        assert_eq!(wire.run(|_, wait| (wait, None)), Outcome::NoAnswer);
        assert_eq!(
            *wire.sends.borrow(),
            [0, 500, 1500].map(Duration::from_millis)
        );
        assert_eq!(wire.elapsed(), BUDGET);
    }

    /// Others' answers and malformed ones all along the budget move neither
    /// a send nor the end; the last malformed one is said.
    #[test]
    fn skipped_answers_move_nothing() {
        let mut foreign = rfc5769_v4();
        foreign[19] ^= 1;
        let wire = Wire::new();
        let every = Duration::from_millis(7);
        let got = wire.run(|_, wait| (every.min(wait), Some(foreign.clone())));
        assert_eq!(got, Outcome::NoAnswer);
        assert_eq!(
            *wire.sends.borrow(),
            [0, 500, 1500].map(Duration::from_millis)
        );
        assert_eq!(wire.elapsed(), BUDGET);

        let mut cut = message(BINDING_SUCCESS, &[]);
        cut[2..4].copy_from_slice(&8u16.to_be_bytes());
        let wire = Wire::new();
        assert_eq!(
            wire.run(|_, wait| (every.min(wait), Some(cut.clone()))),
            Outcome::Malformed("cut short")
        );
        assert_eq!(wire.sends.borrow().len(), 3);
    }

    /// The answer ends the query, after a foreign one and a retransmission.
    #[test]
    fn the_answer_ends_it() {
        let mut foreign = rfc5769_v4();
        foreign[19] ^= 1;
        let good = rfc5769_v4();
        let wire = Wire::new();
        let got = wire.run(|elapsed, wait| {
            if elapsed < Duration::from_millis(600) {
                (wait.min(Duration::from_millis(300)), Some(foreign.clone()))
            } else {
                (Duration::from_millis(20), Some(good.clone()))
            }
        });
        assert_eq!(
            got,
            Outcome::Answer(Answer::Mapped("192.0.2.1:32853".parse().unwrap()))
        );
        assert_eq!(wire.sends.borrow().len(), 2);
    }

    /// An interrupted send is tried again, not counted: the three sends keep
    /// their instants.
    #[test]
    fn an_interrupted_send_is_tried_again() {
        let wire = Wire::new();
        let interrupted = Cell::new(true);
        let got = exchange(
            &TXID,
            || wire.now.get(),
            || {
                if interrupted.replace(false) {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                wire.sends.borrow_mut().push(wire.elapsed());
                Ok(())
            },
            |wait| {
                wire.now.set(wire.now.get() + wait);
                Ok(None)
            },
        );
        assert_eq!(got, Outcome::NoAnswer);
        assert_eq!(
            *wire.sends.borrow(),
            [0, 500, 1500].map(Duration::from_millis)
        );
    }

    /// A port unreachable ends it at once; another receive error too.
    #[test]
    fn refused_ends_it() {
        let start = Instant::now();
        let refused = exchange(
            &TXID,
            || start,
            || Ok(()),
            |_| Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
        );
        assert_eq!(
            refused,
            Outcome::Failed("port unreachable: no STUN server there".into())
        );
        let failed = exchange(
            &TXID,
            || start,
            || Err(io::Error::other("no buffer")),
            |_| Ok(None),
        );
        assert_eq!(failed, Outcome::Failed("send failed: no buffer".into()));
    }
}
