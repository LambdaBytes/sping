//! `sping --ip`: the host's addresses (`context::addresses`) as text, a short
//! table that pipes as it is, or as one JSON object (JSON_CONTRACT.md, "sping
//! --ip"). What is not known is said: `/?` for a prefix, `unknown` for a
//! source, gateway or external address; a state the system does not report is
//! left out of the text and `null` in JSON. With `--external`, what a STUN
//! server saw (`context::stun`) follows; without it, nothing changes.

use std::net::IpAddr;

use serde::Serialize;

use crate::context::addresses::{
    Gateway, HostAddress, HostView, Kind, SOURCE_REFERENCE_V4, SOURCE_REFERENCE_V6, Source, States,
    kind,
};
use crate::context::stun::{External, ExternalView};

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Loopback => "loopback",
        Kind::LinkLocal => "link-local",
        Kind::Private => "private",
        Kind::Shared => "shared (CGNAT)",
        Kind::Global => "global",
    }
}

/// The states that hold, in this order.
fn state_names(states: &States) -> Vec<&'static str> {
    [
        (states.temporary, "temporary"),
        (states.deprecated, "deprecated"),
        (states.tentative, "tentative"),
        (states.duplicate, "duplicate"),
    ]
    .into_iter()
    .filter_map(|(state, name)| (state == Some(true)).then_some(name))
    .collect()
}

fn address_text(a: &HostAddress) -> String {
    match a.prefix_len {
        Some(p) => format!("{}/{p}", a.ip),
        None => format!("{}/?", a.ip),
    }
}

/// `IPv4 192.168.1.100 (eth0) to 1.1.1.1`, `no IPv6 source to …`, or
/// `IPv4 unknown (why) to …`.
fn source_text(family: &str, source: &Source, to: IpAddr) -> String {
    match source {
        Source::Found {
            ip,
            interface: Some(name),
        } => format!("{family} {ip} ({name}) to {to}"),
        Source::Found {
            ip,
            interface: None,
        } => format!("{family} {ip} to {to}"),
        Source::None => format!("no {family} source to {to}"),
        Source::Unknown(why) => format!("{family} unknown ({why}) to {to}"),
    }
}

fn gateway_text(gateway: &Gateway) -> String {
    match gateway {
        Gateway::Found {
            ip,
            interface: Some(name),
        } => format!("IPv4 {ip} ({name})"),
        Gateway::Found {
            ip,
            interface: None,
        } => format!("IPv4 {ip}"),
        Gateway::None => "no IPv4 default gateway".into(),
        Gateway::Unknown(why) => format!("IPv4 unknown ({why})"),
    }
}

/// `IPv4 198.51.100.77:40312 from 10.0.1.2:51234`, `IPv4 unknown (why)`, or
/// `IPv6 not asked (…)` when the server's name gave no address of the family.
fn external_text(family: &str, external: Option<&External>) -> String {
    match external {
        Some(External::Seen {
            mapped,
            local: Some(local),
            ..
        }) => format!("{family} {mapped} from {local}"),
        Some(External::Seen {
            mapped,
            local: None,
            ..
        }) => format!("{family} {mapped}"),
        Some(External::Unknown { reason, .. }) => format!("{family} unknown ({reason})"),
        None => format!("{family} not asked (no {family} address for the server)"),
    }
}

/// The text view: one row per address (the interface named on its first),
/// then the sources, the gateway and, when asked, the external addresses.
pub fn text(view: &HostView, external: Option<&ExternalView>, sep: &str) -> String {
    let label = if external.is_some() {
        "External"
    } else {
        "Gateway"
    };
    let name_width = view
        .addresses
        .iter()
        .map(|a| a.interface.chars().count())
        .max()
        .unwrap_or(0)
        .max(label.len());
    let address_width = view
        .addresses
        .iter()
        .map(|a| address_text(a).len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    let mut previous: Option<&str> = None;
    for a in &view.addresses {
        let name = if previous == Some(a.interface.as_str()) {
            ""
        } else {
            a.interface.as_str()
        };
        previous = Some(a.interface.as_str());
        let mut words = vec![kind_name(kind(a.ip))];
        if let Some(states) = &a.states {
            words.extend(state_names(states));
        }
        let line = format!(
            "{name:<name_width$}  {:<address_width$}  {}",
            address_text(a),
            words.join(sep)
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }
    if view.addresses.is_empty() {
        out.push_str("No addresses.\n");
    }
    out.push('\n');
    out.push_str(&format!(
        "{:<name_width$}  {}{sep}{}\n",
        "Source",
        source_text("IPv4", &view.source_v4, SOURCE_REFERENCE_V4),
        source_text("IPv6", &view.source_v6, SOURCE_REFERENCE_V6),
    ));
    out.push_str(&format!(
        "{:<name_width$}  {}\n",
        "Gateway",
        gateway_text(&view.gateway)
    ));
    if let Some(external) = external {
        out.push_str(&format!(
            "{:<name_width$}  {}{sep}{} (STUN server {})\n",
            "External",
            external_text("IPv4", external.v4.as_ref()),
            external_text("IPv6", external.v6.as_ref()),
            external.server,
        ));
    }
    out
}

#[derive(Serialize)]
struct JsonView<'a> {
    interfaces: Vec<JsonInterface<'a>>,
    source: JsonSources<'a>,
    gateway: JsonGateways<'a>,
    /// Only with `--external`.
    #[serde(skip_serializing_if = "Option::is_none")]
    external: Option<JsonExternal<'a>>,
}

#[derive(Serialize)]
struct JsonInterface<'a> {
    name: &'a str,
    addresses: Vec<JsonAddress>,
}

#[derive(Serialize)]
struct JsonAddress {
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    ip: IpAddr,
    prefix_len: Option<u8>,
    kind: Kind,
    /// IPv6 only: `temporary`, `deprecated`, `tentative`, `duplicate`.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    states: Option<States>,
}

#[derive(Serialize)]
struct JsonSources<'a> {
    ipv4: JsonSource<'a>,
    ipv6: JsonSource<'a>,
}

/// `{"to", "ip", "interface"}`; `ip` `null` when there is no source;
/// `{"to", "unknown"}` when it could not be told.
#[derive(Serialize)]
struct JsonSource<'a> {
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    to: IpAddr,
    #[serde(flatten)]
    found: JsonFound<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum JsonFound<'a> {
    Address {
        ip: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        interface: Option<Option<&'a str>>,
    },
    Unknown {
        unknown: &'a str,
    },
}

impl<'a> JsonSource<'a> {
    fn new(source: &'a Source, to: IpAddr) -> Self {
        let found = match source {
            Source::Found { ip, interface } => JsonFound::Address {
                ip: Some(ip.to_string()),
                interface: Some(interface.as_deref()),
            },
            Source::None => JsonFound::Address {
                ip: None,
                interface: None,
            },
            Source::Unknown(why) => JsonFound::Unknown { unknown: why },
        };
        Self { to, found }
    }
}

#[derive(Serialize)]
struct JsonGateways<'a> {
    /// `null` when there is no default route.
    ipv4: Option<JsonGateway<'a>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum JsonGateway<'a> {
    Found {
        ip: String,
        interface: Option<&'a str>,
    },
    Unknown {
        unknown: &'a str,
    },
}

#[derive(Serialize)]
struct JsonExternal<'a> {
    server: &'a str,
    /// `null` when the server's name gave no address of the family.
    ipv4: Option<JsonSeen<'a>>,
    ipv6: Option<JsonSeen<'a>>,
}

/// `{"ip", "port", "local", "asked"}`: what the server saw, the socket it
/// came from (`null` if the system did not say) and the server's address
/// asked; `{"asked", "unknown"}` when it could not be told (`asked` `null`
/// when no address was asked).
#[derive(Serialize)]
#[serde(untagged)]
enum JsonSeen<'a> {
    Seen {
        ip: String,
        port: u16,
        local: Option<String>,
        asked: String,
    },
    Unknown {
        asked: Option<String>,
        unknown: &'a str,
    },
}

impl<'a> JsonSeen<'a> {
    fn new(external: &'a External) -> Self {
        match external {
            External::Seen {
                mapped,
                local,
                asked,
            } => JsonSeen::Seen {
                ip: mapped.ip().to_string(),
                port: mapped.port(),
                local: local.map(|l| l.to_string()),
                asked: asked.to_string(),
            },
            External::Unknown { asked, reason } => JsonSeen::Unknown {
                asked: asked.map(|a| a.to_string()),
                unknown: reason,
            },
        }
    }
}

/// The JSON view: one object, `{"interfaces", "source", "gateway"}`, and
/// `"external"` when it was asked.
///
/// # Errors
///
/// Serialization failed.
pub fn json(view: &HostView, external: Option<&ExternalView>) -> serde_json::Result<String> {
    let mut interfaces: Vec<JsonInterface> = Vec::new();
    for a in &view.addresses {
        let address = JsonAddress {
            ip: a.ip,
            prefix_len: a.prefix_len,
            kind: kind(a.ip),
            states: a.states,
        };
        match interfaces.last_mut() {
            Some(last) if last.name == a.interface => last.addresses.push(address),
            _ => interfaces.push(JsonInterface {
                name: &a.interface,
                addresses: vec![address],
            }),
        }
    }
    let gateway = match &view.gateway {
        Gateway::Found { ip, interface } => Some(JsonGateway::Found {
            ip: ip.to_string(),
            interface: interface.as_deref(),
        }),
        Gateway::None => None,
        Gateway::Unknown(why) => Some(JsonGateway::Unknown { unknown: why }),
    };
    serde_json::to_string(&JsonView {
        interfaces,
        source: JsonSources {
            ipv4: JsonSource::new(&view.source_v4, SOURCE_REFERENCE_V4),
            ipv6: JsonSource::new(&view.source_v6, SOURCE_REFERENCE_V6),
        },
        gateway: JsonGateways { ipv4: gateway },
        external: external.map(|e| JsonExternal {
            server: &e.server,
            ipv4: e.v4.as_ref().map(JsonSeen::new),
            ipv6: e.v6.as_ref().map(JsonSeen::new),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v6_states(temporary: Option<bool>, deprecated: bool) -> Option<States> {
        Some(States {
            temporary,
            deprecated: Some(deprecated),
            tentative: Some(false),
            duplicate: Some(false),
        })
    }

    /// A host with every kind of row: the interface named once, IPv6 states
    /// that hold, an unknown prefix and an unknown state (Windows' temporary).
    fn host() -> HostView {
        let a = |interface: &str, address: &str, prefix, states| HostAddress {
            interface: interface.into(),
            ip: ip(address),
            prefix_len: prefix,
            states,
        };
        HostView {
            addresses: vec![
                a("eth0", "192.168.1.100", Some(24), None),
                a(
                    "eth0",
                    "2001:db8::5b1:c2ff:1",
                    Some(64),
                    v6_states(Some(true), false),
                ),
                a("eth0", "2001:db8::dead", Some(64), v6_states(None, true)),
                a(
                    "eth0",
                    "fe80::1c2:3ff:fe45:6789",
                    Some(64),
                    v6_states(Some(false), false),
                ),
                a("wwan0", "100.72.10.3", None, None),
                a("lo", "127.0.0.1", Some(8), None),
                a("lo", "::1", Some(128), v6_states(Some(false), false)),
            ],
            source_v4: Source::Found {
                ip: ip("192.168.1.100"),
                interface: Some("eth0".into()),
            },
            source_v6: Source::None,
            gateway: Gateway::Found {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                interface: Some("eth0".into()),
            },
        }
    }

    #[test]
    fn text_view() {
        assert_eq!(
            text(&host(), None, " · "),
            "\
eth0     192.168.1.100/24            private
         2001:db8::5b1:c2ff:1/64     global · temporary
         2001:db8::dead/64           global · deprecated
         fe80::1c2:3ff:fe45:6789/64  link-local
wwan0    100.72.10.3/?               shared (CGNAT)
lo       127.0.0.1/8                 loopback
         ::1/128                     loopback

Source   IPv4 192.168.1.100 (eth0) to 1.1.1.1 · no IPv6 source to 2606:4700:4700::1111
Gateway  IPv4 192.168.1.1 (eth0)
"
        );
    }

    /// What could not be told is said so, with the reason; an interface not
    /// found is left out.
    #[test]
    fn text_view_of_what_is_unknown() {
        let view = HostView {
            addresses: vec![],
            source_v4: Source::Found {
                ip: ip("10.0.0.5"),
                interface: None,
            },
            source_v6: Source::Unknown("permission denied".into()),
            gateway: Gateway::Unknown("cannot read /proc/net/route: x".into()),
        };
        assert_eq!(
            text(&view, None, " | "),
            "No addresses.\n\nSource   IPv4 10.0.0.5 to 1.1.1.1 | IPv6 unknown (permission denied) to 2606:4700:4700::1111\nGateway  IPv4 unknown (cannot read /proc/net/route: x)\n"
        );
        let none = HostView {
            gateway: Gateway::None,
            ..view
        };
        assert!(
            text(&none, None, " | ").ends_with("Gateway  no IPv4 default gateway\n"),
            "{}",
            text(&none, None, " | ")
        );
    }

    #[test]
    fn json_view() {
        assert_eq!(
            json(&host(), None).unwrap(),
            concat!(
                r#"{"interfaces":[{"name":"eth0","addresses":["#,
                r#"{"ip":"192.168.1.100","prefix_len":24,"kind":"private"},"#,
                r#"{"ip":"2001:db8::5b1:c2ff:1","prefix_len":64,"kind":"global","temporary":true,"deprecated":false,"tentative":false,"duplicate":false},"#,
                r#"{"ip":"2001:db8::dead","prefix_len":64,"kind":"global","temporary":null,"deprecated":true,"tentative":false,"duplicate":false},"#,
                r#"{"ip":"fe80::1c2:3ff:fe45:6789","prefix_len":64,"kind":"link_local","temporary":false,"deprecated":false,"tentative":false,"duplicate":false}]},"#,
                r#"{"name":"wwan0","addresses":[{"ip":"100.72.10.3","prefix_len":null,"kind":"shared"}]},"#,
                r#"{"name":"lo","addresses":[{"ip":"127.0.0.1","prefix_len":8,"kind":"loopback"},"#,
                r#"{"ip":"::1","prefix_len":128,"kind":"loopback","temporary":false,"deprecated":false,"tentative":false,"duplicate":false}]}],"#,
                r#""source":{"ipv4":{"to":"1.1.1.1","ip":"192.168.1.100","interface":"eth0"},"#,
                r#""ipv6":{"to":"2606:4700:4700::1111","ip":null}},"#,
                r#""gateway":{"ipv4":{"ip":"192.168.1.1","interface":"eth0"}}}"#
            )
        );
    }

    #[test]
    fn json_view_of_what_is_unknown() {
        let view = HostView {
            addresses: vec![],
            source_v4: Source::Found {
                ip: ip("10.0.0.5"),
                interface: None,
            },
            source_v6: Source::Unknown("permission denied".into()),
            gateway: Gateway::Unknown("cannot read /proc/net/route: x".into()),
        };
        assert_eq!(
            json(&view, None).unwrap(),
            concat!(
                r#"{"interfaces":[],"source":{"ipv4":{"to":"1.1.1.1","ip":"10.0.0.5","interface":null},"#,
                r#""ipv6":{"to":"2606:4700:4700::1111","unknown":"permission denied"}},"#,
                r#""gateway":{"ipv4":{"unknown":"cannot read /proc/net/route: x"}}}"#
            )
        );
        let none = HostView {
            gateway: Gateway::None,
            ..view
        };
        assert!(
            json(&none, None)
                .unwrap()
                .ends_with(r#""gateway":{"ipv4":null}}"#)
        );
    }

    fn external() -> ExternalView {
        ExternalView {
            server: "stun.example.net:3478".into(),
            v4: Some(External::Seen {
                mapped: "198.51.100.77:40312".parse().unwrap(),
                local: Some("192.168.1.100:51234".parse().unwrap()),
                asked: ip("192.0.2.10"),
            }),
            v6: Some(External::Seen {
                mapped: "[2001:db8:77::5]:51022".parse().unwrap(),
                local: None,
                asked: ip("2001:db8::10"),
            }),
        }
    }

    /// Asked, the external line follows the gateway and the label column
    /// widens to it; the rest is the view without it.
    #[test]
    fn text_view_with_external() {
        let with = text(&host(), Some(&external()), " · ");
        assert!(
            with.ends_with(concat!(
                "\nGateway   IPv4 192.168.1.1 (eth0)\n",
                "External  IPv4 198.51.100.77:40312 from 192.168.1.100:51234 · ",
                "IPv6 [2001:db8:77::5]:51022 (STUN server stun.example.net:3478)\n"
            )),
            "{with}"
        );
        assert!(with.starts_with("eth0      192.168.1.100/24 "), "{with}");
        let unknown = ExternalView {
            v4: Some(External::Unknown {
                asked: Some(ip("192.0.2.10")),
                reason: "no answer within 3 s".into(),
            }),
            v6: None,
            ..external()
        };
        let text = text(&host(), Some(&unknown), " | ");
        assert!(
            text.ends_with(concat!(
                "External  IPv4 unknown (no answer within 3 s) | ",
                "IPv6 not asked (no IPv6 address for the server) (STUN server stun.example.net:3478)\n"
            )),
            "{text}"
        );
    }

    #[test]
    fn json_view_with_external() {
        let without = json(&host(), None).unwrap();
        let with = json(&host(), Some(&external())).unwrap();
        assert_eq!(
            with,
            format!(
                "{},{}}}",
                without.strip_suffix('}').unwrap(),
                concat!(
                    r#""external":{"server":"stun.example.net:3478","#,
                    r#""ipv4":{"ip":"198.51.100.77","port":40312,"local":"192.168.1.100:51234","asked":"192.0.2.10"},"#,
                    r#""ipv6":{"ip":"2001:db8:77::5","port":51022,"local":null,"asked":"2001:db8::10"}}"#
                )
            )
        );
        let unknown = ExternalView {
            v4: Some(External::Unknown {
                asked: None,
                reason: "DNS resolution failed for 'x'".into(),
            }),
            v6: None,
            ..external()
        };
        assert!(json(&host(), Some(&unknown)).unwrap().ends_with(concat!(
            r#""external":{"server":"stun.example.net:3478","#,
            r#""ipv4":{"asked":null,"unknown":"DNS resolution failed for 'x'"},"ipv6":null}}"#
        )));
    }
}
