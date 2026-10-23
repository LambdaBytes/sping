//! Exact output of every view for ICMP snapshots. Adding the TCP probe did
//! not change a byte of it: these strings were captured from the views before
//! TCP existed. The 1.6 wording changed the screen text on purpose (quality
//! names, the TTL hint); the JSON strings are still the pre-TCP ones.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::context::NetworkContext;
use crate::context::classify::TargetClass;
use crate::diagnostics::health::Reachability;
use crate::probe::quality::{QualityGrade, Trend};
use crate::probe::trace::UnreachableKind;
use crate::probe::types::{ProbeSnapshot, PulseEntry, Unreachable};
use crate::render::{view_classic, view_compact, view_extended, view_table};

fn ms(v: f64) -> Duration {
    Duration::from_secs_f64(v / 1000.0)
}

/// A target that answers, with network context, a TTL and one loss.
pub(crate) fn replying() -> ProbeSnapshot {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let ctx = NetworkContext {
        interface: "eth0".into(),
        local_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        prefix_len: 24,
        gateway: Some("192.168.1.1".into()),
        target_class: TargetClass::PublicNetwork,
    };
    let mut s = ProbeSnapshot::empty("dns.example".into(), ip, Some(ms(18.5)), Some(ctx));
    s.sent = 10;
    s.received = 9;
    s.lost = 1;
    s.loss_pct = 10.0;
    s.rtt_last = Some(ms(13.8));
    s.rtt_avg = Some(ms(13.9));
    s.rtt_min = Some(ms(13.6));
    s.rtt_max = Some(ms(14.1));
    s.jitter = Some(ms(0.19));
    s.mdev = Some(ms(0.15));
    s.pulse = vec![
        PulseEntry::Reply(ms(13.6)),
        PulseEntry::Reply(ms(14.1)),
        PulseEntry::Loss,
        PulseEntry::Reply(ms(13.8)),
    ];
    s.seq = 10;
    s.quality = Some(QualityGrade::A);
    s.quality_score = Some(95);
    s.trend = Some(Trend::Stable);
    s.ttl = Some(57);
    s.reachability = Reachability::Online;
    s.recent_loss_pct = 10.0;
    s
}

/// The same target right after a timeout.
pub(crate) fn lost() -> ProbeSnapshot {
    let mut s = replying();
    s.sent = 11;
    s.lost = 2;
    s.seq = 11;
    s.loss_pct = 18.2;
    s.rtt_last = None;
    s.ttl = None;
    s.pulse.push(PulseEntry::Loss);
    s
}

/// The same target after a destination unreachable from a router: lost, as
/// a timeout, and said by whom (added in 1.8.0).
pub(crate) fn unreachable() -> ProbeSnapshot {
    let mut s = lost();
    s.unreachable = 1;
    s.icmp_unreachable = Some(Unreachable {
        from: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        kind: UnreachableKind::Host,
    });
    s
}

/// A reply that carried no hop limit (ICMPv6 on Windows: TTL 0).
pub(crate) fn no_hop_limit() -> ProbeSnapshot {
    let mut s = replying();
    s.ttl = Some(0);
    s
}

/// Drop terminal control sequences (cursor moves, clears, colours): the
/// text is what is compared.
pub(crate) fn visible(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

pub(crate) fn classic(snap: &ProbeSnapshot) -> String {
    let mut out = Vec::new();
    let mut view = view_classic::ClassicView::new();
    view.draw(&mut out, snap).unwrap();
    view.summary(&mut out, snap).unwrap();
    visible(&out)
}

pub(crate) fn compact(snap: &ProbeSnapshot) -> String {
    let mut out = Vec::new();
    view_compact::draw_inline(&mut out, snap, None, None, None, 0, 0).unwrap();
    visible(&out)
}

pub(crate) fn extended(snap: &ProbeSnapshot) -> String {
    let mut out = Vec::new();
    view_extended::draw_inline(&mut out, snap, None, None, None, 0, 0).unwrap();
    visible(&out)
}

pub(crate) fn table(snap: &ProbeSnapshot) -> String {
    let mut out = Vec::new();
    view_table::draw_table(&mut out, &[Some(snap.clone())], 0, 0).unwrap();
    visible(&out)
}

#[test]
fn replying_classic() {
    assert_eq!(
        classic(&replying()),
        "Reply from 192.0.2.10: seq=10 ttl=57 time=13.8 ms\n\n--- dns.example ping statistics ---\n10 packets transmitted, 9 received, 10.0% packet loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn replying_compact() {
    assert_eq!(
        compact(&replying()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄                                    \r\nLatency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 10% · sent 10 · recv 9 · ttl 57 · hops ~7\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     intermittent loss\r\n"
    );
}

#[test]
fn replying_extended() {
    assert_eq!(
        extended(&replying()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄                                    \r\nLatency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nRTT dist   p50 13.8 · p95 14.1 · p99 14.1 ms · range 0.4\r\nStatus     Reachable · loss 10% · sent 10 · recv 9 · ttl 57 · hops ~7\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     intermittent loss\r\nPath       local ●──────────────────────────────────────◎ 192.0.2.10\r\n"
    );
}

#[test]
fn replying_table() {
    assert_eq!(
        table(&replying()),
        "sping multi-target  ⠋ probing...\r\n\r\nTarget                      RTT        Avg   Loss    Qual      Trend        TTL  Hops\r\n───────────────────────────────────────────────────────────────────────────────\r\ndns.example (192.0.…    13.8 ms    13.9 ms    10%     A95     stable         57    ~7\r\n"
    );
}

#[test]
fn replying_json() {
    assert_eq!(
        serde_json::to_string(&replying()).unwrap(),
        "{\"target_host\":\"dns.example\",\"target_ip\":\"192.0.2.10\",\"dns_time\":18.5,\"sent\":10,\"received\":9,\"lost\":1,\"loss_pct\":10.0,\"rtt_last\":13.799999999999999,\"rtt_avg\":13.899999999999999,\"rtt_min\":13.6,\"rtt_max\":14.1,\"jitter\":0.19,\"mdev\":0.15,\"pulse\":[{\"Reply\":13.6},{\"Reply\":14.1},\"Loss\",{\"Reply\":13.799999999999999}],\"seq\":10,\"quality\":\"A\",\"quality_score\":95,\"trend\":\"stable\",\"ttl\":57,\"net_ctx\":{\"interface\":\"eth0\",\"local_ip\":\"192.168.1.100\",\"prefix_len\":24,\"gateway\":\"192.168.1.1\",\"target_class\":\"PublicNetwork\"}}"
    );
}

#[test]
fn lost_classic() {
    assert_eq!(
        classic(&lost()),
        "Request timeout for seq=11\n\n--- dns.example ping statistics ---\n11 packets transmitted, 9 received, 18.2% packet loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn lost_compact() {
    assert_eq!(
        compact(&lost()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄✕                                   \r\nLatency    now — · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 18% · sent 11 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     intermittent loss\r\n"
    );
}

#[test]
fn lost_extended() {
    assert_eq!(
        extended(&lost()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄✕                                   \r\nLatency    now — · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nRTT dist   p50 13.8 · p95 14.1 · p99 14.1 ms · range 0.4\r\nStatus     Reachable · loss 18% · sent 11 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     intermittent loss\r\nPath       local ───────────────────────────────────────◉ 192.0.2.10\r\n"
    );
}

#[test]
fn lost_table() {
    assert_eq!(
        table(&lost()),
        "sping multi-target  ⠋ probing...\r\n\r\nTarget                      RTT        Avg   Loss    Qual      Trend        TTL  Hops\r\n───────────────────────────────────────────────────────────────────────────────\r\ndns.example (192.0.…          —    13.9 ms    18%     A95     stable          —     —\r\n"
    );
}

#[test]
fn lost_json() {
    assert_eq!(
        serde_json::to_string(&lost()).unwrap(),
        "{\"target_host\":\"dns.example\",\"target_ip\":\"192.0.2.10\",\"dns_time\":18.5,\"sent\":11,\"received\":9,\"lost\":2,\"loss_pct\":18.2,\"rtt_last\":null,\"rtt_avg\":13.899999999999999,\"rtt_min\":13.6,\"rtt_max\":14.1,\"jitter\":0.19,\"mdev\":0.15,\"pulse\":[{\"Reply\":13.6},{\"Reply\":14.1},\"Loss\",{\"Reply\":13.799999999999999},\"Loss\"],\"seq\":11,\"quality\":\"A\",\"quality_score\":95,\"trend\":\"stable\",\"ttl\":null,\"net_ctx\":{\"interface\":\"eth0\",\"local_ip\":\"192.168.1.100\",\"prefix_len\":24,\"gateway\":\"192.168.1.1\",\"target_class\":\"PublicNetwork\"}}"
    );
}

#[test]
fn unreachable_classic() {
    assert_eq!(
        classic(&unreachable()),
        "From 198.51.100.1: seq=11 Destination Host Unreachable\n\n--- dns.example ping statistics ---\n11 packets transmitted, 9 received, +1 errors, 18.2% packet loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn unreachable_compact() {
    assert_eq!(
        compact(&unreachable()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄✕                                   \r\nLatency    now — · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 18% · sent 11 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     198.51.100.1 reports host unreachable · intermittent loss\r\n"
    );
}

#[test]
fn unreachable_extended() {
    assert_eq!(
        extended(&unreachable()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄✕                                   \r\nLatency    now — · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nRTT dist   p50 13.8 · p95 14.1 · p99 14.1 ms · range 0.4\r\nStatus     Reachable · loss 18% · sent 11 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     198.51.100.1 reports host unreachable · intermittent loss\r\nPath       local ───────────────────────────────────────◉ 192.0.2.10\r\n"
    );
}

/// The table shows the loss, as for a timeout.
#[test]
fn unreachable_table() {
    assert_eq!(table(&unreachable()), table(&lost()));
}

/// The v1 line of a loss, then the new field.
#[test]
fn unreachable_json() {
    assert_eq!(
        serde_json::to_string(&unreachable()).unwrap(),
        "{\"target_host\":\"dns.example\",\"target_ip\":\"192.0.2.10\",\"dns_time\":18.5,\"sent\":11,\"received\":9,\"lost\":2,\"loss_pct\":18.2,\"rtt_last\":null,\"rtt_avg\":13.899999999999999,\"rtt_min\":13.6,\"rtt_max\":14.1,\"jitter\":0.19,\"mdev\":0.15,\"pulse\":[{\"Reply\":13.6},{\"Reply\":14.1},\"Loss\",{\"Reply\":13.799999999999999},\"Loss\"],\"seq\":11,\"quality\":\"A\",\"quality_score\":95,\"trend\":\"stable\",\"ttl\":null,\"net_ctx\":{\"interface\":\"eth0\",\"local_ip\":\"192.168.1.100\",\"prefix_len\":24,\"gateway\":\"192.168.1.1\",\"target_class\":\"PublicNetwork\"},\"icmp_unreachable\":{\"from\":\"198.51.100.1\",\"kind\":\"host\"}}"
    );
}

#[test]
fn no_hop_limit_classic() {
    assert_eq!(
        classic(&no_hop_limit()),
        "Reply from 192.0.2.10: seq=10 time=13.8 ms\n\n--- dns.example ping statistics ---\n10 packets transmitted, 9 received, 10.0% packet loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn no_hop_limit_compact() {
    assert_eq!(
        compact(&no_hop_limit()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄                                    \r\nLatency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 10% · sent 10 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     intermittent loss\r\n"
    );
}

#[test]
fn no_hop_limit_extended() {
    assert_eq!(
        extended(&no_hop_limit()),
        "sping dns.example (192.0.2.10) via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄                                    \r\nLatency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nRTT dist   p50 13.8 · p95 14.1 · p99 14.1 ms · range 0.4\r\nStatus     Reachable · loss 10% · sent 10 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     intermittent loss\r\nPath       local ●──────────────────────────────────────◎ 192.0.2.10\r\n"
    );
}

#[test]
fn no_hop_limit_table() {
    assert_eq!(
        table(&no_hop_limit()),
        "sping multi-target  ⠋ probing...\r\n\r\nTarget                      RTT        Avg   Loss    Qual      Trend        TTL  Hops\r\n───────────────────────────────────────────────────────────────────────────────\r\ndns.example (192.0.…    13.8 ms    13.9 ms    10%     A95     stable          —     —\r\n"
    );
}

#[test]
fn no_hop_limit_json() {
    assert_eq!(
        serde_json::to_string(&no_hop_limit()).unwrap(),
        "{\"target_host\":\"dns.example\",\"target_ip\":\"192.0.2.10\",\"dns_time\":18.5,\"sent\":10,\"received\":9,\"lost\":1,\"loss_pct\":10.0,\"rtt_last\":13.799999999999999,\"rtt_avg\":13.899999999999999,\"rtt_min\":13.6,\"rtt_max\":14.1,\"jitter\":0.19,\"mdev\":0.15,\"pulse\":[{\"Reply\":13.6},{\"Reply\":14.1},\"Loss\",{\"Reply\":13.799999999999999}],\"seq\":10,\"quality\":\"A\",\"quality_score\":95,\"trend\":\"stable\",\"ttl\":0,\"net_ctx\":{\"interface\":\"eth0\",\"local_ip\":\"192.168.1.100\",\"prefix_len\":24,\"gateway\":\"192.168.1.1\",\"target_class\":\"PublicNetwork\"}}"
    );
}

/// The line of a frame that starts with `label`.
fn line<'a>(frame: &'a str, label: &str) -> &'a str {
    frame
        .split("\r\n")
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label} line in {frame:?}"))
}

/// A TTL still at an initial value hints at the system; a lowered one
/// (`replying`, 57) does not.
#[test]
fn initial_ttl_gives_a_hint() {
    let mut s = replying();
    s.ttl = Some(64);
    assert_eq!(
        line(&compact(&s), "Status"),
        "Status     Reachable · loss 10% · sent 10 · recv 9 · ttl 64 (Unix-like)"
    );
    assert!(
        table(&s).contains("     stable   64(Unix)    ~0"),
        "{}",
        table(&s)
    );
    s.ttl = Some(128);
    assert!(line(&extended(&s), "Status").ends_with("· ttl 128 (Windows)"));
}

/// A loopback target is `loopback` on screen, its source on the loopback
/// interface; JSON keeps the value loopback always had.
#[test]
fn loopback_target() {
    let mut s = replying();
    s.target_host = "127.0.0.1".into();
    s.target_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    s.net_ctx = Some(NetworkContext {
        interface: "lo".into(),
        local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        prefix_len: 8,
        gateway: Some("192.168.1.1".into()),
        target_class: TargetClass::Loopback,
    });
    assert_eq!(
        line(&compact(&s), "Context"),
        "Context    if lo · 127.0.0.1/8 · gw ? · wan ? · loopback"
    );
    assert!(
        serde_json::to_string(&s)
            .unwrap()
            .contains("\"net_ctx\":{\"interface\":\"lo\",\"local_ip\":\"127.0.0.1\",\"prefix_len\":8,\"gateway\":\"192.168.1.1\",\"target_class\":\"RoutedInternal\"}")
    );
}

/// An IPv6 target the system has no IPv6 source for: said as such, with no
/// interface (none was looked up).
#[test]
fn no_ipv6_source() {
    let mut s = replying();
    s.target_ip = "2001:db8::10".parse().unwrap();
    s.net_ctx = Some(NetworkContext {
        interface: "unknown".into(),
        local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        prefix_len: 0,
        gateway: Some("192.168.1.1".into()),
        target_class: TargetClass::PublicNetwork,
    });
    for frame in [compact(&s), extended(&s)] {
        assert_eq!(
            line(&frame, "sping"),
            "sping dns.example (2001:db8::10)  ⠋ probing..."
        );
        assert_eq!(
            line(&frame, "Context"),
            "Context    no IPv6 source · gw ? · wan ? · public"
        );
    }
}

/// An address given with its zone is the target's name: shown once.
#[test]
fn zoned_literal_shown_once_in_the_table() {
    let mut s = replying();
    s.target_host = "fe80::1%eth0".into();
    s.target_ip = "fe80::1".parse().unwrap();
    assert!(
        table(&s).contains("\r\nfe80::1%eth0            13.8 ms"),
        "{}",
        table(&s)
    );
}

/// The views warn from the snapshot's high-jitter flag (the quality
/// window's); the flag is not part of the JSON.
#[test]
fn high_jitter_warning_from_the_window_flag() {
    let mut s = replying();
    s.recent_loss_pct = 0.0;
    s.high_jitter = true;
    for frame in [compact(&s), extended(&s)] {
        assert_eq!(
            line(&frame, "Events"),
            "Events     high jitter with no loss · unstable path"
        );
    }
    let json = serde_json::to_string(&s).unwrap();
    s.high_jitter = false;
    assert!(!compact(&s).contains("high jitter"));
    assert_eq!(json, serde_json::to_string(&s).unwrap());
}
