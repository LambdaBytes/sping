//! Exact output of every view for TCP snapshots (`--tcp`): the port, how the
//! last connect ended and the refused count; no TTL, OS hint or hops.

use crate::probe::types::{ProbeSnapshot, TcpState};
use crate::render::golden_icmp::{classic, compact, extended, lost, replying, table};

/// A TCP snapshot from an ICMP one: no TTL, port 443, 2 refusals so far.
fn tcp(icmp: ProbeSnapshot, state: TcpState) -> ProbeSnapshot {
    let mut s = icmp.with_tcp(Some(443));
    s.ttl = None;
    s.refused = Some(2);
    s.tcp_state = Some(state);
    s
}

/// Last connect established.
pub(crate) fn open() -> ProbeSnapshot {
    tcp(replying(), TcpState::Open)
}

/// Last connect refused: an answer, with its time.
pub(crate) fn refused() -> ProbeSnapshot {
    tcp(replying(), TcpState::Refused)
}

/// Last connect unanswered until the timeout.
pub(crate) fn timed_out() -> ProbeSnapshot {
    tcp(lost(), TcpState::Timeout)
}

/// Last connect failed locally (no route): a loss, with the reason.
pub(crate) fn failed() -> ProbeSnapshot {
    let mut s = tcp(lost(), TcpState::Error);
    s.last_error = Some("connect failed: Network is unreachable (os error 101)".into());
    s
}

#[test]
fn open_classic() {
    assert_eq!(
        classic(&open()),
        "Connected to 192.0.2.10:443: seq=10 time=13.8 ms\n\n--- dns.example tcp/443 statistics ---\n10 connects, 9 answered (2 refused), 10.0% loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn open_compact() {
    assert_eq!(
        compact(&open()),
        "sping dns.example (192.0.2.10) tcp/443 via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄                                    \r\nLatency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 10% · sent 10 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     TCP 443 connected · 13.8 ms · intermittent loss\r\n"
    );
}

#[test]
fn open_extended() {
    assert_eq!(
        extended(&open()),
        "sping dns.example (192.0.2.10) tcp/443 via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄                                    \r\nLatency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nRTT dist   p50 13.8 · p95 14.1 · p99 14.1 ms · range 0.4\r\nStatus     Reachable · loss 10% · sent 10 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     TCP 443 connected · 13.8 ms · intermittent loss\r\nPath       local ●──────────────────────────────────────◎ 192.0.2.10\r\n"
    );
}

#[test]
fn open_table() {
    assert_eq!(
        table(&open()),
        "sping multi-target  tcp/443  ⠋ probing...\r\n\r\nTarget                      RTT        Avg   Loss    Qual      Trend        TCP  Hops\r\n───────────────────────────────────────────────────────────────────────────────\r\ndns.example (192.0.…    13.8 ms    13.9 ms    10%     A95     stable       open     —\r\n"
    );
}

#[test]
fn open_json() {
    assert_eq!(
        serde_json::to_string(&open()).unwrap(),
        "{\"target_host\":\"dns.example\",\"target_ip\":\"192.0.2.10\",\"dns_time\":18.5,\"sent\":10,\"received\":9,\"lost\":1,\"loss_pct\":10.0,\"rtt_last\":13.799999999999999,\"rtt_avg\":13.899999999999999,\"rtt_min\":13.6,\"rtt_max\":14.1,\"jitter\":0.19,\"mdev\":0.15,\"pulse\":[{\"Reply\":13.6},{\"Reply\":14.1},\"Loss\",{\"Reply\":13.799999999999999}],\"seq\":10,\"quality\":\"A\",\"quality_score\":95,\"trend\":\"stable\",\"ttl\":null,\"net_ctx\":{\"interface\":\"eth0\",\"local_ip\":\"192.168.1.100\",\"prefix_len\":24,\"gateway\":\"192.168.1.1\",\"target_class\":\"PublicNetwork\"},\"probe\":\"tcp\",\"port\":443,\"refused\":2,\"tcp_state\":\"open\"}"
    );
}

#[test]
fn ipv6_endpoint_classic() {
    let mut s = open();
    s.target_ip = "2001:db8::10".parse().unwrap();
    assert_eq!(
        classic(&s),
        "Connected to [2001:db8::10]:443: seq=10 time=13.8 ms\n\n--- dns.example tcp/443 statistics ---\n10 connects, 9 answered (2 refused), 10.0% loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn refused_classic() {
    assert_eq!(
        classic(&refused()),
        "Refused by 192.0.2.10:443: seq=10 time=13.8 ms\n\n--- dns.example tcp/443 statistics ---\n10 connects, 9 answered (2 refused), 10.0% loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn refused_compact() {
    assert_eq!(
        compact(&refused()),
        "sping dns.example (192.0.2.10) tcp/443 via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄                                    \r\nLatency    now 13.8 ms · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 10% · sent 10 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     TCP 443 refused · host or firewall answered · intermittent loss\r\n"
    );
}

#[test]
fn refused_table() {
    assert_eq!(
        table(&refused()),
        "sping multi-target  tcp/443  ⠋ probing...\r\n\r\nTarget                      RTT        Avg   Loss    Qual      Trend        TCP  Hops\r\n───────────────────────────────────────────────────────────────────────────────\r\ndns.example (192.0.…    13.8 ms    13.9 ms    10%     A95     stable    refused     —\r\n"
    );
}

#[test]
fn refused_json() {
    assert_eq!(
        serde_json::to_string(&refused()).unwrap(),
        "{\"target_host\":\"dns.example\",\"target_ip\":\"192.0.2.10\",\"dns_time\":18.5,\"sent\":10,\"received\":9,\"lost\":1,\"loss_pct\":10.0,\"rtt_last\":13.799999999999999,\"rtt_avg\":13.899999999999999,\"rtt_min\":13.6,\"rtt_max\":14.1,\"jitter\":0.19,\"mdev\":0.15,\"pulse\":[{\"Reply\":13.6},{\"Reply\":14.1},\"Loss\",{\"Reply\":13.799999999999999}],\"seq\":10,\"quality\":\"A\",\"quality_score\":95,\"trend\":\"stable\",\"ttl\":null,\"net_ctx\":{\"interface\":\"eth0\",\"local_ip\":\"192.168.1.100\",\"prefix_len\":24,\"gateway\":\"192.168.1.1\",\"target_class\":\"PublicNetwork\"},\"probe\":\"tcp\",\"port\":443,\"refused\":2,\"tcp_state\":\"refused\"}"
    );
}

#[test]
fn timed_out_classic() {
    assert_eq!(
        classic(&timed_out()),
        "Request timeout for seq=11\n\n--- dns.example tcp/443 statistics ---\n11 connects, 9 answered (2 refused), 18.2% loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn timed_out_compact() {
    assert_eq!(
        compact(&timed_out()),
        "sping dns.example (192.0.2.10) tcp/443 via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄✕                                   \r\nLatency    now — · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 18% · sent 11 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     TCP 443 timeout · no answer · intermittent loss\r\n"
    );
}

#[test]
fn timed_out_table() {
    assert_eq!(
        table(&timed_out()),
        "sping multi-target  tcp/443  ⠋ probing...\r\n\r\nTarget                      RTT        Avg   Loss    Qual      Trend        TCP  Hops\r\n───────────────────────────────────────────────────────────────────────────────\r\ndns.example (192.0.…          —    13.9 ms    18%     A95     stable    timeout     —\r\n"
    );
}

#[test]
fn timed_out_json() {
    assert_eq!(
        serde_json::to_string(&timed_out()).unwrap(),
        "{\"target_host\":\"dns.example\",\"target_ip\":\"192.0.2.10\",\"dns_time\":18.5,\"sent\":11,\"received\":9,\"lost\":2,\"loss_pct\":18.2,\"rtt_last\":null,\"rtt_avg\":13.899999999999999,\"rtt_min\":13.6,\"rtt_max\":14.1,\"jitter\":0.19,\"mdev\":0.15,\"pulse\":[{\"Reply\":13.6},{\"Reply\":14.1},\"Loss\",{\"Reply\":13.799999999999999},\"Loss\"],\"seq\":11,\"quality\":\"A\",\"quality_score\":95,\"trend\":\"stable\",\"ttl\":null,\"net_ctx\":{\"interface\":\"eth0\",\"local_ip\":\"192.168.1.100\",\"prefix_len\":24,\"gateway\":\"192.168.1.1\",\"target_class\":\"PublicNetwork\"},\"probe\":\"tcp\",\"port\":443,\"refused\":2,\"tcp_state\":\"timeout\"}"
    );
}

#[test]
fn failed_classic() {
    assert_eq!(
        classic(&failed()),
        "Probe error for seq=11: connect failed: Network is unreachable (os error 101)\n\n--- dns.example tcp/443 statistics ---\n11 connects, 9 answered (2 refused), 18.2% loss\nrtt min/avg/max/mdev = 13.6 ms/13.9 ms/14.1 ms/0.15 ms\n"
    );
}

#[test]
fn failed_compact() {
    assert_eq!(
        compact(&failed()),
        "sping dns.example (192.0.2.10) tcp/443 via eth0  ⠋ probing...\r\n\r\nPulse      ▁█✕▄✕                                   \r\nLatency    now — · avg 13.9 ms · min 13.6 ms · max 14.1 ms · jitter 0.19 ms · dns 18.5 ms\r\nStatus     Reachable · loss 18% · sent 11 · recv 9\r\nContext    if eth0 · 192.168.1.100/24 · gw ? · wan ? · public\r\nQuality    A (95) · excellent\r\nEvents     connect failed: Network is unreachable (os error 101) · intermittent loss\r\n"
    );
}

#[test]
fn failed_table() {
    assert_eq!(
        table(&failed()),
        "sping multi-target  tcp/443  ⠋ probing...\r\n\r\nTarget                      RTT        Avg   Loss    Qual      Trend        TCP  Hops\r\n───────────────────────────────────────────────────────────────────────────────\r\ndns.example (192.0.…          —    13.9 ms    18%     A95     stable      error     —\r\n"
    );
}
