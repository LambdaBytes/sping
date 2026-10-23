//! Primary probe loop: one probe (ICMP echo or TCP connect) per tick of the
//! interval, each awaited until its answer or its timeout, and a
//! `ProbeSnapshot` published after every probe. A probe that lasts longer
//! than the interval (a loss, with `-W` above `-i`) delays the next one, which
//! goes out as soon as it ends: while nothing answers, the period is `-W`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::backends::tcp::TcpProber;
use crate::backends::{IcmpBackend, ProbeBackend};
use crate::context::dns::{Resolution, ResolvedAddr};
use crate::context::{self, ContextChange, Detected, NetworkContext};
use crate::diagnostics::health::HealthTracker;
use crate::diagnostics::outage::OutageTracker;
use crate::diagnostics::spikes::SpikeDetector;
use crate::probe::quality::QualityScorer;
use crate::probe::stats::ProbeStats;
use crate::probe::types::{
    NameState, ProbeOptions, ProbeResult, ProbeSnapshot, RecentChange, TcpState, Unreachable,
};

/// How long a change of the network context is shown (`context_changed`):
/// longer than a probe, so a slow reader of the snapshots does not miss it.
const CONTEXT_CHANGE_SHOWN: Duration = Duration::from_secs(30);
/// How often hostname targets are re-resolved (DNS failover detection).
const RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(60);

/// Runs the probe loop, sending ICMP at `interval` and publishing snapshots.
/// Stops after `count` probes when set, or on shutdown. `ctx_rx`, when
/// provided, delivers hot network-context updates reflected in later snapshots;
/// `target_tx`, when provided, is told the new address after a DNS failover,
/// so that whoever detects the context does it for the address being probed.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    target_host: String,
    mut target_ip: IpAddr,
    dns_time: Option<Duration>,
    mut net_ctx: Option<NetworkContext>,
    interval: Duration,
    mut opts: ProbeOptions,
    count: Option<u64>,
    probe_tx: watch::Sender<Option<ProbeSnapshot>>,
    mut shutdown: watch::Receiver<bool>,
    mut ctx_rx: Option<watch::Receiver<Detected>>,
    target_tx: Option<watch::Sender<ResolvedAddr>>,
) {
    let backend = match create_backend(&opts) {
        Ok(b) => Arc::new(b),
        Err(e) if opts.tcp_port.is_some() => {
            eprintln!("error: cannot prepare the TCP probe: {e}");
            return;
        }
        Err(e) => {
            eprintln!("error: failed to create ICMP socket: {e}");
            crate::backends::eprint_icmp_hint();
            #[cfg(target_os = "windows")]
            eprintln!("hint: try running as Administrator");
            return;
        }
    };

    let mut stats = ProbeStats::new();
    let mut quality = QualityScorer::new();
    let mut spikes = SpikeDetector::new();
    let mut outage = OutageTracker::new();
    // Hysteresis for the primary target: 3 consecutive failures → Offline,
    // 2 successes → Online. Same policy as the GW/WAN auxiliary probes.
    let mut health = HealthTracker::new(3, 2);
    let mut seq: u16 = 0;
    let mut last_ttl: Option<u8>;
    let mut refused: u64 = 0;
    // Fixed for the run (a DNS failover changes the target, not the port).
    let tcp_port = opts.tcp_port;

    // Empty snapshot so renderers have state before the first reply.
    let _ = probe_tx.send(Some(
        ProbeSnapshot::empty(target_host.clone(), target_ip, dns_time, net_ctx.clone())
            .with_tcp(opts.tcp_port),
    ));

    // Periodic DNS re-resolution for hostname targets: a failover that changes
    // the record should redirect probes without restarting sping. Each lookup
    // sends one value: the address to probe after it and what it found for
    // the snapshot (`name`), so the two never come from different lookups.
    let mut probed = ResolvedAddr {
        ip: target_ip,
        scope_id: opts.scope_id,
    };
    let (lookup_tx, mut lookup_rx) = watch::channel::<Option<Lookup>>(None);
    if !crate::context::dns::is_literal(&target_host) {
        let host = target_host.clone();
        let mut shutdown_rx = shutdown.clone();
        let mut current = probed;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RE_RESOLVE_INTERVAL);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let asked = Instant::now();
                        let resolution = crate::context::dns::re_resolve(&host, current).await;
                        let lookup = lookup_of(resolution, current, asked);
                        current = lookup.target;
                        let _ = lookup_tx.send(Some(lookup));
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { return; }
                    }
                }
            }
        });
    }

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut name = NameTracker::new(Instant::now());
    let mut context =
        ContextTracker::new(probed, opts.interface.is_some() || opts.source.is_some());

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
        }

        // The latest re-resolution: a DNS failover (same address family, see
        // dns::re_resolve) and the name's state, from the same lookup.
        let mut moved = false;
        if lookup_rx.has_changed().unwrap_or(false)
            && let Some(lookup) = *lookup_rx.borrow_and_update()
            && apply_lookup(lookup, &mut probed, &mut name)
        {
            target_ip = probed.ip;
            opts.target = probed.ip;
            opts.scope_id = probed.scope_id;
            if let Some(tx) = &target_tx {
                let _ = tx.send(probed);
            }
            context.moved();
            moved = true;
        }

        // Apply a hot network-context change (WiFi → Ethernet, VPN up/down),
        // if it was detected for the address probed now.
        if let Some(detected) = ctx_rx.as_mut().and_then(|rx| pending_context(rx, moved)) {
            let now = Instant::now();
            // A failover alone sends the new address's context, maybe the
            // same: only a different one is news for the name's lookups.
            if context.apply(&detected, probed, net_ctx.as_ref(), now) == Applied::Changed {
                net_ctx = Some(detected.context);
                name.context_change(now);
            }
        }

        seq = seq.wrapping_add(1);

        let backend = Arc::clone(&backend);
        let opts = opts.clone();
        let s = seq;
        let result = tokio::task::spawn_blocking(move || backend.ping(&opts, s))
            .await
            .unwrap_or(ProbeResult::Error {
                seq: seq as u64,
                message: "probe task panicked".into(),
            });

        let recorded = record_result(
            &result,
            &mut stats,
            &mut quality,
            &mut spikes,
            &mut outage,
            &mut health,
        );
        last_ttl = recorded.ttl;
        if matches!(result, ProbeResult::Refused { .. }) {
            refused += 1;
        }
        let icmp_unreachable = unreachable_of(&result);

        let recovery_duration = outage.take_recovery();

        let snapshot = ProbeSnapshot {
            target_host: target_host.clone(),
            target_ip,
            dns_time,
            sent: stats.sent,
            received: stats.received,
            lost: stats.lost,
            loss_pct: stats.loss_pct(),
            rtt_last: stats.rtt_last(),
            rtt_avg: stats.rtt_avg(),
            rtt_min: stats.rtt_min(),
            rtt_max: stats.rtt_max(),
            jitter: stats.jitter(),
            mdev: stats.mdev(),
            pulse: stats.pulse(),
            seq: stats.sent,
            quality: quality.grade(),
            quality_score: quality.score(),
            trend: quality.trend(),
            outage_duration: outage.current_outage(),
            last_spike_rtt: spikes.last_spike_rtt(),
            spike_guard: spikes.in_cooldown(),
            recovery_duration,
            ttl: last_ttl,
            net_ctx: net_ctx.clone(),
            reachability: health.state(),
            recent_loss_pct: quality.window_loss_pct(),
            high_jitter: quality.high_jitter(),
            last_error: match result {
                ProbeResult::Error { message, .. } => Some(message),
                _ => None,
            },
            unreachable: stats.unreachable,
            name: name.state(),
            context_change: context.recent(Instant::now()),
            probe: None,
            port: None,
            refused: None,
            tcp_state: None,
            icmp_unreachable,
        }
        .with_tcp(tcp_port);
        let snapshot = ProbeSnapshot {
            refused: snapshot.refused.map(|_| refused),
            tcp_state: snapshot.port.and(recorded.tcp_state),
            ..snapshot
        };
        let _ = probe_tx.send(Some(snapshot));

        if count.is_some_and(|c| stats.sent >= c) {
            break;
        }
    }
}

/// The detected context for the probe loop to take: a new one, or after the
/// probe moved the current one even if already seen. One detected for the new
/// address before the move was ignored then, and the watcher does not send
/// the same twice.
fn pending_context(rx: &mut watch::Receiver<Detected>, moved: bool) -> Option<Detected> {
    (moved || rx.has_changed().unwrap_or(false)).then(|| rx.borrow_and_update().clone())
}

/// What a detected context is to the probe loop.
#[derive(Debug, PartialEq, Eq)]
enum Applied {
    /// Detected for another address than the one probed: ignored.
    Ignored,
    /// The context the loop has already.
    Same,
    /// Another context: the loop takes it.
    Changed,
}

/// The context changes the probe loop applies, and the last one while it is
/// shown.
struct ContextTracker {
    /// The target the current context was detected for: only a difference
    /// between two contexts of one target is a change (a failover moves the
    /// target, not the context).
    target: ResolvedAddr,
    /// `-I` or `-S`: the context is the system's route, the probe may leave
    /// by another; no change is reported.
    bound: bool,
    last: Option<(Vec<ContextChange>, Instant)>,
}

impl ContextTracker {
    fn new(target: ResolvedAddr, bound: bool) -> Self {
        Self {
            target,
            bound,
            last: None,
        }
    }

    /// Take a detected context at `now`, against the loop's `current` one;
    /// a change is kept when it differs for the same target.
    fn apply(
        &mut self,
        detected: &Detected,
        probed: ResolvedAddr,
        current: Option<&NetworkContext>,
        now: Instant,
    ) -> Applied {
        if detected.target != probed {
            return Applied::Ignored;
        }
        if !self.bound
            && self.target == probed
            && let Some(current) = current
        {
            let changes = context::changes(current, &detected.context);
            if !changes.is_empty() {
                self.last = Some((changes, now));
            }
        }
        self.target = probed;
        if current == Some(&detected.context) {
            Applied::Same
        } else {
            Applied::Changed
        }
    }

    /// The probe moved to another address: the change kept was about the
    /// one before.
    fn moved(&mut self) {
        self.last = None;
    }

    /// The last change, while shown.
    fn recent(&self, now: Instant) -> Option<RecentChange> {
        let (changes, at) = self.last.as_ref()?;
        let age = now.saturating_duration_since(*at);
        (age < CONTEXT_CHANGE_SHOWN).then(|| RecentChange {
            changes: changes.clone(),
            age,
        })
    }
}

/// One re-resolution, as the probe loop gets it: the address to probe after
/// it (another one after a DNS failover), what it found, and when it was
/// asked.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Lookup {
    target: ResolvedAddr,
    state: NameState,
    asked: Instant,
}

/// The lookup a re-resolution of `current`, asked at `asked`, makes.
fn lookup_of(resolution: Resolution, current: ResolvedAddr, asked: Instant) -> Lookup {
    let (target, state) = match resolution {
        Resolution::Unchanged => (current, NameState::Answered),
        Resolution::Changed(new) => (new, NameState::Answered),
        Resolution::NoAddressOfFamily => (current, NameState::NoAddressOfFamily),
        Resolution::Failed { timed_out } => (current, NameState::Failed { timed_out }),
    };
    Lookup {
        target,
        state,
        asked,
    }
}

/// Take a lookup: move the probe to its address when it differs (returns
/// `true`) and keep its state, both or neither from one lookup.
fn apply_lookup(lookup: Lookup, probed: &mut ResolvedAddr, name: &mut NameTracker) -> bool {
    name.lookup((lookup.state, lookup.asked));
    let moved = lookup.target != *probed;
    *probed = lookup.target;
    moved
}

/// The name's last lookup, as long as it is about the address and the
/// network probed now.
struct NameTracker {
    state: Option<NameState>,
    /// When the context last changed: a lookup asked before is about the
    /// network before it.
    context_changed: Instant,
}

impl NameTracker {
    fn new(now: Instant) -> Self {
        Self {
            state: None,
            context_changed: now,
        }
    }

    /// The network context changed: what was found is about the old one.
    fn context_change(&mut self, now: Instant) {
        self.context_changed = now;
        self.state = None;
    }

    /// A lookup's outcome, unless it was asked before the last context change.
    fn lookup(&mut self, (state, asked): (NameState, Instant)) {
        if asked >= self.context_changed {
            self.state = Some(state);
        }
    }

    fn state(&self) -> Option<NameState> {
        self.state
    }
}

/// Create the probe for `opts`: a TCP connect with `--tcp`, otherwise an ICMP
/// backend matching the target's address family, with the socket options
/// applied. An interface-bind failure only warns and continues unbound
/// (binding is unsupported on Windows and may require privileges elsewhere).
///
/// # Errors
///
/// Fails if socket creation, source binding, or setting the TTL fails.
pub(crate) fn create_backend(opts: &ProbeOptions) -> std::io::Result<ProbeBackend> {
    if opts.tcp_port.is_some() {
        return TcpProber::new(opts).map(ProbeBackend::Tcp);
    }
    let backend = match opts.target {
        IpAddr::V4(_) => IcmpBackend::new()?,
        IpAddr::V6(_) => IcmpBackend::new_v6()?,
    };

    if let Some(ref iface) = opts.interface
        && let Err(e) = backend.bind_interface(iface)
    {
        eprintln!("warning: could not bind to interface {iface}: {e}");
    }

    if let Some(src) = opts.source {
        backend.bind_source(src, opts.scope_id)?;
    }

    if let Some(ttl) = opts.ttl {
        backend.set_ttl(ttl)?;
    }

    Ok(ProbeBackend::Icmp(backend))
}

/// The destination unreachable a probe got, for the snapshot.
pub(crate) fn unreachable_of(result: &ProbeResult) -> Option<Unreachable> {
    match *result {
        ProbeResult::Unreachable { from, kind, .. } => Some(Unreachable { from, kind }),
        _ => None,
    }
}

/// What one probe result leaves for the snapshot.
pub(crate) struct Recorded {
    /// TTL of an ICMP reply; `None` for anything else.
    pub ttl: Option<u8>,
    /// The result as a TCP outcome; meaningful in TCP mode only.
    pub tcp_state: Option<TcpState>,
}

/// Feed one probe result to a target's trackers. A TCP connect, established
/// or refused, is an answer like an ICMP reply (`refused` is a subset of
/// `received`); it carries no TTL. A destination unreachable is a loss, as
/// in `ping`, counted apart (`unreachable`).
pub(crate) fn record_result(
    result: &ProbeResult,
    stats: &mut ProbeStats,
    quality: &mut QualityScorer,
    spikes: &mut SpikeDetector,
    outage: &mut OutageTracker,
    health: &mut HealthTracker,
) -> Recorded {
    let (rtt, ttl, tcp_state) = match result {
        ProbeResult::Reply { rtt, ttl, .. } => (Some(*rtt), Some(*ttl), None),
        ProbeResult::Connected { rtt, .. } => (Some(*rtt), None, Some(TcpState::Open)),
        ProbeResult::Refused { rtt, .. } => (Some(*rtt), None, Some(TcpState::Refused)),
        ProbeResult::Timeout { .. } => {
            stats.record_timeout();
            (None, None, Some(TcpState::Timeout))
        }
        // ICMP only: no TCP outcome.
        ProbeResult::Unreachable { .. } => {
            stats.record_unreachable();
            (None, None, None)
        }
        ProbeResult::Error { .. } => {
            stats.record_error();
            (None, None, Some(TcpState::Error))
        }
    };
    match rtt {
        Some(rtt) => {
            stats.record_reply(rtt);
            quality.record_reply(rtt);
            spikes.record(rtt);
            outage.record_reply();
            health.record_success();
        }
        None => {
            quality.record_loss();
            outage.record_failure();
            health.record_failure();
        }
    }
    Recorded { ttl, tcp_state }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> ResolvedAddr {
        ResolvedAddr::unscoped(s.parse().unwrap())
    }

    /// A destination unreachable is a loss for every tracker, as a timeout
    /// is, counted apart, and its sender kept for the snapshot.
    #[test]
    fn an_unreachable_is_a_loss_counted_apart() {
        use crate::diagnostics::health::Reachability;
        use crate::probe::trace::UnreachableKind;
        let mut stats = ProbeStats::new();
        let mut quality = QualityScorer::new();
        let mut spikes = SpikeDetector::new();
        let mut outage = OutageTracker::new();
        let mut health = HealthTracker::new(3, 2);
        let unreachable = ProbeResult::Unreachable {
            seq: 1,
            from: "192.0.2.1".parse().unwrap(),
            kind: UnreachableKind::Net,
        };
        for _ in 0..3 {
            let recorded = record_result(
                &unreachable,
                &mut stats,
                &mut quality,
                &mut spikes,
                &mut outage,
                &mut health,
            );
            assert_eq!((recorded.ttl, recorded.tcp_state), (None, None));
        }
        assert_eq!(
            (stats.sent, stats.received, stats.lost, stats.unreachable),
            (3, 0, 3, 3)
        );
        assert_eq!(health.state(), Reachability::Offline);
        assert_eq!(quality.window_loss_pct(), 100.0);
        assert_eq!(
            unreachable_of(&unreachable),
            Some(Unreachable {
                from: "192.0.2.1".parse().unwrap(),
                kind: UnreachableKind::Net,
            })
        );
        assert_eq!(unreachable_of(&ProbeResult::Timeout { seq: 2 }), None);
        record_result(
            &ProbeResult::Timeout { seq: 2 },
            &mut stats,
            &mut quality,
            &mut spikes,
            &mut outage,
            &mut health,
        );
        assert_eq!((stats.lost, stats.unreachable), (4, 3));
    }

    /// A failover moves the probe and answered; anything else leaves the
    /// probe where it is.
    #[test]
    fn a_re_resolution_as_a_lookup() {
        let (current, new, asked) = (addr("192.0.2.1"), addr("192.0.2.7"), Instant::now());
        for (resolution, target, state) in [
            (Resolution::Unchanged, current, NameState::Answered),
            (Resolution::Changed(new), new, NameState::Answered),
            (
                Resolution::NoAddressOfFamily,
                current,
                NameState::NoAddressOfFamily,
            ),
            (
                Resolution::Failed { timed_out: true },
                current,
                NameState::Failed { timed_out: true },
            ),
            (
                Resolution::Failed { timed_out: false },
                current,
                NameState::Failed { timed_out: false },
            ),
        ] {
            assert_eq!(
                lookup_of(resolution, current, asked),
                Lookup {
                    target,
                    state,
                    asked
                },
                "{resolution:?}"
            );
        }
    }

    /// A context change drops what was found and any lookup asked before
    /// it; a later lookup counts.
    #[test]
    fn a_lookup_older_than_the_context_is_dropped() {
        let start = Instant::now();
        let failed = NameState::Failed { timed_out: true };
        let mut name = NameTracker::new(start);
        name.lookup((failed, start));
        assert_eq!(name.state(), Some(failed));

        let changed = start + Duration::from_secs(10);
        name.context_change(changed);
        assert_eq!(name.state(), None);
        name.lookup((failed, changed - Duration::from_secs(1)));
        assert_eq!(name.state(), None, "asked before the change");
        name.lookup((NameState::NoAddressOfFamily, changed));
        assert_eq!(name.state(), Some(NameState::NoAddressOfFamily));
        name.lookup((NameState::Answered, changed + Duration::from_secs(60)));
        assert_eq!(name.state(), Some(NameState::Answered));
    }

    /// A lookup moves the probe and sets the name's state at once: after a
    /// failed lookup of A, the failover to B leaves B answered, and a later
    /// failure is B's.
    #[test]
    fn a_lookup_moves_the_probe_and_sets_the_state_together() {
        let (a, b, start) = (addr("192.0.2.1"), addr("192.0.2.7"), Instant::now());
        let mut probed = a;
        let mut name = NameTracker::new(start);
        let failed = NameState::Failed { timed_out: false };
        let lookup = |target, state, secs| Lookup {
            target,
            state,
            asked: start + Duration::from_secs(secs),
        };
        assert!(!apply_lookup(lookup(a, failed, 60), &mut probed, &mut name));
        assert_eq!((probed, name.state()), (a, Some(failed)));
        assert!(apply_lookup(
            lookup(b, NameState::Answered, 120),
            &mut probed,
            &mut name
        ));
        assert_eq!((probed, name.state()), (b, Some(NameState::Answered)));
        assert!(!apply_lookup(
            lookup(b, failed, 180),
            &mut probed,
            &mut name
        ));
        assert_eq!((probed, name.state()), (b, Some(failed)));
    }

    fn ctx(interface: &str) -> NetworkContext {
        NetworkContext {
            interface: interface.into(),
            local_ip: "192.0.2.2".parse().unwrap(),
            prefix_len: 24,
            gateway: Some("192.0.2.1".into()),
            target_class: crate::context::classify::TargetClass::PublicNetwork,
        }
    }

    fn detected(target: ResolvedAddr, interface: &str) -> Detected {
        Detected {
            target,
            context: ctx(interface),
        }
    }

    /// A change is a difference between two contexts of the address probed;
    /// a context detected for another address is ignored; the first context
    /// of a new address after a failover is no change.
    #[test]
    fn context_changes_of_the_address_probed() {
        let (a, b, start) = (addr("192.0.2.10"), addr("192.0.2.20"), Instant::now());
        let mut tracker = ContextTracker::new(a, false);
        let eth0 = ctx("eth0");
        assert!(tracker.recent(start).is_none(), "nothing yet");

        // The same context again: no change.
        assert_eq!(
            tracker.apply(&detected(a, "eth0"), a, Some(&eth0), start),
            Applied::Same
        );
        assert!(tracker.recent(start).is_none());

        // Another interface for the same address: a change.
        let at = start + Duration::from_secs(15);
        assert_eq!(
            tracker.apply(&detected(a, "wlan0"), a, Some(&eth0), at),
            Applied::Changed
        );
        let recent = tracker.recent(at + Duration::from_secs(5)).unwrap();
        assert_eq!(
            recent.changes[0].what,
            crate::context::ContextField::Interface
        );
        assert_eq!(recent.age, Duration::from_secs(5));
        // Shown for 30 s.
        assert!(tracker.recent(at + Duration::from_secs(29)).is_some());
        assert!(tracker.recent(at + Duration::from_secs(30)).is_none());

        // After a failover to B: a late detection for A is ignored; the first
        // one for B is adopted without a change; then B's own change counts.
        let mut tracker = ContextTracker::new(a, false);
        let wlan0 = ctx("wlan0");
        assert_eq!(
            tracker.apply(&detected(a, "wlan0"), b, Some(&eth0), at),
            Applied::Ignored
        );
        assert_eq!(
            tracker.apply(&detected(b, "wlan0"), b, Some(&eth0), at),
            Applied::Changed
        );
        assert!(
            tracker.recent(at).is_none(),
            "a new address is not a change"
        );
        let later = at + Duration::from_secs(15);
        assert_eq!(
            tracker.apply(&detected(b, "eth0"), b, Some(&wlan0), later),
            Applied::Changed
        );
        assert!(tracker.recent(later).is_some());
    }

    /// A failover to an address reached the same way: the context sent for
    /// it is the one the loop has, no news (the name's lookups stand).
    #[test]
    fn a_failover_with_the_same_context_is_no_change() {
        let (a, b, now) = (addr("192.0.2.10"), addr("192.0.2.20"), Instant::now());
        let mut tracker = ContextTracker::new(a, false);
        let eth0 = ctx("eth0");
        assert_eq!(
            tracker.apply(&detected(b, "eth0"), b, Some(&eth0), now),
            Applied::Same
        );
        assert!(tracker.recent(now).is_none());
    }

    /// A change of A's context is not shown once the probe moved to B,
    /// before or after B's first context.
    #[test]
    fn a_move_drops_the_change_kept() {
        let (a, b, now) = (addr("192.0.2.10"), addr("192.0.2.20"), Instant::now());
        let mut tracker = ContextTracker::new(a, false);
        tracker.apply(&detected(a, "wlan0"), a, Some(&ctx("eth0")), now);
        assert!(tracker.recent(now).is_some());
        tracker.moved();
        assert!(tracker.recent(now).is_none());
        tracker.apply(&detected(b, "wlan0"), b, Some(&ctx("wlan0")), now);
        assert!(tracker.recent(now).is_none());
    }

    /// A context seen while it was for another address is taken again once
    /// the probe moved: the watcher does not send it twice.
    #[test]
    fn a_seen_context_is_taken_again_after_a_move() {
        let b = addr("192.0.2.20");
        let (tx, mut rx) = watch::channel(detected(addr("192.0.2.10"), "eth0"));
        assert_eq!(pending_context(&mut rx, false), None, "nothing new");
        tx.send(detected(b, "wlan0")).unwrap();
        assert_eq!(pending_context(&mut rx, false), Some(detected(b, "wlan0")));
        assert_eq!(pending_context(&mut rx, false), None, "seen");
        assert_eq!(pending_context(&mut rx, true), Some(detected(b, "wlan0")));
    }

    /// With -I or -S the context is the system's route: no change is kept,
    /// though the context is still applied.
    #[test]
    fn no_context_change_under_explicit_binding() {
        let (a, now) = (addr("192.0.2.10"), Instant::now());
        let mut tracker = ContextTracker::new(a, true);
        assert_eq!(
            tracker.apply(&detected(a, "wlan0"), a, Some(&ctx("eth0")), now),
            Applied::Changed
        );
        assert!(tracker.recent(now).is_none());
    }

    /// A newer change replaces the one shown.
    #[test]
    fn a_newer_context_change_replaces_the_older() {
        let (a, start) = (addr("192.0.2.10"), Instant::now());
        let mut tracker = ContextTracker::new(a, false);
        tracker.apply(&detected(a, "wlan0"), a, Some(&ctx("eth0")), start);
        let later = start + Duration::from_secs(15);
        tracker.apply(&detected(a, "eth1"), a, Some(&ctx("wlan0")), later);
        let recent = tracker.recent(later).unwrap();
        let text = |s: &str| Some(crate::context::ContextValue::Text(s.into()));
        assert_eq!(recent.changes[0].from, text("wlan0"));
        assert_eq!(recent.changes[0].to, text("eth1"));
        assert_eq!(recent.age, Duration::ZERO);
    }
}
