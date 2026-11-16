//! Auxiliary reachability probes (default gateway, WAN reference). Run at a
//! slower cadence and feed the correlator to localize failures (LAN vs WAN).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::backends::IcmpBackend;
use crate::diagnostics::health::{HealthTracker, Reachability};
use crate::probe::types::ProbeOptions;

/// State of an auxiliary probe (gateway or WAN).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuxiliaryState {
    /// Human-readable probe name (e.g. "gateway", "wan").
    pub label: String,
    /// Address currently being probed; may change on hot network updates.
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    pub target: IpAddr,
    /// Hysteresis-filtered reachability state.
    pub reachability: Reachability,
    /// RTT of the most recent probe; `None` if it failed.
    #[serde(serialize_with = "ser_opt_duration_ms")]
    pub last_rtt: Option<Duration>,
}

fn ser_opt_duration_ms<S: serde::Serializer>(
    d: &Option<Duration>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match d {
        Some(d) => s.serialize_some(&(d.as_secs_f64() * 1000.0)),
        None => s.serialize_none(),
    }
}

/// Run an auxiliary probe loop at a slower `interval`, publishing
/// `AuxiliaryState`. The target arrives via a watch channel so it can be
/// retargeted on hot network changes (e.g. default gateway changes on WiFi →
/// Ethernet). While there is none (no default gateway yet) the probe waits
/// for the first one: no socket, nothing published. Once it has a target it
/// keeps the last one when the channel says there is none.
pub async fn run(
    label: String,
    mut target_rx: watch::Receiver<Option<IpAddr>>,
    interval: Duration,
    tx: watch::Sender<Option<AuxiliaryState>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let Some(mut target) = first_target(&mut target_rx, &mut shutdown).await else {
        return;
    };
    let mut backend = match backend_for(target) {
        Ok(b) => b,
        Err(e) => {
            // \r\n: the TUI may already be in raw mode.
            eprint!("warning: {label} auxiliary probe disabled: {e}\r\n");
            return;
        }
    };

    // Hysteresis: 3 consecutive failures → offline, 2 successes → online
    let mut health = HealthTracker::new(3, 2);
    let mut seq: u16 = 0;

    loop {
        seq = seq.wrapping_add(1);

        let new_target = *target_rx.borrow();
        if let Some(new_target) = new_target
            && new_target != target
        {
            if new_target.is_ipv4() != target.is_ipv4() {
                backend = match backend_for(new_target) {
                    Ok(b) => b,
                    Err(e) => {
                        // What is published is about the old target, and
                        // nothing can be said of the new one.
                        let _ = tx.send(None);
                        eprint!("warning: {label} auxiliary probe disabled: {e}\r\n");
                        return;
                    }
                };
            }
            // Retarget: reset hysteresis, the old state is meaningless.
            target = new_target;
            health = HealthTracker::new(3, 2);
        }

        let opts = ProbeOptions {
            target,
            scope_id: 0,
            timeout: Duration::from_secs(2),
            payload_size: 32,
            ttl: None,
            interface: None,
            source: None,
            // The auxiliary probes stay ICMP, whatever the main probe.
            tcp_port: None,
        };

        let backend = Arc::clone(&backend);
        let s = seq;
        let result = tokio::task::spawn_blocking(move || backend.ping(&opts, s)).await;

        let mut last_rtt = None;
        match result {
            Ok(crate::probe::types::ProbeResult::Reply { rtt, .. }) => {
                health.record_success();
                last_rtt = Some(rtt);
            }
            _ => {
                health.record_failure();
            }
        }

        let state = AuxiliaryState {
            label: label.clone(),
            target,
            reachability: health.state(),
            last_rtt,
        };
        let _ = tx.send(Some(state));

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// The ICMP backend of `target`'s family: an echo goes out only through a
/// socket of its own family.
fn backend_for(target: IpAddr) -> std::io::Result<Arc<IcmpBackend>> {
    match target {
        IpAddr::V4(_) => IcmpBackend::new(),
        IpAddr::V6(_) => IcmpBackend::new_v6(),
    }
    .map(Arc::new)
}

/// The first target, as soon as there is one; `None` when the probe is to
/// end without one: shutdown, or nobody left to name a target or to ask for
/// the shutdown. A target there from the start is taken whatever `shutdown`
/// says, as the probe loop takes it.
async fn first_target(
    target_rx: &mut watch::Receiver<Option<IpAddr>>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<IpAddr> {
    loop {
        // Copied out: no borrow of the channel is held across the wait.
        let target = *target_rx.borrow_and_update();
        if target.is_some() {
            return target;
        }
        if *shutdown.borrow() {
            return None;
        }
        tokio::select! {
            changed = target_rx.changed() => changed.ok()?,
            changed = shutdown.changed() => {
                changed.ok()?;
                // Decided here: this change is now seen, so the probe loop
                // would not be told of it by a target that came with it.
                if *shutdown.borrow() {
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::types::ProbeResult;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    /// What `wait` gives, unless it is still waiting after 5 s: a wait that
    /// should have ended.
    async fn within<T>(wait: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("the wait ends")
    }

    // The WAN probe's case, and the gateway's when there is one at the
    // start: the target is taken at once, with its sender gone and even with
    // the shutdown already asked for, as the probe loop always did.
    #[tokio::test]
    async fn a_target_there_from_the_start_is_taken_at_once() {
        let (target_tx, mut target_rx) = watch::channel(Some(GATEWAY));
        drop(target_tx);
        let (_shutdown_tx, mut shutdown) = watch::channel(true);
        assert_eq!(
            within(first_target(&mut target_rx, &mut shutdown)).await,
            Some(GATEWAY)
        );
    }

    // A run that starts with no default gateway and gets one later: the
    // wait ends with it. It used to have no probe at all.
    #[tokio::test]
    async fn a_target_that_arrives_later_ends_the_wait() {
        let (target_tx, mut target_rx) = watch::channel(None);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let arrival = async {
            tokio::task::yield_now().await;
            target_tx.send(Some(GATEWAY)).expect("a receiver");
        };
        let (target, ()) =
            within(async { tokio::join!(first_target(&mut target_rx, &mut shutdown), arrival) })
                .await;
        assert_eq!(target, Some(GATEWAY));
    }

    // No target and the shutdown: asked for during the wait, or before it
    // (a receiver has already seen the value it subscribed to, so only
    // reading it tells).
    #[tokio::test]
    async fn the_shutdown_ends_the_wait() {
        let (_target_tx, mut target_rx) = watch::channel(None);
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let asked = async {
            tokio::task::yield_now().await;
            shutdown_tx.send(true).expect("a receiver");
        };
        let (target, ()) =
            within(async { tokio::join!(first_target(&mut target_rx, &mut shutdown), asked) })
                .await;
        assert_eq!(target, None);

        let mut late = shutdown_tx.subscribe();
        assert_eq!(within(first_target(&mut target_rx, &mut late)).await, None);
    }

    // A target and the shutdown that arrive together: either the wait ends
    // with no target, or the shutdown is still there for the probe loop to
    // see. Which of the two `select!` takes first is random: many rounds.
    #[tokio::test]
    async fn a_target_with_the_shutdown_never_hides_the_shutdown() {
        for _ in 0..64 {
            let (target_tx, mut target_rx) = watch::channel(None);
            let (shutdown_tx, mut shutdown) = watch::channel(false);
            let both = async {
                tokio::task::yield_now().await;
                target_tx.send(Some(GATEWAY)).expect("a receiver");
                shutdown_tx.send(true).expect("a receiver");
            };
            let (target, ()) =
                within(async { tokio::join!(first_target(&mut target_rx, &mut shutdown), both) })
                    .await;
            if target.is_some() {
                assert!(shutdown.has_changed().expect("a sender"));
            }
        }
    }

    // A target of the other family (none changes family today, but `run`
    // takes what its channel says) is probed through a socket of its own
    // family, each way. Through the first target's socket it never answered.
    #[tokio::test]
    async fn a_target_of_the_other_family_is_probed_through_its_own_socket() {
        // Whether `target` answers a backend asked directly. The family is
        // chosen here, not by `backend_for`: this is what tells the probe's
        // fault from an address that does not answer.
        fn answers(target: IpAddr) -> bool {
            let backend = match target {
                IpAddr::V4(_) => IcmpBackend::new(),
                IpAddr::V6(_) => IcmpBackend::new_v6(),
            };
            let opts = ProbeOptions {
                target,
                scope_id: 0,
                timeout: Duration::from_secs(2),
                payload_size: 32,
                ttl: None,
                interface: None,
                source: None,
                tcp_port: None,
            };
            backend.is_ok_and(|b| matches!(b.ping(&opts, 1), ProbeResult::Reply { .. }))
        }

        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        // Only where both loopback addresses answer.
        for target in [v4, v6] {
            if !answers(target) {
                eprintln!("{target} does not answer here: not run");
                return;
            }
        }

        let (target_tx, target_rx) = watch::channel(Some(v4));
        let (tx, mut rx) = watch::channel(None);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let interval = Duration::from_millis(10);
        let probe = tokio::spawn(run("WAN".into(), target_rx, interval, tx, shutdown));
        for target in [v4, v6, v4] {
            target_tx.send(Some(target)).expect("the probe listens");
            let answered = |state: &Option<AuxiliaryState>| {
                state
                    .as_ref()
                    .is_some_and(|s| s.target == target && s.last_rtt.is_some())
            };
            // 30 s: the probe waits 2 s for each echo, and a loaded or
            // emulated host may lose some.
            let wait = tokio::time::timeout(Duration::from_secs(30), rx.wait_for(answered));
            match wait.await {
                Ok(published) => {
                    published.expect("the probe publishes");
                }
                Err(_) => {
                    // The probe's fault only if the address still answers.
                    assert!(!answers(target), "no answer from {target}, which answers");
                    eprintln!("{target} stopped answering: not run");
                    break;
                }
            }
        }
        shutdown_tx.send(true).expect("the probe listens");
        within(probe).await.expect("the probe ends");
    }

    // Nobody left to name a target, or to ask for the shutdown: the wait
    // ends instead of spinning on a closed channel.
    #[tokio::test]
    async fn a_closed_channel_ends_the_wait() {
        let (target_tx, mut target_rx) = watch::channel(None);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let gone = async {
            tokio::task::yield_now().await;
            drop(target_tx);
        };
        let (target, ()) =
            within(async { tokio::join!(first_target(&mut target_rx, &mut shutdown), gone) }).await;
        assert_eq!(target, None);

        let (_target_tx, mut target_rx) = watch::channel(None);
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let gone = async {
            tokio::task::yield_now().await;
            drop(shutdown_tx);
        };
        let (target, ()) =
            within(async { tokio::join!(first_target(&mut target_rx, &mut shutdown), gone) }).await;
        assert_eq!(target, None);
    }
}
