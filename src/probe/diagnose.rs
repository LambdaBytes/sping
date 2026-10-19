//! `--diagnose` (experimental): the diagnosis planner (`diagnostics::planner`)
//! next to the main probe of a single target. While the target is down, the
//! planner's requests run here, each on sockets of its own, and the state of
//! the diagnosis is published for the views.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, MissedTickBehavior};

use crate::backends::IcmpBackend;
use crate::backends::tcp::TcpProber;
use crate::config::Config;
use crate::context::Detected;
use crate::context::dns::{self, Family, ResolvedAddr};
use crate::context::iface;
use crate::diagnostics::evidence::{
    Action, Connection, Outcome, Reason, Request, RequestId, SourceCheck, Via,
};
use crate::diagnostics::health::Reachability;
use crate::diagnostics::planner::{Diagnosis, MainProbe, Planner, Scope, Status, Step, Tick};
use crate::probe::trace::{self, TraceOptions, TraceStatus};
use crate::probe::types::{ProbeOptions, ProbeResult, ProbeSnapshot};

/// TCP ports tried on the main address when the main probe is ICMP.
const TCP_PORTS: [u16; 2] = [443, 80];
/// How often the planner is asked again while nothing else happens: requests
/// the traffic window held back start without waiting for the next probe.
const TICK: Duration = Duration::from_secs(1);

/// What the views show of the diagnosis.
#[derive(Debug, Clone, PartialEq)]
pub enum DiagnoseState {
    /// The target is not down.
    Idle,
    Diagnosing {
        target: IpAddr,
    },
    Done {
        target: IpAddr,
        diagnosis: Arc<Diagnosis>,
    },
}

/// The command line as the extra probes take it: what the user made explicit
/// holds for them (step 4 of 1.7, invariant 3).
#[derive(Debug, Clone)]
pub struct Extra {
    /// The target as given: a name, or an address.
    name: String,
    literal: bool,
    family: Option<Family>,
    source: Option<IpAddr>,
    interface: Option<String>,
    timeout: Duration,
    payload_size: usize,
    tcp_port: Option<u16>,
}

impl Extra {
    pub fn from_config(cfg: &Config) -> Self {
        let name = cfg.targets[0].clone();
        Self {
            literal: dns::is_literal(&name),
            name,
            family: cfg.family,
            source: cfg.source,
            interface: cfg.interface.clone(),
            timeout: cfg.timeout,
            payload_size: cfg.payload_size,
            tcp_port: cfg.tcp_port,
        }
    }

    /// What the planner may try. The other family is left out for an
    /// address (no name to look up), `-4`/`-6` and `-S`, in that order; with
    /// `--tcp` only that port is tried, else 443 and 80.
    pub fn scope(&self) -> Scope {
        let other_family = if self.literal {
            Some(Reason::Literal)
        } else if self.family.is_some() {
            Some(Reason::ExplicitFamily)
        } else if self.source.is_some() {
            Some(Reason::ExplicitSource)
        } else {
            None
        };
        let trace = self.trace_options();
        Scope {
            main: match self.tcp_port {
                Some(port) => MainProbe::Tcp { port },
                None => MainProbe::Icmp {
                    tcp_ports: TCP_PORTS.to_vec(),
                },
            },
            other_family,
            trace_probes: u32::from(trace.max_hops) * u32::from(trace.probes_per_hop),
        }
    }

    /// The longest a whole diagnosis takes: the lookup's timeout, level 2
    /// (three echoes one after another, the connects alongside) and the
    /// trace's budget.
    pub fn budget(&self) -> Duration {
        dns::DNS_TIMEOUT + 3 * self.timeout + self.trace_options().budget
    }

    /// The trace: `-W` for each probe, `-s`, `-S` and `-I`; `-t` is the main
    /// probe's only.
    pub fn trace_options(&self) -> TraceOptions {
        TraceOptions {
            probe_timeout: self.timeout,
            payload_size: self.payload_size,
            source: self.source,
            interface: self.interface.clone(),
            ..TraceOptions::default()
        }
    }

    /// An extra probe to `target`: `-W`, `-s`, `-I`, and `-S` when it is of
    /// `target`'s family (the other family is not tried with `-S`); never
    /// `-t`.
    pub fn probe_options(&self, target: ResolvedAddr, tcp_port: Option<u16>) -> ProbeOptions {
        ProbeOptions {
            target: target.ip,
            scope_id: target.scope_id,
            timeout: self.timeout,
            payload_size: self.payload_size,
            ttl: None,
            interface: self.interface.clone(),
            source: self
                .source
                .filter(|source| source.is_ipv4() == target.ip.is_ipv4()),
            tcp_port,
        }
    }

    /// The source the system would send from. `-S` and `-I` choose the
    /// route themselves (or are ignored where the main probe ignores them),
    /// so the system's answer would not be the probe's.
    fn source_check(&self, target: ResolvedAddr) -> SourceCheck {
        if self.source.is_some() || self.interface.is_some() {
            return SourceCheck::Unknown("source check unavailable with -S/-I".into());
        }
        match iface::usable_source(target) {
            Ok(Some(source)) => SourceCheck::Usable(source),
            Ok(None) => SourceCheck::NoSource,
            Err(e) => SourceCheck::Unknown(e.to_string()),
        }
    }

    /// `count` echo requests, one after another, on an ICMP socket of their
    /// own; stops early on `cancel`.
    fn echo(&self, target: ResolvedAddr, count: u8, cancel: &AtomicBool) -> (Outcome, Via) {
        let backend = match target.ip {
            IpAddr::V4(_) => IcmpBackend::new(),
            IpAddr::V6(_) => IcmpBackend::new_v6(),
        };
        let backend = match backend {
            Ok(backend) => backend,
            Err(e) => {
                return (
                    Outcome::Failed(format!("cannot open an ICMP socket: {e}")),
                    Via::default(),
                );
            }
        };
        let mut via = Via::default();
        // Bound on Linux only; elsewhere the call is a no-op or refuses.
        if let Some(iface) = &self.interface
            && cfg!(target_os = "linux")
            && backend.bind_interface(iface).is_ok()
        {
            via.interface = Some(iface.clone());
        }
        let opts = self.probe_options(target, None);
        let results: Vec<ProbeResult> = (1..=u16::from(count))
            .take_while(|_| !cancel.load(Ordering::Relaxed))
            .map(|seq| backend.ping(&opts, seq))
            .collect();
        (echo_outcome(&results), via)
    }

    /// One TCP connect, warning about nothing.
    fn connect(&self, target: ResolvedAddr, port: u16) -> (Outcome, Via) {
        let opts = self.probe_options(target, Some(port));
        match TcpProber::quiet(&opts) {
            Ok(prober) => {
                let via = Via {
                    source: opts.source,
                    interface: prober.interface().map(String::from),
                };
                (connect_outcome(prober.ping(&opts, 1)), via)
            }
            Err(e) => (
                Outcome::Failed(format!("cannot prepare the TCP probe: {e}")),
                Via::default(),
            ),
        }
    }

    /// The trace. Its source is `-S` where it was bound (on Unix, opening the
    /// trace binds it; Windows binds nothing); whether `-I` was bound, it
    /// does not tell.
    fn trace(&self, target: ResolvedAddr, cancel: &AtomicBool) -> (Outcome, Via) {
        let opts = self.trace_options();
        let result = trace::trace(target, &opts, cancel);
        let opened = !matches!(
            result.status,
            TraceStatus::Unavailable(_) | TraceStatus::LocalError { ttl: None, .. }
        );
        let via = Via {
            source: opts.source.filter(|_| cfg!(unix) && opened),
            interface: None,
        };
        (Outcome::Trace(result), via)
    }

    /// The blocking actions.
    fn run_blocking(&self, action: Action, cancel: &AtomicBool) -> (Outcome, Via) {
        match action {
            Action::Source { target } => {
                (Outcome::Source(self.source_check(target)), Via::default())
            }
            Action::Echo { target, count } => self.echo(target, count, cancel),
            Action::Connect { target, port } => self.connect(target, port),
            Action::Trace { target } => self.trace(target, cancel),
            Action::Resolve => (
                Outcome::Failed("a lookup is not a blocking action".into()),
                Via::default(),
            ),
        }
    }
}

/// The echoes as evidence. An error does not tell whether its request left
/// (it also comes after sending): with no reply and an error, the outcome is
/// that error, not a silence.
pub(crate) fn echo_outcome(results: &[ProbeResult]) -> Outcome {
    let replies = results
        .iter()
        .filter(|r| matches!(r, ProbeResult::Reply { .. }))
        .count();
    let sent = replies
        + results
            .iter()
            .filter(|r| matches!(r, ProbeResult::Timeout { .. }))
            .count();
    if replies == 0
        && let Some(message) = results.iter().find_map(|r| match r {
            ProbeResult::Error { message, .. } => Some(message.clone()),
            _ => None,
        })
    {
        return Outcome::Failed(message);
    }
    Outcome::Echo {
        sent: sent as u8,
        replies: replies as u8,
    }
}

/// A connect as evidence; a local error is a failure, not an answer.
pub(crate) fn connect_outcome(result: ProbeResult) -> Outcome {
    match result {
        ProbeResult::Connected { .. } => Outcome::Connect(Connection::Open),
        ProbeResult::Refused { .. } => Outcome::Connect(Connection::Refused),
        ProbeResult::Timeout { .. } => Outcome::Connect(Connection::Timeout),
        ProbeResult::Error { message, .. } => Outcome::Failed(message),
        ProbeResult::Reply { .. } => Outcome::Failed("an ICMP reply to a TCP connect".into()),
    }
}

/// A finished request.
#[derive(Debug)]
pub struct Finished {
    pub id: RequestId,
    pub outcome: Outcome,
    pub via: Via,
}

/// Carries out the planner's requests.
pub trait Execute {
    /// Start `request`. Its outcome goes to `done` once, also when `cancel`
    /// stopped it early.
    fn start(
        &self,
        request: Request,
        cancel: Arc<AtomicBool>,
        done: mpsc::UnboundedSender<Finished>,
    );
}

/// The real executor: one task per request, blocking work off the runtime.
pub struct Executor {
    extra: Arc<Extra>,
}

impl Executor {
    pub fn new(extra: Extra) -> Self {
        Self {
            extra: Arc::new(extra),
        }
    }
}

impl Execute for Executor {
    fn start(
        &self,
        request: Request,
        cancel: Arc<AtomicBool>,
        done: mpsc::UnboundedSender<Finished>,
    ) {
        let extra = Arc::clone(&self.extra);
        tokio::spawn(async move {
            let (outcome, via) = match request.action {
                Action::Resolve => {
                    let outcome = match dns::resolve_both(&extra.name).await {
                        Ok(families) => Outcome::Resolved(Ok(families)),
                        Err(e) => Outcome::Resolved(Err(e.to_string())),
                    };
                    (outcome, Via::default())
                }
                action => tokio::task::spawn_blocking(move || extra.run_blocking(action, &cancel))
                    .await
                    .unwrap_or_else(|e| {
                        (
                            Outcome::Failed(format!("the probe task failed: {e}")),
                            Via::default(),
                        )
                    }),
            };
            let _ = done.send(Finished {
                id: request.id,
                outcome,
                via,
            });
        });
    }
}

/// What the loop watches.
pub struct Inputs {
    pub probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    /// The address the main probe sends to, after a DNS failover too.
    pub target_rx: watch::Receiver<ResolvedAddr>,
    pub ctx_rx: watch::Receiver<Detected>,
}

/// Runs the planner until `shutdown`, or until probing `finished` and the
/// diagnosis in progress, if any, concluded or ran out of its `budget`
/// (counted from when it started). After `finished`, a run where nothing
/// answered is diagnosed as down even before the hysteresis says so (`-c 1`).
/// The last state is published before returning; on `shutdown` the
/// operations still running are cancelled and nothing waits for them.
pub async fn run(
    mut planner: Planner,
    executor: impl Execute,
    mut inputs: Inputs,
    budget: Duration,
    mut finished: oneshot::Receiver<()>,
    mut shutdown: watch::Receiver<bool>,
    state_tx: watch::Sender<DiagnoseState>,
) {
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    let mut running: HashMap<RequestId, Arc<AtomicBool>> = HashMap::new();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Once probing finished: the deadline, and whether nothing answered.
    let mut closing: Option<(Instant, bool)> = None;

    loop {
        let down = closing.is_some_and(|(_, down)| down);
        let deadline = closing.map(|(deadline, _)| deadline);
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            _ = &mut finished, if closing.is_none() => {
                let down = inputs
                    .probe_rx
                    .borrow()
                    .as_ref()
                    .is_some_and(|s| s.sent > 0 && s.received == 0);
                let step = tick(&mut planner, &mut inputs, down);
                begin(step, &executor, &mut running, &done_tx);
                let since = planner
                    .diagnosing_since()
                    .map_or_else(Instant::now, Instant::from_std);
                closing = Some((since + budget, down));
            }
            Some(done) = done_rx.recv() => {
                // A failover or a context change that came meanwhile is
                // applied first: it may make this outcome stale.
                let step = tick(&mut planner, &mut inputs, down);
                begin(step, &executor, &mut running, &done_tx);
                running.remove(&done.id);
                let now = Instant::now().into_std();
                if let Ok(next) = planner.record(done.id, done.outcome, done.via, now) {
                    begin(Step { start: next, cancel: Vec::new() }, &executor, &mut running, &done_tx);
                }
            }
            Ok(()) = inputs.probe_rx.changed() => {
                let step = tick(&mut planner, &mut inputs, down);
                begin(step, &executor, &mut running, &done_tx);
            }
            _ = ticker.tick() => {
                let step = tick(&mut planner, &mut inputs, down);
                begin(step, &executor, &mut running, &done_tx);
            }
            () = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                break;
            }
        }
        publish(&planner, &state_tx);
        if closing.is_some() && !matches!(planner.status(), Status::Diagnosing) {
            break;
        }
    }
    for cancel in running.values() {
        cancel.store(true, Ordering::Relaxed);
    }
    publish(&planner, &state_tx);
}

/// The planner's view of now: the main target's state (down when `down`),
/// its address and network context.
fn tick(planner: &mut Planner, inputs: &mut Inputs, down: bool) -> Step {
    // Always marked as seen, so that `changed` waits for the next one.
    let reachability = inputs
        .probe_rx
        .borrow_and_update()
        .as_ref()
        .map_or(Reachability::Unknown, |s| s.reachability);
    let main = if down {
        Reachability::Offline
    } else {
        reachability
    };
    let target = *inputs.target_rx.borrow_and_update();
    let detected = inputs.ctx_rx.borrow_and_update().clone();
    // A context detected for another address, the one before a failover, is
    // not the target's (as in the scheduler's `ContextTracker`).
    planner.tick(&Tick {
        now: Instant::now().into_std(),
        target,
        context: (detected.target == target).then_some(&detected.context),
        main,
    })
}

/// Cancel what `step` says and start the rest.
fn begin(
    step: Step,
    executor: &impl Execute,
    running: &mut HashMap<RequestId, Arc<AtomicBool>>,
    done: &mpsc::UnboundedSender<Finished>,
) {
    for id in step.cancel {
        if let Some(cancel) = running.get(&id) {
            cancel.store(true, Ordering::Relaxed);
        }
    }
    for request in step.start {
        let cancel = Arc::new(AtomicBool::new(false));
        running.insert(request.id, Arc::clone(&cancel));
        executor.start(request, cancel, done.clone());
    }
}

/// The planner's state, about the address of its incident (not the latest
/// one on the channel: a failover the planner has not applied yet, as when a
/// shutdown came first, is not its incident's).
fn publish(planner: &Planner, state_tx: &watch::Sender<DiagnoseState>) {
    let state = match (planner.status(), planner.incident_target()) {
        (Status::Diagnosing, Some(target)) => DiagnoseState::Diagnosing { target: target.ip },
        (Status::Done(diagnosis), Some(target)) => DiagnoseState::Done {
            target: target.ip,
            diagnosis: Arc::new(diagnosis.clone()),
        },
        _ => DiagnoseState::Idle,
    };
    state_tx.send_if_modified(|current| {
        if *current == state {
            return false;
        }
        *current = state;
        true
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Args;
    use crate::context::classify::TargetClass;
    use crate::diagnostics::planner::Conclusion;
    use crate::probe::trace::{Hop, HopProbe, ReplyKind, TraceResult};
    use clap::Parser;
    use std::sync::Mutex;

    fn extra(args: &[&str]) -> Extra {
        let args = Args::parse_from(std::iter::once("sping").chain(args.iter().copied()));
        Extra::from_config(&Config::from_args(&args).unwrap())
    }

    fn addr(s: &str) -> ResolvedAddr {
        ResolvedAddr::unscoped(s.parse().unwrap())
    }

    /// What each explicit option lets the planner try (invariant 3).
    #[test]
    fn explicit_options_shape_the_scope() {
        let icmp = MainProbe::Icmp {
            tcp_ports: vec![443, 80],
        };
        for (args, main, other_family) in [
            (&["example.com"][..], icmp.clone(), None),
            (
                &["example.com", "--tcp", "8443"],
                MainProbe::Tcp { port: 8443 },
                None,
            ),
            (
                &["example.com", "-4"],
                icmp.clone(),
                Some(Reason::ExplicitFamily),
            ),
            (
                &["example.com", "-6"],
                icmp.clone(),
                Some(Reason::ExplicitFamily),
            ),
            (
                &["example.com", "-S", "192.0.2.2"],
                icmp.clone(),
                Some(Reason::ExplicitSource),
            ),
            // An address has no name to look up, whatever else is given.
            (&["192.0.2.9"], icmp.clone(), Some(Reason::Literal)),
            (
                &["192.0.2.9", "-4", "-S", "192.0.2.2"],
                icmp.clone(),
                Some(Reason::Literal),
            ),
            (&["fe80::1%lo"], icmp.clone(), Some(Reason::Literal)),
            // -4 before -S.
            (
                &["example.com", "-4", "-S", "192.0.2.2"],
                icmp.clone(),
                Some(Reason::ExplicitFamily),
            ),
            // Neither -I, -W, -s nor -t changes what is tried.
            (
                &["example.com", "-I", "lo", "-W", "3", "-s", "100", "-t", "5"],
                icmp.clone(),
                None,
            ),
        ] {
            let scope = extra(args).scope();
            assert_eq!(format!("{:?}", scope.main), format!("{main:?}"), "{args:?}");
            assert_eq!(scope.other_family, other_family, "{args:?}");
            assert_eq!(scope.trace_probes, 90, "{args:?}");
        }
    }

    /// The extra probes take -W, -s, -I and -S of their family; never -t.
    #[test]
    fn extra_probes_take_the_explicit_options() {
        let x = extra(&[
            "example.com",
            "-I",
            "lo",
            "-W",
            "3",
            "-s",
            "100",
            "-t",
            "5",
            "-S",
            "192.0.2.2",
        ]);
        let v4 = x.probe_options(addr("198.51.100.7"), None);
        assert_eq!(v4.timeout, Duration::from_secs(3));
        assert_eq!(v4.payload_size, 100);
        assert_eq!(v4.ttl, None);
        assert_eq!(v4.interface.as_deref(), Some("lo"));
        assert_eq!(v4.source, Some("192.0.2.2".parse().unwrap()));
        assert_eq!(v4.tcp_port, None);
        let v6 = x.probe_options(addr("2001:db8::7"), Some(443));
        assert_eq!(v6.source, None, "-S is IPv4: not for an IPv6 probe");
        assert_eq!(v6.tcp_port, Some(443));

        let trace = x.trace_options();
        assert_eq!(trace.probe_timeout, Duration::from_secs(3));
        assert_eq!(trace.payload_size, 100);
        assert_eq!(trace.interface.as_deref(), Some("lo"));
        assert_eq!(trace.source, Some("192.0.2.2".parse().unwrap()));
        assert_eq!((trace.max_hops, trace.probes_per_hop), (30, 3));

        assert_eq!(x.budget(), Duration::from_secs(5 + 3 * 3 + 20));
    }

    /// Under -S or -I the system's route is not the probe's: no answer.
    #[test]
    fn no_source_check_under_explicit_binding() {
        for args in [
            &["example.com", "-S", "192.0.2.2"][..],
            &["example.com", "-I", "lo"],
        ] {
            assert_eq!(
                extra(args).source_check(addr("198.51.100.7")),
                SourceCheck::Unknown("source check unavailable with -S/-I".into()),
                "{args:?}"
            );
        }
        assert_eq!(
            extra(&["example.com"]).source_check(addr("127.0.0.1")),
            SourceCheck::Usable("127.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn echo_results_as_evidence() {
        let reply = || ProbeResult::Reply {
            seq: 1,
            rtt: Duration::from_millis(3),
            ttl: 60,
        };
        let timeout = || ProbeResult::Timeout { seq: 1 };
        let error = |m: &str| ProbeResult::Error {
            seq: 1,
            message: m.into(),
        };
        for (results, outcome) in [
            (
                vec![reply(), reply(), reply()],
                Outcome::Echo {
                    sent: 3,
                    replies: 3,
                },
            ),
            (
                vec![timeout(), timeout(), timeout()],
                Outcome::Echo {
                    sent: 3,
                    replies: 0,
                },
            ),
            // An answer is an answer, whatever failed around it.
            (
                vec![error("recv failed"), reply(), timeout()],
                Outcome::Echo {
                    sent: 2,
                    replies: 1,
                },
            ),
            // Without an answer, an error may hide a request that left.
            (
                vec![timeout(), error("recv failed")],
                Outcome::Failed("recv failed".into()),
            ),
            (
                vec![error("send failed"); 3],
                Outcome::Failed("send failed".into()),
            ),
        ] {
            assert_eq!(echo_outcome(&results), outcome, "{results:?}");
        }
    }

    #[test]
    fn connect_results_as_evidence() {
        let rtt = Duration::from_millis(3);
        assert_eq!(
            connect_outcome(ProbeResult::Connected { seq: 1, rtt }),
            Outcome::Connect(Connection::Open)
        );
        assert_eq!(
            connect_outcome(ProbeResult::Refused { seq: 1, rtt }),
            Outcome::Connect(Connection::Refused)
        );
        assert_eq!(
            connect_outcome(ProbeResult::Timeout { seq: 1 }),
            Outcome::Connect(Connection::Timeout)
        );
        assert_eq!(
            connect_outcome(ProbeResult::Error {
                seq: 1,
                message: "connect failed: x".into()
            }),
            Outcome::Failed("connect failed: x".into())
        );
    }

    /// A request as the executor got it: what, its cancel flag, where its
    /// outcome goes.
    type Started = (Request, Arc<AtomicBool>, mpsc::UnboundedSender<Finished>);

    /// An executor that only remembers what it was asked; the test answers.
    #[derive(Clone, Default)]
    struct Script {
        started: Arc<Mutex<Vec<Started>>>,
    }

    impl Execute for Script {
        fn start(
            &self,
            request: Request,
            cancel: Arc<AtomicBool>,
            done: mpsc::UnboundedSender<Finished>,
        ) {
            self.started.lock().unwrap().push((request, cancel, done));
        }
    }

    impl Script {
        fn actions(&self) -> Vec<Action> {
            self.started
                .lock()
                .unwrap()
                .iter()
                .map(|(r, ..)| r.action.clone())
                .collect()
        }

        /// Answer the request started `n`-th.
        fn answer(&self, n: usize, outcome: Outcome) {
            let started = self.started.lock().unwrap();
            let (request, _, done) = &started[n];
            done.send(Finished {
                id: request.id,
                outcome,
                via: Via::default(),
            })
            .unwrap();
        }

        fn cancelled(&self, n: usize) -> bool {
            self.started.lock().unwrap()[n].1.load(Ordering::Relaxed)
        }
    }

    const BUDGET: Duration = Duration::from_secs(30);

    fn context(interface: &str) -> crate::context::NetworkContext {
        crate::context::NetworkContext {
            interface: interface.into(),
            local_ip: "192.0.2.2".parse().unwrap(),
            prefix_len: 24,
            gateway: Some("192.0.2.1".into()),
            target_class: TargetClass::PublicNetwork,
        }
    }

    fn snapshot(sent: u64, received: u64, reachability: Reachability) -> Option<ProbeSnapshot> {
        let mut snap = ProbeSnapshot::empty(
            "198.51.100.7".into(),
            "198.51.100.7".parse().unwrap(),
            None,
            None,
        );
        snap.sent = sent;
        snap.received = received;
        snap.reachability = reachability;
        Some(snap)
    }

    /// The loop with a scripted executor, for an address target (no lookup,
    /// no TCP ports): the source check, then the trace.
    struct Bench {
        probe_tx: watch::Sender<Option<ProbeSnapshot>>,
        target_tx: watch::Sender<ResolvedAddr>,
        ctx_tx: watch::Sender<Detected>,
        finished_tx: Option<oneshot::Sender<()>>,
        shutdown_tx: watch::Sender<bool>,
        state_rx: watch::Receiver<DiagnoseState>,
        script: Script,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Bench {
        fn new() -> Self {
            let scope = Scope {
                main: MainProbe::Icmp { tcp_ports: vec![] },
                other_family: Some(Reason::Literal),
                trace_probes: 90,
            };
            let (probe_tx, probe_rx) = watch::channel(snapshot(0, 0, Reachability::Unknown));
            let (target_tx, target_rx) = watch::channel(addr("198.51.100.7"));
            let (ctx_tx, ctx_rx) = watch::channel(Detected {
                target: addr("198.51.100.7"),
                context: context("eth0"),
            });
            let (finished_tx, finished_rx) = oneshot::channel();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (state_tx, state_rx) = watch::channel(DiagnoseState::Idle);
            let script = Script::default();
            let handle = tokio::spawn(run(
                Planner::new(scope),
                script.clone(),
                Inputs {
                    probe_rx,
                    target_rx,
                    ctx_rx,
                },
                BUDGET,
                finished_rx,
                shutdown_rx,
                state_tx,
            ));
            Self {
                probe_tx,
                target_tx,
                ctx_tx,
                finished_tx: Some(finished_tx),
                shutdown_tx,
                state_rx,
                script,
                handle,
            }
        }

        fn finish(&mut self) {
            self.finished_tx.take().unwrap().send(()).unwrap();
        }

        fn state(&self) -> DiagnoseState {
            self.state_rx.borrow().clone()
        }
    }

    /// Let the loop run what is ready, without moving the clock.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    fn usable() -> Outcome {
        Outcome::Source(SourceCheck::Usable("192.0.2.2".parse().unwrap()))
    }

    fn reached() -> Outcome {
        Outcome::Trace(TraceResult {
            status: TraceStatus::Reached { ttl: 1 },
            hops: vec![Hop {
                ttl: 1,
                probes: vec![HopProbe::Reply {
                    from: "198.51.100.7".parse().unwrap(),
                    rtt: Duration::from_millis(1),
                    kind: ReplyKind::EchoReply,
                }],
                partial: false,
            }],
        })
    }

    /// The target down: source check, then trace, then the conclusion; with
    /// probing finished, the loop ends once it concluded.
    #[tokio::test(start_paused = true)]
    async fn closing_waits_for_the_diagnosis_in_progress() {
        let mut b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        assert_eq!(
            b.script.actions(),
            [Action::Source {
                target: addr("198.51.100.7")
            }]
        );
        assert_eq!(
            b.state(),
            DiagnoseState::Diagnosing {
                target: "198.51.100.7".parse().unwrap()
            }
        );
        b.script.answer(0, usable());
        settle().await;
        assert!(matches!(b.script.actions()[1], Action::Trace { .. }));

        b.finish();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!b.handle.is_finished(), "the trace is still running");
        b.script.answer(1, reached());
        settle().await;
        assert!(b.handle.is_finished());
        let DiagnoseState::Done { diagnosis, .. } = b.state() else {
            panic!("not concluded: {:?}", b.state());
        };
        assert_eq!(
            diagnosis.conclusions[0].conclusion,
            Conclusion::TargetAnswersIcmp { ttl: 1 }
        );
    }

    /// The wait ends with the budget, counted from when the diagnosis began,
    /// not from when probing finished; what still runs is cancelled.
    #[tokio::test(start_paused = true)]
    async fn closing_stops_at_the_budget_from_the_start() {
        let mut b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        b.script.answer(0, usable());
        settle().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        b.finish();
        tokio::time::sleep(BUDGET - Duration::from_secs(10) - Duration::from_millis(100)).await;
        assert!(!b.handle.is_finished());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(b.handle.is_finished());
        assert!(matches!(b.state(), DiagnoseState::Diagnosing { .. }));
        assert!(b.script.cancelled(1), "the trace is cancelled");
    }

    /// `-c 1` with no answer: diagnosed at the end although the hysteresis
    /// never said down, and still down while the requests take their time.
    #[tokio::test(start_paused = true)]
    async fn a_run_without_answers_is_diagnosed_at_the_end() {
        let mut b = Bench::new();
        b.probe_tx
            .send(snapshot(1, 0, Reachability::Unknown))
            .unwrap();
        settle().await;
        assert!(b.script.actions().is_empty(), "not down yet");
        b.finish();
        settle().await;
        assert_eq!(b.script.actions().len(), 1);
        tokio::time::sleep(Duration::from_secs(3)).await;
        b.script.answer(0, usable());
        settle().await;
        assert!(matches!(b.script.actions()[1], Action::Trace { .. }));
        tokio::time::sleep(Duration::from_secs(3)).await;
        b.script.answer(1, reached());
        settle().await;
        assert!(
            matches!(b.state(), DiagnoseState::Done { .. }),
            "{:?}",
            b.state()
        );
        assert!(b.handle.is_finished());
    }

    /// Nothing down: closing ends at once.
    #[tokio::test(start_paused = true)]
    async fn closing_with_nothing_down_ends_at_once() {
        let mut b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 3, Reachability::Online))
            .unwrap();
        settle().await;
        b.finish();
        settle().await;
        assert!(b.handle.is_finished());
        assert!(b.script.actions().is_empty());
        assert_eq!(b.state(), DiagnoseState::Idle);
    }

    /// Ctrl+C / SIGTERM during the wait: everything is cancelled and the loop
    /// returns at once, the diagnosis left unfinished.
    #[tokio::test(start_paused = true)]
    async fn shutdown_during_the_wait_returns_at_once() {
        let mut b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        b.script.answer(0, usable());
        settle().await;
        b.finish();
        settle().await;
        b.shutdown_tx.send(true).unwrap();
        settle().await;
        assert!(b.handle.is_finished());
        assert!(b.script.cancelled(1));
        assert!(matches!(b.state(), DiagnoseState::Diagnosing { .. }));
    }

    /// A new generation during the wait starts a new diagnosis but does not
    /// renew the deadline; one before the end counts from its own start.
    #[tokio::test(start_paused = true)]
    async fn restarts_and_the_deadline() {
        // During the wait: the deadline stays.
        let mut b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        b.finish();
        tokio::time::sleep(Duration::from_secs(10)).await;
        b.target_tx.send(addr("198.51.100.8")).unwrap();
        settle().await;
        tokio::time::sleep(BUDGET - Duration::from_secs(10) + Duration::from_millis(100)).await;
        assert!(b.handle.is_finished(), "the deadline moved");

        // Before the end: from the new incident.
        let mut b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
        b.ctx_tx
            .send(Detected {
                target: addr("198.51.100.7"),
                context: context("wlan0"),
            })
            .unwrap();
        settle().await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        b.finish();
        tokio::time::sleep(BUDGET - Duration::from_secs(2) - Duration::from_millis(100)).await;
        assert!(
            !b.handle.is_finished(),
            "the deadline counts from the restart"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(b.handle.is_finished());
    }

    /// An outcome that arrives with a failover is judged after it: stale, it
    /// concludes nothing about the old address.
    #[tokio::test(start_paused = true)]
    async fn a_failover_is_applied_before_an_outcome() {
        let b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        b.script.answer(0, usable());
        settle().await;
        // Both at once, before the loop runs again.
        b.target_tx.send(addr("198.51.100.8")).unwrap();
        b.script.answer(1, reached());
        settle().await;
        assert_eq!(
            b.state(),
            DiagnoseState::Diagnosing {
                target: "198.51.100.8".parse().unwrap()
            }
        );
        assert_eq!(
            b.script.actions()[2],
            Action::Source {
                target: addr("198.51.100.8")
            }
        );
    }

    /// A failover while the latest context is still the old address': that
    /// context is not the new target's, and the new target's own, when it
    /// comes, is its first, not a change. What started for it goes on.
    #[tokio::test(start_paused = true)]
    async fn a_failover_target_keeps_its_requests_when_its_context_comes() {
        let b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        b.target_tx.send(addr("198.51.100.8")).unwrap();
        b.probe_tx
            .send(snapshot(4, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        assert_eq!(
            b.script.actions()[1],
            Action::Source {
                target: addr("198.51.100.8")
            }
        );

        b.ctx_tx
            .send(Detected {
                target: addr("198.51.100.8"),
                context: context("wlan0"),
            })
            .unwrap();
        b.probe_tx
            .send(snapshot(5, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        assert_eq!(b.script.actions().len(), 2, "{:?}", b.script.actions());
        assert!(!b.script.cancelled(1), "the source check was cancelled");
    }

    /// A failover followed by a shutdown before the planner applied it: the
    /// last state stays about the address diagnosed, not the new one.
    #[tokio::test(start_paused = true)]
    async fn the_last_state_names_the_address_diagnosed() {
        let b = Bench::new();
        b.probe_tx
            .send(snapshot(3, 0, Reachability::Offline))
            .unwrap();
        settle().await;
        b.script.answer(0, usable());
        settle().await;
        b.script.answer(1, reached());
        settle().await;
        let target: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(matches!(b.state(), DiagnoseState::Done { target: t, .. } if t == target));
        b.target_tx.send(addr("198.51.100.8")).unwrap();
        b.shutdown_tx.send(true).unwrap();
        settle().await;
        assert!(b.handle.is_finished());
        assert!(
            matches!(b.state(), DiagnoseState::Done { target: t, .. } if t == target),
            "{:?}",
            b.state()
        );
    }
}
