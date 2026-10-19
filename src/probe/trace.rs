//! Bounded traceroute: ICMP echo requests with an increasing TTL (IPv6 hop
//! limit), one round of probes per hop, until the target answers, a hop
//! reports it unreachable, the path goes silent, the TTL limit or the time
//! budget is reached, or the caller cancels. It reports what was observed,
//! hop by hop; interpreting it (a rate-limited router, where the latency
//! starts) is the diagnosis' job.
//!
//! The platform probers (`backends::trace_unix`, `backends::windows_icmp`)
//! send and receive; `run` decides when to stop, so its rules are tested with
//! a scripted prober.

// One platform's prober builds only some of these variants and options
// (Windows binds neither `-S` nor `-I`; macOS waits for E1).
#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};

use crate::context::dns::ResolvedAddr;

/// How far and how long a trace may go.
#[derive(Debug, Clone)]
pub struct TraceOptions {
    /// Highest TTL tried.
    pub max_hops: u8,
    /// Probes sent per hop (at least one is sent).
    pub probes_per_hop: u8,
    /// How long each probe waits for its answer (`-W`).
    pub probe_timeout: Duration,
    /// Ceiling for the whole trace.
    pub budget: Duration,
    /// Consecutive silent hops after which the trace stops.
    pub silent_stop: u8,
    /// ICMP payload size (`-s`).
    pub payload_size: usize,
    /// Source address (`-S`), where the platform binds one.
    pub source: Option<IpAddr>,
    /// Interface (`-I`), where the platform binds one.
    pub interface: Option<String>,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            max_hops: 30,
            probes_per_hop: 3,
            probe_timeout: Duration::from_secs(2),
            budget: Duration::from_secs(20),
            silent_stop: 3,
            payload_size: 56,
            source: None,
            interface: None,
        }
    }
}

/// The hops observed and why the trace stopped.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceResult {
    pub status: TraceStatus,
    pub hops: Vec<Hop>,
}

/// Why a trace stopped.
#[derive(Debug, Clone, PartialEq)]
pub enum TraceStatus {
    /// The target answered at `ttl`.
    Reached { ttl: u8 },
    /// `from` reported the target unreachable at `ttl`.
    Unreachable {
        ttl: u8,
        from: IpAddr,
        kind: UnreachableKind,
    },
    /// No answer from the target up to the highest TTL.
    MaxHops,
    /// `hops` consecutive hops sent probes and got no answer.
    SilentTail { hops: u8 },
    /// The time budget ran out; the last hop may be partial.
    BudgetExhausted,
    /// The caller cancelled; the last hop may be partial.
    Cancelled,
    /// This system cannot trace from here.
    Unavailable(Unavailable),
    /// Nothing could be sent: none of the probes of `ttl`, or (`ttl: None`)
    /// the socket could not be prepared.
    LocalError { ttl: Option<u8>, message: String },
    /// The probe calls of `ttl` failed without telling whether the probes
    /// left (Windows).
    ProbeError { ttl: u8, message: String },
}

/// Why a trace cannot run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
    /// It needs privileges this process lacks.
    Permission,
    /// Not implemented for this platform or address family.
    Platform,
}

/// One TTL and what each of its probes got.
#[derive(Debug, Clone, PartialEq)]
pub struct Hop {
    pub ttl: u8,
    /// In sending order. Several `from` addresses (load balancing) are kept
    /// as they came.
    pub probes: Vec<HopProbe>,
    /// The round was interrupted (budget or cancel): `probes` holds only
    /// the probes that finished.
    pub partial: bool,
}

/// Outcome of one probe.
#[derive(Debug, Clone, PartialEq)]
pub enum HopProbe {
    /// An ICMP message about this probe arrived from `from`.
    Reply {
        from: IpAddr,
        rtt: Duration,
        kind: ReplyKind,
    },
    /// Sent; no answer within its timeout.
    Silent,
    /// Sending failed locally: the probe did not leave.
    NotSent(String),
    /// The call failed without telling whether the probe left.
    Failed(String),
}

/// What the answer to a probe said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// A router on the way: the TTL ran out there.
    TimeExceeded,
    /// The target itself.
    EchoReply,
    Unreachable(UnreachableKind),
    /// Any other ICMP message about the probe (packet too big, parameter
    /// problem, ...).
    Other(OtherReply),
}

/// Destination-unreachable reasons, both families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnreachableKind {
    Net,
    Host,
    Protocol,
    Port,
    AdminProhibited,
    Other,
}

/// An answer the trace does not classify further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtherReply {
    Icmp { icmp_type: u8, code: u8 },
    WindowsStatus(u32),
}

/// Why a round stopped before all its probes finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interrupted {
    Budget,
    Cancel,
}

/// What a prober returns for one TTL.
#[derive(Debug, Clone, PartialEq)]
pub struct Round {
    /// The probes that finished, in sending order.
    pub probes: Vec<HopProbe>,
    pub interrupted: Option<Interrupted>,
}

/// Sends and receives the probes of a trace on one platform.
pub trait HopProber {
    /// Send one probe per `seqs` entry with `ttl` and collect their
    /// outcomes in sending order. A probe waits at most `probe_timeout` for
    /// its answer and nothing waits past `deadline`. When `cancel` is set or
    /// `deadline` passes before every probe finished, return the finished
    /// ones and the reason.
    fn probe_round(
        &mut self,
        ttl: u8,
        seqs: &[u16],
        probe_timeout: Duration,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Round;
}

/// Why a prober could not be opened.
#[derive(Debug, Clone, PartialEq)]
pub enum OpenError {
    Unavailable(Unavailable),
    Local(String),
}

/// Trace the path to `target` with this platform's prober.
pub fn trace(target: ResolvedAddr, opts: &TraceOptions, cancel: &AtomicBool) -> TraceResult {
    match crate::backends::TraceProber::open(target, opts) {
        Ok(mut prober) => run(&mut prober, opts, cancel),
        Err(OpenError::Unavailable(why)) => TraceResult {
            status: TraceStatus::Unavailable(why),
            hops: Vec::new(),
        },
        Err(OpenError::Local(message)) => TraceResult {
            status: TraceStatus::LocalError { ttl: None, message },
            hops: Vec::new(),
        },
    }
}

/// Sequence numbers for `n` probes. One counter serves every trace of the
/// process and is never reset: a late answer to an earlier trace cannot
/// carry a sequence number of the round in progress until 65536 trace
/// probes later.
pub(crate) fn next_seqs(n: usize) -> Vec<u16> {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let first = NEXT.fetch_add(n as u16, Ordering::Relaxed);
    (0..n as u16).map(|i| first.wrapping_add(i)).collect()
}

/// Run a trace with `prober`, one round per TTL, and decide after each round
/// whether to go on. The round's hop is always kept, also when it was
/// interrupted.
pub fn run(prober: &mut impl HopProber, opts: &TraceOptions, cancel: &AtomicBool) -> TraceResult {
    let deadline = Instant::now() + opts.budget;
    let per_hop = opts.probes_per_hop.max(1) as usize;
    let mut hops: Vec<Hop> = Vec::new();
    let mut silent_hops: u8 = 0;

    for ttl in 1..=opts.max_hops {
        if cancel.load(Ordering::Relaxed) {
            return TraceResult {
                status: TraceStatus::Cancelled,
                hops,
            };
        }
        if Instant::now() >= deadline {
            return TraceResult {
                status: TraceStatus::BudgetExhausted,
                hops,
            };
        }

        let seqs = next_seqs(per_hop);
        let round = prober.probe_round(ttl, &seqs, opts.probe_timeout, deadline, cancel);
        // A cancel that came while the round finished stops the trace too.
        let cancelled = cancel.load(Ordering::Relaxed);
        let verdict = judge(ttl, &round, cancelled);
        hops.push(Hop {
            ttl,
            probes: round.probes,
            partial: round.interrupted.is_some(),
        });

        match verdict {
            Verdict::Stop(status) => return TraceResult { status, hops },
            Verdict::Answered => silent_hops = 0,
            Verdict::Silent => {
                silent_hops += 1;
                if silent_hops >= opts.silent_stop.max(1) {
                    return TraceResult {
                        status: TraceStatus::SilentTail { hops: silent_hops },
                        hops,
                    };
                }
            }
        }
    }

    TraceResult {
        status: TraceStatus::MaxHops,
        hops,
    }
}

/// What a round means for the trace.
enum Verdict {
    Stop(TraceStatus),
    /// Something answered: the path goes on.
    Answered,
    /// Probes left and nothing answered.
    Silent,
}

/// The rules, in order: an answer from the target, or an unreachable, ends
/// the trace (an observed fact outranks an interruption); then an
/// interruption, or a cancel that came once the round was over
/// (`cancelled`); then a round where nothing left; then silence.
fn judge(ttl: u8, round: &Round, cancelled: bool) -> Verdict {
    let replies = || {
        round.probes.iter().filter_map(|p| match p {
            HopProbe::Reply { from, kind, .. } => Some((*from, *kind)),
            _ => None,
        })
    };
    if replies().any(|(_, kind)| kind == ReplyKind::EchoReply) {
        return Verdict::Stop(TraceStatus::Reached { ttl });
    }
    if let Some((from, kind)) = replies().find_map(|(from, kind)| match kind {
        ReplyKind::Unreachable(kind) => Some((from, kind)),
        _ => None,
    }) {
        return Verdict::Stop(TraceStatus::Unreachable { ttl, from, kind });
    }
    match round
        .interrupted
        .or(cancelled.then_some(Interrupted::Cancel))
    {
        Some(Interrupted::Budget) => return Verdict::Stop(TraceStatus::BudgetExhausted),
        Some(Interrupted::Cancel) => return Verdict::Stop(TraceStatus::Cancelled),
        None => {}
    }
    if replies().next().is_some() {
        return Verdict::Answered;
    }
    if round.probes.iter().any(|p| matches!(p, HopProbe::Silent)) {
        return Verdict::Silent;
    }
    // No reply and nothing known to have left.
    let first_failed = round.probes.iter().find_map(|p| match p {
        HopProbe::Failed(message) => Some(message.clone()),
        _ => None,
    });
    if let Some(message) = first_failed {
        return Verdict::Stop(TraceStatus::ProbeError { ttl, message });
    }
    let message = round
        .probes
        .iter()
        .find_map(|p| match p {
            HopProbe::NotSent(message) => Some(message.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "no probe was sent".into());
    Verdict::Stop(TraceStatus::LocalError {
        ttl: Some(ttl),
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    const R1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    const R2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2));
    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 2));

    fn reply(from: IpAddr, kind: ReplyKind) -> HopProbe {
        HopProbe::Reply {
            from,
            rtt: Duration::from_millis(1),
            kind,
        }
    }

    fn te(from: IpAddr) -> HopProbe {
        reply(from, ReplyKind::TimeExceeded)
    }

    fn echo() -> HopProbe {
        reply(TARGET, ReplyKind::EchoReply)
    }

    fn full(probes: Vec<HopProbe>) -> Round {
        Round {
            probes,
            interrupted: None,
        }
    }

    fn silent() -> Round {
        full(vec![HopProbe::Silent; 3])
    }

    /// Plays back one scripted round per call and records what it was asked.
    struct Scripted {
        rounds: VecDeque<Round>,
        asked: Vec<(u8, Vec<u16>)>,
        /// Set the cancel flag while playing this TTL's round.
        cancel_at: Option<u8>,
    }

    impl Scripted {
        fn new(rounds: Vec<Round>) -> Self {
            Self {
                rounds: rounds.into(),
                asked: Vec::new(),
                cancel_at: None,
            }
        }
    }

    impl HopProber for Scripted {
        fn probe_round(
            &mut self,
            ttl: u8,
            seqs: &[u16],
            _probe_timeout: Duration,
            _deadline: Instant,
            cancel: &AtomicBool,
        ) -> Round {
            self.asked.push((ttl, seqs.to_vec()));
            if self.cancel_at == Some(ttl) {
                cancel.store(true, Ordering::Relaxed);
            }
            self.rounds.pop_front().expect("no scripted round left")
        }
    }

    fn trace_with(rounds: Vec<Round>, opts: TraceOptions) -> (TraceResult, Scripted) {
        let mut prober = Scripted::new(rounds);
        let result = run(&mut prober, &opts, &AtomicBool::new(false));
        (result, prober)
    }

    #[test]
    fn reaches_the_target() {
        let (result, prober) = trace_with(
            vec![
                full(vec![te(R1); 3]),
                full(vec![te(R2); 3]),
                full(vec![echo(); 3]),
            ],
            TraceOptions::default(),
        );
        assert_eq!(result.status, TraceStatus::Reached { ttl: 3 });
        assert_eq!(result.hops.len(), 3);
        assert!(result.hops.iter().all(|h| !h.partial));
        let ttls: Vec<u8> = prober.asked.iter().map(|(ttl, _)| *ttl).collect();
        assert_eq!(ttls, [1, 2, 3]);
    }

    #[test]
    fn an_unreachable_ends_the_trace_from_a_router_or_the_target() {
        let prohibited = ReplyKind::Unreachable(UnreachableKind::AdminProhibited);
        let (result, _) = trace_with(
            vec![full(vec![te(R1); 3]), full(vec![reply(R2, prohibited); 3])],
            TraceOptions::default(),
        );
        assert_eq!(
            result.status,
            TraceStatus::Unreachable {
                ttl: 2,
                from: R2,
                kind: UnreachableKind::AdminProhibited
            }
        );

        let port = ReplyKind::Unreachable(UnreachableKind::Port);
        let (result, _) = trace_with(
            vec![full(vec![reply(TARGET, port)])],
            TraceOptions::default(),
        );
        assert_eq!(
            result.status,
            TraceStatus::Unreachable {
                ttl: 1,
                from: TARGET,
                kind: UnreachableKind::Port
            }
        );
    }

    #[test]
    fn stops_at_the_highest_ttl() {
        let opts = TraceOptions {
            max_hops: 3,
            ..TraceOptions::default()
        };
        let (result, _) = trace_with(vec![full(vec![te(R1)]); 3], opts);
        assert_eq!(result.status, TraceStatus::MaxHops);
        assert_eq!(result.hops.len(), 3);
    }

    #[test]
    fn stops_after_consecutive_silent_hops() {
        let (result, _) = trace_with(
            vec![full(vec![te(R1); 3]), silent(), silent(), silent()],
            TraceOptions::default(),
        );
        assert_eq!(result.status, TraceStatus::SilentTail { hops: 3 });
        assert_eq!(result.hops.len(), 4);
    }

    /// A router that does not answer is not the end of the path.
    #[test]
    fn a_silent_router_in_the_middle_does_not_stop_the_trace() {
        let (result, _) = trace_with(
            vec![
                silent(),
                silent(),
                full(vec![te(R2)]),
                silent(),
                silent(),
                full(vec![echo()]),
            ],
            TraceOptions::default(),
        );
        assert_eq!(result.status, TraceStatus::Reached { ttl: 6 });
    }

    #[test]
    fn any_answer_resets_the_silence_count() {
        let too_big = reply(
            R1,
            ReplyKind::Other(OtherReply::Icmp {
                icmp_type: 2,
                code: 0,
            }),
        );
        let (result, _) = trace_with(
            vec![
                silent(),
                silent(),
                full(vec![too_big]),
                silent(),
                silent(),
                full(vec![echo()]),
            ],
            TraceOptions::default(),
        );
        assert_eq!(result.status, TraceStatus::Reached { ttl: 6 });
    }

    #[test]
    fn an_interrupted_round_is_kept_as_a_partial_hop() {
        for (interrupted, status) in [
            (Interrupted::Budget, TraceStatus::BudgetExhausted),
            (Interrupted::Cancel, TraceStatus::Cancelled),
        ] {
            let (result, _) = trace_with(
                vec![
                    full(vec![te(R1); 3]),
                    Round {
                        probes: vec![te(R2)],
                        interrupted: Some(interrupted),
                    },
                ],
                TraceOptions::default(),
            );
            assert_eq!(result.status, status);
            assert_eq!(result.hops.len(), 2);
            assert!(result.hops[1].partial);
            assert_eq!(result.hops[1].probes, [te(R2)]);
        }
    }

    /// The target's answer is a fact: it outranks the interruption.
    #[test]
    fn the_target_answering_in_an_interrupted_round_is_reached() {
        let (result, _) = trace_with(
            vec![Round {
                probes: vec![echo()],
                interrupted: Some(Interrupted::Cancel),
            }],
            TraceOptions::default(),
        );
        assert_eq!(result.status, TraceStatus::Reached { ttl: 1 });
        assert!(result.hops[0].partial);
    }

    #[test]
    fn cancelled_or_out_of_budget_before_a_round() {
        let mut prober = Scripted::new(Vec::new());
        let result = run(
            &mut prober,
            &TraceOptions::default(),
            &AtomicBool::new(true),
        );
        assert_eq!(result.status, TraceStatus::Cancelled);
        assert!(result.hops.is_empty() && prober.asked.is_empty());

        let opts = TraceOptions {
            budget: Duration::ZERO,
            ..TraceOptions::default()
        };
        let result = run(&mut prober, &opts, &AtomicBool::new(false));
        assert_eq!(result.status, TraceStatus::BudgetExhausted);
        assert!(prober.asked.is_empty());
    }

    /// A cancel that comes during a round the prober completes (a Windows
    /// call that times out) still ends the trace as cancelled, unless the
    /// round brought the target's answer.
    #[test]
    fn a_cancel_during_a_completed_round_is_honoured() {
        let mut prober = Scripted::new(vec![full(vec![te(R1)]), silent(), silent(), silent()]);
        prober.cancel_at = Some(4);
        let result = run(
            &mut prober,
            &TraceOptions::default(),
            &AtomicBool::new(false),
        );
        assert_eq!(result.status, TraceStatus::Cancelled);
        assert_eq!(result.hops.len(), 4);
        assert!(!result.hops[3].partial);

        let mut prober = Scripted::new(vec![full(vec![te(R1)]), full(vec![echo()])]);
        prober.cancel_at = Some(2);
        let result = run(
            &mut prober,
            &TraceOptions::default(),
            &AtomicBool::new(false),
        );
        assert_eq!(result.status, TraceStatus::Reached { ttl: 2 });
    }

    #[test]
    fn nothing_sent_is_a_local_error_at_any_hop() {
        let not_sent = || HopProbe::NotSent("send failed: Network is unreachable".into());
        let (result, _) = trace_with(vec![full(vec![not_sent(); 3])], TraceOptions::default());
        assert_eq!(
            result.status,
            TraceStatus::LocalError {
                ttl: Some(1),
                message: "send failed: Network is unreachable".into()
            }
        );

        let (result, _) = trace_with(
            vec![
                full(vec![te(R1)]),
                full(vec![te(R2)]),
                full(vec![not_sent(); 3]),
            ],
            TraceOptions::default(),
        );
        assert_eq!(
            result.status,
            TraceStatus::LocalError {
                ttl: Some(3),
                message: "send failed: Network is unreachable".into()
            }
        );
    }

    /// A failed call does not say the probe stayed home.
    #[test]
    fn a_failed_call_is_a_probe_error_not_a_local_one() {
        let (result, _) = trace_with(
            vec![full(vec![
                HopProbe::Failed("ICMP call failed".into()),
                HopProbe::NotSent("send failed".into()),
            ])],
            TraceOptions::default(),
        );
        assert_eq!(
            result.status,
            TraceStatus::ProbeError {
                ttl: 1,
                message: "ICMP call failed".into()
            }
        );
    }

    /// A probe that did leave and got nothing makes the round silent, even
    /// next to one that could not be sent.
    #[test]
    fn a_silent_probe_next_to_a_failed_send_is_silence() {
        let round = || {
            full(vec![
                HopProbe::NotSent("send failed".into()),
                HopProbe::Silent,
            ])
        };
        let (result, _) = trace_with(vec![round(), round(), round()], TraceOptions::default());
        assert_eq!(result.status, TraceStatus::SilentTail { hops: 3 });
    }

    #[test]
    fn load_balanced_answers_are_kept_as_they_came() {
        let (result, _) = trace_with(
            vec![full(vec![te(R1), te(R2), te(R1)]), full(vec![echo()])],
            TraceOptions::default(),
        );
        assert_eq!(result.hops[0].probes, [te(R1), te(R2), te(R1)]);
    }

    /// Sequence numbers never repeat within a trace and go on from one trace
    /// to the next.
    #[test]
    fn sequence_numbers_are_unique_and_continue_across_traces() {
        let (_, first) = trace_with(
            vec![full(vec![te(R1)]), full(vec![echo()])],
            TraceOptions::default(),
        );
        let (_, second) = trace_with(vec![full(vec![echo()])], TraceOptions::default());
        let seqs: Vec<u16> = first
            .asked
            .iter()
            .chain(&second.asked)
            .flat_map(|(_, seqs)| seqs.clone())
            .collect();
        assert_eq!(seqs.len(), 9);
        let unique: std::collections::HashSet<u16> = seqs.iter().copied().collect();
        assert_eq!(unique.len(), seqs.len());
        // Within a round, consecutive.
        for (_, round) in first.asked.iter().chain(&second.asked) {
            for pair in round.windows(2) {
                assert_eq!(pair[1], pair[0].wrapping_add(1));
            }
        }
    }

    // Real traces. They need a network (and, for the bench, the namespaces
    // of `scripts/trace-bench.sh`), so they only run when asked for:
    // `cargo test --release <name> -- --ignored --nocapture`.

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
    }

    /// `SPING_TRACE_TARGET`: an address or a name.
    fn live_target() -> ResolvedAddr {
        use std::net::ToSocketAddrs;
        let target = env("SPING_TRACE_TARGET");
        let addr = (target.as_str(), 0)
            .to_socket_addrs()
            .unwrap_or_else(|e| panic!("cannot resolve {target}: {e}"))
            .next()
            .unwrap_or_else(|| panic!("{target} has no address"));
        ResolvedAddr::from(addr)
    }

    fn show(result: &TraceResult) {
        for hop in &result.hops {
            let probes: Vec<String> = hop
                .probes
                .iter()
                .map(|p| match p {
                    HopProbe::Reply { from, rtt, kind } => {
                        format!("{from} {:.2} ms {kind:?}", rtt.as_secs_f64() * 1000.0)
                    }
                    other => format!("{other:?}"),
                })
                .collect();
            let partial = if hop.partial { " (partial)" } else { "" };
            println!("{:>2}{partial}  {}", hop.ttl, probes.join("  |  "));
        }
        println!("status: {:?}", result.status);
    }

    /// The probe pings `target` every 20 ms while two traces run to it.
    fn coexistence(
        target: ResolvedAddr,
        opts: &TraceOptions,
    ) -> (Vec<TraceResult>, Vec<crate::probe::types::ProbeResult>) {
        use crate::backends::IcmpBackend;
        use crate::probe::types::ProbeOptions;
        use std::sync::Arc;

        let stop = Arc::new(AtomicBool::new(false));
        let pinger = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let backend = match target.ip {
                    IpAddr::V4(_) => IcmpBackend::new(),
                    IpAddr::V6(_) => IcmpBackend::new_v6(),
                }
                .expect("probe socket");
                let opts = ProbeOptions {
                    target: target.ip,
                    scope_id: target.scope_id,
                    timeout: Duration::from_secs(1),
                    ..ProbeOptions::default()
                };
                let mut results = Vec::new();
                let mut seq: u16 = 0;
                while !stop.load(Ordering::Relaxed) {
                    results.push(backend.ping(&opts, seq));
                    seq = seq.wrapping_add(1);
                    std::thread::sleep(Duration::from_millis(20));
                }
                results
            })
        };
        let traces = (0..2)
            .map(|_| trace(target, opts, &AtomicBool::new(false)))
            .collect();
        stop.store(true, Ordering::Relaxed);
        (traces, pinger.join().expect("pinger thread"))
    }

    /// Trace `SPING_TRACE_TARGET` and print the hops (hardware check).
    #[test]
    #[ignore = "live network: set SPING_TRACE_TARGET"]
    fn trace_live() {
        let result = trace(
            live_target(),
            &TraceOptions::default(),
            &AtomicBool::new(false),
        );
        show(&result);
        assert_traced(&result);
    }

    /// A real trace ran: no unavailable or failed tracing, at least one hop
    /// answered, and the target's echo reply only at the last hop.
    fn assert_traced(result: &TraceResult) {
        assert!(
            !matches!(
                result.status,
                TraceStatus::Unavailable(_)
                    | TraceStatus::LocalError { .. }
                    | TraceStatus::ProbeError { .. }
            ),
            "{:?}",
            result.status
        );
        let answered = |hop: &Hop| {
            hop.probes
                .iter()
                .any(|p| matches!(p, HopProbe::Reply { .. }))
        };
        assert!(result.hops.iter().any(answered), "no hop answered");
        let early_echo = result.hops.iter().rev().skip(1).any(|hop| {
            hop.probes.iter().any(|p| {
                matches!(
                    p,
                    HopProbe::Reply {
                        kind: ReplyKind::EchoReply,
                        ..
                    }
                )
            })
        });
        assert!(!early_echo, "an echo reply before the last hop");
    }

    /// The probe and two traces to `SPING_TRACE_TARGET` at once (hardware
    /// check): the probe keeps getting its own replies, and each trace reads
    /// as it would alone.
    #[test]
    #[ignore = "live network: set SPING_TRACE_TARGET"]
    fn trace_coexistence_live() {
        use crate::probe::types::ProbeResult;
        let (traces, probes) = coexistence(live_target(), &TraceOptions::default());
        for result in &traces {
            show(result);
            assert_traced(result);
        }
        let replies = probes
            .iter()
            .filter(|r| matches!(r, ProbeResult::Reply { .. }))
            .count();
        println!("probe: {replies} replies out of {}", probes.len());
        assert!(replies > 0, "the probe got no reply");
        assert!(
            probes
                .iter()
                .all(|r| !matches!(r, ProbeResult::Error { .. })),
            "{probes:?}"
        );
    }

    /// One case of `scripts/trace-bench.sh`, run inside its namespaces:
    /// client → R1 → R2 → target. `SPING_TRACE_CASE` names the case,
    /// `SPING_TRACE_TARGET` the family (10.0.3.2 or fd00:3::2) and
    /// `SPING_TRACE_SOCKET` the socket the bench allows (`dgram`, or `raw`
    /// with ping sockets denied).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run by scripts/trace-bench.sh inside its network namespaces"]
    fn trace_bench() {
        let case = env("SPING_TRACE_CASE");
        let target: IpAddr = env("SPING_TRACE_TARGET").parse().expect("target address");
        let raw = env("SPING_TRACE_SOCKET") == "raw";
        let (r1, r2): (IpAddr, IpAddr) = if target.is_ipv6() {
            ("fd00:1::1".parse().unwrap(), "fd00:2::2".parse().unwrap())
        } else {
            ("10.0.1.1".parse().unwrap(), "10.0.2.2".parse().unwrap())
        };
        let addr = ResolvedAddr::unscoped(target);
        let opts = TraceOptions {
            probe_timeout: Duration::from_millis(500),
            ..TraceOptions::default()
        };
        let prober = crate::backends::TraceProber::open(addr, &opts).expect("trace socket");
        assert_eq!(prober.is_raw(), raw, "socket type");
        drop(prober);

        let all = |hop: &Hop, kind: ReplyKind, from: IpAddr| {
            hop.probes.len() == 3
                && !hop.partial
                && hop.probes.iter().all(|p| {
                    matches!(p, HopProbe::Reply { from: f, kind: k, .. } if *f == from && *k == kind)
                })
        };
        let silent =
            |hop: &Hop| hop.probes == [HopProbe::Silent, HopProbe::Silent, HopProbe::Silent];
        let run_case = |opts: &TraceOptions, cancel_after: Option<Duration>| {
            let cancel = std::sync::Arc::new(AtomicBool::new(false));
            if let Some(after) = cancel_after {
                let cancel = std::sync::Arc::clone(&cancel);
                std::thread::spawn(move || {
                    std::thread::sleep(after);
                    cancel.store(true, Ordering::Relaxed);
                });
            }
            let start = Instant::now();
            let result = trace(addr, opts, &cancel);
            show(&result);
            (result, start.elapsed())
        };

        match case.as_str() {
            "reach" => {
                let (r, _) = run_case(&opts, None);
                assert_eq!(r.status, TraceStatus::Reached { ttl: 3 });
                assert!(all(&r.hops[0], ReplyKind::TimeExceeded, r1));
                assert!(all(&r.hops[1], ReplyKind::TimeExceeded, r2));
                assert!(all(&r.hops[2], ReplyKind::EchoReply, target));
            }
            "silent-router" => {
                let (r, _) = run_case(&opts, None);
                assert_eq!(r.status, TraceStatus::Reached { ttl: 3 });
                assert!(silent(&r.hops[0]));
                assert!(all(&r.hops[1], ReplyKind::TimeExceeded, r2));
                assert!(all(&r.hops[2], ReplyKind::EchoReply, target));
            }
            "prohibited" => {
                // R2 refuses before it looks at the TTL.
                let (r, _) = run_case(&opts, None);
                let refused = ReplyKind::Unreachable(UnreachableKind::AdminProhibited);
                assert_eq!(
                    r.status,
                    TraceStatus::Unreachable {
                        ttl: 2,
                        from: r2,
                        kind: UnreachableKind::AdminProhibited
                    }
                );
                assert!(all(&r.hops[0], ReplyKind::TimeExceeded, r1));
                assert!(all(&r.hops[1], refused, r2));
            }
            "silent-tail" => {
                let (r, _) = run_case(&opts, None);
                assert_eq!(r.status, TraceStatus::SilentTail { hops: 3 });
                assert_eq!(r.hops.len(), 4);
                assert!(all(&r.hops[0], ReplyKind::TimeExceeded, r1));
                assert!(r.hops[1..].iter().all(silent));
            }
            "budget" => {
                let opts = TraceOptions {
                    budget: Duration::from_secs(2),
                    silent_stop: 30,
                    ..opts
                };
                let (r, elapsed) = run_case(&opts, None);
                assert_eq!(r.status, TraceStatus::BudgetExhausted);
                assert!(elapsed < Duration::from_millis(2300), "took {elapsed:?}");
            }
            "cancel" => {
                let opts = TraceOptions {
                    budget: Duration::from_secs(60),
                    silent_stop: 30,
                    ..opts
                };
                let (r, elapsed) = run_case(&opts, Some(Duration::from_secs(1)));
                assert_eq!(r.status, TraceStatus::Cancelled);
                assert!(elapsed < Duration::from_millis(1300), "took {elapsed:?}");
            }
            "coexist" => {
                let (traces, probes) = coexistence(addr, &opts);
                for r in &traces {
                    show(r);
                    // The probe's replies are never taken for the trace's:
                    // no echo reply before the target's hop.
                    assert_eq!(r.status, TraceStatus::Reached { ttl: 3 });
                    assert!(all(&r.hops[0], ReplyKind::TimeExceeded, r1));
                    assert!(all(&r.hops[1], ReplyKind::TimeExceeded, r2));
                }
                assert!(!probes.is_empty());
                assert!(
                    probes
                        .iter()
                        .all(|p| matches!(p, crate::probe::types::ProbeResult::Reply { .. })),
                    "{probes:?}"
                );
            }
            other => panic!("unknown case {other}"),
        }
    }
}
