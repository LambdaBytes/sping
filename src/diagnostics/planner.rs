//! Diagnosis planner: while the main target is down, decides which evidence
//! to gather, level by level and with bounded traffic, and what it shows. No
//! I/O, clock or randomness: the executor (`--diagnose`) carries out each
//! request and reports its outcome, and every call brings the instant.
//!
//! Levels, each started once the previous one has nothing pending: 1, what
//! sends no probes (the main address' source, the name's other family and its
//! source); 2, a few probes (TCP ports of the main address, the other
//! family); 3, the trace of the main address.
//!
//! Traffic: a request's probes (its worst case) count from its start until
//! `WINDOW` after its outcome, and what counts never passes `CEILING`, so no
//! window of that length sees more probes sent, however long an operation
//! takes. At most `MAX_IN_FLIGHT` operations run at once, those of a closed
//! incident included until their outcome; the trace runs alone: it starts
//! with nothing running, and nothing that sends probes starts while it runs.
//!
//! Gateway and WAN state are not evidence here: their hysteresis outlives a
//! context change that keeps their address, a gateway that never answers ping
//! is `Offline` from the start, and nothing shows the gateway is on the
//! target's path. The trace tells the path; the correlator keeps its gateway
//! and WAN findings.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::context::NetworkContext;
use crate::context::dns::{Families, Family, ResolvedAddr};
use crate::diagnostics::evidence::{
    Action, Connection, Evidence, Gap, Generation, Outcome, Reason, Request, RequestId, Role,
    SourceCheck, Via,
};
use crate::diagnostics::health::Reachability;
use crate::probe::trace::{Hop, HopProbe, TraceStatus, UnreachableKind};

/// Traffic ceiling: probes counted at once (see the module docs). A traffic
/// bound, not a diagnostic threshold.
pub const CEILING: u32 = 100;
pub const WINDOW: Duration = Duration::from_secs(60);
/// Operations running at once.
pub const MAX_IN_FLIGHT: usize = 3;
/// Echo requests sent to the other family.
pub const OTHER_FAMILY_ECHOES: u8 = 3;

/// What the planner may try; the executor builds it from the command line.
#[derive(Debug, Clone)]
pub struct Scope {
    pub main: MainProbe,
    /// Why the other family is not tried; `None`: it is.
    pub other_family: Option<Reason>,
    /// Probes one trace may send at most (highest TTL × probes per hop).
    pub trace_probes: u32,
}

/// The main probe's transport.
#[derive(Debug, Clone)]
pub enum MainProbe {
    /// ICMP: `tcp_ports` are tried on the main address, in this order.
    Icmp { tcp_ports: Vec<u16> },
    /// TCP to `port`: the other family is tried on it, and no other port.
    Tcp { port: u16 },
}

/// The monitoring state at `now`. Instants never go back between calls.
pub struct Tick<'a> {
    pub now: Instant,
    /// The address the main probe sends to; it moves with a DNS failover.
    pub target: ResolvedAddr,
    /// The network context detected for `target`; `None` while the latest
    /// detection is about another address (the one before a failover).
    pub context: Option<&'a NetworkContext>,
    pub main: Reachability,
}

/// What `tick` asks of the executor.
#[derive(Debug, Default, PartialEq)]
pub struct Step {
    pub start: Vec<Request>,
    /// Requests of a closed incident still running: cancel what can be
    /// cancelled. Each still owes its outcome, which frees its slot.
    pub cancel: Vec<RequestId>,
}

/// Why an outcome was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// Not running: never started, or its outcome already came.
    NotRunning,
    /// Its incident is closed (recovery, or a new generation). Its slot is
    /// free.
    Stale,
    /// Not what its action gives. Kept as a failure of the request; its slot
    /// is free and the next `tick` goes on.
    Mismatch,
}

#[derive(Debug, PartialEq)]
pub enum Status<'a> {
    /// The main target is not down.
    Idle,
    Diagnosing,
    /// Concluded; it stands while the outage and the generation last.
    Done(&'a Diagnosis),
}

/// What the evidence of one incident shows.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnosis {
    /// In order: the trace's or the missing source, then what answers on the
    /// main address, then the other family.
    pub conclusions: Vec<Concluded>,
    pub gaps: Vec<Gap>,
    pub evidence: Vec<Evidence>,
}

/// A conclusion and the evidence it rests on.
#[derive(Debug, Clone, PartialEq)]
pub struct Concluded {
    pub conclusion: Conclusion,
    pub because: Vec<RequestId>,
}

/// What was observed, and nothing more: no cause is claimed beyond it. In
/// JSON, an object with a stable snake_case `code` and the fields.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Conclusion {
    /// The system has no source address of the main address' family for it:
    /// no route or no address, or only one that does not leave the host.
    NoSource { family: Family },
    /// The trace: `from` reported the target unreachable at `ttl`.
    ReportedUnreachable {
        ttl: u8,
        from: IpAddr,
        kind: UnreachableKind,
    },
    /// The trace: the last hop that answered (`None`: none did), then
    /// `silent` hops in a row without an answer. A path that breaks there and
    /// a target that filters ICMP behind silent routers look the same.
    SilentAfter {
        #[serde(rename = "last_hop")]
        last: Option<LastHop>,
        silent: u8,
    },
    /// The trace: the target answered an echo request at `ttl`.
    TargetAnswersIcmp { ttl: u8 },
    /// The main address answered a TCP connect to `port`, the first of the
    /// scope's ports that did (`refused`: something answered for the port).
    AnswersTcp { port: u16, refused: bool },
    /// The name's address of the other family, `address`, answered: that
    /// address, not every one of the family.
    OtherFamilyWorks { family: Family, address: IpAddr },
    /// Probes to the name's address of the other family left and got no
    /// answer.
    OtherFamilyFails { family: Family, address: IpAddr },
}

/// A hop of the trace and every address that answered there, in order: with
/// load balancing several do, and no path through them is inferred.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LastHop {
    pub ttl: u8,
    pub from: Vec<IpAddr>,
}

/// Decides, from the monitoring state and the outcomes of its requests, what
/// to find out next and what it shows.
pub struct Planner {
    scope: Scope,
    /// The current generation's target and the context detected for it
    /// (`None` until one is); `None` before the first tick.
    key: Option<(ResolvedAddr, Option<NetworkContext>)>,
    generation: Generation,
    incident: Option<Incident>,
    next_id: u64,
    /// Requests of any incident still running, or whose probes still count.
    started: Vec<Started>,
}

/// A started request: running until its outcome, its probes counted until
/// `WINDOW` after that.
struct Started {
    id: RequestId,
    cost: u32,
    trace: bool,
    /// When its outcome came; `None` while it runs.
    ended: Option<Instant>,
}

impl Started {
    fn running(&self) -> bool {
        self.ended.is_none()
    }

    fn counts_at(&self, now: Instant) -> bool {
        self.ended
            .is_none_or(|ended| self.cost > 0 && now.saturating_duration_since(ended) < WINDOW)
    }
}

/// An outage of the main target in one generation.
struct Incident {
    target: ResolvedAddr,
    generation: Generation,
    /// The `tick` that opened it.
    started: Instant,
    /// Started and without an outcome.
    pending: Vec<Request>,
    evidence: Vec<Evidence>,
    done: Option<Diagnosis>,
}

impl Planner {
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            key: None,
            generation: Generation(0),
            incident: None,
            next_id: 0,
            started: Vec::new(),
        }
    }

    /// The monitoring state: a new target, or another context for the same
    /// one, starts a generation and closes the incident; the main target down
    /// opens one, up closes it. A target's first context is not a change: a
    /// failover moves the target first, and its context is detected after.
    pub fn tick(&mut self, tick: &Tick) -> Step {
        let mut cancel = Vec::new();
        let changed = match &self.key {
            Some((target, known)) if *target == tick.target => {
                matches!((known, tick.context), (Some(known), Some(detected)) if known != detected)
            }
            _ => true,
        };
        if changed {
            if self.key.is_some() {
                self.generation.0 += 1;
            }
            self.key = Some((tick.target, tick.context.cloned()));
            cancel.extend(self.close());
        } else if let Some((_, known)) = &mut self.key
            && known.is_none()
        {
            *known = tick.context.cloned();
        }
        if tick.main == Reachability::Offline {
            if self.incident.is_none() {
                self.incident = Some(Incident {
                    target: tick.target,
                    generation: self.generation,
                    started: tick.now,
                    pending: Vec::new(),
                    evidence: Vec::new(),
                    done: None,
                });
            }
        } else {
            cancel.extend(self.close());
        }
        Step {
            start: self.advance(tick.now),
            cancel,
        }
    }

    /// The outcome of a request, at `now`: returns the requests to start
    /// next. On `Err` nothing is started; the next `tick` goes on.
    pub fn record(
        &mut self,
        id: RequestId,
        outcome: Outcome,
        via: Via,
        now: Instant,
    ) -> Result<Vec<Request>, Rejected> {
        let started = self
            .started
            .iter_mut()
            .find(|s| s.id == id && s.running())
            .ok_or(Rejected::NotRunning)?;
        started.ended = Some(now);
        let incident = self.incident.as_mut().ok_or(Rejected::Stale)?;
        let pending = incident
            .pending
            .iter()
            .position(|r| r.id == id)
            .ok_or(Rejected::Stale)?;
        let request = incident.pending.remove(pending);
        let fits = fits(&request.action, &outcome);
        incident.evidence.push(Evidence {
            id,
            role: request.role,
            action: request.action,
            outcome: if fits {
                outcome
            } else {
                Outcome::Failed("the outcome does not match the request".into())
            },
            via,
            generation: incident.generation,
            at: now,
        });
        if !fits {
            return Err(Rejected::Mismatch);
        }
        Ok(self.advance(now))
    }

    pub fn status(&self) -> Status<'_> {
        match &self.incident {
            None => Status::Idle,
            Some(Incident { done: None, .. }) => Status::Diagnosing,
            Some(Incident {
                done: Some(diagnosis),
                ..
            }) => Status::Done(diagnosis),
        }
    }

    /// The address the current incident is about; `None` while idle.
    pub fn incident_target(&self) -> Option<ResolvedAddr> {
        self.incident.as_ref().map(|incident| incident.target)
    }

    /// When the current incident opened (the `now` of that `tick`): a new
    /// generation opens another. `None` while idle.
    pub fn diagnosing_since(&self) -> Option<Instant> {
        self.incident.as_ref().map(|incident| incident.started)
    }

    /// Ends the incident, if any; returns its requests still running.
    fn close(&mut self) -> Vec<RequestId> {
        self.incident
            .take()
            .map(|incident| incident.pending.iter().map(|r| r.id).collect())
            .unwrap_or_default()
    }

    /// Starts what the incident needs next, as far as the slots and the
    /// traffic window allow, in order; concludes once nothing is missing or
    /// pending.
    fn advance(&mut self, now: Instant) -> Vec<Request> {
        let Some(incident) = self.incident.as_mut() else {
            return Vec::new();
        };
        if incident.done.is_some() {
            return Vec::new();
        }
        self.started.retain(|s| s.counts_at(now));

        let needed = needs(&self.scope, incident.target, &incident.evidence);
        if needed.is_empty() && incident.pending.is_empty() {
            incident.done = Some(conclude(&self.scope, incident.target, &incident.evidence));
            return Vec::new();
        }
        let mut start = Vec::new();
        for (role, action) in needed {
            if incident
                .pending
                .iter()
                .any(|r| r.role == role && r.action == action)
            {
                continue;
            }
            let cost = cost(&self.scope, &action);
            let trace = matches!(action, Action::Trace { .. });
            let running = self.started.iter().filter(|s| s.running()).count();
            let trace_running = self.started.iter().any(|s| s.trace && s.running());
            let counted: u32 = self.started.iter().map(|s| s.cost).sum();
            if running >= MAX_IN_FLIGHT
                || (trace && running > 0)
                || (cost > 0 && trace_running)
                || counted + cost > CEILING
            {
                break;
            }
            let id = RequestId(self.next_id);
            self.next_id += 1;
            self.started.push(Started {
                id,
                cost,
                trace,
                ended: None,
            });
            let request = Request { id, role, action };
            incident.pending.push(request.clone());
            start.push(request);
        }
        start
    }
}

/// Probes a request may send.
fn cost(scope: &Scope, action: &Action) -> u32 {
    match action {
        Action::Source { .. } | Action::Resolve => 0,
        Action::Echo { count, .. } => u32::from(*count),
        Action::Connect { .. } => 1,
        Action::Trace { .. } => scope.trace_probes,
    }
}

/// Whether `outcome` is what `action` gives. A failure fits any action.
fn fits(action: &Action, outcome: &Outcome) -> bool {
    match (action, outcome) {
        (_, Outcome::Failed(_))
        | (Action::Source { .. }, Outcome::Source(_))
        | (Action::Resolve, Outcome::Resolved(_))
        | (Action::Connect { .. }, Outcome::Connect(_))
        | (Action::Trace { .. }, Outcome::Trace(_)) => true,
        (Action::Echo { count, .. }, Outcome::Echo { sent, replies }) => {
            sent <= count && replies <= sent
        }
        _ => false,
    }
}

/// The requests of the lowest level with something missing (pending ones
/// included); empty once every level is settled.
fn needs(scope: &Scope, target: ResolvedAddr, evidence: &[Evidence]) -> Vec<(Role, Action)> {
    let has = |role: Role, action: &Action| {
        evidence
            .iter()
            .any(|e| e.role == role && e.action == *action)
    };
    let other = other_address(target, evidence);

    // Level 1: no probes.
    let mut level = Vec::new();
    let main_source = Action::Source { target };
    if !has(Role::Main, &main_source) {
        level.push((Role::Main, main_source));
    }
    if scope.other_family.is_none() {
        if !evidence.iter().any(|e| e.role == Role::Name) {
            level.push((Role::Name, Action::Resolve));
        }
        if let Some(other) = other {
            let source = Action::Source { target: other };
            if !has(Role::OtherFamily, &source) {
                level.push((Role::OtherFamily, source));
            }
        }
    }
    if !level.is_empty() {
        return level;
    }

    // Level 2: a few probes.
    let main_has_source = !no_source(Role::Main, evidence);
    if let MainProbe::Icmp { tcp_ports } = &scope.main
        && main_has_source
    {
        for &port in tcp_ports {
            let connect = Action::Connect { target, port };
            if !has(Role::Tcp, &connect) && !level.iter().any(|(_, a)| *a == connect) {
                level.push((Role::Tcp, connect));
            }
        }
    }
    if let Some(other) = other
        && !no_source(Role::OtherFamily, evidence)
    {
        let probe = match scope.main {
            MainProbe::Icmp { .. } => Action::Echo {
                target: other,
                count: OTHER_FAMILY_ECHOES,
            },
            MainProbe::Tcp { port } => Action::Connect {
                target: other,
                port,
            },
        };
        if !has(Role::OtherFamily, &probe) {
            level.push((Role::OtherFamily, probe));
        }
    }
    if !level.is_empty() {
        return level;
    }

    // Level 3: the trace.
    let trace = Action::Trace { target };
    if trace_wanted(evidence) && cost(scope, &trace) <= CEILING && !has(Role::Trace, &trace) {
        level.push((Role::Trace, trace));
    }
    level
}

/// The name's address of the other family, once the lookup gave one.
fn other_address(target: ResolvedAddr, evidence: &[Evidence]) -> Option<ResolvedAddr> {
    evidence.iter().find_map(|e| match &e.outcome {
        Outcome::Resolved(Ok(families)) if e.role == Role::Name => other_of(families, target),
        _ => None,
    })
}

fn other_of(families: &Families, target: ResolvedAddr) -> Option<ResolvedAddr> {
    if target.ip.is_ipv4() {
        families.v6
    } else {
        families.v4
    }
}

/// Whether the source check of `role` found that the system has none.
fn no_source(role: Role, evidence: &[Evidence]) -> bool {
    evidence.iter().any(|e| {
        e.role == role
            && matches!(e.action, Action::Source { .. })
            && e.outcome == Outcome::Source(SourceCheck::NoSource)
    })
}

/// The trace is wanted unless the main address has no source or answered a
/// TCP connect: a refusal is an answer too.
fn trace_wanted(evidence: &[Evidence]) -> bool {
    !no_source(Role::Main, evidence) && tcp_answer(evidence, None).is_none()
}

/// The `Tcp` evidence that answered, for `port` or any.
fn tcp_answer(evidence: &[Evidence], port: Option<u16>) -> Option<(&Evidence, bool)> {
    evidence.iter().find_map(|e| match (&e.action, &e.outcome) {
        (Action::Connect { port: p, .. }, Outcome::Connect(c))
            if e.role == Role::Tcp
                && port.is_none_or(|port| port == *p)
                && *c != Connection::Timeout =>
        {
            Some((e, *c == Connection::Refused))
        }
        _ => None,
    })
}

fn family(ip: IpAddr) -> Family {
    if ip.is_ipv4() { Family::V4 } else { Family::V6 }
}

/// The conclusions and gaps of a settled incident.
fn conclude(scope: &Scope, target: ResolvedAddr, evidence: &[Evidence]) -> Diagnosis {
    let mut conclusions = Vec::new();
    let mut gaps = Vec::new();
    let gap = |role, reason| Gap { role, reason };
    if let Some(reason) = &scope.other_family {
        gaps.push(gap(Role::OtherFamily, reason.clone()));
    }

    for e in evidence {
        let mut concluded = |conclusion| {
            conclusions.push(Concluded {
                conclusion,
                because: vec![e.id],
            })
        };
        match (&e.action, &e.outcome) {
            (_, Outcome::Failed(message)) => {
                gaps.push(gap(e.role, Reason::Failed(message.clone())))
            }
            (Action::Source { .. }, Outcome::Source(SourceCheck::NoSource)) => match e.role {
                Role::Main => concluded(Conclusion::NoSource {
                    family: family(target.ip),
                }),
                role => gaps.push(gap(role, Reason::NoSource)),
            },
            (Action::Source { .. }, Outcome::Source(SourceCheck::Unknown(message))) => {
                gaps.push(gap(e.role, Reason::Unknown(message.clone())))
            }
            (Action::Resolve, Outcome::Resolved(Err(message))) => {
                gaps.push(gap(e.role, Reason::ResolveFailed(message.clone())))
            }
            (Action::Resolve, Outcome::Resolved(Ok(families)))
                if other_of(families, target).is_none() =>
            {
                gaps.push(gap(Role::OtherFamily, Reason::NoAddress))
            }
            (Action::Echo { target: other, .. }, &Outcome::Echo { sent, replies }) => {
                let (family, address) = (family(other.ip), other.ip);
                if sent == 0 {
                    gaps.push(gap(
                        e.role,
                        Reason::Failed("no echo request was sent".into()),
                    ));
                } else if replies > 0 {
                    concluded(Conclusion::OtherFamilyWorks { family, address });
                } else {
                    concluded(Conclusion::OtherFamilyFails { family, address });
                }
            }
            (Action::Connect { target: other, .. }, Outcome::Connect(c))
                if e.role == Role::OtherFamily =>
            {
                let (family, address) = (family(other.ip), other.ip);
                concluded(if *c == Connection::Timeout {
                    Conclusion::OtherFamilyFails { family, address }
                } else {
                    Conclusion::OtherFamilyWorks { family, address }
                });
            }
            (Action::Trace { .. }, Outcome::Trace(result)) => match &result.status {
                TraceStatus::Reached { ttl } => {
                    concluded(Conclusion::TargetAnswersIcmp { ttl: *ttl })
                }
                &TraceStatus::Unreachable { ttl, from, kind } => {
                    concluded(Conclusion::ReportedUnreachable { ttl, from, kind })
                }
                TraceStatus::SilentTail { hops } => concluded(Conclusion::SilentAfter {
                    last: last_answer(&result.hops),
                    silent: *hops,
                }),
                TraceStatus::MaxHops | TraceStatus::BudgetExhausted | TraceStatus::Cancelled => {
                    gaps.push(gap(e.role, Reason::Inconclusive))
                }
                TraceStatus::Unavailable(why) => gaps.push(gap(e.role, Reason::Unavailable(*why))),
                TraceStatus::LocalError { message, .. }
                | TraceStatus::ProbeError { message, .. } => {
                    gaps.push(gap(e.role, Reason::Failed(message.clone())))
                }
            },
            _ => {}
        }
    }

    if let MainProbe::Icmp { tcp_ports } = &scope.main
        && let Some((port, (e, refused))) = tcp_ports
            .iter()
            .find_map(|&port| tcp_answer(evidence, Some(port)).map(|answer| (port, answer)))
    {
        conclusions.push(Concluded {
            conclusion: Conclusion::AnswersTcp { port, refused },
            because: vec![e.id],
        });
    }
    if trace_wanted(evidence) && cost(scope, &Action::Trace { target }) > CEILING {
        gaps.push(gap(Role::Trace, Reason::Ceiling));
    }

    conclusions.sort_by_key(|c| match c.conclusion {
        Conclusion::NoSource { .. }
        | Conclusion::ReportedUnreachable { .. }
        | Conclusion::SilentAfter { .. }
        | Conclusion::TargetAnswersIcmp { .. } => 0,
        Conclusion::AnswersTcp { .. } => 1,
        Conclusion::OtherFamilyWorks { .. } | Conclusion::OtherFamilyFails { .. } => 2,
    });
    Diagnosis {
        conclusions,
        gaps,
        evidence: evidence.to_vec(),
    }
}

/// The highest hop that answered, with every address that did there.
fn last_answer(hops: &[Hop]) -> Option<LastHop> {
    hops.iter().rev().find_map(|hop| {
        let mut from = Vec::new();
        for probe in &hop.probes {
            if let HopProbe::Reply { from: f, .. } = probe
                && !from.contains(f)
            {
                from.push(*f);
            }
        }
        (!from.is_empty()).then_some(LastHop { ttl: hop.ttl, from })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::classify::TargetClass;
    use crate::probe::trace::{ReplyKind, TraceResult, Unavailable};
    use std::collections::VecDeque;

    const MAIN: &str = "198.51.100.7";
    const OTHER: &str = "2001:db8::7";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> ResolvedAddr {
        ResolvedAddr::unscoped(ip(s))
    }

    fn context(interface: &str) -> NetworkContext {
        NetworkContext {
            interface: interface.into(),
            local_ip: ip("192.0.2.2"),
            prefix_len: 24,
            gateway: Some("192.0.2.1".into()),
            target_class: TargetClass::PublicNetwork,
        }
    }

    fn icmp(tcp_ports: &[u16]) -> Scope {
        Scope {
            main: MainProbe::Icmp {
                tcp_ports: tcp_ports.to_vec(),
            },
            other_family: None,
            trace_probes: 90,
        }
    }

    fn hop(ttl: u8, probes: Vec<HopProbe>) -> Hop {
        Hop {
            ttl,
            probes,
            partial: false,
        }
    }

    fn silent(ttl: u8) -> Hop {
        hop(ttl, vec![HopProbe::Silent; 3])
    }

    fn reply(from: &str, ms: u64) -> HopProbe {
        HopProbe::Reply {
            from: ip(from),
            rtt: Duration::from_millis(ms),
            kind: ReplyKind::TimeExceeded,
        }
    }

    fn trace(status: TraceStatus, hops: Vec<Hop>) -> Outcome {
        Outcome::Trace(TraceResult { status, hops })
    }

    /// A network where nothing answers the main address: sources usable,
    /// both families found, echoes and connects unanswered, a trace that
    /// goes silent after the first hop.
    fn base(r: &Request) -> Outcome {
        match &r.action {
            Action::Source { target } => {
                Outcome::Source(SourceCheck::Usable(if target.ip.is_ipv4() {
                    ip("192.0.2.2")
                } else {
                    ip("2001:db8:5::2")
                }))
            }
            Action::Resolve => Outcome::Resolved(Ok(Families {
                v4: Some(addr(MAIN)),
                v6: Some(addr(OTHER)),
                time: Some(Duration::from_millis(3)),
            })),
            Action::Echo { count, .. } => Outcome::Echo {
                sent: *count,
                replies: 0,
            },
            Action::Connect { .. } => Outcome::Connect(Connection::Timeout),
            Action::Trace { .. } => trace(
                TraceStatus::SilentTail { hops: 3 },
                vec![
                    hop(1, vec![reply("192.0.2.1", 1); 3]),
                    silent(2),
                    silent(3),
                    silent(4),
                ],
            ),
        }
    }

    /// The planner, the main target and context it sees, and what the
    /// executor started and has not answered yet. Time is in seconds from
    /// `base`.
    struct Run {
        planner: Planner,
        base: Instant,
        now: u64,
        target: ResolvedAddr,
        context: NetworkContext,
        /// Whether `context` was detected for `target`; when not, the latest
        /// detection is about another address and the planner gets `None`.
        context_detected: bool,
        /// Started, in order, with the second it was started at.
        started: Vec<(u64, Request)>,
        /// Started and not answered.
        queue: VecDeque<Request>,
        /// The second each request's outcome came.
        ended: Vec<(RequestId, u64)>,
        cancelled: Vec<RequestId>,
        max_running: usize,
    }

    impl Run {
        fn new(scope: Scope) -> Self {
            Self {
                planner: Planner::new(scope),
                base: Instant::now(),
                now: 0,
                target: addr(MAIN),
                context: context("eth0"),
                context_detected: true,
                started: Vec::new(),
                queue: VecDeque::new(),
                ended: Vec::new(),
                cancelled: Vec::new(),
                max_running: 0,
            }
        }

        fn at(&self) -> Instant {
            self.base + Duration::from_secs(self.now)
        }

        /// Takes what the planner started; checks that the trace runs alone.
        fn begin(&mut self, requests: Vec<Request>) {
            for request in requests {
                if is_trace(&request.action) {
                    assert!(
                        self.queue.is_empty(),
                        "a trace started with {:?} running",
                        self.queue
                    );
                } else if sends_probes(&request.action) {
                    assert!(
                        !self.queue.iter().any(|r| is_trace(&r.action)),
                        "{request:?} started while a trace runs"
                    );
                }
                self.started.push((self.now, request.clone()));
                self.queue.push_back(request);
                assert!(
                    self.queue.len() <= MAX_IN_FLIGHT,
                    "{:?} running",
                    self.queue
                );
            }
            self.max_running = self.max_running.max(self.queue.len());
        }

        fn tick(&mut self, main: Reachability) -> Step {
            let step = self.planner.tick(&Tick {
                now: self.at(),
                target: self.target,
                context: self.context_detected.then_some(&self.context),
                main,
            });
            self.begin(step.start.clone());
            self.cancelled.extend(&step.cancel);
            step
        }

        fn answer(&mut self, id: RequestId, outcome: Outcome) -> Result<(), Rejected> {
            if self.queue.iter().any(|r| r.id == id) {
                self.ended.push((id, self.now));
            }
            self.queue.retain(|r| r.id != id);
            let next = self
                .planner
                .record(id, outcome, Via::default(), self.at())?;
            self.begin(next);
            Ok(())
        }

        /// Answers the oldest request still running with `script`.
        fn answer_next(&mut self, script: &mut impl FnMut(&Request) -> Outcome) -> Request {
            let request = self.queue.front().cloned().expect("nothing is running");
            let _ = self.answer(request.id, script(&request));
            request
        }

        /// Answers everything started with `script`, ticking the main target
        /// down once a second when nothing runs, until the diagnosis is done.
        fn settle(&mut self, mut script: impl FnMut(&Request) -> Outcome) -> Diagnosis {
            for _ in 0..1000 {
                if let Status::Done(diagnosis) = self.planner.status() {
                    return diagnosis.clone();
                }
                if self.queue.is_empty() {
                    self.now += 1;
                    self.tick(Reachability::Offline);
                } else {
                    self.answer_next(&mut script);
                }
            }
            panic!("the diagnosis never finished");
        }

        fn actions(&self) -> Vec<(Role, Action)> {
            self.started
                .iter()
                .map(|(_, r)| (r.role, r.action.clone()))
                .collect()
        }

        fn started_any(&self, wanted: impl Fn(&Action) -> bool) -> bool {
            self.started.iter().any(|(_, r)| wanted(&r.action))
        }
    }

    fn diagnose(scope: Scope, script: impl FnMut(&Request) -> Outcome) -> (Run, Diagnosis) {
        let mut run = Run::new(scope);
        run.tick(Reachability::Offline);
        let diagnosis = run.settle(script);
        (run, diagnosis)
    }

    fn conclusions(diagnosis: &Diagnosis) -> Vec<Conclusion> {
        diagnosis
            .conclusions
            .iter()
            .map(|c| c.conclusion.clone())
            .collect()
    }

    fn gap(role: Role, reason: Reason) -> Gap {
        Gap { role, reason }
    }

    fn is_trace(action: &Action) -> bool {
        matches!(action, Action::Trace { .. })
    }

    fn sends_probes(action: &Action) -> bool {
        !matches!(action, Action::Source { .. } | Action::Resolve)
    }

    #[test]
    fn only_an_outage_starts_a_diagnosis() {
        let mut run = Run::new(icmp(&[443, 80]));
        for main in [Reachability::Online, Reachability::Unknown] {
            assert_eq!(run.tick(main), Step::default());
            assert_eq!(run.planner.status(), Status::Idle);
        }
        run.tick(Reachability::Offline);
        assert_eq!(
            run.actions(),
            [
                (Role::Main, Action::Source { target: addr(MAIN) }),
                (Role::Name, Action::Resolve),
            ]
        );
        assert_eq!(run.planner.status(), Status::Diagnosing);
    }

    /// An evidence keeps the request it answers (destination and port), how
    /// it went (source and interface, as the executor tells), its generation
    /// and when it came.
    #[test]
    fn evidence_keeps_its_request_and_provenance() {
        let mut run = Run::new(icmp(&[443]));
        run.tick(Reachability::Offline);
        run.settle_until(|a| matches!(a, Action::Connect { .. }));
        let connect = run
            .queue
            .iter()
            .find(|r| matches!(r.action, Action::Connect { .. }))
            .cloned()
            .unwrap();
        let via = Via {
            source: Some(ip("192.0.2.2")),
            interface: Some("eth0".into()),
        };
        run.now = 7;
        run.queue.retain(|r| r.id != connect.id);
        let next = run
            .planner
            .record(
                connect.id,
                Outcome::Connect(Connection::Refused),
                via.clone(),
                run.at(),
            )
            .unwrap();
        run.begin(next);
        let diagnosis = run.settle(base);
        let evidence = diagnosis
            .evidence
            .iter()
            .find(|e| e.id == connect.id)
            .unwrap();
        assert_eq!(
            (evidence.role, &evidence.action, &evidence.outcome),
            (
                Role::Tcp,
                &Action::Connect {
                    target: addr(MAIN),
                    port: 443
                },
                &Outcome::Connect(Connection::Refused)
            )
        );
        assert_eq!(evidence.via, via);
        assert_eq!(evidence.generation, Generation(0));
        assert_eq!(evidence.at, run.base + Duration::from_secs(7));
        assert_eq!(diagnosis.conclusions[0].because, [connect.id]);
    }

    /// Each level starts once the previous one has nothing pending; the other
    /// family's address counts although it is not the main one; a concluded
    /// incident asks for nothing more.
    #[test]
    fn levels_run_in_order_and_compare_the_families() {
        let mut run = Run::new(icmp(&[443, 80]));
        let mut script = |r: &Request| match r.action {
            Action::Echo { count, .. } => Outcome::Echo {
                sent: count,
                replies: count,
            },
            _ => base(r),
        };
        run.tick(Reachability::Offline);
        run.answer_next(&mut script);
        assert_eq!(run.started.len(), 2, "the lookup is still pending");
        run.answer_next(&mut script);
        assert_eq!(
            run.started[2].1.action,
            Action::Source {
                target: addr(OTHER)
            }
        );
        run.answer_next(&mut script);
        let level2: Vec<_> = run.actions()[3..].to_vec();
        assert_eq!(
            level2,
            [
                (
                    Role::Tcp,
                    Action::Connect {
                        target: addr(MAIN),
                        port: 443
                    }
                ),
                (
                    Role::Tcp,
                    Action::Connect {
                        target: addr(MAIN),
                        port: 80
                    }
                ),
                (
                    Role::OtherFamily,
                    Action::Echo {
                        target: addr(OTHER),
                        count: OTHER_FAMILY_ECHOES
                    }
                ),
            ]
        );
        run.answer_next(&mut script);
        run.answer_next(&mut script);
        assert_eq!(run.started.len(), 6, "no trace before level 2 is over");
        run.answer_next(&mut script);
        assert_eq!(
            run.started[6].1,
            Request {
                id: run.started[6].1.id,
                role: Role::Trace,
                action: Action::Trace { target: addr(MAIN) }
            }
        );
        run.answer_next(&mut script);

        let Status::Done(diagnosis) = run.planner.status() else {
            panic!("not concluded");
        };
        assert_eq!(
            conclusions(diagnosis),
            [
                Conclusion::SilentAfter {
                    last: Some(LastHop {
                        ttl: 1,
                        from: vec![ip("192.0.2.1")]
                    }),
                    silent: 3
                },
                Conclusion::OtherFamilyWorks {
                    family: Family::V6,
                    address: ip(OTHER),
                },
            ]
        );
        assert_eq!(diagnosis.evidence.len(), 7);
        assert!(diagnosis.gaps.is_empty());

        run.now += 30;
        assert_eq!(run.tick(Reachability::Offline), Step::default());
        assert_eq!(run.started.len(), 7);
    }

    /// An IPv6-only host probing the name's IPv4 address: nothing is sent to
    /// the main address, and the other family answers.
    #[test]
    fn no_source_for_the_main_family_sends_nothing_to_it() {
        let (run, diagnosis) = diagnose(icmp(&[443, 80]), |r| match r.action {
            Action::Source { target } if target == addr(MAIN) => {
                Outcome::Source(SourceCheck::NoSource)
            }
            Action::Echo { count, .. } => Outcome::Echo {
                sent: count,
                replies: 1,
            },
            _ => base(r),
        });
        assert!(!run.started_any(|a| matches!(a, Action::Connect { .. }) || is_trace(a)));
        assert_eq!(
            conclusions(&diagnosis),
            [
                Conclusion::NoSource { family: Family::V4 },
                Conclusion::OtherFamilyWorks {
                    family: Family::V6,
                    address: ip(OTHER),
                },
            ]
        );
        assert_eq!(diagnosis.conclusions[0].because, [run.started[0].1.id]);
    }

    /// A TCP answer on the main address spares the trace: the first of the
    /// scope's ports that answered, refusals included. A target that filters
    /// ICMP and serves 443 gets no path conclusion.
    #[test]
    fn a_tcp_answer_spares_the_trace() {
        for (ports, open, refused, expected) in [
            (&[443, 80][..], &[443][..], &[][..], (443, false)),
            (&[443, 80], &[], &[80], (80, true)),
            (&[80, 443], &[443], &[80], (80, true)),
        ] {
            let (run, diagnosis) = diagnose(icmp(ports), |r| match r.action {
                Action::Connect { port, .. } if open.contains(&port) => {
                    Outcome::Connect(Connection::Open)
                }
                Action::Connect { port, .. } if refused.contains(&port) => {
                    Outcome::Connect(Connection::Refused)
                }
                _ => base(r),
            });
            assert!(!run.started_any(is_trace), "{ports:?}");
            assert_eq!(
                conclusions(&diagnosis),
                [
                    Conclusion::AnswersTcp {
                        port: expected.0,
                        refused: expected.1
                    },
                    Conclusion::OtherFamilyFails {
                        family: Family::V6,
                        address: ip(OTHER),
                    },
                ],
                "{ports:?}"
            );
        }
    }

    /// With a TCP main probe the other family is tried on that port and no
    /// other; its answer does not spare the trace of the main address.
    #[test]
    fn the_other_family_answering_does_not_spare_the_trace() {
        for connection in [Connection::Open, Connection::Refused] {
            let scope = Scope {
                main: MainProbe::Tcp { port: 8443 },
                ..icmp(&[])
            };
            let (run, diagnosis) = diagnose(scope, |r| match r.action {
                Action::Connect { .. } => Outcome::Connect(connection),
                _ => base(r),
            });
            let connects: Vec<_> = run
                .actions()
                .into_iter()
                .filter(|(_, a)| matches!(a, Action::Connect { .. }))
                .collect();
            assert_eq!(
                connects,
                [(
                    Role::OtherFamily,
                    Action::Connect {
                        target: addr(OTHER),
                        port: 8443
                    }
                )]
            );
            assert!(run.started_any(is_trace));
            assert!(matches!(
                conclusions(&diagnosis)[..],
                [
                    Conclusion::SilentAfter { .. },
                    Conclusion::OtherFamilyWorks {
                        family: Family::V6,
                        ..
                    }
                ]
            ));
        }
    }

    #[test]
    fn a_hop_reporting_the_target_unreachable() {
        let (_, diagnosis) = diagnose(icmp(&[443]), |r| match r.action {
            Action::Trace { .. } => trace(
                TraceStatus::Unreachable {
                    ttl: 4,
                    from: ip("203.0.113.9"),
                    kind: UnreachableKind::AdminProhibited,
                },
                vec![],
            ),
            _ => base(r),
        });
        assert_eq!(
            conclusions(&diagnosis)[0],
            Conclusion::ReportedUnreachable {
                ttl: 4,
                from: ip("203.0.113.9"),
                kind: UnreachableKind::AdminProhibited
            }
        );
    }

    /// The last hop that answered, whatever came before: a silent or slow hop
    /// in between is no conclusion.
    #[test]
    fn silent_after_the_last_hop_that_answered() {
        let (_, diagnosis) = diagnose(icmp(&[443]), |r| match r.action {
            Action::Trace { .. } => trace(
                TraceStatus::SilentTail { hops: 3 },
                vec![
                    hop(1, vec![reply("192.0.2.1", 1); 3]),
                    silent(2),
                    hop(3, vec![reply("203.0.113.3", 900); 3]),
                    hop(4, vec![reply("203.0.113.4", 12); 3]),
                    silent(5),
                    silent(6),
                    silent(7),
                ],
            ),
            _ => base(r),
        });
        assert_eq!(
            conclusions(&diagnosis),
            [
                Conclusion::SilentAfter {
                    last: Some(LastHop {
                        ttl: 4,
                        from: vec![ip("203.0.113.4")]
                    }),
                    silent: 3
                },
                Conclusion::OtherFamilyFails {
                    family: Family::V6,
                    address: ip(OTHER),
                },
            ]
        );
    }

    /// A target that filters ICMP behind three silent routers, with 443 and
    /// 80 silent too: what was observed, and nothing about the target.
    #[test]
    fn a_target_filtering_icmp_behind_silent_routers() {
        let (_, diagnosis) = diagnose(icmp(&[443, 80]), |r| match r.action {
            Action::Trace { .. } => trace(
                TraceStatus::SilentTail { hops: 3 },
                vec![
                    hop(1, vec![reply("192.0.2.1", 1); 3]),
                    hop(2, vec![reply("203.0.113.2", 8); 3]),
                    silent(3),
                    silent(4),
                    silent(5),
                ],
            ),
            Action::Echo { count, .. } => Outcome::Echo {
                sent: count,
                replies: count,
            },
            _ => base(r),
        });
        assert_eq!(
            conclusions(&diagnosis),
            [
                Conclusion::SilentAfter {
                    last: Some(LastHop {
                        ttl: 2,
                        from: vec![ip("203.0.113.2")]
                    }),
                    silent: 3
                },
                Conclusion::OtherFamilyWorks {
                    family: Family::V6,
                    address: ip(OTHER),
                },
            ]
        );
    }

    /// Load balancing: every address of the last hop that answered, once, in
    /// order. No hop answering at all is said as such.
    #[test]
    fn the_last_hop_keeps_every_address_that_answered() {
        for (hops, last) in [
            (
                vec![
                    hop(1, vec![reply("192.0.2.1", 1); 3]),
                    hop(
                        2,
                        vec![
                            reply("203.0.113.21", 9),
                            reply("203.0.113.22", 9),
                            reply("203.0.113.21", 9),
                        ],
                    ),
                    silent(3),
                    silent(4),
                    silent(5),
                ],
                Some(LastHop {
                    ttl: 2,
                    from: vec![ip("203.0.113.21"), ip("203.0.113.22")],
                }),
            ),
            (vec![silent(1), silent(2), silent(3)], None),
        ] {
            let hops = hops.clone();
            let (_, diagnosis) = diagnose(icmp(&[]), |r| match r.action {
                Action::Trace { .. } => trace(TraceStatus::SilentTail { hops: 3 }, hops.clone()),
                _ => base(r),
            });
            assert_eq!(
                conclusions(&diagnosis)[0],
                Conclusion::SilentAfter {
                    last: last.clone(),
                    silent: 3
                }
            );
        }
    }

    /// The target answering the trace is that and only that, with an ICMP or
    /// a TCP main probe.
    #[test]
    fn the_target_answering_the_trace() {
        for scope in [
            icmp(&[443]),
            Scope {
                main: MainProbe::Tcp { port: 443 },
                ..icmp(&[])
            },
        ] {
            let (_, diagnosis) = diagnose(scope, |r| match r.action {
                Action::Trace { .. } => trace(
                    TraceStatus::Reached { ttl: 5 },
                    vec![hop(1, vec![reply("192.0.2.1", 1); 3])],
                ),
                _ => base(r),
            });
            assert_eq!(
                conclusions(&diagnosis),
                [
                    Conclusion::TargetAnswersIcmp { ttl: 5 },
                    Conclusion::OtherFamilyFails {
                        family: Family::V6,
                        address: ip(OTHER),
                    },
                ]
            );
        }
    }

    /// A trace that cannot run or stopped before it could tell is a gap, not
    /// a conclusion.
    #[test]
    fn a_trace_that_cannot_tell_is_a_gap() {
        let message = || "socket: permission denied".to_string();
        for (status, reason) in [
            (
                TraceStatus::Unavailable(Unavailable::Permission),
                Reason::Unavailable(Unavailable::Permission),
            ),
            (TraceStatus::BudgetExhausted, Reason::Inconclusive),
            (TraceStatus::Cancelled, Reason::Inconclusive),
            (TraceStatus::MaxHops, Reason::Inconclusive),
            (
                TraceStatus::LocalError {
                    ttl: None,
                    message: message(),
                },
                Reason::Failed(message()),
            ),
            (
                TraceStatus::ProbeError {
                    ttl: 2,
                    message: message(),
                },
                Reason::Failed(message()),
            ),
        ] {
            let status = status.clone();
            let (_, diagnosis) = diagnose(icmp(&[443]), |r| match r.action {
                Action::Trace { .. } => trace(status.clone(), vec![]),
                _ => base(r),
            });
            assert_eq!(
                conclusions(&diagnosis),
                [Conclusion::OtherFamilyFails {
                    family: Family::V6,
                    address: ip(OTHER),
                }],
                "{status:?}"
            );
            assert_eq!(diagnosis.gaps, [gap(Role::Trace, reason)]);
        }
    }

    /// Explicit options keep the other family out: no lookup, no probe, a gap
    /// that says why. No TCP ports, no connects.
    #[test]
    fn explicit_options_keep_the_other_family_out() {
        for reason in [
            Reason::ExplicitFamily,
            Reason::ExplicitSource,
            Reason::Literal,
        ] {
            let scope = Scope {
                other_family: Some(reason.clone()),
                ..icmp(&[])
            };
            let (run, diagnosis) = diagnose(scope, base);
            assert_eq!(
                run.actions(),
                [
                    (Role::Main, Action::Source { target: addr(MAIN) }),
                    (Role::Trace, Action::Trace { target: addr(MAIN) }),
                ]
            );
            assert_eq!(diagnosis.gaps, [gap(Role::OtherFamily, reason)]);
        }
    }

    /// What keeps the other family from being probed, and an unknown source
    /// that does not.
    #[test]
    fn what_the_other_family_lacks() {
        let only_v4 = |r: &Request| match r.action {
            Action::Resolve => Outcome::Resolved(Ok(Families {
                v4: Some(addr(MAIN)),
                v6: None,
                time: None,
            })),
            _ => base(r),
        };
        let failed_lookup = |r: &Request| match r.action {
            Action::Resolve => Outcome::Resolved(Err("DNS resolution failed".into())),
            _ => base(r),
        };
        let no_source = |r: &Request| match r.action {
            Action::Source { target } if target == addr(OTHER) => {
                Outcome::Source(SourceCheck::NoSource)
            }
            _ => base(r),
        };
        let unknown_source = |r: &Request| match r.action {
            Action::Source { target } if target == addr(OTHER) => {
                Outcome::Source(SourceCheck::Unknown("permission denied".into()))
            }
            _ => base(r),
        };
        type Script = fn(&Request) -> Outcome;
        for (script, expected, echoed) in [
            (
                only_v4 as Script,
                gap(Role::OtherFamily, Reason::NoAddress),
                false,
            ),
            (
                failed_lookup,
                gap(
                    Role::Name,
                    Reason::ResolveFailed("DNS resolution failed".into()),
                ),
                false,
            ),
            (no_source, gap(Role::OtherFamily, Reason::NoSource), false),
            // An unknown source is said, and the other family is tried anyway.
            (
                unknown_source,
                gap(
                    Role::OtherFamily,
                    Reason::Unknown("permission denied".into()),
                ),
                true,
            ),
        ] {
            let (run, diagnosis) = diagnose(icmp(&[]), script);
            let echo = run.started_any(|a| matches!(a, Action::Echo { .. }));
            assert_eq!(echo, echoed, "{expected:?}");
            assert_eq!(diagnosis.gaps, [expected]);
        }
    }

    /// Only probes that left and got no answer make a failure; a failure to
    /// carry out the request is a gap.
    #[test]
    fn an_echo_that_never_left_is_not_a_failure() {
        for (outcome, conclusion, gaps) in [
            (
                Outcome::Echo {
                    sent: 0,
                    replies: 0,
                },
                None,
                vec![gap(
                    Role::OtherFamily,
                    Reason::Failed("no echo request was sent".into()),
                )],
            ),
            (
                Outcome::Failed("socket: permission denied".into()),
                None,
                vec![gap(
                    Role::OtherFamily,
                    Reason::Failed("socket: permission denied".into()),
                )],
            ),
            (
                Outcome::Echo {
                    sent: 2,
                    replies: 0,
                },
                Some(Conclusion::OtherFamilyFails {
                    family: Family::V6,
                    address: ip(OTHER),
                }),
                vec![],
            ),
            (
                Outcome::Echo {
                    sent: 2,
                    replies: 1,
                },
                Some(Conclusion::OtherFamilyWorks {
                    family: Family::V6,
                    address: ip(OTHER),
                }),
                vec![],
            ),
        ] {
            let outcome = outcome.clone();
            let (_, diagnosis) = diagnose(icmp(&[]), |r| match r.action {
                Action::Echo { .. } => outcome.clone(),
                _ => base(r),
            });
            let other: Vec<_> = conclusions(&diagnosis)
                .into_iter()
                .filter(|c| {
                    matches!(
                        c,
                        Conclusion::OtherFamilyWorks { .. } | Conclusion::OtherFamilyFails { .. }
                    )
                })
                .collect();
            assert_eq!(other, Vec::from_iter(conclusion), "{outcome:?}");
            assert_eq!(diagnosis.gaps, gaps, "{outcome:?}");
        }
    }

    /// An outcome that is not what its request gives is refused, kept as a
    /// failure, and frees its slot: the incident still concludes.
    #[test]
    fn a_mismatched_outcome_frees_its_slot() {
        for wrong in [
            Outcome::Echo {
                sent: 4,
                replies: 0,
            },
            Outcome::Echo {
                sent: 2,
                replies: 3,
            },
            Outcome::Connect(Connection::Open),
        ] {
            let mut run = Run::new(icmp(&[]));
            run.tick(Reachability::Offline);
            run.settle_until(|a| matches!(a, Action::Echo { .. }));
            let echo = run.queue.front().cloned().unwrap();
            assert_eq!(run.answer(echo.id, wrong.clone()), Err(Rejected::Mismatch));
            assert_eq!(
                run.answer(echo.id, base(&echo)),
                Err(Rejected::NotRunning),
                "answered once"
            );
            let diagnosis = run.settle(base);
            assert_eq!(
                diagnosis.gaps,
                [gap(
                    Role::OtherFamily,
                    Reason::Failed("the outcome does not match the request".into())
                )],
                "{wrong:?}"
            );
        }
    }

    impl Run {
        /// Answers with `base` until a request `wanted` is running.
        fn settle_until(&mut self, wanted: impl Fn(&Action) -> bool) {
            for _ in 0..100 {
                if self.queue.iter().any(|r| wanted(&r.action)) {
                    return;
                }
                if self.queue.is_empty() {
                    self.now += 1;
                    self.tick(Reachability::Offline);
                } else {
                    self.answer_next(&mut base);
                }
            }
            panic!("never started");
        }
    }

    /// A DNS failover or a context change starts a generation: the running
    /// trace is to be cancelled and its late outcome refused; the new
    /// generation starts at once what sends no probes, and its probes wait
    /// until the old trace ends (`Run::begin` checks it at every start).
    #[test]
    fn a_new_generation_drops_what_was_running() {
        for failover in [true, false] {
            let mut run = Run::new(Scope {
                trace_probes: 9,
                ..icmp(&[443, 80])
            });
            run.tick(Reachability::Offline);
            run.settle_until(is_trace);
            let old = run.queue.front().cloned().unwrap();

            if failover {
                run.target = addr("198.51.100.8");
            } else {
                run.context = context("wlan0");
            }
            run.now += 1;
            let step = run.tick(Reachability::Offline);
            assert_eq!(step.cancel, [old.id]);
            assert_eq!(step.start[0].action, Action::Source { target: run.target });

            // Everything but the old trace answered: level 1 only.
            let before = run.started.len() - step.start.len();
            for _ in 0..20 {
                match run.queue.iter().find(|r| r.id != old.id).cloned() {
                    Some(r) => run.answer(r.id, base(&r)).unwrap(),
                    None => {
                        run.now += 1;
                        run.tick(Reachability::Offline);
                    }
                }
            }
            assert!(
                run.started[before..]
                    .iter()
                    .all(|(_, r)| !sends_probes(&r.action))
            );
            assert_eq!(run.queue.len(), 1, "only the old trace runs");
            assert_eq!(run.planner.status(), Status::Diagnosing);

            assert_eq!(run.answer(old.id, base(&old)), Err(Rejected::Stale));
            let diagnosis = run.settle(base);
            assert!(run.started_any(|a| *a == Action::Trace { target: run.target }));
            assert!(
                diagnosis
                    .evidence
                    .iter()
                    .all(|e| e.generation == Generation(1) && e.id != old.id)
            );
            assert!(run.max_running <= MAX_IN_FLIGHT, "{}", run.max_running);
        }
    }

    /// A failover moves the target before its context is detected: the new
    /// target's first context is not a change, and what started for it goes
    /// on. A later change of that context starts a generation.
    #[test]
    fn the_first_context_after_a_failover_is_not_a_change() {
        let mut run = Run::new(icmp(&[443, 80]));
        run.tick(Reachability::Offline);
        run.target = addr("198.51.100.8");
        run.context_detected = false;
        run.now += 1;
        let step = run.tick(Reachability::Offline);
        assert_eq!(step.start[0].action, Action::Source { target: run.target });
        let source = step.start[0].id;

        // Its context, on another interface than the old address'.
        run.context = context("wlan0");
        run.context_detected = true;
        run.now += 1;
        let step = run.tick(Reachability::Offline);
        assert!(step.cancel.is_empty(), "{:?}", step.cancel);

        run.context = context("eth1");
        run.now += 1;
        let step = run.tick(Reachability::Offline);
        assert!(step.cancel.contains(&source), "{:?}", step.cancel);
        let diagnosis = run.settle(base);
        assert!(
            diagnosis
                .evidence
                .iter()
                .all(|e| e.generation == Generation(2))
        );
    }

    /// Level 2 of a closed generation still running fills every slot: the
    /// new generation starts nothing until their outcomes free them.
    #[test]
    fn the_in_flight_cap_holds_across_generations() {
        let mut run = Run::new(icmp(&[443, 80]));
        run.tick(Reachability::Offline);
        run.settle_until(|a| matches!(a, Action::Echo { .. }));
        let level2: Vec<_> = run.queue.iter().map(|r| r.id).collect();
        assert_eq!(level2.len(), MAX_IN_FLIGHT);

        run.context = context("wlan0");
        run.now += 1;
        let step = run.tick(Reachability::Offline);
        assert_eq!(step.cancel, level2);
        assert!(step.start.is_empty(), "{:?}", step.start);

        let old = run.queue.front().cloned().unwrap();
        assert_eq!(run.answer(old.id, base(&old)), Err(Rejected::Stale));
        run.now += 1;
        let step = run.tick(Reachability::Offline);
        assert_eq!(step.start.len(), 1, "one slot is free");

        let diagnosis = run.settle(base);
        assert!(
            diagnosis
                .evidence
                .iter()
                .all(|e| e.generation == Generation(1))
        );
    }

    /// The trace starts with nothing running, also when what runs is a
    /// lookup left by a closed incident.
    #[test]
    fn the_trace_waits_for_what_a_closed_incident_left() {
        let mut run = Run::new(icmp(&[443, 80]));
        run.tick(Reachability::Offline);
        let lookup = run
            .queue
            .iter()
            .find(|r| r.action == Action::Resolve)
            .cloned()
            .unwrap();
        run.now += 1;
        run.tick(Reachability::Online);
        let source = run
            .queue
            .iter()
            .find(|r| r.id != lookup.id)
            .cloned()
            .unwrap();
        assert_eq!(run.answer(source.id, base(&source)), Err(Rejected::Stale));

        run.now += 1;
        run.tick(Reachability::Offline);
        for _ in 0..30 {
            match run.queue.iter().find(|r| r.id != lookup.id).cloned() {
                Some(r) => run.answer(r.id, base(&r)).unwrap(),
                None => {
                    run.now += 1;
                    run.tick(Reachability::Offline);
                }
            }
        }
        assert!(!run.started_any(is_trace));
        assert_eq!(run.planner.status(), Status::Diagnosing);

        assert_eq!(run.answer(lookup.id, base(&lookup)), Err(Rejected::Stale));
        run.settle(base);
        assert!(run.started_any(is_trace));
    }

    /// Recovery closes the incident: what runs is to be cancelled and its
    /// outcome refused, once.
    #[test]
    fn recovery_closes_the_incident() {
        let mut run = Run::new(icmp(&[443, 80]));
        run.tick(Reachability::Offline);
        let level1: Vec<_> = run.queue.iter().map(|r| r.id).collect();
        let step = run.tick(Reachability::Online);
        assert_eq!(
            step,
            Step {
                start: vec![],
                cancel: level1.clone()
            }
        );
        assert_eq!(run.planner.status(), Status::Idle);
        for id in level1 {
            let outcome = Outcome::Failed("cancelled".into());
            assert_eq!(run.answer(id, outcome.clone()), Err(Rejected::Stale));
            assert_eq!(run.answer(id, outcome), Err(Rejected::NotRunning));
        }
    }

    #[test]
    fn a_trace_above_the_ceiling_is_a_gap() {
        let (run, diagnosis) = diagnose(
            Scope {
                trace_probes: CEILING + 1,
                ..icmp(&[443])
            },
            base,
        );
        assert!(!run.started_any(is_trace));
        assert_eq!(diagnosis.gaps, [gap(Role::Trace, Reason::Ceiling)]);
    }

    /// Two incidents a minute apart, the first trace using its whole 20 s:
    /// its probes count until 60 s after its outcome, so the second trace
    /// waits until then and no 60 s see more than the ceiling sent.
    #[test]
    fn the_window_bounds_back_to_back_incidents() {
        // Answers, at `at`, what runs now (not what that starts).
        fn answer_running(run: &mut Run, at: u64) {
            run.now = at;
            for _ in 0..run.queue.len() {
                run.answer_next(&mut base);
            }
        }
        let started_at = |run: &Run, wanted: fn(&Action) -> bool| -> Vec<u64> {
            run.started
                .iter()
                .filter(|(_, r)| wanted(&r.action))
                .map(|&(at, _)| at)
                .collect()
        };
        let mut run = Run::new(icmp(&[443, 80]));
        run.tick(Reachability::Offline);
        answer_running(&mut run, 1); // the other family's source
        answer_running(&mut run, 2); // level 2 starts at 2: 5 probes
        answer_running(&mut run, 6); // the trace starts at 6: 90
        answer_running(&mut run, 26);
        assert!(matches!(run.planner.status(), Status::Done(_)));
        run.now = 30;
        run.tick(Reachability::Online);

        run.now = 60;
        run.tick(Reachability::Offline);
        answer_running(&mut run, 60);
        answer_running(&mut run, 60); // level 2 at 60: 5 + 90 + 5 = 100
        answer_running(&mut run, 64);
        for now in 65..=86 {
            run.now = now;
            run.tick(Reachability::Offline);
        }
        let echo = |a: &Action| matches!(a, Action::Echo { .. });
        assert_eq!(started_at(&run, echo), [2, 60]);
        assert_eq!(started_at(&run, is_trace), [6, 86]);
    }

    /// Ten minutes of a target going up and down, failovers and context
    /// changes, and operations that take their time: the probes of the
    /// operations that run at some moment of any 60 s stay within the
    /// ceiling, no more than three operations run at once, those of closed
    /// incidents included, and the trace runs alone (`Run::begin`).
    #[test]
    fn traffic_stays_bounded_while_everything_changes() {
        let scope = icmp(&[443, 80]);
        let mut run = Run::new(scope.clone());
        let lasts = |action: &Action| match action {
            Action::Source { .. } | Action::Resolve => 0,
            Action::Connect { .. } => 1,
            Action::Echo { .. } => 3,
            Action::Trace { .. } => 17,
        };
        let mut due: Vec<(u64, Request)> = Vec::new();
        let mut seen = 0;
        for t in 0..600 {
            run.now = t;
            // Outcomes due by now, oldest first, each starting what follows.
            loop {
                due.extend(
                    run.started[seen..]
                        .iter()
                        .map(|(at, r)| (at + lasts(&r.action), r.clone())),
                );
                seen = run.started.len();
                due.sort_by_key(|(at, r)| (*at, r.id.0));
                if due.first().is_none_or(|(at, _)| *at > t) {
                    break;
                }
                let (_, request) = due.remove(0);
                let _ = run.answer(request.id, base(&request));
            }
            if t % 101 == 100 {
                run.target = if run.target == addr(MAIN) {
                    addr("198.51.100.8")
                } else {
                    addr(MAIN)
                };
            }
            if t % 37 == 36 {
                run.context = context(if run.context.interface == "eth0" {
                    "wlan0"
                } else {
                    "eth0"
                });
            }
            let main = if t % 50 < 35 {
                Reachability::Offline
            } else {
                Reachability::Online
            };
            run.tick(main);
        }

        let cost_of = |action: &Action| match action {
            Action::Echo { count, .. } => u32::from(*count),
            Action::Connect { .. } => 1,
            Action::Trace { .. } => scope.trace_probes,
            Action::Source { .. } | Action::Resolve => 0,
        };
        let ended = |id: RequestId| run.ended.iter().find(|(e, _)| *e == id).map(|&(_, at)| at);
        for w in 0..600 {
            let in_window: u32 = run
                .started
                .iter()
                .filter(|(start, r)| *start <= w && ended(r.id).is_none_or(|end| w < end + 60))
                .map(|(_, r)| cost_of(&r.action))
                .sum();
            assert!(
                in_window <= CEILING,
                "{in_window} probes in the 60 s up to {w}"
            );
        }
        assert!(run.max_running <= MAX_IN_FLIGHT, "{}", run.max_running);
        let traces = run
            .started
            .iter()
            .filter(|(_, r)| is_trace(&r.action))
            .count();
        assert!(
            traces >= 5,
            "only {traces} traces: the run does not exercise the ceiling"
        );
    }
}
