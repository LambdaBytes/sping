//! Evidence for the diagnosis planner (`diagnostics::planner`): what it asks
//! the executor to find out, what came back, and under which incident and
//! generation it was observed.

use std::net::IpAddr;
use std::time::Instant;

use serde::Serialize;

use crate::context::dns::{Families, ResolvedAddr};
use crate::probe::trace::{TraceResult, Unavailable};

/// Names one request, unique within the planner. Its outcome is matched by
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub(super) u64);

/// The main target's address and network context, numbered: a DNS failover
/// or a context change starts the next one, and what was observed under an
/// earlier one no longer counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation(pub(super) u64);

#[cfg(test)]
impl RequestId {
    /// For tests elsewhere that build evidence by hand.
    pub fn new(n: u64) -> Self {
        Self(n)
    }
}

#[cfg(test)]
impl Generation {
    /// For tests elsewhere that build evidence by hand.
    pub fn new(n: u64) -> Self {
        Self(n)
    }
}

/// Something the executor must find out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub role: Role,
    pub action: Action,
}

/// What an evidence is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The main probe's address.
    Main,
    /// The target name's address of the other family.
    OtherFamily,
    /// TCP ports of the main address, with an ICMP main probe.
    Tcp,
    /// The path to the main address.
    Trace,
    /// The target name's addresses.
    Name,
}

/// What to do. Each costs what it may send (`planner::cost`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The source address the system would send from to `target`
    /// (`iface::usable_source`, with the probe's `-S`/`-I`). Sends nothing.
    Source { target: ResolvedAddr },
    /// Both families of the target name (`dns::resolve_both`): one lookup.
    Resolve,
    /// `count` ICMP echo requests.
    Echo { target: ResolvedAddr, count: u8 },
    /// One TCP connect.
    Connect { target: ResolvedAddr, port: u16 },
    /// A bounded trace (`probe::trace`).
    Trace { target: ResolvedAddr },
}

/// What came back for a request.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// For `Source`.
    Source(SourceCheck),
    /// For `Resolve`: the families found, or why the lookup failed.
    Resolved(Result<Families, String>),
    /// For `Echo`: the probes that left and the ones answered.
    Echo { sent: u8, replies: u8 },
    /// For `Connect`. A local error is `Failed`.
    Connect(Connection),
    /// For `Trace`.
    Trace(TraceResult),
    /// The request could not be carried out (any action).
    Failed(String),
}

/// The source address for a destination (`iface::usable_source`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCheck {
    Usable(IpAddr),
    /// No route or no address of the family, or only one that does not leave
    /// the host.
    NoSource,
    /// It could not be told (a denied socket, a prohibit route...).
    Unknown(String),
}

/// How a TCP connect ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connection {
    Open,
    /// Something answered for the port (the host, or a device in its name).
    Refused,
    /// No answer within the timeout.
    Timeout,
}

/// The source address and interface an operation used, as the executor
/// knows them (`None`: it does not).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Via {
    pub source: Option<IpAddr>,
    pub interface: Option<String>,
}

/// An outcome accepted for the current incident, with what it answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub id: RequestId,
    pub role: Role,
    pub action: Action,
    pub outcome: Outcome,
    pub via: Via,
    pub generation: Generation,
    /// When the outcome was recorded.
    pub at: Instant,
}

/// Something the diagnosis could not establish, and why.
/// In JSON: `{"about": role, "reason": code, "detail": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    #[serde(rename = "about")]
    pub role: Role,
    #[serde(flatten)]
    pub reason: Reason,
}

/// Why something was not tried or told nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", content = "detail", rename_all = "snake_case")]
pub enum Reason {
    /// The family was chosen explicitly (`-4`/`-6`).
    ExplicitFamily,
    /// The probes are bound to one family's source (`-S`).
    ExplicitSource,
    /// The target is an address: there is no name to look up.
    Literal,
    /// The lookup gave no address of the family.
    NoAddress,
    /// The system has no source address for it.
    NoSource,
    /// The lookup failed.
    ResolveFailed(String),
    /// It would send more than the traffic ceiling allows at once.
    Ceiling,
    /// The trace cannot run here.
    Unavailable(Unavailable),
    /// The trace stopped before it could tell (time budget, cancel, highest
    /// TTL).
    Inconclusive,
    /// It failed locally, or nothing was sent.
    Failed(String),
    /// It could not be told (a source check under `-S`/`-I`, a denied
    /// socket...).
    Unknown(String),
}
