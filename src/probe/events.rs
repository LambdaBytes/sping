//! Discrete probe lifecycle events. Reserved for a future event-stream API;
//! the current pipeline publishes aggregated `ProbeSnapshot` values instead.

use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ProbeEvent {
    ProbeStarted { target: IpAddr },
    ReplyReceived { seq: u64, rtt: Duration, ttl: u8 },
    TimeoutDetected { seq: u64 },
    DnsResolved { ip: IpAddr, duration: Duration },
    DnsFailed { error: String },
    OutageStarted,
    OutageRecovered { duration: Duration },
    SpikeDetected { rtt: Duration },
}
