//! Lifetime probe statistics: counters, RTT min/avg/max, RFC 3550-style
//! jitter, ping-compatible `mdev`, and a fixed-size pulse ring buffer.

use std::collections::VecDeque;
use std::time::Duration;

use crate::probe::types::PulseEntry;

/// Pulse buffer size: 40 samples → 40 block chars (1 sample per char).
const PULSE_WIDTH: usize = 40;

/// Lifetime probe statistics plus a rolling pulse buffer of recent samples.
pub struct ProbeStats {
    pub sent: u64,
    pub received: u64,
    /// Probes lost (timeouts and errors).
    pub lost: u64,
    rtt_last: Option<Duration>,
    rtt_sum: Duration,
    rtt_sum_ms: f64,
    rtt_sum_sq_ms: f64,
    rtt_min: Option<Duration>,
    rtt_max: Option<Duration>,
    prev_rtt: Option<Duration>,
    jitter_sum: f64,
    jitter_count: u64,
    pulse: VecDeque<PulseEntry>,
}

impl ProbeStats {
    pub fn new() -> Self {
        Self {
            sent: 0,
            received: 0,
            lost: 0,
            rtt_last: None,
            rtt_sum: Duration::ZERO,
            rtt_sum_ms: 0.0,
            rtt_sum_sq_ms: 0.0,
            rtt_min: None,
            rtt_max: None,
            prev_rtt: None,
            jitter_sum: 0.0,
            jitter_count: 0,
            pulse: VecDeque::with_capacity(PULSE_WIDTH),
        }
    }

    /// Record a successful reply: counters, RTT aggregates, jitter, pulse.
    pub fn record_reply(&mut self, rtt: Duration) {
        self.sent += 1;
        self.received += 1;
        self.rtt_sum += rtt;
        let ms = rtt.as_secs_f64() * 1000.0;
        self.rtt_sum_ms += ms;
        self.rtt_sum_sq_ms += ms * ms;

        // Jitter: RFC 3550 style — absolute difference between consecutive RTTs
        if let Some(prev) = self.prev_rtt {
            let diff = rtt.abs_diff(prev);
            self.jitter_sum += diff.as_secs_f64() * 1000.0;
            self.jitter_count += 1;
        }
        self.prev_rtt = Some(rtt);
        self.rtt_last = Some(rtt);
        self.rtt_min = Some(self.rtt_min.map_or(rtt, |m| m.min(rtt)));
        self.rtt_max = Some(self.rtt_max.map_or(rtt, |m| m.max(rtt)));

        self.push_pulse(PulseEntry::Reply(rtt));
    }

    /// Record a timeout: counts as lost and clears the last RTT.
    pub fn record_timeout(&mut self) {
        self.sent += 1;
        self.lost += 1;
        self.rtt_last = None;
        self.push_pulse(PulseEntry::Loss);
    }

    /// Record a send/receive error: counted as lost, same as a timeout.
    pub fn record_error(&mut self) {
        self.sent += 1;
        self.lost += 1;
        self.rtt_last = None;
        self.push_pulse(PulseEntry::Loss);
    }

    fn push_pulse(&mut self, entry: PulseEntry) {
        if self.pulse.len() >= PULSE_WIDTH {
            self.pulse.pop_front();
        }
        self.pulse.push_back(entry);
    }

    /// Lifetime loss percentage (0-100); 0 before any probe is sent.
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.lost as f64 / self.sent as f64) * 100.0
        }
    }

    /// RTT of the most recent reply; `None` after a timeout/error.
    pub fn rtt_last(&self) -> Option<Duration> {
        self.rtt_last
    }

    /// Lifetime mean RTT; `None` until the first reply.
    pub fn rtt_avg(&self) -> Option<Duration> {
        if self.received == 0 {
            None
        } else {
            Some(self.rtt_sum / self.received as u32)
        }
    }

    /// Lifetime minimum RTT; `None` until the first reply.
    pub fn rtt_min(&self) -> Option<Duration> {
        self.rtt_min
    }

    /// Lifetime maximum RTT; `None` until the first reply.
    pub fn rtt_max(&self) -> Option<Duration> {
        self.rtt_max
    }

    /// Mean absolute difference between consecutive RTTs (RFC 3550 style);
    /// `None` until there are at least two replies.
    pub fn jitter(&self) -> Option<Duration> {
        if self.jitter_count == 0 {
            None
        } else {
            let avg_ms = self.jitter_sum / self.jitter_count as f64;
            Some(Duration::from_secs_f64(avg_ms / 1000.0))
        }
    }

    /// Standard deviation of RTT, like ping's `mdev`.
    pub fn mdev(&self) -> Option<Duration> {
        if self.received == 0 {
            return None;
        }
        let n = self.received as f64;
        let mean = self.rtt_sum_ms / n;
        let var = (self.rtt_sum_sq_ms / n - mean * mean).max(0.0);
        Some(Duration::from_secs_f64(var.sqrt() / 1000.0))
    }

    /// Snapshot of the pulse ring buffer, oldest first (at most 40 entries).
    pub fn pulse(&self) -> Vec<PulseEntry> {
        self.pulse.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdev_constant_rtt_is_zero() {
        let mut s = ProbeStats::new();
        for _ in 0..5 {
            s.record_reply(Duration::from_millis(20));
        }
        let mdev = s.mdev().unwrap();
        assert!(mdev.as_secs_f64() < 1e-9, "mdev should be ~0, got {mdev:?}");
    }

    #[test]
    fn test_mdev_known_values() {
        let mut s = ProbeStats::new();
        // 10 ms and 30 ms → mean 20, stddev 10
        s.record_reply(Duration::from_millis(10));
        s.record_reply(Duration::from_millis(30));
        let mdev_ms = s.mdev().unwrap().as_secs_f64() * 1000.0;
        assert!(
            (mdev_ms - 10.0).abs() < 0.01,
            "expected ~10 ms, got {mdev_ms}"
        );
    }

    #[test]
    fn test_mdev_none_without_replies() {
        let mut s = ProbeStats::new();
        s.record_timeout();
        assert!(s.mdev().is_none());
    }
}
