//! RTT spike detection over a rolling median window. A spike must exceed the
//! median by both an absolute floor (10 ms) and a multiplier (3x) — the floor
//! avoids false positives on low-latency LAN paths. 5 s cooldown suppresses repeats.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

const WINDOW: usize = 10;
const ABS_THRESHOLD_MS: f64 = 10.0;
const SPIKE_MULTIPLIER: f64 = 3.0;
const COOLDOWN: Duration = Duration::from_secs(5);

pub struct SpikeDetector {
    window: VecDeque<f64>, // recent RTTs in ms
    last_spike_time: Option<Instant>,
    last_spike_rtt: Option<Duration>,
    spike_count: u64,
}

impl SpikeDetector {
    pub fn new() -> Self {
        Self {
            window: VecDeque::with_capacity(WINDOW),
            last_spike_time: None,
            last_spike_rtt: None,
            spike_count: 0,
        }
    }

    /// Feed a new RTT sample. Returns `true` if it is a spike. Detection
    /// requires at least 3 prior samples and is suppressed during the
    /// cooldown; the sample enters the window either way.
    pub fn record(&mut self, rtt: Duration) -> bool {
        let ms = rtt.as_secs_f64() * 1000.0;

        let is_spike = self.check_spike(ms);

        if self.window.len() >= WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(ms);

        if is_spike {
            self.last_spike_time = Some(Instant::now());
            self.last_spike_rtt = Some(rtt);
            self.spike_count += 1;
        }

        is_spike
    }

    fn check_spike(&self, ms: f64) -> bool {
        if self.window.len() < 3 {
            return false;
        }

        if let Some(last) = self.last_spike_time
            && last.elapsed() < COOLDOWN
        {
            return false;
        }

        let median = self.median();

        let above_absolute = ms > median + ABS_THRESHOLD_MS;
        let above_multiplier = ms > median * SPIKE_MULTIPLIER;

        above_absolute && above_multiplier
    }

    fn median(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.window.iter().copied().collect();
        sorted.sort_by(|a, b| a.total_cmp(b));
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        }
    }

    /// RTT of the most recently detected spike, if any.
    pub fn last_spike_rtt(&self) -> Option<Duration> {
        self.last_spike_rtt
    }

    /// Whether the spike guard (cooldown) is active.
    pub fn in_cooldown(&self) -> bool {
        self.last_spike_time.is_some_and(|t| t.elapsed() < COOLDOWN)
    }

    #[allow(dead_code)] // useful for future extended diagnostics
    pub fn spike_count(&self) -> u64 {
        self.spike_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_spike_on_stable() {
        let mut d = SpikeDetector::new();
        for _ in 0..10 {
            assert!(!d.record(Duration::from_millis(20)));
        }
    }

    #[test]
    fn test_detects_real_spike() {
        let mut d = SpikeDetector::new();
        for _ in 0..5 {
            d.record(Duration::from_millis(20));
        }
        // Big spike: 200ms vs 20ms median (10x, well above 3x)
        assert!(d.record(Duration::from_millis(200)));
    }

    #[test]
    fn test_no_false_spike_low_latency() {
        let mut d = SpikeDetector::new();
        // LAN: 1ms baseline
        for _ in 0..5 {
            d.record(Duration::from_millis(1));
        }
        // 4ms is 4x but only 3ms above — below 10ms absolute threshold
        assert!(!d.record(Duration::from_millis(4)));
    }

    #[test]
    fn test_cooldown_prevents_spam() {
        let mut d = SpikeDetector::new();
        for _ in 0..5 {
            d.record(Duration::from_millis(20));
        }
        assert!(d.record(Duration::from_millis(200)));
        // Immediately after: cooldown active
        assert!(!d.record(Duration::from_millis(200)));
        assert!(d.in_cooldown());
    }
}
