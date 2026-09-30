//! Outage timing: starts on the first failure, ends on the next reply.
//! Recovery is a one-shot event carrying the ended outage's duration.

use std::time::{Duration, Instant};

pub struct OutageTracker {
    outage_start: Option<Instant>,
    last_outage_duration: Option<Duration>,
    recovered: bool,
}

impl OutageTracker {
    /// No outage in progress.
    pub fn new() -> Self {
        Self {
            outage_start: None,
            last_outage_duration: None,
            recovered: false,
        }
    }

    /// Ends any ongoing outage, capturing its duration and arming the
    /// one-shot recovery event.
    pub fn record_reply(&mut self) {
        if let Some(start) = self.outage_start.take() {
            self.last_outage_duration = Some(start.elapsed());
            self.recovered = true;
        }
    }

    /// Starts the outage clock on the first failure; later failures leave
    /// the start time unchanged.
    pub fn record_failure(&mut self) {
        self.recovered = false;
        if self.outage_start.is_none() {
            self.outage_start = Some(Instant::now());
        }
    }

    /// Current outage duration, or `None` if not in outage.
    pub fn current_outage(&self) -> Option<Duration> {
        self.outage_start.map(|s| s.elapsed())
    }

    /// Duration of the just-ended outage; one-shot, cleared on read.
    pub fn take_recovery(&mut self) -> Option<Duration> {
        if self.recovered {
            self.recovered = false;
            self.last_outage_duration.take()
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn in_outage(&self) -> bool {
        self.outage_start.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_outage_initially() {
        let t = OutageTracker::new();
        assert!(!t.in_outage());
        assert!(t.current_outage().is_none());
    }

    #[test]
    fn test_outage_starts_on_failure() {
        let mut t = OutageTracker::new();
        t.record_failure();
        assert!(t.in_outage());
        assert!(t.current_outage().is_some());
    }

    #[test]
    fn test_recovery() {
        let mut t = OutageTracker::new();
        t.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        t.record_reply();
        assert!(!t.in_outage());
        let dur = t.take_recovery().unwrap();
        assert!(dur >= Duration::from_millis(10));
    }

    #[test]
    fn test_recovery_consumed_once() {
        let mut t = OutageTracker::new();
        t.record_failure();
        t.record_reply();
        assert!(t.take_recovery().is_some());
        assert!(t.take_recovery().is_none());
    }
}
