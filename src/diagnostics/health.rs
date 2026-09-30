//! Reachability tracking with hysteresis: N consecutive failures to go
//! `Offline`, M consecutive successes to go `Online` — prevents flicker.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Reachability {
    /// No threshold crossed yet (initial state).
    Unknown,
    Online,
    Offline,
}

impl std::fmt::Display for Reachability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reachability::Unknown => write!(f, "?"),
            Reachability::Online => write!(f, "●"),
            Reachability::Offline => write!(f, "○"),
        }
    }
}

/// Tracks reachability with hysteresis: `fail_threshold` consecutive failures
/// to go Offline, `recover_threshold` consecutive successes to go Online.
pub struct HealthTracker {
    state: Reachability,
    consecutive_ok: u32,
    consecutive_fail: u32,
    fail_threshold: u32,
    recover_threshold: u32,
}

impl HealthTracker {
    /// Starts in `Unknown`.
    pub fn new(fail_threshold: u32, recover_threshold: u32) -> Self {
        Self {
            state: Reachability::Unknown,
            consecutive_ok: 0,
            consecutive_fail: 0,
            fail_threshold,
            recover_threshold,
        }
    }

    /// Resets the failure streak; goes `Online` at `recover_threshold`.
    pub fn record_success(&mut self) {
        self.consecutive_ok += 1;
        self.consecutive_fail = 0;

        if self.consecutive_ok >= self.recover_threshold {
            self.state = Reachability::Online;
        }
    }

    /// Resets the success streak; goes `Offline` at `fail_threshold`.
    pub fn record_failure(&mut self) {
        self.consecutive_fail += 1;
        self.consecutive_ok = 0;

        if self.consecutive_fail >= self.fail_threshold {
            self.state = Reachability::Offline;
        }
    }

    pub fn state(&self) -> Reachability {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starts_unknown() {
        let h = HealthTracker::new(3, 2);
        assert_eq!(h.state(), Reachability::Unknown);
    }

    #[test]
    fn test_goes_online_after_threshold() {
        let mut h = HealthTracker::new(3, 2);
        h.record_success();
        assert_eq!(h.state(), Reachability::Unknown); // not yet
        h.record_success();
        assert_eq!(h.state(), Reachability::Online);
    }

    #[test]
    fn test_goes_offline_after_threshold() {
        let mut h = HealthTracker::new(3, 2);
        // First go online
        h.record_success();
        h.record_success();
        assert_eq!(h.state(), Reachability::Online);
        // Now fail
        h.record_failure();
        h.record_failure();
        assert_eq!(h.state(), Reachability::Online); // not yet
        h.record_failure();
        assert_eq!(h.state(), Reachability::Offline);
    }

    #[test]
    fn test_hysteresis_prevents_flicker() {
        let mut h = HealthTracker::new(3, 2);
        h.record_success();
        h.record_success();
        assert_eq!(h.state(), Reachability::Online);
        // Single failure should NOT go offline
        h.record_failure();
        assert_eq!(h.state(), Reachability::Online);
        // Recovery resets the counter
        h.record_success();
        assert_eq!(h.state(), Reachability::Online);
    }

    #[test]
    fn test_recovery_from_offline() {
        let mut h = HealthTracker::new(3, 2);
        h.record_failure();
        h.record_failure();
        h.record_failure();
        assert_eq!(h.state(), Reachability::Offline);
        h.record_success();
        assert_eq!(h.state(), Reachability::Offline); // not yet
        h.record_success();
        assert_eq!(h.state(), Reachability::Online);
    }
}
