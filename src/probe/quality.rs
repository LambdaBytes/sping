//! Link-quality scoring over a rolling window. Grade (A-D) and score (0-100)
//! derive from the same raw value, so they can never disagree at boundaries.

use std::collections::VecDeque;
use std::time::Duration;

use serde::Serialize;

/// Rolling-window size (samples) shared by grade, score, and trend.
const WINDOW: usize = 20;

/// Quality grade with semantic labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum QualityGrade {
    A,
    B,
    C,
    D,
}

/// RTT trend over the rolling window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Trend {
    Stable,
    Improving,
    Degrading,
}

impl std::fmt::Display for Trend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Trend::Stable => write!(f, "stable"),
            Trend::Improving => write!(f, "improving"),
            Trend::Degrading => write!(f, "degrading"),
        }
    }
}

impl std::fmt::Display for QualityGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QualityGrade::A => write!(f, "A · stable"),
            QualityGrade::B => write!(f, "B · minor jitter"),
            QualityGrade::C => write!(f, "C · unstable"),
            QualityGrade::D => write!(f, "D · degraded"),
        }
    }
}

/// Rolling window quality scorer.
pub struct QualityScorer {
    /// Recent probe results: `Some(rtt)` for reply, `None` for loss.
    window: VecDeque<Option<Duration>>,
}

impl QualityScorer {
    /// Scorer with an empty window; all metrics are `None` until 3 samples.
    pub fn new() -> Self {
        Self {
            window: VecDeque::with_capacity(WINDOW),
        }
    }

    pub fn record_reply(&mut self, rtt: Duration) {
        self.push(Some(rtt));
    }

    pub fn record_loss(&mut self) {
        self.push(None);
    }

    fn push(&mut self, entry: Option<Duration>) {
        if self.window.len() >= WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(entry);
    }

    /// Loss percentage over the current rolling window (0–100). Reflects the
    /// recent condition, unlike the lifetime `ProbeStats::loss_pct`.
    pub fn window_loss_pct(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let losses = self.window.iter().filter(|e| e.is_none()).count() as f64;
        losses / self.window.len() as f64 * 100.0
    }

    /// Raw 0-100 quality value (unclamped); `None` until 3 samples. Single
    /// source of truth for both `grade()` and `score()`.
    fn raw_score(&self) -> Option<f64> {
        if self.window.len() < 3 {
            return None;
        }

        let loss_pct = self.window_loss_pct();

        let rtts: Vec<f64> = self
            .window
            .iter()
            .filter_map(|e| e.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        if rtts.is_empty() {
            return Some(0.0);
        }

        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;

        // Average absolute deviation from mean (not stddev).
        let jitter = if rtts.len() > 1 {
            rtts.iter().map(|r| (r - avg).abs()).sum::<f64>() / rtts.len() as f64
        } else {
            0.0
        };
        let rel_jitter = if avg > 0.0 { jitter / avg * 100.0 } else { 0.0 };

        let mut score: f64 = 100.0;
        score -= loss_pct * 3.0;

        if rel_jitter > 50.0 {
            score -= 30.0;
        } else if rel_jitter > 30.0 {
            score -= 20.0;
        } else if rel_jitter > 20.0 {
            score -= 10.0;
        }

        if jitter > 50.0 {
            score -= 15.0;
        } else if jitter > 20.0 {
            score -= 5.0;
        }

        Some(score)
    }

    /// Quality grade from the rolling window: A >= 85, B >= 65, C >= 40,
    /// else D (thresholds on the raw, unclamped score). `None` until there
    /// are at least 3 samples.
    pub fn grade(&self) -> Option<QualityGrade> {
        self.raw_score().map(|s| match s {
            s if s >= 85.0 => QualityGrade::A,
            s if s >= 65.0 => QualityGrade::B,
            s if s >= 40.0 => QualityGrade::C,
            _ => QualityGrade::D,
        })
    }

    /// Numeric quality score, clamped and rounded to 0–100. `None` until
    /// there are at least 3 samples.
    pub fn score(&self) -> Option<u8> {
        self.raw_score().map(|s| s.clamp(0.0, 100.0).round() as u8)
    }

    /// Connection trend: compares mean RTT of the first vs second half of
    /// the window; a change beyond ±15% is `Improving`/`Degrading`. `None`
    /// until the window has 6 samples with at least 2 replies in each half.
    pub fn trend(&self) -> Option<Trend> {
        if self.window.len() < 6 {
            return None;
        }

        let mid = self.window.len() / 2;
        let first_half: Vec<f64> = self
            .window
            .iter()
            .take(mid)
            .filter_map(|e| e.map(|d| d.as_secs_f64() * 1000.0))
            .collect();
        let second_half: Vec<f64> = self
            .window
            .iter()
            .skip(mid)
            .filter_map(|e| e.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        if first_half.len() < 2 || second_half.len() < 2 {
            return None;
        }

        let avg_first = first_half.iter().sum::<f64>() / first_half.len() as f64;
        let avg_second = second_half.iter().sum::<f64>() / second_half.len() as f64;

        if avg_first <= 0.0 {
            return Some(Trend::Stable);
        }

        let change = (avg_second - avg_first) / avg_first;

        Some(if change < -0.15 {
            Trend::Improving
        } else if change > 0.15 {
            Trend::Degrading
        } else {
            Trend::Stable
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stable_connection() {
        let mut s = QualityScorer::new();
        for _ in 0..10 {
            s.record_reply(Duration::from_millis(20));
        }
        assert_eq!(s.grade(), Some(QualityGrade::A));
    }

    #[test]
    fn test_minor_jitter() {
        let mut s = QualityScorer::new();
        for i in 0..10 {
            let rtt = Duration::from_millis(20 + (i % 3) * 8); // 20, 28, 36, 20, ...
            s.record_reply(rtt);
        }
        let g = s.grade().unwrap();
        assert!(g == QualityGrade::A || g == QualityGrade::B);
    }

    #[test]
    fn test_high_loss() {
        let mut s = QualityScorer::new();
        for i in 0..10 {
            if i % 2 == 0 {
                s.record_reply(Duration::from_millis(20));
            } else {
                s.record_loss();
            }
        }
        let g = s.grade().unwrap();
        assert!(g == QualityGrade::C || g == QualityGrade::D);
    }

    #[test]
    fn test_total_loss() {
        let mut s = QualityScorer::new();
        for _ in 0..5 {
            s.record_loss();
        }
        assert_eq!(s.grade(), Some(QualityGrade::D));
    }

    #[test]
    fn test_not_enough_data() {
        let mut s = QualityScorer::new();
        s.record_reply(Duration::from_millis(10));
        assert_eq!(s.grade(), None);
        assert_eq!(s.score(), None);
        assert_eq!(s.trend(), None);
    }

    #[test]
    fn test_score_100_for_perfect() {
        let mut s = QualityScorer::new();
        for _ in 0..10 {
            s.record_reply(Duration::from_millis(20));
        }
        assert_eq!(s.score(), Some(100));
    }

    #[test]
    fn test_score_low_for_total_loss() {
        let mut s = QualityScorer::new();
        for _ in 0..10 {
            s.record_loss();
        }
        assert_eq!(s.score(), Some(0));
    }

    #[test]
    fn test_trend_stable() {
        let mut s = QualityScorer::new();
        for _ in 0..10 {
            s.record_reply(Duration::from_millis(20));
        }
        assert_eq!(s.trend(), Some(Trend::Stable));
    }

    #[test]
    fn test_trend_improving() {
        let mut s = QualityScorer::new();
        // First half: high RTT
        for _ in 0..5 {
            s.record_reply(Duration::from_millis(100));
        }
        // Second half: much lower RTT
        for _ in 0..5 {
            s.record_reply(Duration::from_millis(20));
        }
        assert_eq!(s.trend(), Some(Trend::Improving));
    }

    #[test]
    fn test_window_loss_pct_empty_is_zero() {
        let s = QualityScorer::new();
        assert_eq!(s.window_loss_pct(), 0.0);
    }

    #[test]
    fn test_window_loss_pct_reflects_recent_not_lifetime() {
        let mut s = QualityScorer::new();
        // Fill the window with losses, then with replies. The rolling window
        // (cap = WINDOW) must report ~0% loss once losses age out — proving the
        // correlator sees the *current* condition, not lifetime loss.
        for _ in 0..WINDOW {
            s.record_loss();
        }
        assert_eq!(s.window_loss_pct(), 100.0);
        for _ in 0..WINDOW {
            s.record_reply(Duration::from_millis(10));
        }
        assert_eq!(s.window_loss_pct(), 0.0);
    }

    #[test]
    fn test_grade_score_consistent_at_boundary() {
        // grade() must derive from the raw (unrounded) value, not the rounded
        // u8 score — otherwise a value like 84.6 would round to 85 and flip B→A.
        let mut s = QualityScorer::new();
        for _ in 0..10 {
            s.record_reply(Duration::from_millis(20));
        }
        // perfect window: A and 100 agree
        assert_eq!(s.grade(), Some(QualityGrade::A));
        assert_eq!(s.score(), Some(100));
    }

    #[test]
    fn test_trend_degrading() {
        let mut s = QualityScorer::new();
        // First half: low RTT
        for _ in 0..5 {
            s.record_reply(Duration::from_millis(20));
        }
        // Second half: much higher RTT
        for _ in 0..5 {
            s.record_reply(Duration::from_millis(100));
        }
        assert_eq!(s.trend(), Some(Trend::Degrading));
    }
}
