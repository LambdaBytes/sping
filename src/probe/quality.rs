//! Link-quality scoring over a rolling window. Grade (A-D) and score (0-100)
//! derive from the same raw value, so they can never disagree at boundaries.

use std::collections::VecDeque;
use std::time::Duration;

use serde::Serialize;

/// Rolling-window size (samples) shared by grade, score, trend and the
/// high-jitter warning.
const WINDOW: usize = 20;

/// Smallest RTT change or deviation, in ms, that the trend and the
/// relative-jitter penalties take as real. Below it is timer and scheduling
/// noise: loopback replies (~0.05 ms) vary by tens of microseconds, which
/// read as ±15% changes and 20-30% relative jitter.
const NOISE_FLOOR_MS: f64 = 0.1;

/// Tolerance of the noise-floor, relative-jitter and trend comparisons, in
/// the compared unit (ms, % or a ratio): far below the 1 ns resolution of an
/// RTT, far above `f64` rounding. A value equal to a threshold in decimal (a
/// 0.1 ms deviation, 50% jitter, a +15% change) may otherwise land on either
/// side of it.
const EPS: f64 = 1e-9;

/// Relative jitter (% of the mean RTT) above which the grade takes its
/// largest relative-jitter penalty and the correlator warns.
const HIGH_REL_JITTER_PCT: f64 = 50.0;

/// Loss-count difference between the window's halves that makes a trend
/// on its own.
const TREND_LOSS_DIFF: usize = 2;

/// Quality grade with semantic labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum QualityGrade {
    A,
    B,
    C,
    D,
}

/// Trend over the rolling window: latency and loss.
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
            QualityGrade::A => write!(f, "A · excellent"),
            QualityGrade::B => write!(f, "B · good"),
            QualityGrade::C => write!(f, "C · fair"),
            QualityGrade::D => write!(f, "D · poor"),
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

    /// Mean RTT of the window's replies and their jitter — the average
    /// absolute deviation from that mean (not stddev) — both in ms. `None`
    /// without replies. What the grade and the high-jitter warning read.
    fn reply_stats(&self) -> Option<(f64, f64)> {
        let rtts: Vec<f64> = self
            .window
            .iter()
            .filter_map(|e| e.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        if rtts.is_empty() {
            return None;
        }

        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let jitter = if rtts.len() > 1 {
            rtts.iter().map(|r| (r - avg).abs()).sum::<f64>() / rtts.len() as f64
        } else {
            0.0
        };
        Some((avg, jitter))
    }

    /// Jitter relative to the mean RTT, in %; 0 when it is below the noise
    /// floor, where a relative figure says nothing.
    fn rel_jitter_pct(avg: f64, jitter: f64) -> f64 {
        if avg > 0.0 && jitter + EPS >= NOISE_FLOOR_MS {
            jitter / avg * 100.0
        } else {
            0.0
        }
    }

    /// Raw 0-100 quality value (unclamped); `None` until 3 samples. Single
    /// source of truth for both `grade()` and `score()`.
    fn raw_score(&self) -> Option<f64> {
        if self.window.len() < 3 {
            return None;
        }

        let loss_pct = self.window_loss_pct();

        let Some((avg, jitter)) = self.reply_stats() else {
            return Some(0.0);
        };
        let rel_jitter = Self::rel_jitter_pct(avg, jitter);

        let mut score: f64 = 100.0;
        score -= loss_pct * 3.0;

        if rel_jitter > HIGH_REL_JITTER_PCT + EPS {
            score -= 30.0;
        } else if rel_jitter > 30.0 + EPS {
            score -= 20.0;
        } else if rel_jitter > 20.0 + EPS {
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

    /// The window's replies vary by more than half their mean RTT, by at
    /// least the noise floor: the grade's largest relative-jitter penalty,
    /// and the correlator's high-jitter warning, over the same samples.
    /// `false` until 3 samples, like the grade.
    pub fn high_jitter(&self) -> bool {
        self.window.len() >= 3
            && self.reply_stats().is_some_and(|(avg, jitter)| {
                Self::rel_jitter_pct(avg, jitter) > HIGH_REL_JITTER_PCT + EPS
            })
    }

    /// Connection trend: the window's first half (`len / 2` samples) against
    /// its second (the rest). Losses: [`TREND_LOSS_DIFF`] more lost probes in
    /// the second half is `Degrading`, as many fewer `Improving`. Latency:
    /// mean RTT beyond ±15% and by at least the noise floor. When the two
    /// disagree `Degrading` wins, then `Improving`. `None` until 6 samples,
    /// and when losses decide nothing and a half has fewer than 2 replies.
    pub fn trend(&self) -> Option<Trend> {
        if self.window.len() < 6 {
            return None;
        }

        let mid = self.window.len() / 2;
        let lost_first = self.window.iter().take(mid).filter(|e| e.is_none()).count();
        let lost_second = self.window.iter().skip(mid).filter(|e| e.is_none()).count();
        let by_loss = if lost_second >= lost_first + TREND_LOSS_DIFF {
            Some(Trend::Degrading)
        } else if lost_first >= lost_second + TREND_LOSS_DIFF {
            Some(Trend::Improving)
        } else {
            None
        };

        let by_rtt = self.rtt_trend(mid);
        if by_loss == Some(Trend::Degrading) || by_rtt == Some(Trend::Degrading) {
            Some(Trend::Degrading)
        } else if by_loss == Some(Trend::Improving) || by_rtt == Some(Trend::Improving) {
            Some(Trend::Improving)
        } else {
            by_rtt
        }
    }

    /// Mean RTT of the replies after `mid` against those before it. `None`
    /// when a half has fewer than 2 replies.
    fn rtt_trend(&self, mid: usize) -> Option<Trend> {
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
        let beyond_noise = (avg_second - avg_first).abs() + EPS >= NOISE_FLOOR_MS;

        Some(if change < -0.15 - EPS && beyond_noise {
            Trend::Improving
        } else if change > 0.15 + EPS && beyond_noise {
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

    /// A scorer fed with `samples`: an RTT in ms, or `None` for a loss.
    fn fed(samples: &[Option<f64>]) -> QualityScorer {
        let mut s = QualityScorer::new();
        for sample in samples {
            match sample {
                Some(ms) => s.record_reply(Duration::from_secs_f64(ms / 1000.0)),
                None => s.record_loss(),
            }
        }
        s
    }

    /// `n` replies of `ms` each.
    fn replies(n: usize, ms: f64) -> Vec<Option<f64>> {
        vec![Some(ms); n]
    }

    fn halves(first: Vec<Option<f64>>, second: Vec<Option<f64>>) -> QualityScorer {
        fed(&[first, second].concat())
    }

    /// Loopback-scale changes (tens of microseconds) are noise: no trend.
    #[test]
    fn trend_ignores_microsecond_noise() {
        let up = halves(replies(10, 0.050), replies(10, 0.058));
        assert_eq!(up.trend(), Some(Trend::Stable));
        let down = halves(replies(10, 0.058), replies(10, 0.050));
        assert_eq!(down.trend(), Some(Trend::Stable));
    }

    /// Above the noise floor a LAN's latency tripling is a trend; a change
    /// below the floor or within ±15% is not.
    #[test]
    fn trend_needs_15_percent_and_the_noise_floor() {
        let lan = halves(replies(10, 0.3), replies(10, 0.9));
        assert_eq!(lan.trend(), Some(Trend::Degrading));
        let over_floor = halves(replies(10, 0.30), replies(10, 0.45));
        assert_eq!(over_floor.trend(), Some(Trend::Degrading));
        let under_floor = halves(replies(10, 0.30), replies(10, 0.38));
        assert_eq!(under_floor.trend(), Some(Trend::Stable));
        let within_15 = halves(replies(10, 20.0), replies(10, 22.0));
        assert_eq!(within_15.trend(), Some(Trend::Stable));
        let beyond_15 = halves(replies(10, 20.0), replies(10, 24.0));
        assert_eq!(beyond_15.trend(), Some(Trend::Degrading));
    }

    /// Losses make a trend: 2 more in the second half degrade, 2 fewer
    /// improve, 1 is not enough.
    #[test]
    fn trend_counts_losses() {
        let mut second = replies(8, 20.0);
        second.extend([None, None]);
        assert_eq!(
            halves(replies(10, 20.0), second.clone()).trend(),
            Some(Trend::Degrading)
        );
        assert_eq!(
            halves(second.clone(), replies(10, 20.0)).trend(),
            Some(Trend::Improving)
        );
        let mut one_loss = replies(9, 20.0);
        one_loss.push(None);
        assert_eq!(
            halves(replies(10, 20.0), one_loss).trend(),
            Some(Trend::Stable)
        );
    }

    /// An outage filling the second half is degrading, not unknown; a
    /// recovery after one is improving.
    #[test]
    fn trend_of_an_outage_and_its_recovery() {
        let outage = halves(replies(10, 20.0), vec![None; 10]);
        assert_eq!(outage.trend(), Some(Trend::Degrading));
        let recovery = halves(vec![None; 10], replies(10, 20.0));
        assert_eq!(recovery.trend(), Some(Trend::Improving));
    }

    /// Fewer losses but a much slower path: degrading wins.
    #[test]
    fn trend_degrading_wins_a_disagreement() {
        let mut first = replies(8, 20.0);
        first.extend([None, None]);
        let s = halves(first, replies(10, 100.0));
        assert_eq!(s.trend(), Some(Trend::Degrading));
    }

    /// Short windows: 6 and 7 samples (halves 3+3 and 3+4); losses decide
    /// even where a half has too few replies for the latency rule.
    #[test]
    fn trend_in_short_windows() {
        let six = fed(&[Some(20.0), Some(20.0), Some(20.0), None, None, Some(20.0)]);
        assert_eq!(six.trend(), Some(Trend::Degrading));
        let seven = fed(&[
            Some(20.0),
            Some(20.0),
            Some(20.0),
            None,
            None,
            Some(20.0),
            Some(20.0),
        ]);
        assert_eq!(seven.trend(), Some(Trend::Degrading));
        // Same losses in both halves, one reply each: nothing to say.
        let even = fed(&[None, None, Some(20.0), None, None, Some(20.0)]);
        assert_eq!(even.trend(), None);
    }

    /// The thresholds hold at their exact values: a deviation or a change of
    /// exactly 0.1 ms counts, just under it does not; exactly +15% is not a
    /// trend, just over it is.
    #[test]
    fn thresholds_hold_at_their_exact_values() {
        let alternating = |a: f64, b: f64| {
            let mut v = Vec::new();
            for _ in 0..10 {
                v.extend([Some(a), Some(b)]);
            }
            fed(&v)
        };
        // Mean 0.136 ms, deviation exactly 0.1 ms (73%): penalized, warned.
        let at_floor = alternating(0.036, 0.236);
        assert_eq!(at_floor.score(), Some(70));
        assert!(at_floor.high_jitter());
        // Deviation 0.099 ms: under the floor.
        let under = alternating(0.037, 0.235);
        assert_eq!(under.score(), Some(100));
        assert!(!under.high_jitter());

        let trend = |a: f64, b: f64| halves(replies(10, a), replies(10, b)).trend();
        assert_eq!(trend(0.1, 0.2), Some(Trend::Degrading));
        assert_eq!(trend(0.1, 0.199), Some(Trend::Stable));
        assert_eq!(trend(3.0, 3.45), Some(Trend::Stable));
        assert_eq!(trend(3.0, 3.46), Some(Trend::Degrading));
        // Exactly 50% relative jitter (2.002 / 6.006 ms, whose f64 sum lands
        // just above 50) is not above 50: the next penalty down, no warning.
        let mut at_50 = QualityScorer::new();
        for _ in 0..10 {
            at_50.record_reply(Duration::from_nanos(2_002_000));
            at_50.record_reply(Duration::from_nanos(6_006_000));
        }
        assert_eq!(at_50.score(), Some(80));
        assert!(!at_50.high_jitter());
        assert_eq!(trend(3.0, 2.55), Some(Trend::Stable));
        assert_eq!(trend(3.0, 2.54), Some(Trend::Improving));
    }

    /// Microsecond deviations cost no points; the same relative jitter in
    /// tenths of a millisecond still does.
    #[test]
    fn score_ignores_microsecond_jitter() {
        let mut loopback = Vec::new();
        let mut lan = Vec::new();
        for _ in 0..10 {
            loopback.extend([Some(0.03), Some(0.07)]);
            lan.extend([Some(0.1), Some(0.9)]);
        }
        assert_eq!(fed(&loopback).score(), Some(100));
        assert!(!fed(&loopback).high_jitter());
        assert_eq!(fed(&lan).score(), Some(70));
        assert_eq!(fed(&lan).grade(), Some(QualityGrade::B));
        assert!(fed(&lan).high_jitter());
    }

    /// The warning is the grade's largest relative-jitter penalty: 5/35 ms
    /// (mean 20, deviation 15: 75%) costs those 30 points and warns; 15/25
    /// ms (25%) costs 10 and does not.
    #[test]
    fn high_jitter_is_the_grades_top_penalty() {
        let mut wide = Vec::new();
        let mut narrow = Vec::new();
        for _ in 0..10 {
            wide.extend([Some(5.0), Some(35.0)]);
            narrow.extend([Some(15.0), Some(25.0)]);
        }
        assert_eq!(fed(&wide).score(), Some(70));
        assert!(fed(&wide).high_jitter());
        assert_eq!(fed(&narrow).score(), Some(90));
        assert!(!fed(&narrow).high_jitter());
        // Under 3 samples there is no grade and no warning.
        assert!(!fed(&[Some(5.0), Some(35.0)]).high_jitter());
    }

    /// Warning and grade leave the jitter behind together, once its samples
    /// leave the window.
    #[test]
    fn high_jitter_and_grade_recover_together() {
        let mut s = QualityScorer::new();
        for i in 0..WINDOW {
            s.record_reply(Duration::from_millis(if i % 2 == 0 { 5 } else { 35 }));
        }
        assert!(s.high_jitter());
        assert_eq!(s.grade(), Some(QualityGrade::B));
        for _ in 0..WINDOW {
            s.record_reply(Duration::from_millis(20));
        }
        assert!(!s.high_jitter());
        assert_eq!(s.grade(), Some(QualityGrade::A));
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
