//! Pulse strip rendering: RTT samples mapped to 8-level block glyphs scaled
//! between the p5 and p95 percentiles, plus RTT distribution and echo-path.

use std::io::Write;

use crossterm::queue;
use crossterm::style::{Color, ResetColor, SetForegroundColor};

use crate::probe::types::PulseEntry;
use crate::render::icons;

/// Unified display width for Pulse, Path, and Histogram (in chars).
pub const DISPLAY_WIDTH: usize = 40;

// Block/loss glyphs come from render::icons so Unicode and ASCII
// environments render the same layout.

/// A sample counts as a spike when its RTT exceeds `median * SPIKE_MULTIPLIER`
/// and `median + 5 ms` (the absolute floor avoids flagging sub-ms noise).
const SPIKE_MULTIPLIER: f64 = 2.0;

/// Pulse renderer using 8-level block characters, one char per sample.
pub struct PulseScaler;

impl PulseScaler {
    /// Render the pulse strip with color: spikes in yellow, loss in red,
    /// padded to `DISPLAY_WIDTH` characters.
    pub fn render_wave(w: &mut impl Write, pulse: &[PulseEntry]) -> std::io::Result<()> {
        if pulse.is_empty() {
            write!(w, "{}", icons::dash())?;
            return Ok(());
        }

        let (levels, is_spike, has_reply) = compute_levels(pulse);
        if !has_reply {
            for e in pulse.iter().take(DISPLAY_WIDTH) {
                match e {
                    PulseEntry::Loss => {
                        queue!(w, SetForegroundColor(Color::Red))?;
                        write!(w, "{}", icons::loss_char())?;
                        queue!(w, ResetColor)?;
                    }
                    _ => write!(w, " ")?,
                }
            }
            return Ok(());
        }

        let mut chars_written = 0;
        for (i, entry) in pulse.iter().enumerate() {
            if chars_written >= DISPLAY_WIDTH {
                break;
            }
            match entry {
                PulseEntry::Reply(_) => {
                    if let Some(level) = levels[i] {
                        let ch = icons::blocks()[level.min(7)];
                        if is_spike[i] {
                            queue!(w, SetForegroundColor(Color::DarkYellow))?;
                            write!(w, "{ch}")?;
                            queue!(w, ResetColor)?;
                        } else {
                            write!(w, "{ch}")?;
                        }
                    } else {
                        write!(w, "{}", icons::blocks()[0])?;
                    }
                }
                PulseEntry::Loss => {
                    queue!(w, SetForegroundColor(Color::Red))?;
                    write!(w, "{}", icons::loss_char())?;
                    queue!(w, ResetColor)?;
                }
                PulseEntry::Empty => write!(w, " ")?,
            }
            chars_written += 1;
        }

        while chars_written < DISPLAY_WIDTH {
            write!(w, " ")?;
            chars_written += 1;
        }

        Ok(())
    }

    /// Plain-text fallback (no color), padded to `DISPLAY_WIDTH` characters.
    pub fn render(pulse: &[PulseEntry]) -> String {
        if pulse.is_empty() {
            return icons::dash().into();
        }

        let (levels, _, has_reply) = compute_levels(pulse);
        if !has_reply {
            let mut out: String = pulse
                .iter()
                .take(DISPLAY_WIDTH)
                .map(|e| match e {
                    PulseEntry::Loss => icons::loss_char(),
                    _ => ' ',
                })
                .collect();
            while out.chars().count() < DISPLAY_WIDTH {
                out.push(' ');
            }
            return out;
        }

        let mut out = String::new();
        for (i, entry) in pulse.iter().enumerate() {
            if out.chars().count() >= DISPLAY_WIDTH {
                break;
            }
            match entry {
                PulseEntry::Reply(_) => {
                    let level = levels[i].unwrap_or(0);
                    out.push(icons::blocks()[level.min(7)]);
                }
                PulseEntry::Loss => out.push(icons::loss_char()),
                PulseEntry::Empty => out.push(' '),
            }
        }
        while out.chars().count() < DISPLAY_WIDTH {
            out.push(' ');
        }
        out
    }
}

/// Compute levels (0–7) for each sample and spike flags.
fn compute_levels(pulse: &[PulseEntry]) -> (Vec<Option<usize>>, Vec<bool>, bool) {
    let rtts_ms: Vec<Option<f64>> = pulse
        .iter()
        .map(|e| match e {
            PulseEntry::Reply(d) => Some(d.as_secs_f64() * 1000.0),
            _ => None,
        })
        .collect();

    let valid: Vec<f64> = rtts_ms.iter().filter_map(|r| *r).collect();
    if valid.is_empty() {
        return (vec![None; pulse.len()], vec![false; pulse.len()], false);
    }

    let mut sorted = valid.clone();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let p5 = percentile(&sorted, 5.0);
    let p95 = percentile(&sorted, 95.0);
    let range = (p95 - p5).max(0.01);
    let median = percentile(&sorted, 50.0);

    let levels: Vec<Option<usize>> = rtts_ms
        .iter()
        .map(|r| {
            r.map(|ms| {
                let clamped = ms.clamp(p5, p95);
                let ratio = (clamped - p5) / range;
                (ratio * 7.0).round() as usize
            })
        })
        .collect();

    let is_spike: Vec<bool> = rtts_ms
        .iter()
        .map(|r| match r {
            Some(ms) => *ms > median * SPIKE_MULTIPLIER && *ms > median + 5.0,
            None => false,
        })
        .collect();

    (levels, is_spike, true)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let k = (p / 100.0) * (sorted.len() - 1) as f64;
    let floor = k.floor() as usize;
    let ceil = k.ceil() as usize;
    if floor == ceil {
        sorted[floor]
    } else {
        let frac = k - floor as f64;
        sorted[floor] * (1.0 - frac) + sorted[ceil] * frac
    }
}

/// RTT distribution summary over the pulse window, in milliseconds.
pub struct RttDist {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    /// Spread between the 95th and 5th percentiles.
    pub spread: f64,
    /// Number of samples classified as spikes.
    pub spikes: usize,
}

/// RTT distribution over the pulse samples; `None` with fewer than 3 replies.
pub fn compute_rtt_dist(pulse: &[PulseEntry]) -> Option<RttDist> {
    let mut rtts: Vec<f64> = pulse
        .iter()
        .filter_map(|e| match e {
            PulseEntry::Reply(d) => Some(d.as_secs_f64() * 1000.0),
            _ => None,
        })
        .collect();

    if rtts.len() < 3 {
        return None;
    }

    rtts.sort_by(|a, b| a.total_cmp(b));

    let p5 = percentile(&rtts, 5.0);
    let p50 = percentile(&rtts, 50.0);
    let p95 = percentile(&rtts, 95.0);
    let p99 = percentile(&rtts, 99.0);
    let median = p50;

    let spikes = rtts
        .iter()
        .filter(|&&ms| ms > median * SPIKE_MULTIPLIER && ms > median + 5.0)
        .count();

    Some(RttDist {
        p50,
        p95,
        p99,
        spread: p95 - p5,
        spikes,
    })
}

/// Render the echo-path animation: a probe glyph bounces between origin and
/// target across `DISPLAY_WIDTH` columns, driven by `frame`. The probe parks
/// at the target while no reply is coming in (`rtt_now` is `None`).
pub fn render_echo_path(
    w: &mut impl Write,
    _target: &str,
    rtt_now: Option<f64>,
    _rtt_avg: f64,
    frame: usize,
) -> std::io::Result<()> {
    let path_len = DISPLAY_WIDTH;
    let target_pos = path_len - 1;
    let cycle_len = target_pos * 2;

    let pos = if rtt_now.is_some() {
        let phase = frame % cycle_len;
        if phase < target_pos {
            phase
        } else {
            cycle_len - phase
        }
    } else {
        target_pos
    };

    let (path_ch, probe_ch, target_ch, hit_ch) = icons::path_glyphs();
    for i in 0..path_len {
        if i == pos && i == target_pos {
            write!(w, "{hit_ch}")?;
        } else if i == pos {
            write!(w, "{probe_ch}")?;
        } else if i == target_pos {
            write!(w, "{target_ch}")?;
        } else {
            write!(w, "{path_ch}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_block_pulse_stable() {
        let pulse: Vec<PulseEntry> = (0..8)
            .map(|_| PulseEntry::Reply(Duration::from_millis(20)))
            .collect();
        let rendered = PulseScaler::render(&pulse);
        assert!(!rendered.is_empty());
        assert!(!rendered.contains('✕'));
    }

    #[test]
    fn test_block_pulse_with_loss() {
        let mut pulse = Vec::new();
        for _ in 0..4 {
            pulse.push(PulseEntry::Reply(Duration::from_millis(20)));
        }
        pulse.push(PulseEntry::Loss);
        let rendered = PulseScaler::render(&pulse);
        assert!(rendered.contains('✕'));
    }

    #[test]
    fn test_render_padded_to_width() {
        let pulse: Vec<PulseEntry> = vec![
            PulseEntry::Reply(Duration::from_millis(10)),
            PulseEntry::Reply(Duration::from_millis(20)),
        ];
        let rendered = PulseScaler::render(&pulse);
        assert_eq!(rendered.chars().count(), DISPLAY_WIDTH);
    }

    #[test]
    fn test_path_animation_cycle() {
        let mut buf = Vec::new();
        render_echo_path(&mut buf, "test", Some(10.0), 10.0, 0).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("●") || s.contains("◉"));
        assert_eq!(s.chars().count(), DISPLAY_WIDTH);
    }

    #[test]
    fn test_percentile_basic() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert!((percentile(&data, 50.0) - 5.5).abs() < 0.01);
    }
}
