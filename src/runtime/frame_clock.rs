//! Fixed-rate frame clock driving TUI redraws, decoupling render frequency
//! from the probe interval.

use std::time::Duration;

use tokio::time::{Interval, MissedTickBehavior, interval};

pub struct FrameClock {
    interval: Interval,
}

impl FrameClock {
    /// Create a frame clock at the given FPS (clamped to 4–30).
    pub fn new(fps: u32) -> Self {
        let fps = fps.clamp(4, 30);
        let period = Duration::from_millis(1000 / fps as u64);
        let mut interval = interval(period);
        // After a stall (the process stopped, a write the terminal held)
        // the frame that was due is drawn once; tokio's default draws one
        // for every tick missed, back to back.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Self { interval }
    }

    /// Wait for the next frame tick.
    pub async fn tick(&mut self) {
        self.interval.tick().await;
    }
}

impl Default for FrameClock {
    fn default() -> Self {
        Self::new(10) // 10 FPS default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Instant, advance};

    /// After a stall (the process stopped for 10 s) the frame that was due
    /// is drawn and the clock goes on at its rate: the second that follows
    /// has its ten frames and that one, not one for every tick missed.
    #[tokio::test(start_paused = true)]
    async fn a_stall_is_not_made_up_for() {
        let mut clock = FrameClock::default();
        clock.tick().await;
        advance(Duration::from_millis(10_050)).await;

        let resumed = Instant::now();
        let mut frames = 0;
        loop {
            clock.tick().await;
            if resumed.elapsed() >= Duration::from_secs(1) {
                break;
            }
            frames += 1;
        }
        assert!((10..=11).contains(&frames), "{frames} frames");
    }
}
