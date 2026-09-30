//! Fixed-rate frame clock driving TUI redraws, decoupling render frequency
//! from the probe interval.

use std::time::Duration;

use tokio::time::{Interval, interval};

pub struct FrameClock {
    interval: Interval,
}

impl FrameClock {
    /// Create a frame clock at the given FPS (clamped to 4–30).
    pub fn new(fps: u32) -> Self {
        let fps = fps.clamp(4, 30);
        let period = Duration::from_millis(1000 / fps as u64);
        Self {
            interval: interval(period),
        }
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
