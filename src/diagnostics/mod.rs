//! Interpretation layer: correlates probe state into diagnostic events,
//! tracks outage/recovery timing, detects RTT spikes, applies hysteresis.

pub mod correlator;
pub mod health;
pub mod outage;
pub mod spikes;
