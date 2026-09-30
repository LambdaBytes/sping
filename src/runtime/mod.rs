//! Runtime plumbing: watch-channel event bus wiring the probe, diagnostics,
//! and render layers together, plus the fixed-rate frame clock for the TUI.

pub mod bus;
pub mod frame_clock;
pub mod shutdown;
