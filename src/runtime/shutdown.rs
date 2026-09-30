//! Shutdown is handled directly via `tokio::signal::ctrl_c()` in `app.rs`.
//! This module is reserved for future structured shutdown coordination
//! (e.g. SIGTERM handling, graceful drain of in-flight probes).
