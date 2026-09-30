//! Central event bus built on `tokio::sync::watch` channels. Each channel
//! retains only the latest value, so renderers always read current state and
//! slow consumers never apply backpressure to the probe loop.

use tokio::sync::watch;

use crate::probe::auxiliary::AuxiliaryState;
use crate::probe::types::ProbeSnapshot;

pub struct Bus {
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    probe_tx: watch::Sender<Option<ProbeSnapshot>>,
    probe_rx: watch::Receiver<Option<ProbeSnapshot>>,
    gateway_tx: watch::Sender<Option<AuxiliaryState>>,
    gateway_rx: watch::Receiver<Option<AuxiliaryState>>,
    wan_tx: watch::Sender<Option<AuxiliaryState>>,
    wan_rx: watch::Receiver<Option<AuxiliaryState>>,
}

impl Bus {
    /// Create a bus with all channels initialized to their idle state
    /// (`false` for shutdown, `None` for probe/gateway/WAN snapshots).
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (probe_tx, probe_rx) = watch::channel(None);
        let (gateway_tx, gateway_rx) = watch::channel(None);
        let (wan_tx, wan_rx) = watch::channel(None);
        Self {
            shutdown_tx,
            shutdown_rx,
            probe_tx,
            probe_rx,
            gateway_tx,
            gateway_rx,
            wan_tx,
            wan_rx,
        }
    }

    /// Sender for the shutdown flag (`true` requests termination).
    pub fn shutdown_sender(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Receiver for the shutdown flag.
    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Sender for primary-target probe snapshots.
    pub fn probe_sender(&self) -> watch::Sender<Option<ProbeSnapshot>> {
        self.probe_tx.clone()
    }

    /// Receiver for primary-target probe snapshots (`None` until the first
    /// snapshot is published).
    pub fn subscribe_probe(&self) -> watch::Receiver<Option<ProbeSnapshot>> {
        self.probe_rx.clone()
    }

    /// Sender for gateway auxiliary-probe state.
    pub fn gateway_sender(&self) -> watch::Sender<Option<AuxiliaryState>> {
        self.gateway_tx.clone()
    }

    /// Receiver for gateway auxiliary-probe state.
    pub fn subscribe_gateway(&self) -> watch::Receiver<Option<AuxiliaryState>> {
        self.gateway_rx.clone()
    }

    /// Sender for WAN auxiliary-probe state.
    pub fn wan_sender(&self) -> watch::Sender<Option<AuxiliaryState>> {
        self.wan_tx.clone()
    }

    /// Receiver for WAN auxiliary-probe state.
    pub fn subscribe_wan(&self) -> watch::Receiver<Option<AuxiliaryState>> {
        self.wan_rx.clone()
    }
}
