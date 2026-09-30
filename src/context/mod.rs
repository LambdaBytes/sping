//! Network context detection. Best-effort: undetected values fall back to
//! `"unknown"`, `0.0.0.0`, or `None`.

pub mod classify;
pub mod dns;
pub mod gateway;
pub mod iface;
pub mod route;

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

use crate::context::classify::TargetClass;

/// Network context snapshot, re-detected periodically for hot interface/gateway changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkContext {
    /// `"unknown"` if detection failed.
    pub interface: String,
    /// Source IP for the target; `0.0.0.0` if detection failed.
    #[serde(serialize_with = "crate::probe::types::ser_ip")]
    pub local_ip: IpAddr,
    /// `0` when unknown.
    pub prefix_len: u8,
    /// `None` when no default route was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    pub target_class: TargetClass,
}

/// Detect full network context for a target IP.
pub fn detect(target_ip: IpAddr) -> NetworkContext {
    let local_ip = iface::detect_local_ip(target_ip).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    let iface_info = iface::interface_for_ip(local_ip);
    let interface = iface_info
        .as_ref()
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "unknown".into());
    let prefix_len = iface_info.as_ref().map(|i| i.prefix_len).unwrap_or(0);

    let gw = gateway::detect();

    let target_class = classify::classify(target_ip, local_ip, prefix_len, gw);

    NetworkContext {
        interface,
        local_ip,
        prefix_len,
        gateway: gw.map(|ip| ip.to_string()),
        target_class,
    }
}
