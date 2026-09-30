//! Default gateway detection, delegating to [`crate::context::route`].

use std::net::Ipv4Addr;

use crate::context::route;

/// Detect the default gateway IP; `None` when no IPv4 default route is found.
pub fn detect() -> Option<Ipv4Addr> {
    route::default_gateway().map(|(gw, _)| gw)
}
