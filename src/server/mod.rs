// src/server/mod.rs
//! Server module for the AeroNyx Privacy Network Server.
//!
//! This module provides the core server functionality including client
//! session management, packet routing, and performance metrics.

pub mod core;
pub mod session;
pub mod routing;
pub mod metrics;
pub mod client;
pub mod packet;
pub mod globals;

// Re-export commonly used items
pub use core::VpnServer;
// Removed unused re-exports based on warnings
// pub use session::SessionManager;
// pub use routing::PacketRouter;
// pub use metrics::ServerMetricsCollector;
// pub use client::handle_client;
// pub use packet::write_to_tun;
// pub use globals::SERVER_TUN_DEVICE;
