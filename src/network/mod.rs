// src/network/mod.rs
//! Network module for the AeroNyx Privacy Network Server.
//!
//! This module provides networking functionality for managing TUN devices,
//! IP pools, packet routing, and network monitoring.

pub mod ip_pool;
pub mod tun;
pub mod monitor;

// Re-export commonly used items
pub use ip_pool::{IpPoolManager, IpAllocation};
pub use tun::{setup_tun_device, configure_nat};
pub use monitor::{NetworkMonitor, NetworkStats};
