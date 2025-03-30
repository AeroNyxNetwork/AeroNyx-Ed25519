// src/network/mod.rs
//! Network module for the AeroNyx Privacy Network Server.
//!
//! This module provides networking functionality for managing TUN devices,
//! IP pools, and packet routing.

pub mod ip_pool;
pub mod monitor;
pub mod tun;

// Re-export commonly used items
pub use ip_pool::{IpPool, IpPoolManager, IpAllocation};
pub use monitor::{NetworkMonitor, NetworkStats};
pub use tun::{TunDevice, setup_tun_device, configure_nat};
