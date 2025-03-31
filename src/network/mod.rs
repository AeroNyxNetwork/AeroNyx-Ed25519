// src/network/mod.rs
//! Network module for the AeroNyx Privacy Network Server.
//!
//! This module provides networking functionality for managing TUN devices,
//! IP pools, packet routing, and network monitoring.

pub mod ip_pool;
pub mod tun;
pub mod monitor;

// Re-export commonly used items
// Removed unused IpAllocation import (if only manager is used externally)
pub use ip_pool::IpPoolManager;
pub use tun::{setup_tun_device, configure_nat};
// Removed unused NetworkStats import (if only monitor is used externally)
pub use monitor::NetworkMonitor;

/// Get the first usable IP address from a subnet
pub fn get_first_ip_from_subnet(subnet: &str) -> String {
    use ipnetwork::Ipv4Network;
    use std::str::FromStr;

    match Ipv4Network::from_str(subnet) {
        Ok(network) => {
            // .nth(0) is network addr, .nth(1) is typically first usable host/gateway
            if let Some(ip) = network.nth(1) {
                return ip.to_string();
            } else {
                 tracing::error!("Subnet {} is too small to provide a usable IP.", subnet);
            }
        }
        Err(e) => {
             tracing::error!("Invalid subnet format '{}': {}", subnet, e);
        }
    }

    // Default fallback
    "0.0.0.0".to_string()
}
