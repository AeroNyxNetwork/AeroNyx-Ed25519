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

/// Get the first usable IP address from a subnet
pub fn get_first_ip_from_subnet(subnet: &str) -> String {
    use ipnetwork::Ipv4Network;
    use std::str::FromStr;
    
    match Ipv4Network::from_str(subnet) {
        Ok(network) => {
            if let Some(ip) = network.nth(1) {
                return ip.to_string();
            }
        }
        Err(_) => {}
    }
    
    // Default fallback
    "0.0.0.0".to_string()
}
