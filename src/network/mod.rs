// src/network/mod.rs
//! Network module for the AeroNyx Privacy Network Server.
//!
//! This module provides networking functionality for managing TUN devices,
//! IP pools, packet routing, and network monitoring.

pub mod ip_pool;
pub mod tun;
pub mod monitor;

// Re-export commonly used items
// Removed IpAllocation, NetworkStats if not used outside this module
pub use ip_pool::IpPoolManager;
pub use tun::{setup_tun_device, configure_nat};
pub use monitor::NetworkMonitor;


/// Get the first usable IP address from a subnet
pub fn get_first_ip_from_subnet(subnet: &str) -> String {
    use ipnetwork::Ipv4Network;
    use std::str::FromStr;

    match Ipv4Network::from_str(subnet) {
        Ok(network) => {
            // .nth(0) is network addr, .nth(1) is first usable host IP
            if let Some(ip) = network.nth(1) {
                return ip.to_string();
            } else {
                 // Handle case where subnet is too small (e.g., /31, /32)
                 eprintln!("Warning: Subnet {} is too small to provide a usable host IP.", subnet);
            }
        }
        Err(e) => {
             eprintln!("Error parsing subnet {}: {}", subnet, e);
        }
    }

    // Default fallback if parsing fails or subnet is too small
    "0.0.0.0".to_string()
}
