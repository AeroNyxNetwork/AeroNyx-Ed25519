// src/network/tun.rs
//! TUN device management.
//!
//! This module provides functionality for setting up and managing
//! TUN devices for VPN connections.

use ipnetwork::Ipv4Network;
// Removed unused Result as IoResult import
use std::process::Command;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// Removed unused TUN_MTU import if not used here
// use crate::config::constants::TUN_MTU;

/// Error type for TUN device operations
#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN device creation failed: {0}")]
    Creation(String),

    #[error("TUN device configuration failed: {0}")]
    Configuration(String),

    #[error("Invalid subnet: {0}")]
    InvalidSubnet(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Command execution failed: {0}")]
    CommandError(String),
}


/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name
    pub name: String,
    /// CIDR subnet
    pub subnet: String,
    /// Server IP address (first usable IP in subnet)
    pub server_ip: String,
    /// MTU size
    pub mtu: u16,
}

/// Configure and create a TUN device
pub fn setup_tun_device(config: &TunConfig) -> Result<tun::platform::Device, TunError> {
    info!("Setting up TUN device: {}", config.name);

    // Parse the subnet
    let network = Ipv4Network::from_str(&config.subnet)
        .map_err(|e| TunError::InvalidSubnet(format!("Invalid subnet: {}", e)))?;

    // Use the provided server_ip from TunConfig
    let server_ip_addr = std::net::Ipv4Addr::from_str(&config.server_ip)
        .map_err(|e| TunError::InvalidSubnet(format!("Invalid server IP in config: {}", e)))?;

    let netmask = network.mask();

    debug!("TUN configuration: IP={}, Mask={}, MTU={}", config.server_ip, netmask, config.mtu);

    // Create TUN device configuration
    let mut tun_config = tun::Configuration::default();

    tun_config
        .name(&config.name)
        .address(server_ip_addr) // Use the parsed Ipv4Addr
        .netmask(netmask)
        .mtu(config.mtu as i32)
        .up();

    // Try to create the TUN device
    let device = tun::create(&tun_config)
        .map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("permission denied") || err_str.contains("Operation not permitted") {
                TunError::PermissionDenied(
                    "Permission denied when creating TUN device. Run as root or with CAP_NET_ADMIN.".into()
                )
            } else {
                TunError::Creation(err_str)
            }
        })?;

    info!("TUN device {} created successfully with IP {}/{}",
         config.name, config.server_ip, network.prefix());

    // Apply additional optimizations
    if let Err(e) = apply_tun_optimizations(&config.name) {
        warn!("Failed to apply TUN optimizations: {}", e); // Log optimization failures as warnings
    }


    Ok(device)
}

/// Apply optimizations to improve TUN device performance
fn apply_tun_optimizations(device_name: &str) -> Result<(), TunError> {
    debug!("Applying optimizations for TUN device {}", device_name);

    // Set queue length
     let output = Command::new("ip")
         .args(["link", "set", "dev", device_name, "txqueuelen", "1000"])
         .output()
         .map_err(|e| TunError::Io(e))?; // Map IO error
     if !output.status.success() {
         warn!("Failed to set txqueuelen for {}: {}", device_name, String::from_utf8_lossy(&output.stderr));
     }

    // Check if ethtool exists before trying to use it
    if Command::new("which").arg("ethtool").status().map_or(false, |s| s.success()) {
        let output_offload = Command::new("ethtool")
            .args(["-K", device_name, "tso", "off", "gso", "off", "gro", "off"])
            .output()
            .map_err(|e| TunError::Io(e))?;
         if !output_offload.status.success() {
             // Log as debug because this often fails if not applicable
             debug!("Failed to disable offloading features for {}: {}", device_name, String::from_utf8_lossy(&output_offload.stderr));
         }
    } else {
        debug!("ethtool not found, skipping offload settings for {}", device_name);
    }


    Ok(())
}

/// Configure NAT for the TUN device
pub fn configure_nat(tun_name: &str, subnet: &str) -> Result<(), TunError> {
    info!("Configuring NAT for TUN device {} with subnet {}", tun_name, subnet);

    // Get the main interface for outgoing traffic
    let main_interface = get_main_interface()?;
    debug!("Main interface for NAT: {}", main_interface);

    // Enable IP forwarding
    enable_ip_forwarding()?;

    // Configure NAT with iptables
    setup_iptables_rules(tun_name, subnet, &main_interface)?;

    info!("NAT configured successfully");

    Ok(())
}

/// Get the main network interface for outgoing traffic
fn get_main_interface() -> Result<String, TunError> {
    // Try to get the default route interface
    let output = Command::new("ip")
        .args(["route", "get", "1.1.1.1"]) // Use a reliable external IP
        .output()
        .map_err(|e| TunError::CommandError(format!("Failed to execute 'ip route': {}", e)))?;

    if !output.status.success() {
         // Try 'route -n' as fallback
         let output_route = Command::new("route").arg("-n").output().map_err(|e| TunError::CommandError(format!("Failed to execute 'route -n': {}",e)))?;
         if output_route.status.success() {
              let route_str = String::from_utf8_lossy(&output_route.stdout);
              for line in route_str.lines() {
                  let parts: Vec<&str> = line.split_whitespace().collect();
                  if parts.len() >= 8 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                       return Ok(parts[7].to_string());
                  }
              }
         }
        return Err(TunError::Configuration("Could not determine default route interface".into()));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Parse 'dev' field robustly
    let mut parts = output_str.split_whitespace();
     while let Some(part) = parts.next() {
         if part == "dev" {
             if let Some(iface) = parts.next() {
                 return Ok(iface.to_string());
             }
         }
     }


    Err(TunError::Configuration("Could not parse default interface from 'ip route'".into()))
}


/// Enable IP forwarding in the kernel
fn enable_ip_forwarding() -> Result<(), TunError> {
    debug!("Enabling IP forwarding");

    // Enable IPv4 forwarding via /proc/sys
    if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
         // Try using sysctl as fallback or if direct write fails
         let output = Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .output()
            .map_err(|io_err| TunError::CommandError(format!("Failed to execute sysctl: {}", io_err)))?;

         if !output.status.success() {
             let stderr = String::from_utf8_lossy(&output.stderr);
             error!("Failed to enable IPv4 forwarding using /proc/sys ({}) and sysctl ({}). Check permissions.", e, stderr);
             return Err(TunError::Configuration(format!(
                "Failed to enable IPv4 forwarding (tried /proc/sys and sysctl): {}, {}", e, stderr
            )));
         } else {
              debug!("Enabled IPv4 forwarding via sysctl.");
         }
    } else {
         debug!("Enabled IPv4 forwarding via /proc/sys.");
    }


    // Make it persistent by updating sysctl.conf (use a specific file)
    let sysctl_path = "/etc/sysctl.d/99-aeronyx-ipforward.conf";
    if !std::path::Path::new(sysctl_path).exists() {
        if let Some(parent) = std::path::Path::new(sysctl_path).parent() {
            if !parent.exists() {
                 std::fs::create_dir_all(parent).map_err(|e| TunError::Io(e))?;
            }
        }
        std::fs::write(sysctl_path, "net.ipv4.ip_forward = 1\n")
            .map_err(|e| TunError::Configuration(format!("Failed to write persistent sysctl configuration: {}", e)))?;

        // Apply the configuration (optional, system usually reads on boot)
        // let _ = Command::new("sysctl").args(["-p", sysctl_path]).output();
         info!("Created persistent IP forwarding rule in {}", sysctl_path);
    }


    Ok(())
}


/// Setup iptables rules for NAT
fn setup_iptables_rules(tun_name: &str, subnet: &str, main_iface: &str) -> Result<(), TunError> {
    debug!("Setting up iptables rules for NAT (Subnet: {}, TUN: {}, Main Iface: {})", subnet, tun_name, main_iface);

    let rules = [
        // Delete existing rules first to prevent duplicates (ignore errors)
        vec!["-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", main_iface, "-j", "MASQUERADE"],
        vec!["-D", "FORWARD", "-i", tun_name, "-o", main_iface, "-j", "ACCEPT"],
        vec!["-D", "FORWARD", "-i", main_iface, "-o", tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        // Add the necessary rules
        vec!["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", main_iface, "-j", "MASQUERADE"],
        vec!["-A", "FORWARD", "-i", tun_name, "-o", main_iface, "-j", "ACCEPT"],
        vec!["-A", "FORWARD", "-i", main_iface, "-o", tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ];

    for rule in rules {
        let is_delete = rule[1] == "-D"; // Check if it's a delete rule
        let output = Command::new("iptables")
            .args(&rule)
            .output()
            .map_err(|e| TunError::CommandError(format!("Failed to execute iptables: {}", e)))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
             if !is_delete || !error.contains("No chain/target/match by that name") { // Only error if add fails, or delete fails for reasons other than not found
                 error!("iptables command failed ({:?}): {}", rule, error);
                return Err(TunError::Configuration(format!("Failed to set iptables rule ({:?}): {}", rule, error)));
            } else {
                 debug!("iptables delete rule ({:?}) failed (likely rule didn't exist): {}", rule, error);
            }
        } else {
             debug!("iptables rule applied successfully: {:?}", rule);
        }
    }

    // Make iptables rules persistent if the netfilter-persistent package is installed
     if Command::new("which").arg("netfilter-persistent").status().map_or(false, |s| s.success()) {
        info!("Attempting to save iptables rules persistently with netfilter-persistent...");
        let save_output = Command::new("netfilter-persistent")
            .args(["save"])
            .output()
            .map_err(|e| TunError::CommandError(format!("Failed to execute netfilter-persistent save: {}",e)))?;
         if !save_output.status.success() {
              warn!("Failed to save iptables rules persistently: {}", String::from_utf8_lossy(&save_output.stderr));
         } else {
              info!("iptables rules saved persistently.");
         }
    } else if Command::new("which").arg("iptables-save").status().map_or(false, |s| s.success()) &&
               Command::new("which").arg("service").status().map_or(false, |s| s.success()) {
        // Fallback for systems using iptables-save/service (like older CentOS/RHEL)
        info!("Attempting to save iptables rules persistently with iptables-save...");
        let save_output = Command::new("sh") // Use shell to handle redirection
             .arg("-c")
             .arg("iptables-save > /etc/sysconfig/iptables")
             .output()
             .map_err(|e| TunError::CommandError(format!("Failed to execute iptables-save: {}",e)))?;
         if !save_output.status.success() {
             warn!("Failed to save iptables rules persistently using iptables-save: {}", String::from_utf8_lossy(&save_output.stderr));
         } else {
             // Try restarting iptables service to load rules (may not be necessary, but good practice)
             let _ = Command::new("service").args(["iptables", "restart"]).output();
             info!("iptables rules saved persistently (using iptables-save).");
         }
    } else {
        warn!("Could not find netfilter-persistent or iptables-save. iptables rules might not be persistent.");
    }


    Ok(())
}


/// Process IP packet and extract destination IP
pub fn process_packet(packet: &[u8]) -> Option<(String, Vec<u8>)> {
    if packet.len() < 20 {
        return None; // Packet too small for IPv4 header
    }

    // Check if it's an IPv4 packet (version field is in the top 4 bits)
    let version = packet[0] >> 4;
    if version != 4 {
        return None; // Not an IPv4 packet
    }

    // Extract destination IP from bytes 16-19
    let dest_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    // Return the destination IP and the full packet
    Some((dest_ip.to_string(), packet.to_vec()))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_packet() {
        // Create a mock IPv4 packet
        let mut packet = vec![0u8; 20]; // Minimum IPv4 header size
        packet[0] = 0x45; // IPv4, header length 5 words
        packet[16] = 10;  // Destination IP: 10.7.0.5
        packet[17] = 7;
        packet[18] = 0;
        packet[19] = 5;

        let result = process_packet(&packet);
        assert!(result.is_some());

        let (dest_ip, _) = result.unwrap();
        assert_eq!(dest_ip, "10.7.0.5");
    }

    #[test]
    fn test_non_ipv4_packet() {
        // Mock IPv6 packet (version 6)
        let mut packet = vec![0u8; 40]; // IPv6 header
        packet[0] = 0x60; // IPv6 version

        let result = process_packet(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_packet_too_small() {
        // Packet smaller than IPv4 header
        let packet = vec![0u8; 10];

        let result = process_packet(&packet);
        assert!(result.is_none());
    }
}
