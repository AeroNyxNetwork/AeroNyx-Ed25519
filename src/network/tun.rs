// src/network/tun.rs
//! TUN device management.
//!
//! This module provides functionality for setting up and managing
//! TUN devices for VPN connections.

use ipnetwork::Ipv4Network;
use std::io::Result as IoResult;
use std::process::Command;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::config::constants::TUN_MTU;

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
    
    // Get first usable IP (typically .1 in the subnet)
    let server_ip = network.nth(1)
        .ok_or_else(|| TunError::InvalidSubnet("Subnet too small".into()))?;
    
    let netmask = network.mask();
    
    debug!("TUN configuration: IP={}, Mask={}, MTU={}", server_ip, netmask, config.mtu);
    
    // Create TUN device configuration
    let mut tun_config = tun::Configuration::default();
    
    tun_config
        .name(&config.name)
        .address(server_ip)
        .netmask(netmask)
        .mtu(config.mtu as i32)
        .up();
    
    // Try to create the TUN device
    let device = tun::create(&tun_config)
        .map_err(|e| {
            // Check if the error is due to permissions
            if e.to_string().contains("permission denied") {
                TunError::PermissionDenied(
                    "Permission denied when creating TUN device. Run as root or with appropriate capabilities.".into()
                )
            } else {
                TunError::Creation(e.to_string())
            }
        })?;
    
    info!("TUN device {} created successfully with IP {}/{}", 
         config.name, server_ip, network.prefix());
    
    // Apply additional optimizations
    apply_tun_optimizations(&config.name)?;
    
    Ok(device)
}

/// Apply optimizations to improve TUN device performance
fn apply_tun_optimizations(device_name: &str) -> Result<(), TunError> {
    debug!("Applying optimizations for TUN device {}", device_name);
    
    // Set queue length for better performance under load
    if let Err(e) = Command::new("ip")
        .args(["link", "set", "dev", device_name, "txqueuelen", "1000"])
        .output() {
        warn!("Failed to set txqueuelen: {}", e);
    }
    
    // Disable TCP segmentation offload if possible (can cause issues with VPN)
    if Command::new("ethtool")
        .arg("-v")
        .output()
        .is_ok() {
        
        if let Err(e) = Command::new("ethtool")
            .args(["-K", device_name, "tso", "off", "gso", "off", "gro", "off"])
            .output() {
            debug!("Failed to disable offloading features: {}", e);
        }
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
        .args(["route", "get", "1.1.1.1"])
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    for line in output_str.lines() {
        if let Some(idx) = line.find("dev ") {
            let parts: Vec<&str> = line[idx+4..].split_whitespace().collect();
            if !parts.is_empty() {
                return Ok(parts[0].to_string());
            }
        }
    }
    
    // Fallbacks for common interface names
    for iface in &["eth0", "ens3", "enp0s3", "wlan0"] {
        if std::path::Path::new(&format!("/sys/class/net/{}", iface)).exists() {
            return Ok(iface.to_string());
        }
    }
    
    // Default fallback
    warn!("Could not determine main network interface, using 'eth0'");
    Ok("eth0".to_string())
}

/// Enable IP forwarding in the kernel
fn enable_ip_forwarding() -> Result<(), TunError> {
    debug!("Enabling IP forwarding");
    
    // Enable IPv4 forwarding
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| TunError::Configuration(format!("Failed to enable IPv4 forwarding: {}", e)))?;
    
    // Make it persistent by updating sysctl.conf if it doesn't already have the setting
    let sysctl_path = "/etc/sysctl.d/99-aeronyx-ipforward.conf";
    if !std::path::Path::new(sysctl_path).exists() {
        std::fs::write(sysctl_path, "net.ipv4.ip_forward = 1\n")
            .map_err(|e| TunError::Configuration(format!("Failed to update sysctl configuration: {}", e)))?;
        
        // Apply the configuration
        Command::new("sysctl")
            .args(["-p", sysctl_path])
            .output()?;
    }
    
    Ok(())
}

/// Setup iptables rules for NAT
fn setup_iptables_rules(tun_name: &str, subnet: &str, main_iface: &str) -> Result<(), TunError> {
    debug!("Setting up iptables rules for NAT");
    
    // Clear any existing rules for this subnet to avoid duplicates
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", main_iface, "-j", "MASQUERADE"])
        .output();
    
    // Add NAT rule
    let output = Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", main_iface, "-j", "MASQUERADE"])
        .output()?;
    
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(TunError::Configuration(format!("Failed to set up NAT: {}", error)));
    }
    
    // Forward rule from TUN to main interface
    let _ = Command::new("iptables")
        .args([
            "-A", "FORWARD",
            "-i", tun_name,
            "-o", main_iface,
            "-j", "ACCEPT"
        ])
        .output()?;
    
    // Forward rule from main interface to TUN
    let _ = Command::new("iptables")
        .args([
            "-A", "FORWARD",
            "-i", main_iface,
            "-o", tun_name,
            "-m", "state",
            "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
        .output()?;
    
    // Make iptables rules persistent if the netfilter-persistent package is installed
    if std::path::Path::new("/usr/sbin/netfilter-persistent").exists() {
        let _ = Command::new("netfilter-persistent")
            .args(["save"])
            .output();
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
    let dest_ip = format!(
        "{}.{}.{}.{}",
        packet[16], packet[17], packet[18], packet[19]
    );
    
    // Return the destination IP and the full packet
    Some((dest_ip, packet.to_vec()))
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
