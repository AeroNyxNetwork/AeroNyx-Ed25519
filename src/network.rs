use ipnetwork::Ipv4Network;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tun::Configuration;

use crate::types::{Result, VpnError};

/// Configure and create a TUN device
pub fn setup_tun_device(name: &str) -> Result<tun::platform::Device> {
    let mut config = Configuration::default();
    
    // Configure TUN device
    config.name(name)
        .up() // Set the interface up
        .mtu(1500) // Set MTU
        .address(Ipv4Addr::from_str("10.7.0.1").unwrap()) // Server IP address
        .netmask(Ipv4Addr::from_str("255.255.255.0").unwrap()) // Subnet mask
        .destination(Ipv4Addr::from_str("10.7.0.2").unwrap()); // Default route
    
    // Create the TUN device
    let dev = tun::create(&config).map_err(|e| VpnError::Network(e.to_string()))?;
    
    tracing::info!("TUN device {} created successfully", name);
    
    Ok(dev)
}

/// Generate IP pool from CIDR subnet
pub fn generate_ip_pool(subnet: &str) -> Result<VecDeque<String>> {
    // Parse CIDR notation
    let network = Ipv4Network::from_str(subnet)
        .map_err(|e| VpnError::Network(format!("Invalid subnet: {}", e)))?;
    
    // Calculate usable host addresses (excluding network and broadcast)
    let mut pool = VecDeque::new();
    
    // Skip the first IP (network address) and the server IP (usually .1)
    let mut host_count = 0;
    
    for ip in network.iter() {
        host_count += 1;
        
        // Skip network address, broadcast address, and server address (.1)
        if host_count <= 2 {
            continue;
        }
        
        // Add the IP to the pool
        pool.push_back(ip.to_string());
        
        // Limit the pool size for very large subnets
        if pool.len() >= 1000 {
            break;
        }
    }
    
    if pool.is_empty() {
        return Err(VpnError::Network("Subnet too small".into()));
    }
    
    tracing::info!("Generated IP pool with {} addresses from subnet {}", pool.len(), subnet);
    
    Ok(pool)
}

/// Process IP packet and extract destination IP
pub fn process_packet(packet: &[u8]) -> Option<(String, Vec<u8>)> {
    if packet.len() < 20 {
        return None;
    }
    
    // Check if it's an IPv4 packet
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    
    // Extract destination IP
    let dest_ip = format!(
        "{}.{}.{}.{}",
        packet[16], packet[17], packet[18], packet[19]
    );
    
    Some((dest_ip, packet.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_pool_generation() {
        let pool = generate_ip_pool("10.7.0.0/24").unwrap();
        assert!(!pool.is_empty());
        assert!(pool.contains(&"10.7.0.2".to_string()));
        assert!(pool.contains(&"10.7.0.254".to_string()));
    }
    
    #[test]
    fn test_process_packet() {
        // Create a mock IPv4 packet
        let mut packet = vec![0u8; 20]; // Minimum IPv4 header
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
}
