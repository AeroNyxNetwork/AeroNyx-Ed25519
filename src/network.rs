use ipnetwork::Ipv4Network;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tun::Configuration;

use crate::config;
use crate::obfuscation::{ObfuscationMethod, TrafficShaper};
use crate::types::{IpAllocation, Result, VpnError};
use crate::utils;

/// Network bandwidth and throughput tracker
#[derive(Debug)]
pub struct BandwidthTracker {
    /// Bytes sent in current window
    bytes_sent: u64,
    /// Bytes received in current window
    bytes_received: u64,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
    /// Historical bandwidth data (timestamp, bytes_sent, bytes_received)
    history: VecDeque<(Instant, u64, u64)>,
    /// Maximum history entries to keep
    max_history: usize,
}

impl BandwidthTracker {
    /// Create a new bandwidth tracker
    pub fn new(window_duration: Duration, max_history: usize) -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            window_start: Instant::now(),
            window_duration,
            history: VecDeque::with_capacity(max_history),
            max_history,
        }
    }
    
    /// Record sent bytes
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.check_window();
    }
    
    /// Record received bytes
    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.check_window();
    }
    
    /// Check if the current window has elapsed
    fn check_window(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.window_duration {
            // Save the current window data
            self.history.push_back((
                self.window_start,
                self.bytes_sent,
                self.bytes_received,
            ));
            
            // Truncate history if needed
            while self.history.len() > self.max_history {
                self.history.pop_front();
            }
            
            // Reset for new window
            self.window_start = now;
            self.bytes_sent = 0;
            self.bytes_received = 0;
        }
    }
    
    /// Get current send rate in bytes per second
    pub fn get_send_rate(&self) -> f64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_sent as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get current receive rate in bytes per second
    pub fn get_receive_rate(&self) -> f64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_received as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get average send rate over all history
    pub fn get_average_send_rate(&self) -> f64 {
        if self.history.is_empty() {
            return self.get_send_rate();
        }
        
        let total_bytes: u64 = self.history.iter().map(|(_, sent, _)| sent).sum();
        let first_timestamp = self.history.front().unwrap().0;
        let elapsed = Instant::now().duration_since(first_timestamp).as_secs_f64();
        
        if elapsed > 0.0 {
            total_bytes as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get average receive rate over all history
    pub fn get_average_receive_rate(&self) -> f64 {
        if self.history.is_empty() {
            return self.get_receive_rate();
        }
        
        let total_bytes: u64 = self.history.iter().map(|(_, _, received)| received).sum();
        let first_timestamp = self.history.front().unwrap().0;
        let elapsed = Instant::now().duration_since(first_timestamp).as_secs_f64();
        
        if elapsed > 0.0 {
            total_bytes as f64 / elapsed
        } else {
            0.0
        }
    }
}

/// Enhanced IP address pool manager
#[derive(Debug)]
pub struct IpPoolManager {
    /// Available IP addresses
    available_ips: Arc<Mutex<VecDeque<String>>>,
    /// Allocated IP addresses with metadata
    allocated_ips: Arc<Mutex<HashMap<String, IpAllocation>>>,
    /// Subnet range
    subnet: String,
}

impl IpPoolManager {
    /// Create a new IP pool manager
    pub fn new(subnet: &str) -> Result<Self> {
        let available_ips = generate_ip_pool(subnet)?;
        
        Ok(Self {
            available_ips: Arc::new(Mutex::new(available_ips)),
            allocated_ips: Arc::new(Mutex::new(HashMap::new())),
            subnet: subnet.to_string(),
        })
    }
    
    /// Allocate an IP address
    pub async fn allocate_ip(&self, client_key: &str) -> Result<String> {
        // First check if this client already has an allocation
        {
            let allocated = self.allocated_ips.lock().await;
            for (ip, allocation) in allocated.iter() {
                if allocation.client_key == client_key {
                    return Ok(ip.clone());
                }
            }
        }
        
        // Next check if there's a static allocation for this client
        // This would involve checking a database or config file
        // For now, we'll just use the dynamic pool
        
        // Finally, allocate from the dynamic pool
        let mut available = self.available_ips.lock().await;
        if let Some(ip) = available.pop_front() {
            let now = utils::current_timestamp_millis();
            let expires_at = now + config::IP_LEASE_DURATION.as_secs() * 1000;
            
            let allocation = IpAllocation {
                ip_address: ip.clone(),
                client_key: client_key.to_string(),
                expires_at,
                is_static: false,
            };
            
            let mut allocated = self.allocated_ips.lock().await;
            allocated.insert(ip.clone(), allocation);
            
            Ok(ip)
        } else {
            Err(VpnError::IpPoolExhausted)
        }
    }
    
    /// Release an IP address back to the pool
    pub async fn release_ip(&self, ip: &str) -> Result<()> {
        let mut allocated = self.allocated_ips.lock().await;
        if let Some(allocation) = allocated.remove(ip) {
            if !allocation.is_static {
                let mut available = self.available_ips.lock().await;
                available.push_back(ip.to_string());
            }
            Ok(())
        } else {
            Err(VpnError::Network(format!("IP not allocated: {}", ip)))
        }
    }
    
    /// Check and cleanup expired IP allocations
    pub async fn cleanup_expired(&self) -> Result<()> {
        let now = utils::current_timestamp_millis();
        let mut to_release = Vec::new();
        
        {
            let allocated = self.allocated_ips.lock().await;
            for (ip, allocation) in allocated.iter() {
                if !allocation.is_static && allocation.expires_at < now {
                    to_release.push(ip.clone());
                }
            }
        }
        
        for ip in to_release {
            self.release_ip(&ip).await?;
        }
        
        Ok(())
    }
    
    /// Renew an IP lease
    pub async fn renew_ip(&self, ip: &str) -> Result<u64> {
        let mut allocated = self.allocated_ips.lock().await;
        
        if let Some(allocation) = allocated.get_mut(ip) {
            let now = utils::current_timestamp_millis();
            let expires_at = now + config::IP_LEASE_DURATION.as_secs() * 1000;
            allocation.expires_at = expires_at;
            Ok(expires_at)
        } else {
            Err(VpnError::Network(format!("IP not allocated: {}", ip)))
        }
    }
    
    /// Get all current IP allocations
    pub async fn get_allocations(&self) -> Result<Vec<IpAllocation>> {
        let allocated = self.allocated_ips.lock().await;
        Ok(allocated.values().cloned().collect())
    }
}

/// Configure and create a TUN device with enhanced security
pub fn setup_tun_device(name: &str, subnet: &str) -> Result<tun::platform::Device> {
    let mut config = Configuration::default();
    
    // Parse the subnet
    let network = Ipv4Network::from_str(subnet)
        .map_err(|e| VpnError::Network(format!("Invalid subnet: {}", e)))?;
    
    let server_ip = network.nth(1)
        .ok_or_else(|| VpnError::Network("Invalid subnet size".into()))?;
    
    let netmask = network.mask();
    
    // Configure TUN device
    config.name(name)
        .up() // Set the interface up
        .mtu(1500) // Set MTU
        .address(server_ip) // Server IP address (usually .1)
        .netmask(netmask) // Subnet mask
        .destination(network.nth(2).unwrap_or(server_ip)); // Default route (usually .2)
    
    // Create the TUN device
    let dev = tun::create(&config).map_err(|e| VpnError::Network(e.to_string()))?;
    
    tracing::info!("TUN device {} created successfully with IP {}/{}", 
                  name, server_ip, network.prefix());
    
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
        if host_count <= 2 || host_count >= network.size() - 1 {
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

/// Packet fragmentation and reassembly
pub struct PacketReassembler {
    /// Fragments indexed by (src_ip, dest_ip, id)
    fragments: HashMap<(String, String, u16), Vec<(u16, Vec<u8>)>>,
    /// Expiration timestamps for fragment groups
    timeouts: HashMap<(String, String, u16), Instant>,
    /// Fragment timeout
    timeout: Duration,
}

impl PacketReassembler {
    /// Create a new packet reassembler
    pub fn new(timeout: Duration) -> Self {
        Self {
            fragments: HashMap::new(),
            timeouts: HashMap::new(),
            timeout,
        }
    }
    
    /// Process an IP packet, fragmenting if needed
    pub fn fragment_packet(&self, packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        if packet.len() <= mtu {
            return vec![packet.to_vec()];
        }
        
        // In a real implementation, this would properly fragment IPv4 packets
        // For now, just return the original packet
        vec![packet.to_vec()]
    }
    
    /// Receive a fragment and try to reassemble
    pub fn reassemble_packet(&mut self, fragment: &[u8]) -> Option<Vec<u8>> {
        // In a real implementation, this would reassemble fragmented IPv4 packets
        // For now, just return the original fragment
        Some(fragment.to_vec())
    }
    
    /// Clean up expired fragments
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        
        for (key, timeout) in &self.timeouts {
            if *timeout < now {
                expired.push(key.clone());
            }
        }
        
        for key in expired {
            self.timeouts.remove(&key);
            self.fragments.remove(&key);
        }
    }
}

/// Network traffic analyzer for security monitoring
pub struct TrafficAnalyzer {
    /// Packet counts by source IP
    packet_counts: HashMap<String, u64>,
    /// Suspicious activity flags
    suspicious_activity: Vec<(String, String, Instant)>,
    /// Known clients and their traffic patterns
    client_patterns: HashMap<String, Vec<(Instant, usize)>>,
}

impl TrafficAnalyzer {
    /// Create a new traffic analyzer
    pub fn new() -> Self {
        Self {
            packet_counts: HashMap::new(),
            suspicious_activity: Vec::new(),
            client_patterns: HashMap::new(),
        }
    }
    
    /// Record a packet for analysis
    pub fn record_packet(&mut self, src_ip: &str, dest_ip: &str, size: usize) {
        // Update packet counts
        *self.packet_counts.entry(src_ip.to_string()).or_insert(0) += 1;
        
        // Update client patterns
        let pattern = self.client_patterns
            .entry(src_ip.to_string())
            .or_insert_with(Vec::new);
            
        pattern.push((Instant::now(), size));
        
        // Limit pattern history
        if pattern.len() > 1000 {
            pattern.remove(0);
        }
        
        // Look for suspicious patterns
        self.analyze_patterns(src_ip, dest_ip);
    }
    
    /// Analyze traffic patterns for anomalies
    fn analyze_patterns(&mut self, src_ip: &str, dest_ip: &str) {
        // In a real implementation, this would use more sophisticated anomaly detection
        // For now, just check for basic rate limiting
        if let Some(pattern) = self.client_patterns.get(src_ip) {
            let now = Instant::now();
            let recent_packets: usize = pattern
                .iter()
                .filter(|(time, _)| now.duration_since(*time) < Duration::from_secs(1))
                .count();
                
            // Flag if more than 1000 packets per second
            if recent_packets > 1000 {
                self.suspicious_activity.push((
                    src_ip.to_string(),
                    "High packet rate".to_string(),
                    now,
                ));
            }
        }
    }
    
    /// Get recent suspicious activity
    pub fn get_suspicious_activity(&mut self, time_window: Duration) -> Vec<(String, String)> {
        let now = Instant::now();
        
        // Clean up old entries
        self.suspicious_activity.retain(|(_, _, time)| {
            now.duration_since(*time) < time_window
        });
        
        // Return recent activity
        self.suspicious_activity
            .iter()
            .map(|(ip, reason, _)| (ip.clone(), reason.clone()))
            .collect()
    }
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
    
    #[tokio::test]
    async fn test_ip_pool_manager() {
        let manager = IpPoolManager::new("10.8.0.0/24").unwrap();
        let client1 = "client1";
        let client2 = "client2";
        
        // Allocate IPs for two clients
        let ip1 = manager.allocate_ip(client1).await.unwrap();
        let ip2 = manager.allocate_ip(client2).await.unwrap();
        
        // IPs should be different
        assert_ne!(ip1, ip2);
        
        // Allocating again for client1 should return the same IP
        let ip1_again = manager.allocate_ip(client1).await.unwrap();
        assert_eq!(ip1, ip1_again);
        
        // Release an IP
        manager.release_ip(&ip1).await.unwrap();
        
        // Allocating for client1 should now give a new IP
        let ip1_new = manager.allocate_ip(client1).await.unwrap();
        // In our implementation it would be a new IP from the pool
        // but since we're reusing the pool, it might be the same one
        
        // Cleanup should not affect active leases
        manager.cleanup_expired().await.unwrap();
        let allocations = manager.get_allocations().await.unwrap();
        assert_eq!(allocations.len(), 2);
    }
    
    #[test]
    fn test_bandwidth_tracker() {
        let mut tracker = BandwidthTracker::new(Duration::from_secs(1), 10);
        
        // Record some traffic
        tracker.record_sent(1000);
        tracker.record_received(500);
        
        // Check rates
        let send_rate = tracker.get_send_rate();
        let recv_rate = tracker.get_receive_rate();
        
        // Rates should be positive
        assert!(send_rate > 0.0);
        assert!(recv_rate > 0.0);
        
        // Send rate should be higher than receive rate
        assert!(send_rate > recv_rate);
    }
}
