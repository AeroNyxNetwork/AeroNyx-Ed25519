// src/network/ip_pool.rs
//! IP address pool management.
//!
//! This module provides functionality for allocating and managing
//! IP addresses for VPN clients.

use ipnetwork::Ipv4Network;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::utils;

/// Error type for IP pool operations
#[derive(Debug, Error)]
pub enum IpPoolError {
    #[error("IP pool is exhausted")]
    PoolExhausted,
    
    #[error("Invalid subnet: {0}")]
    InvalidSubnet(String),
    
    #[error("IP not allocated: {0}")]
    NotAllocated(String),
    
    #[error("IP already allocated: {0}")]
    AlreadyAllocated(String),
    
    #[error("Network error: {0}")]
    Network(String),
}

/// IP allocation information
#[derive(Debug, Clone)]
pub struct IpAllocation {
    /// Allocated IP address
    pub ip_address: String,
    /// Client identifier (public key)
    pub client_id: String,
    /// Expiration timestamp (milliseconds since epoch)
    pub expires_at: u64,
    /// Is this a static allocation
    pub is_static: bool,
}

/// IP address pool
#[derive(Debug)]
pub struct IpPool {
    /// Available IP addresses
    available: VecDeque<String>,
    /// Allocated IP addresses with metadata
    allocated: HashMap<String, IpAllocation>,
    /// Subnet
    subnet: Ipv4Network,
}

impl IpPool {
    /// Create a new IP pool from a subnet
    pub fn new(subnet: &str) -> Result<Self, IpPoolError> {
        let network = Ipv4Network::from_str(subnet)
            .map_err(|e| IpPoolError::InvalidSubnet(e.to_string()))?;
        
        let mut available = VecDeque::new();
        
        // Skip network address (first IP) and server address (usually second IP)
        let mut host_count = 0;
        
        for ip in network.iter() {
            host_count += 1;
            
            // Skip network address, broadcast address, and server address (usually .1)
            if host_count <= 2 || host_count >= network.size() - 1 {
                continue;
            }
            
            available.push_back(ip.to_string());
        }
        
        if available.is_empty() {
            return Err(IpPoolError::InvalidSubnet("Subnet too small".to_string()));
        }
        
        Ok(Self {
            available,
            allocated: HashMap::new(),
            subnet: network,
        })
    }
    
    /// Allocate an IP address
    pub fn allocate_ip(&mut self, client_id: &str, lease_duration_secs: u64) -> Result<String, IpPoolError> {
        // Check if client already has an allocation
        for (ip, allocation) in &self.allocated {
            if allocation.client_id == client_id {
                return Ok(ip.clone());
            }
        }
        
        // Get next available IP
        if let Some(ip) = self.available.pop_front() {
            let now = utils::current_timestamp_millis();
            let expires_at = now + (lease_duration_secs * 1000);
            
            let allocation = IpAllocation {
                ip_address: ip.clone(),
                client_id: client_id.to_string(),
                expires_at,
                is_static: false,
            };
            
            self.allocated.insert(ip.clone(), allocation);
            
            Ok(ip)
        } else {
            Err(IpPoolError::PoolExhausted)
        }
    }
    
    /// Release an IP address
    pub fn release_ip(&mut self, ip: &str) -> Result<(), IpPoolError> {
        if let Some(allocation) = self.allocated.remove(ip) {
            if !allocation.is_static {
                self.available.push_back(ip.to_string());
            }
            Ok(())
        } else {
            Err(IpPoolError::NotAllocated(ip.to_string()))
        }
    }
    
    /// Renew an IP lease
    pub fn renew_ip(&mut self, ip: &str, lease_duration_secs: u64) -> Result<u64, IpPoolError> {
        if let Some(allocation) = self.allocated.get_mut(ip) {
            let now = utils::current_timestamp_millis();
            let expires_at = now + (lease_duration_secs * 1000);
            allocation.expires_at = expires_at;
            Ok(expires_at)
        } else {
            Err(IpPoolError::NotAllocated(ip.to_string()))
        }
    }
    
    /// Assign a static IP
    pub fn assign_static_ip(&mut self, ip: &str, client_id: &str) -> Result<(), IpPoolError> {
        // Check if IP is in our subnet
        let ip_addr = Ipv4Addr::from_str(ip)
            .map_err(|e| IpPoolError::InvalidSubnet(e.to_string()))?;
            
        if !self.subnet.contains(ip_addr) {
            return Err(IpPoolError::InvalidSubnet(format!(
                "IP {} is not in subnet {}", ip, self.subnet
            )));
        }
        
        // Check if IP is already allocated
        if let Some(allocation) = self.allocated.get(ip) {
            if allocation.client_id != client_id {
                return Err(IpPoolError::AlreadyAllocated(ip.to_string()));
            }
            
            // Already allocated to this client, just make it static
            self.allocated.get_mut(ip).unwrap().is_static = true;
            return Ok(());
        }
        
        // Remove from available if present
        self.available.retain(|available_ip| available_ip != ip);
        
        // Create a static allocation
        let allocation = IpAllocation {
            ip_address: ip.to_string(),
            client_id: client_id.to_string(),
            expires_at: u64::MAX, // Never expires
            is_static: true,
        };
        
        self.allocated.insert(ip.to_string(), allocation);
        
        Ok(())
    }
    
    /// Check if a client has an IP allocation
    pub fn get_client_ip(&self, client_id: &str) -> Option<String> {
        for (ip, allocation) in &self.allocated {
            if allocation.client_id == client_id {
                return Some(ip.clone());
            }
        }
        None
    }
    
    /// Get allocations for a client
    pub fn get_client_allocation(&self, client_id: &str) -> Option<IpAllocation> {
        for allocation in self.allocated.values() {
            if allocation.client_id == client_id {
                return Some(allocation.clone());
            }
        }
        None
    }
    
    /// Get client ID for an IP
    pub fn get_ip_client(&self, ip: &str) -> Option<String> {
        self.allocated.get(ip).map(|a| a.client_id.clone())
    }
    
    /// Clean up expired allocations
    pub fn cleanup_expired(&mut self) -> Vec<String> {
        let now = utils::current_timestamp_millis();
        let mut expired = Vec::new();
        
        // Find expired allocations
        for (ip, allocation) in &self.allocated {
            if !allocation.is_static && allocation.expires_at < now {
                expired.push(ip.clone());
            }
        }
        
        // Release expired IPs
        for ip in &expired {
            self.release_ip(ip).ok();
        }
        
        expired
    }
    
    /// Get pool statistics
    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.available.len(),
            self.allocated.len(),
            self.allocated.values().filter(|a| a.is_static).count(),
        )
    }
    
    /// Get the first IP in the subnet (network address)
    pub fn get_network_address(&self) -> String {
        self.subnet.network().to_string()
    }
    
    /// Get the subnet mask
    pub fn get_subnet_mask(&self) -> String {
        format!("{}", Ipv4Addr::from(self.subnet.mask()))
    }
    
    /// Get the broadcast address
    pub fn get_broadcast_address(&self) -> String {
        self.subnet.broadcast().to_string()
    }
    
    /// Get all allocations
    pub fn get_allocations(&self) -> Vec<IpAllocation> {
        self.allocated.values().cloned().collect()
    }
}

/// IP pool manager
#[derive(Debug)]
pub struct IpPoolManager {
    /// IP pool
    pool: Arc<Mutex<IpPool>>,
    /// Default lease duration in seconds
    default_lease_duration: u64,
}

impl IpPoolManager {
    /// Create a new IP pool manager
    pub async fn new(subnet: &str, default_lease_duration: u64) -> Result<Self, IpPoolError> {
        let pool = IpPool::new(subnet)?;
        
        Ok(Self {
            pool: Arc::new(Mutex::new(pool)),
            default_lease_duration,
        })
    }
    
    /// Allocate an IP address
    pub async fn allocate_ip(&self, client_id: &str) -> Result<String, IpPoolError> {
        let mut pool = self.pool.lock().await;
        let ip = pool.allocate_ip(client_id, self.default_lease_duration)?;
        
        debug!("Allocated IP {} to client {}", ip, client_id);
        
        Ok(ip)
    }
    
    /// Allocate an IP address with a specific lease duration
    pub async fn allocate_ip_with_lease(&self, client_id: &str, lease_duration_secs: u64) -> Result<String, IpPoolError> {
        let mut pool = self.pool.lock().await;
        let ip = pool.allocate_ip(client_id, lease_duration_secs)?;
        
        debug!("Allocated IP {} to client {} with lease {}s", ip, client_id, lease_duration_secs);
        
        Ok(ip)
    }
    
    /// Release an IP address
    pub async fn release_ip(&self, ip: &str) -> Result<(), IpPoolError> {
        let mut pool = self.pool.lock().await;
        pool.release_ip(ip)?;
        
        debug!("Released IP {}", ip);
        
        Ok(())
    }
    
    /// Renew an IP lease
    pub async fn renew_ip(&self, ip: &str) -> Result<u64, IpPoolError> {
        let mut pool = self.pool.lock().await;
        let expires_at = pool.renew_ip(ip, self.default_lease_duration)?;
        
        debug!("Renewed IP {} lease", ip);
        
        Ok(expires_at)
    }
    
    /// Assign a static IP
    pub async fn assign_static_ip(&self, ip: &str, client_id: &str) -> Result<(), IpPoolError> {
        let mut pool = self.pool.lock().await;
        pool.assign_static_ip(ip, client_id)?;
        
        info!("Assigned static IP {} to client {}", ip, client_id);
        
        Ok(())
    }
    
    /// Clean up expired allocations
    pub async fn cleanup_expired(&self) -> Vec<String> {
        let mut pool = self.pool.lock().await;
        let expired = pool.cleanup_expired();
        
        if !expired.is_empty() {
            debug!("Cleaned up {} expired IP allocations", expired.len());
        }
        
        expired
    }
    
    /// Get IP allocation for a client
    pub async fn get_client_allocation(&self, client_id: &str) -> Option<IpAllocation> {
        let pool = self.pool.lock().await;
        pool.get_client_allocation(client_id)
    }
    
    /// Get client IP
    pub async fn get_client_ip(&self, client_id: &str) -> Option<String> {
        let pool = self.pool.lock().await;
        pool.get_client_ip(client_id)
    }
    
    /// Get client for an IP
    pub async fn get_ip_client(&self, ip: &str) -> Option<String> {
        let pool = self.pool.lock().await;
        pool.get_ip_client(ip)
    }
    
    /// Get pool statistics
    pub async fn get_stats(&self) -> (usize, usize, usize) {
        let pool = self.pool.lock().await;
        pool.get_stats()
    }
    
    /// Get network details
    pub async fn get_network_details(&self) -> (String, String, String) {
        let pool = self.pool.lock().await;
        (
            pool.get_network_address(),
            pool.get_subnet_mask(),
            pool.get_broadcast_address(),
        )
    }
    
    /// Get all allocations
    pub async fn get_allocations(&self) -> Vec<IpAllocation> {
        let pool = self.pool.lock().await;
        pool.get_allocations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_pool_basic() {
        let mut pool = IpPool::new("192.168.1.0/24").unwrap();
        
        // Allocate an IP
        let client1 = "client1";
        let ip1 = pool.allocate_ip(client1, 3600).unwrap();
        
        // Should be 192.168.1.3 (skipping network, broadcast, and server IP)
        assert_eq!(ip1, "192.168.1.3");
        
        // Allocate another IP
        let client2 = "client2";
        let ip2 = pool.allocate_ip(client2, 3600).unwrap();
        
        // Should be different
        assert_ne!(ip1, ip2);
        
        // Get client allocation
        let allocation = pool.get_client_allocation(client1).unwrap();
        assert_eq!(allocation.ip_address, ip1);
        
        // Release an IP
        pool.release_ip(&ip1).unwrap();
        
        // Client should no longer have an allocation
        assert!(pool.get_client_allocation(client1).is_none());
        
        // Allocate again, should get the same IP since it was returned to the pool
        let ip1_again = pool.allocate_ip(client1, 3600).unwrap();
        assert_eq!(ip1, ip1_again);
        
        // Assign a static IP
        pool.assign_static_ip("192.168.1.10", "client3").unwrap();
        
        // Check static allocation
        let allocation = pool.get_client_allocation("client3").unwrap();
        assert!(allocation.is_static);
        assert_eq!(allocation.ip_address, "192.168.1.10");
    }
    
    #[tokio::test]
    async fn test_ip_pool_manager() {
        let manager = IpPoolManager::new("10.7.0.0/24", 3600).await.unwrap();
        
        // Allocate IPs
        let ip1 = manager.allocate_ip("client1").await.unwrap();
        let ip2 = manager.allocate_ip("client2").await.unwrap();
        
        // IPs should be different
        assert_ne!(ip1, ip2);
        
        // Get client IP
        let client_ip = manager.get_client_ip("client1").await.unwrap();
        assert_eq!(client_ip, ip1);
        
        // Get IP's client
        let client = manager.get_ip_client(&ip1).await.unwrap();
        assert_eq!(client, "client1");
        
        // Release IP
        manager.release_ip(&ip1).await.unwrap();
        
        // Client should no longer have an IP
        assert!(manager.get_client_ip("client1").await.is_none());
        
        // Get network details
        let (network, mask, broadcast) = manager.get_network_details().await;
        assert_eq!(network, "10.7.0.0");
        assert_eq!(mask, "255.255.255.0");
        assert_eq!(broadcast, "10.7.0.255");
        
        // Get stats
        let (available, allocated, static_count) = manager.get_stats().await;
        assert!(available > 0);
        assert_eq!(allocated, 1); // Only client2 remains
        assert_eq!(static_count, 0);
    }
    
    #[test]
    fn test_ip_pool_cleanup() {
        let mut pool = IpPool::new("192.168.1.0/24").unwrap();
        
        // Allocate with a short lease
        let client = "client";
        let ip = pool.allocate_ip(client, 0).unwrap(); // Expires immediately
        
        // Clean up expired
        let expired = pool.cleanup_expired();
        
        // Should have cleaned up one IP
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], ip);
        
        // Client should no longer have an allocation
        assert!(pool.get_client_allocation(client).is_none());
    }
}
