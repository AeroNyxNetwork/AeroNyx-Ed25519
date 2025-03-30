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

/// IP address pool manager
#[derive(Debug)]
pub struct IpPoolManager {
    /// Available IP addresses
    available_ips: Arc<Mutex<VecDeque<String>>>,
    /// Allocated IP addresses with metadata
    allocated_ips: Arc<Mutex<HashMap<String, IpAllocation>>>,
    /// Subnet range
    subnet: Ipv4Network,
    /// Default lease duration in seconds
    default_lease_duration: u64,
}

impl IpPoolManager {
    /// Create a new IP pool manager
    pub async fn new(subnet: &str, default_lease_duration: u64) -> Result<Self, IpPoolError> {
        // Parse the subnet
        let network = Ipv4Network::from_str(subnet)
            .map_err(|e| IpPoolError::InvalidSubnet(e.to_string()))?;
        
        // Generate pool of available IPs
        let available_ips = generate_ip_pool(&network)?;
        
        Ok(Self {
            available_ips: Arc::new(Mutex::new(available_ips)),
            allocated_ips: Arc::new(Mutex::new(HashMap::new())),
            subnet: network,
            default_lease_duration,
        })
    }
    
    /// Allocate an IP address
    pub async fn allocate_ip(&self, client_id: &str) -> Result<String, IpPoolError> {
        // First check if this client already has an allocation
        {
            let allocated = self.allocated_ips.lock().await;
            for (ip, allocation) in allocated.iter() {
                if allocation.client_id == client_id {
                    return Ok(ip.clone());
                }
            }
        }
        
        // Check if there's a static allocation for this client
        // This would need to be implemented based on your static allocation storage method
        
        // Allocate from the dynamic pool
        let mut available = self.available_ips.lock().await;
        if let Some(ip) = available.pop_front() {
            let now = utils::current_timestamp_millis();
            let expires_at = now + (self.default_lease_duration * 1000);
            
            let allocation = IpAllocation {
                ip_address: ip.clone(),
                client_id: client_id.to_string(),
                expires_at,
                is_static: false,
            };
            
            let mut allocated = self.allocated_ips.lock().await;
            allocated.insert(ip.clone(), allocation);
            
            debug!("Allocated IP {} to client {}", ip, client_id);
            Ok(ip)
        } else {
            warn!("IP pool exhausted, cannot allocate IP for client {}", client_id);
            Err(IpPoolError::PoolExhausted)
        }
    }
    
    /// Allocate an IP address with a specific lease duration
    pub async fn allocate_ip_with_lease(&self, client_id: &str, lease_duration_secs: u64) -> Result<String, IpPoolError> {
        // First check if this client already has an allocation
        {
            let allocated = self.allocated_ips.lock().await;
            for (ip, allocation) in allocated.iter() {
                if allocation.client_id == client_id {
                    return Ok(ip.clone());
                }
            }
        }
        
        // Allocate from the dynamic pool
        let mut available = self.available_ips.lock().await;
        if let Some(ip) = available.pop_front() {
            let now = utils::current_timestamp_millis();
            let expires_at = now + (lease_duration_secs * 1000);
            
            let allocation = IpAllocation {
                ip_address: ip.clone(),
                client_id: client_id.to_string(),
                expires_at,
                is_static: false,
            };
            
            let mut allocated = self.allocated_ips.lock().await;
            allocated.insert(ip.clone(), allocation);
            
            debug!("Allocated IP {} to client {} with lease {}s", ip, client_id, lease_duration_secs);
            Ok(ip)
        } else {
            warn!("IP pool exhausted, cannot allocate IP for client {}", client_id);
            Err(IpPoolError::PoolExhausted)
        }
    }
    
    /// Release an IP address
    pub async fn release_ip(&self, ip: &str) -> Result<(), IpPoolError> {
        let mut allocated = self.allocated_ips.lock().await;
        if let Some(allocation) = allocated.remove(ip) {
            if !allocation.is_static {
                let mut available = self.available_ips.lock().await;
                available.push_back(ip.to_string());
                debug!("Released IP {} (previously allocated to {})", ip, allocation.client_id);
            }
            Ok(())
        } else {
            Err(IpPoolError::NotAllocated(ip.to_string()))
        }
    }
    
    /// Renew an IP lease
    pub async fn renew_ip(&self, ip: &str) -> Result<u64, IpPoolError> {
        let mut allocated = self.allocated_ips.lock().await;
        
        if let Some(allocation) = allocated.get_mut(ip) {
            let now = utils::current_timestamp_millis();
            let expires_at = now + (self.default_lease_duration * 1000);
            allocation.expires_at = expires_at;
            
            debug!("Renewed IP {} lease for client {}", ip, allocation.client_id);
            Ok(expires_at)
        } else {
            Err(IpPoolError::NotAllocated(ip.to_string()))
        }
    }
    
    /// Renew an IP lease with a specific duration
    pub async fn renew_ip_with_lease(&self, ip: &str, lease_duration_secs: u64) -> Result<u64, IpPoolError> {
        let mut allocated = self.allocated_ips.lock().await;
        
        if let Some(allocation) = allocated.get_mut(ip) {
            let now = utils::current_timestamp_millis();
            let expires_at = now + (lease_duration_secs * 1000);
            allocation.expires_at = expires_at;
            
            debug!("Renewed IP {} lease for client {} with duration {}s", 
                  ip, allocation.client_id, lease_duration_secs);
            Ok(expires_at)
        } else {
            Err(IpPoolError::NotAllocated(ip.to_string()))
        }
    }
    
    /// Assign a static IP
    pub async fn assign_static_ip(&self, ip: &str, client_id: &str) -> Result<(), IpPoolError> {
        // Check if IP is in our subnet
        let ip_addr = Ipv4Addr::from_str(ip)
            .map_err(|e| IpPoolError::InvalidSubnet(e.to_string()))?;
            
        if !self.subnet.contains(ip_addr) {
            return Err(IpPoolError::InvalidSubnet(format!(
                "IP {} is not in subnet {}", ip, self.subnet
            )));
        }
        
        let mut allocated = self.allocated_ips.lock().await;
        
        // Check if IP is already allocated
        if let Some(allocation) = allocated.get(ip) {
            if allocation.client_id != client_id {
                return Err(IpPoolError::AlreadyAllocated(format!(
                    "IP {} is already allocated to client {}", 
                    ip, allocation.client_id
                )));
            }
            
            // Already allocated to this client, just make it static
            let mut allocation = allocation.clone();
            allocation.is_static = true;
            allocated.insert(ip.to_string(), allocation);
            
            debug!("Changed IP {} allocation for client {} to static", ip, client_id);
            return Ok(());
        }
        
        // Remove from available pool if present
        {
            let mut available = self.available_ips.lock().await;
            let index = available.iter().position(|available_ip| available_ip == ip);
            if let Some(idx) = index {
                available.remove(idx);
            }
        }
        
        // Create a static allocation
        let allocation = IpAllocation {
            ip_address: ip.to_string(),
            client_id: client_id.to_string(),
            expires_at: u64::MAX, // Never expires
            is_static: true,
        };
        
        allocated.insert(ip.to_string(), allocation);
        
        info!("Assigned static IP {} to client {}", ip, client_id);
        Ok(())
    }
    
    /// Clean up expired allocations
    pub async fn cleanup_expired(&self) -> Vec<String> {
        let now = utils::current_timestamp_millis();
        let mut to_release = Vec::<String>::new();
        
        // Find expired allocations
        {
            let allocated = self.allocated_ips.lock().await;
            for (ip, allocation) in allocated.iter() {
                if !allocation.is_static && allocation.expires_at < now {
                    to_release.push(ip.clone());
                }
            }
        }
        
        // Release expired IPs
        for ip in &to_release {
            if let Err(e) = self.release_ip(ip).await {
                warn!("Error releasing expired IP {}: {}", ip, e);
            }
        }
        
        if !to_release.is_empty() {
            debug!("Cleaned up {} expired IP allocations", to_release.len());
        }
        
        to_release
    }
    
    /// Get client allocation
    pub async fn get_client_allocation(&self, client_id: &str) -> Option<IpAllocation> {
        let allocated = self.allocated_ips.lock().await;
        for allocation in allocated.values() {
            if allocation.client_id == client_id {
                return Some(allocation.clone());
            }
        }
        None
    }
    
    /// Get client IP
    pub async fn get_client_ip(&self, client_id: &str) -> Option<String> {
        let allocated = self.allocated_ips.lock().await;
        for (ip, allocation) in allocated.iter() {
            if allocation.client_id == client_id {
                return Some(ip.clone());
            }
        }
        None
    }
    
    /// Get client for an IP
    pub async fn get_ip_client(&self, ip: &str) -> Option<String> {
        let allocated = self.allocated_ips.lock().await;
        allocated.get(ip).map(|a| a.client_id.clone())
    }
    
    /// Get pool statistics
    pub async fn get_stats(&self) -> (usize, usize, usize) {
        let available = self.available_ips.lock().await;
        let allocated = self.allocated_ips.lock().await;
        
        let available_count = available.len();
        let allocated_count = allocated.len();
        let static_count = allocated.values()
            .filter(|a| a.is_static)
            .count();
            
        (available_count, allocated_count, static_count)
    }
    
    /// Get network details
    pub async fn get_network_details(&self) -> (String, String, String) {
        (
            self.subnet.network().to_string(),
            format!("{}", Ipv4Addr::from(self.subnet.mask())),
            self.subnet.broadcast().to_string(),
        )
    }
    
    /// Get all allocations
    pub async fn get_allocations(&self) -> Vec<IpAllocation> {
        let allocated = self.allocated_ips.lock().await;
        allocated.values().cloned().collect()
    }
}

/// Generate IP pool from CIDR subnet
fn generate_ip_pool(network: &Ipv4Network) -> Result<VecDeque<String>, IpPoolError> {
    // Calculate usable host addresses (excluding network and broadcast)
    let mut pool = VecDeque::new();
    
    // Skip the first IP (network address) and the second IP (usually server IP)
    let mut host_count = 0;
    
    for ip in network.iter() {
        host_count += 1;
        
        // Skip network address (.0), server address (.1), and broadcast address (last)
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
        return Err(IpPoolError::InvalidSubnet("Subnet too small".to_string()));
    }
    
    info!("Generated IP pool with {} addresses from subnet {}", pool.len(), network);
    
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ip_pool_basic() {
        let pool_manager = IpPoolManager::new("192.168.1.0/24", 3600).await.unwrap();
        
        // Allocate an IP
        let client1 = "client1";
        let ip1 = pool_manager.allocate_ip(client1).await.unwrap();
        
        // Should be 192.168.1.2 or higher (skipping .0 and .1)
        assert!(ip1.starts_with("192.168.1."));
        let last_octet = ip1.split('.').last().unwrap().parse::<u32>().unwrap();
        assert!(last_octet >= 2);
        
        // Allocate another IP
        let client2 = "client2";
        let ip2 = pool_manager.allocate_ip(client2).await.unwrap();
        
        // Should be different
        assert_ne!(ip1, ip2);
        
        // Get client allocation
        let allocation = pool_manager.get_client_allocation(client1).await.unwrap();
        assert_eq!(allocation.ip_address, ip1);
        
        // Release an IP
        pool_manager.release_ip(&ip1).await.unwrap();
        
        // Client should no longer have an allocation
        assert!(pool_manager.get_client_allocation(client1).await.is_none());
        
        // Stats should show available IPs
        let (available, allocated, static_count) = pool_manager.get_stats().await;
        assert!(available > 0);
        assert_eq!(allocated, 1); // Only client2 remains
        assert_eq!(static_count, 0);
    }
    
    #[tokio::test]
    async fn test_static_ip_allocation() {
        let pool_manager = IpPoolManager::new("10.0.0.0/24", 3600).await.unwrap();
        
        // Assign a static IP
        let client = "static-client";
        let static_ip = "10.0.0.100";
        pool_manager.assign_static_ip(static_ip, client).await.unwrap();
        
        // Get allocation
        let allocation = pool_manager.get_client_allocation(client).await.unwrap();
        assert_eq!(allocation.ip_address, static_ip);
        assert!(allocation.is_static);
        
        // Try to allocate for the same client
        let ip = pool_manager.allocate_ip(client).await.unwrap();
        
        // Should get the same static IP
        assert_eq!(ip, static_ip);
        
        // Static IPs should persist after cleanup
        pool_manager.cleanup_expired().await;
        let allocation = pool_manager.get_client_allocation(client).await.unwrap();
        assert_eq!(allocation.ip_address, static_ip);
        assert!(allocation.is_static);
    }
    
    #[tokio::test]
    async fn test_ip_lease_renewal() {
        let pool_manager = IpPoolManager::new("172.16.0.0/24", 10).await.unwrap();
        
        // Allocate IP with short lease
        let client = "temp-client";
        let ip = pool_manager.allocate_ip(client).await.unwrap();
        
        // Get original expiration
        let allocation = pool_manager.get_client_allocation(client).await.unwrap();
        let original_expiry = allocation.expires_at;
        
        // Wait a bit
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Renew with longer lease
        let new_expiry = pool_manager.renew_ip_with_lease(&ip, 60).await.unwrap();
        
        // Should have a later expiration time
        assert!(new_expiry > original_expiry);
        
        // Check allocation was updated
        let allocation = pool_manager.get_client_allocation(client).await.unwrap();
        assert_eq!(allocation.expires_at, new_expiry);
    }
    
    #[tokio::test]
    async fn test_subnet_validation() {
        // Valid subnet
        assert!(IpPoolManager::new("192.168.1.0/24", 3600).await.is_ok());
        
        // Invalid subnet format
        assert!(IpPoolManager::new("not-a-subnet", 3600).await.is_err());
        
        // Subnet too small (e.g., single IP)
        assert!(IpPoolManager::new("192.168.1.1/32", 3600).await.is_err());
    }
}
