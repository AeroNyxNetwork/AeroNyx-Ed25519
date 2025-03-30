// src/utils/security.rs
//! Security utilities for the application.
//!
//! This module provides functions for security-related operations
//! such as rate limiting, input validation, and secure defaults.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{warn, debug};

use crate::utils::logging::log_security_event;

/// Rate limiting tracker for connections with optimized performance
#[derive(Debug)]
pub struct RateLimiter {
    /// Map of IP to (count, first_seen) with sharded locks for reduced contention
    connections: Vec<Arc<Mutex<HashMap<IpAddr, (usize, Instant)>>>>,
    /// Maximum connections per window
    max_connections: usize,
    /// Time window for rate limiting
    window: Duration,
    /// Cleanup interval to avoid checking on every request
    cleanup_interval: Duration,
    /// Last cleanup timestamp per shard
    last_cleanup: Arc<Vec<Mutex<Instant>>>,
}

impl RateLimiter {
    /// Create a new rate limiter with improved performance
    pub fn new(max_connections: usize, window: Duration) -> Self {
        // Use multiple shards to reduce lock contention
        const SHARD_COUNT: usize = 16;
        
        let mut connections = Vec::with_capacity(SHARD_COUNT);
        let mut last_cleanup = Vec::with_capacity(SHARD_COUNT);
        let now = Instant::now();
        
        for _ in 0..SHARD_COUNT {
            connections.push(Arc::new(Mutex::new(HashMap::new())));
            last_cleanup.push(Mutex::new(now));
        }
        
        Self {
            connections,
            max_connections,
            window,
            // Only clean up at most once per second
            cleanup_interval: Duration::from_secs(1),
            last_cleanup: Arc::new(last_cleanup),
        }
    }
    
    /// Get the shard index for an IP address
    #[inline]
    fn get_shard_index(&self, ip: &IpAddr) -> usize {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                // Use the last octet for sharding
                (octets[3] as usize) % self.connections.len()
            },
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                // Use the last segment for sharding
                (segments[7] as usize) % self.connections.len()
            },
        }
    }
    
    /// Check if an IP address should be rate limited with improved efficiency
    pub async fn check_rate_limit(&self, ip: &IpAddr) -> bool {
        let shard_idx = self.get_shard_index(ip);
        let connections_shard = &self.connections[shard_idx];
        let mut connections = connections_shard.lock().await;
        
        let now = Instant::now();
        
        // Periodically clean up expired entries instead of on every request
        let mut last_cleanup = self.last_cleanup[shard_idx].lock().await;
        if now.duration_since(*last_cleanup) >= self.cleanup_interval {
            connections.retain(|_, (_, first_seen)| {
                now.duration_since(*first_seen) < self.window
            });
            *last_cleanup = now;
        }
        
        // Check and update rate for this IP
        let entry = connections.entry(*ip).or_insert((0, now));
        
        // Reset counter if it's been more than the window
        if now.duration_since(entry.1) >= self.window {
            *entry = (1, now);
            return true;
        }
        
        // Increment counter and check limit
        entry.0 += 1;
        
        if entry.0 > self.max_connections {
            // Use structured logging with additional metadata
            log_security_event(
                "RATE_LIMIT_EXCEEDED",
                &format!("IP {} exceeded rate limit of {} connections per {:?}", 
                          ip, self.max_connections, self.window)
            );
            
            debug!(
                ip = %ip,
                count = entry.0,
                limit = self.max_connections,
                window = ?self.window,
                "Rate limit exceeded"
            );
            
            false
        } else {
            true
        }
    }
    
    /// Reset rate limit for an IP address
    pub async fn reset_limit(&self, ip: &IpAddr) {
        let shard_idx = self.get_shard_index(ip);
        let mut connections = self.connections[shard_idx].lock().await;
        connections.remove(ip);
    }
    
    /// Get current connection count for an IP (useful for testing/monitoring)
    pub async fn get_connection_count(&self, ip: &IpAddr) -> Option<usize> {
        let shard_idx = self.get_shard_index(ip);
        let connections = self.connections[shard_idx].lock().await;
        
        connections.get(ip).map(|(count, _)| *count)
    }
}

/// Security-related string validation utilities
pub struct StringValidator;

impl StringValidator {
    /// Check if a string is a valid Solana public key
    pub fn is_valid_solana_pubkey(key: &str) -> bool {
        // Basic validation for Solana public keys
        // They are base58 encoded and 32-44 characters long
        if key.len() < 32 || key.len() > 44 {
            return false;
        }
        
        // Check if it contains only valid base58 characters
        key.chars().all(|c| {
            (c >= 'a' && c <= 'z') || 
            (c >= 'A' && c <= 'Z' && c != 'I' && c != 'O') || 
            (c >= '1' && c <= '9')
        })
    }
    
    /// Sanitize a log message to prevent log injection
    pub fn sanitize_log(input: &str) -> String {
        input.replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }
    
    /// Sanitize an identifier to ensure it only contains safe characters
    pub fn sanitize_identifier(input: &str) -> String {
        input.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect()
    }
}

/// Attempt to detect potentially malicious patterns
pub fn detect_attack_patterns(data: &[u8]) -> Option<String> {
    // Check for unusually large packets
    if data.len() > 16384 {
        return Some("Unusually large packet".to_string());
    }
    
    // Simple heuristic for potential shellcode
    // Real implementations would use more sophisticated pattern matching
    if data.len() > 20 {
        let mut consecutive_nonascii = 0;
        for &byte in data {
            if byte < 32 || byte > 126 {
                consecutive_nonascii += 1;
                if consecutive_nonascii > 15 {
                    return Some("Potential shellcode pattern detected".to_string());
                }
            } else {
                consecutive_nonascii = 0;
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(3, Duration::from_secs(1));
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        
        // First 3 attempts should succeed
        assert!(limiter.check_rate_limit(&ip).await);
        assert!(limiter.check_rate_limit(&ip).await);
        assert!(limiter.check_rate_limit(&ip).await);
        
        // Fourth attempt should fail
        assert!(!limiter.check_rate_limit(&ip).await);
        
        // Reset and try again
        limiter.reset_limit(&ip).await;
        assert!(limiter.check_rate_limit(&ip).await);
    }
    
    #[tokio::test]
    async fn test_rate_limiter_sharding() {
        let limiter = RateLimiter::new(5, Duration::from_secs(1));
        
        // Test IPv4 sharding
        let ip1 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let ip2 = "192.168.1.2".parse::<IpAddr>().unwrap();
        
        // These should go to different shards
        assert!(limiter.get_shard_index(&ip1) != limiter.get_shard_index(&ip2));
        
        // Test IPv6 sharding
        let ip3 = "2001:db8::1".parse::<IpAddr>().unwrap();
        let ip4 = "2001:db8::2".parse::<IpAddr>().unwrap();
        
        // These should also go to different shards
        assert!(limiter.get_shard_index(&ip3) != limiter.get_shard_index(&ip4));
    }
    
    #[tokio::test]
    async fn test_cleanup_interval() {
        let limiter = RateLimiter::new(10, Duration::from_millis(50));
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        
        // Add an entry
        assert!(limiter.check_rate_limit(&ip).await);
        
        // Verify it exists
        assert_eq!(limiter.get_connection_count(&ip).await, Some(1));
        
        // Wait for longer than the window but less than cleanup interval
        tokio::time::sleep(Duration::from_millis(60)).await;
        
        // The entry should still exist because cleanup hasn't run yet
        assert_eq!(limiter.get_connection_count(&ip).await, Some(1));
        
        // But when we check again, it should reset the counter due to being past the window
        assert!(limiter.check_rate_limit(&ip).await);
        assert_eq!(limiter.get_connection_count(&ip).await, Some(1));
        
        // Now wait for longer than the cleanup interval
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // The cleanup should have removed the entry by now
        // But we'll need to trigger a cleanup by calling check_rate_limit
        assert!(limiter.check_rate_limit(&ip).await);
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Now check that we're back to 1 (not accumulating across expired windows)
        assert_eq!(limiter.get_connection_count(&ip).await, Some(1));
    }
    
    #[test]
    fn test_is_valid_solana_pubkey() {
        // Valid-looking pubkey (this is just an example, not an actual pubkey)
        assert!(StringValidator::is_valid_solana_pubkey(
            "AiUYgGCmQxtYbboLnNer8nY3Lnkarn3awthiCgqMkwkp"
        ));
        
        // Too short
        assert!(!StringValidator::is_valid_solana_pubkey("abc123"));
        
        // Contains invalid characters for base58
        assert!(!StringValidator::is_valid_solana_pubkey(
            "AiUYgGCmQxtYbboLnNer8nY3Lnkarn3awthiCgqMkwkp0"
        ));
    }
    
    #[test]
    fn test_sanitize_log() {
        assert_eq!(
            StringValidator::sanitize_log("hello\nworld"),
            "hello\\nworld"
        );
        assert_eq!(
            StringValidator::sanitize_log("tab\there"),
            "tab\\there"
        );
    }
    
    #[test]
    fn test_detect_attack_patterns() {
        // Normal text data
        let normal_data = b"This is a normal text data packet";
        assert!(detect_attack_patterns(normal_data).is_none());
        
        // Potential shellcode with many non-ASCII bytes
        let mut suspicious_data = Vec::new();
        for _ in 0..20 {
            suspicious_data.push(0x90); // NOP sled
        }
        assert!(detect_attack_patterns(&suspicious_data).is_some());
    }
}
