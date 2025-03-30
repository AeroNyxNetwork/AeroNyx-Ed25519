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

/// Rate limiting tracker for connections
#[derive(Debug)]
pub struct RateLimiter {
    /// Map of IP to (count, first_seen)
    connections: Arc<Mutex<HashMap<IpAddr, (usize, Instant)>>>,
    /// Maximum connections per window
    max_connections: usize,
    /// Time window for rate limiting
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_connections: usize, window: Duration) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_connections,
            window,
        }
    }
    
    /// Check if an IP address should be rate limited
    pub async fn check_rate_limit(&self, ip: &IpAddr) -> bool {
        let mut connections = self.connections.lock().await;
        
        let now = Instant::now();
        
        // Clean up expired entries
        connections.retain(|_, (_, first_seen)| {
            now.duration_since(*first_seen) < self.window
        });
        
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
            log_security_event(
                "RATE_LIMIT_EXCEEDED",
                &format!("IP {} exceeded connection rate limit", ip)
            );
            debug!("Rate limit exceeded for IP: {}", ip);
            false
        } else {
            true
        }
    }
    
    /// Reset rate limit for an IP address
    pub async fn reset_limit(&self, ip: &IpAddr) {
        let mut connections = self.connections.lock().await;
        connections.remove(ip);
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
