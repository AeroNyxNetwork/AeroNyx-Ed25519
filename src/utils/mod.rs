// src/utils/mod.rs
//! Utility functions and helpers.
//!
//! This module contains general-purpose utilities used across
//! the application.

pub mod logging;
pub mod security;
pub mod system;

use rand::{distributions::Alphanumeric, Rng, thread_rng};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Get current timestamp in milliseconds
pub fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

/// Check if an Instant has expired given a TTL
pub fn is_expired(timestamp: Instant, ttl: Duration) -> bool {
    timestamp.elapsed() > ttl
}

/// Generate a random alphanumeric string of specified length
pub fn random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate a random delay for jitter
pub fn random_jitter(max_ms: u64) -> Duration {
    let millis = thread_rng().gen_range(0..max_ms);
    Duration::from_millis(millis)
}

/// Convert bytes to a hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

/// Generate random padding bytes
pub fn generate_padding(min_size: usize, max_size: usize) -> Vec<u8> {
    let size = thread_rng().gen_range(min_size..=max_size);
    let mut padding = vec![0u8; size];
    thread_rng().fill(&mut padding[..]);
    padding
}

/// Decide whether to add padding based on probability
pub fn should_add_padding(probability: f32) -> bool {
    thread_rng().gen::<f32>() < probability
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_string() {
        let s1 = random_string(10);
        let s2 = random_string(10);
        
        assert_eq!(s1.len(), 10);
        assert_eq!(s2.len(), 10);
        assert_ne!(s1, s2); // Ensure randomness
    }
    
    #[test]
    fn test_is_expired() {
        let now = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        
        assert!(!is_expired(now, Duration::from_millis(50)));
        assert!(is_expired(now, Duration::from_millis(5)));
    }
    
    #[test]
    fn test_hex_conversion() {
        let original = vec![0, 1, 2, 3, 255];
        let hex = bytes_to_hex(&original);
        let bytes = hex_to_bytes(&hex).unwrap();
        assert_eq!(original, bytes);
    }
    
    #[test]
    fn test_padding() {
        let padding = generate_padding(10, 20);
        assert!(padding.len() >= 10);
        assert!(padding.len() <= 20);
    }
}
