use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rand::{Rng, thread_rng};
use crate::config;
use crate::types::Result;
use crate::types::VpnError;

/// Generate a random delay for jitter
pub fn random_jitter() -> Duration {
    let millis = thread_rng().gen_range(0..config::JITTER_MAX_MS);
    Duration::from_millis(millis)
}

/// Generate random padding bytes
pub fn generate_padding(min_size: usize, max_size: usize) -> Vec<u8> {
    let size = thread_rng().gen_range(min_size..=max_size);
    let mut padding = vec![0u8; size];
    thread_rng().fill(&mut padding[..]);
    padding
}

/// Decide whether to add padding based on probability
pub fn should_add_padding() -> bool {
    thread_rng().gen::<f32>() < config::PAD_PROBABILITY
}

/// Generate padding if enabled and probability hits
pub fn maybe_add_padding() -> Vec<u8> {
    if config::ENABLE_TRAFFIC_PADDING && should_add_padding() {
        generate_padding(config::MIN_PADDING_SIZE, config::MAX_PADDING_SIZE)
    } else {
        Vec::new()
    }
}

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
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut thread_rng(), length)
}

/// Convert bytes to a hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).map_err(|e| VpnError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_jitter() {
        let jitter = random_jitter();
        assert!(jitter.as_millis() <= config::JITTER_MAX_MS as u128);
    }
    
    #[test]
    fn test_generate_padding() {
        let min_size = 10;
        let max_size = 20;
        let padding = generate_padding(min_size, max_size);
        assert!(padding.len() >= min_size && padding.len() <= max_size);
    }
    
    #[test]
    fn test_is_expired() {
        let now = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        assert!(!is_expired(now, Duration::from_millis(20)));
        assert!(is_expired(now, Duration::from_millis(5)));
    }
    
    #[test]
    fn test_hex_conversion() {
        let original = vec![0, 1, 2, 3, 255];
        let hex = bytes_to_hex(&original);
        let bytes = hex_to_bytes(&hex).unwrap();
        assert_eq!(original, bytes);
    }
}
