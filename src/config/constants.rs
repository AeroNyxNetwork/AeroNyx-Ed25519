// src/config/constants.rs
//! Application constants and fixed settings.
//!
//! This module contains fixed values that are used throughout the application,
//! such as timeouts, buffer sizes, and security parameters.

use std::time::Duration;

/// Cryptographic constants
pub const CHALLENGE_SIZE: usize = 32;
pub const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
pub const MAX_SECRET_CACHE_SIZE: usize = 2000;
pub const SECRET_CACHE_TTL: Duration = Duration::from_secs(600); // 10 minutes
pub const SESSION_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12; // For ChaCha20-Poly1305
pub const TAG_SIZE: usize = 16; // For ChaCha20-Poly1305
pub const PACKET_SIZE_LIMIT: usize = 16384; // 16KB
pub const MIN_PACKET_SIZE: usize = 64; // Minimum size for padding

/// Authentication challenge timeout (30 seconds)
pub const AUTH_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Network constants
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);
pub const TLS_PROTOCOLS: &[&str] = &["TLSv1.3"]; // Only support TLS 1.3 for better security
pub const CIPHER_SUITES: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];
pub const MAX_CONNECTIONS_PER_IP: usize = 10;
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub const MAX_PACKETS_PER_WINDOW: usize = 2000;

/// Traffic obfuscation constants
pub const ENABLE_TRAFFIC_PADDING: bool = true;
pub const PAD_PROBABILITY: f32 = 0.1;
pub const MIN_PADDING_SIZE: usize = 16;
pub const MAX_PADDING_SIZE: usize = 128;
pub const JITTER_MAX_MS: u64 = 50;

/// IP allocation constants
pub const IP_LEASE_DURATION_SECS: u64 = 86400; // 24 hours
pub const IP_RENEWAL_THRESHOLD_SECS: u64 = 79200; // 22 hours

/// Access control
pub const ACCESS_CONTROL_ENABLED: bool = true;
pub const ACCESS_CONTROL_FILE: &str = "access_control.json";

/// Logging
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Performance optimizations
pub const SOCKET_BUFFER_SIZE: usize = 1048576; // 1MB buffer size
pub const TUN_MTU: u16 = 1500; // Default MTU size
pub const PACKET_READ_BUFFER_SIZE: usize = 2048; // Buffer size for packet reads

/// Security settings
pub const AUTH_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_AUTH_ATTEMPTS: usize = 3;
pub const SERVER_SIGNATURE_VERIFY_ENABLED: bool = true;
pub const HMAC_VERIFY_ENABLED: bool = true;
pub const REPLAY_PROTECTION_ENABLED: bool = true;
pub const MAX_PACKET_COUNTER_SKEW: u64 = 100;

/// Get durations as functions to avoid constant Duration construction issues
pub fn get_ip_lease_duration() -> Duration {
    Duration::from_secs(IP_LEASE_DURATION_SECS)
}

pub fn get_ip_renewal_threshold() -> Duration {
    Duration::from_secs(IP_RENEWAL_THRESHOLD_SECS)
}

/// Test helpers
#[cfg(test)]
pub mod test {
    use super::*;
    
    pub const TEST_CHALLENGE_SIZE: usize = 16;
    pub const TEST_SESSION_TTL: Duration = Duration::from_secs(5);
}
