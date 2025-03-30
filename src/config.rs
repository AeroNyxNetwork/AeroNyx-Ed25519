use std::time::Duration;

/// Cryptographic constants
pub const CHALLENGE_SIZE: usize = 32;
pub const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
pub const MAX_SECRET_CACHE_SIZE: usize = 1000;
pub const SECRET_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
pub const SESSION_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12; // For ChaCha20-Poly1305
pub const TAG_SIZE: usize = 16; // For ChaCha20-Poly1305
pub const PACKET_SIZE_LIMIT: usize = 16384; // 16KB
pub const MIN_PACKET_SIZE: usize = 64; // Minimum size for padding

/// Network constants
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
pub const TLS_PROTOCOLS: &[&str] = &["TLSv1.3"];
pub const CIPHER_SUITES: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];
pub const MAX_CONNECTIONS_PER_IP: usize = 5;
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub const MAX_PACKETS_PER_WINDOW: usize = 1000;

/// Traffic obfuscation constants
pub const ENABLE_TRAFFIC_PADDING: bool = true;
pub const PAD_PROBABILITY: f32 = 0.2; // 20% chance of padding
pub const MIN_PADDING_SIZE: usize = 16;
pub const MAX_PADDING_SIZE: usize = 256;
pub const JITTER_MAX_MS: u64 = 100; // Maximum jitter in milliseconds

/// IP allocation
pub const IP_LEASE_DURATION: Duration = Duration::from_hours(24);
pub const IP_RENEWAL_THRESHOLD: Duration = Duration::from_hours(20);

/// Access control
pub const ACCESS_CONTROL_ENABLED: bool = true;
pub const ACCESS_CONTROL_FILE: &str = "access_control.json";

/// Logging
pub const DEFAULT_LOG_LEVEL: &str = "info";

// Helper methods for testing
#[cfg(test)]
pub mod test {
    use super::*;
    
    pub const TEST_CHALLENGE_SIZE: usize = 16;
    pub const TEST_SESSION_TTL: Duration = Duration::from_secs(5);
}
