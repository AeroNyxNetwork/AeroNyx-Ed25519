use std::time::Duration;

/// Cryptographic constants
pub const CHALLENGE_SIZE: usize = 32;
pub const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
pub const MAX_SECRET_CACHE_SIZE: usize = 2000; // Increased from 1000 for better performance
pub const SECRET_CACHE_TTL: Duration = Duration::from_secs(600); // 10 minutes, increased from 5
pub const SESSION_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12; // For ChaCha20-Poly1305
pub const TAG_SIZE: usize = 16; // For ChaCha20-Poly1305
pub const PACKET_SIZE_LIMIT: usize = 16384; // 16KB
pub const MIN_PACKET_SIZE: usize = 64; // Minimum size for padding

/// Network constants - Optimized for performance
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60); // Increased from 30 to reduce network overhead
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120); // Increased from 60 to handle slow connections better
pub const TLS_PROTOCOLS: &[&str] = &["TLSv1.3"]; // Only support TLS 1.3 for better security
pub const CIPHER_SUITES: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];
pub const MAX_CONNECTIONS_PER_IP: usize = 10; // Increased from 5 to allow for more legitimate connections
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub const MAX_PACKETS_PER_WINDOW: usize = 2000; // Increased from 1000 for better performance

/// Traffic obfuscation constants - Optimized settings
pub const ENABLE_TRAFFIC_PADDING: bool = true;
pub const PAD_PROBABILITY: f32 = 0.1; // Reduced from 0.2 to decrease overhead while maintaining security
pub const MIN_PADDING_SIZE: usize = 16;
pub const MAX_PADDING_SIZE: usize = 128; // Reduced from 256 to improve performance
pub const JITTER_MAX_MS: u64 = 50; // Reduced from 100ms to decrease latency

/// IP allocation - Optimized for longer sessions
pub const IP_LEASE_DURATION: Duration = Duration::from_hours(24);
pub const IP_RENEWAL_THRESHOLD: Duration = Duration::from_hours(22); // Changed from 20 to reduce renewal overhead

/// Access control
pub const ACCESS_CONTROL_ENABLED: bool = true;
pub const ACCESS_CONTROL_FILE: &str = "access_control.json";

/// Logging
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Performance optimizations
pub const SOCKET_BUFFER_SIZE: usize = 1048576; // 1MB buffer size
pub const TUN_MTU: u16 = 1500; // Default MTU size
pub const WORK_STEALING_THREADS: usize = 8; // Number of work-stealing threads for async operations
pub const PACKET_READ_BUFFER_SIZE: usize = 2048; // Buffer size for packet reads

/// Security enhancements
pub const AUTH_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(30); // 30 seconds for challenge completion
pub const MAX_AUTH_ATTEMPTS: usize = 3; // Maximum authentication attempts per connection
pub const SERVER_SIGNATURE_VERIFY_ENABLED: bool = true; // Enable verification of server signatures
pub const HMAC_VERIFY_ENABLED: bool = true; // Enable HMAC verification
pub const REPLAY_PROTECTION_ENABLED: bool = true; // Enable replay attack protection
pub const MAX_PACKET_COUNTER_SKEW: u64 = 100; // Maximum allowed packet counter skew

/// Extension methods for Duration
pub trait DurationExt {
    fn from_hours(hours: u64) -> Self;
}

impl DurationExt for Duration {
    fn from_hours(hours: u64) -> Self {
        Duration::from_secs(hours * 3600)
    }
}

// Helper methods for testing
#[cfg(test)]
pub mod test {
    use super::*;
    
    pub const TEST_CHALLENGE_SIZE: usize = 16;
    pub const TEST_SESSION_TTL: Duration = Duration::from_secs(5);
}
