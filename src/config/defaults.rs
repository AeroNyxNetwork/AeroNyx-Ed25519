// src/config/defaults.rs
//! Default configurations for the AeroNyx Privacy Network Server.
//!
//! This module provides sensible default values for configuration settings
//! when not explicitly specified by the user.

/// Default server listening port
pub const DEFAULT_PORT: u16 = 8080;

/// Default server listening address
pub const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0";

/// Default TUN device name
pub const DEFAULT_TUN_NAME: &str = "tun0";

/// Default subnet for VPN clients
pub const DEFAULT_SUBNET: &str = "10.7.0.0/24";

/// Default log level
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Default TLS certificate file
pub const DEFAULT_CERT_FILE: &str = "server.crt";

/// Default TLS key file
pub const DEFAULT_KEY_FILE: &str = "server.key";

/// Default access control list file
pub const DEFAULT_ACL_FILE: &str = "access_control.json";

/// Default traffic obfuscation method
pub const DEFAULT_OBFUSCATION_METHOD: &str = "xor";

/// Default key rotation interval in seconds
pub const DEFAULT_KEY_ROTATION_INTERVAL: u64 = 3600; // 1 hour

/// Default session timeout in seconds
pub const DEFAULT_SESSION_TIMEOUT: u64 = 86400; // 24 hours

/// Default maximum connections per IP
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 5;

/// Default data directory
pub const DEFAULT_DATA_DIR: &str = "/var/lib/aeronyx";

/// Default key file
pub const DEFAULT_SERVER_KEY_FILE: &str = "server_keypair.json";

/// Default reconnection attempts
pub const DEFAULT_RECONNECT_ATTEMPTS: u8 = 3;
