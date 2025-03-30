// src/protocol/types.rs
//! Protocol message types for client-server communication.
//!
//! This module defines the message types used in the AeroNyx Privacy Network
//! protocol for authentication, key exchange, and data transfer.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for protocol message handling
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Invalid field value: {0}")]
    InvalidValue(String),
    
    #[error("Message too large")]
    MessageTooLarge,
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),
    
    #[error("Protocol version mismatch: client {0}, server {1}")]
    VersionMismatch(String, String),
}

/// Packet types for client-server communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PacketType {
    /// Authentication request
    Auth {
        /// Client public key
        public_key: String,
        /// Client version
        version: String,
        /// Supported features
        features: Vec<String>,
        /// Nonce for security
        nonce: String,
    },
    
    /// Challenge for authentication
    Challenge {
        /// Challenge data to sign
        data: Vec<u8>,
        /// Server public key
        server_key: String,
        /// Challenge expiration timestamp
        expires_at: u64,
        /// Challenge ID
        id: String,
    },
    
    /// Challenge response
    ChallengeResponse {
        /// Signature of the challenge
        signature: String,
        /// Client public key
        public_key: String,
        /// Challenge ID
        challenge_id: String,
    },
    
    /// IP assignment
    IpAssign {
        /// Assigned IP address
        ip_address: String,
        /// Lease duration in seconds
        lease_duration: u64,
        /// Session ID
        session_id: String,
        /// Encrypted session key
        encrypted_session_key: Vec<u8>,
        /// Nonce for key encryption
        key_nonce: Vec<u8>,
    },
    
    /// Encrypted data packet
    Data {
        /// Encrypted packet data
        encrypted: Vec<u8>,
        /// Encryption nonce
        nonce: Vec<u8>,
        /// Packet counter for replay protection
        counter: u64,
        /// Optional padding data
        padding: Option<Vec<u8>>,
    },
    
    /// Ping message for latency measurement and keepalive
    Ping {
        /// Timestamp
        timestamp: u64,
        /// Sequence number
        sequence: u64,
    },
    
    /// Pong response
    Pong {
        /// Echo timestamp
        echo_timestamp: u64,
        /// Server timestamp
        server_timestamp: u64,
        /// Sequence number
        sequence: u64,
    },
    
    /// Session key rotation
    KeyRotation {
        /// Encrypted new key
        encrypted_new_key: Vec<u8>,
        /// Encryption nonce
        nonce: Vec<u8>,
        /// Key ID
        key_id: String,
        /// Signature for verification
        signature: String,
    },
    
    /// IP renewal request
    IpRenewal {
        /// Session ID
        session_id: String,
        /// Current IP address
        ip_address: String,
    },
    
    /// IP renewal response
    IpRenewalResponse {
        /// Session ID
        session_id: String,
        /// New lease expiration timestamp
        expires_at: u64,
        /// Success flag
        success: bool,
    },
    
    /// Disconnect notification
    Disconnect {
        /// Reason code
        reason: u16,
        /// Human-readable message
        message: String,
    },
    
    /// Error notification
    Error {
        /// Error code
        code: u16,
        /// Human-readable message
        message: String,
    },
}

/// Disconnect reason codes
pub mod disconnect_reason {
    pub const USER_INITIATED: u16 = 0;
    pub const SESSION_EXPIRED: u16 = 1;
    pub const SERVER_SHUTDOWN: u16 = 2;
    pub const AUTHENTICATION_FAILED: u16 = 3;
    pub const PROTOCOL_VIOLATION: u16 = 4;
    pub const TOO_MANY_CONNECTIONS: u16 = 5;
    pub const IDLE_TIMEOUT: u16 = 6;
    pub const INTERNAL_ERROR: u16 = 7;
    pub const ACCESS_DENIED: u16 = 8;
}

/// Error codes
pub mod error_code {
    pub const GENERAL_ERROR: u16 = 1000;
    pub const AUTHENTICATION_FAILED: u16 = 1001;
    pub const INVALID_MESSAGE: u16 = 1002;
    pub const RATE_LIMITED: u16 = 1003;
    pub const SESSION_EXPIRED: u16 = 1004;
    pub const UNAUTHORIZED: u16 = 1005;
    pub const INTERNAL_ERROR: u16 = 1006;
    pub const RESOURCE_EXHAUSTED: u16 = 1007;
    pub const INVALID_STATE: u16 = 1008;
    pub const VERSION_MISMATCH: u16 = 1009;
}

/// Client connection state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    /// Initial state
    New,
    /// Authentication request received
    Authenticating,
    /// Challenge sent
    Challenged,
    /// Successfully authenticated
    Authenticated,
    /// IP assigned
    Connected,
    /// Disconnecting
    Disconnecting,
    /// Disconnected
    Disconnected,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: String,
    /// Client public key
    pub client_key: String,
    /// Assigned IP address
    pub ip_address: String,
    /// Creation timestamp (milliseconds since epoch)
    pub created_at: u64,
    /// Expiration timestamp (milliseconds since epoch)
    pub expires_at: u64,
    /// Last activity timestamp (milliseconds since epoch)
    pub last_activity: u64,
}

impl Session {
    /// Check if the session has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }
    
    /// Check if the session has been inactive for too long
    pub fn is_inactive(&self, current_time: u64, timeout_ms: u64) -> bool {
        current_time > self.last_activity + timeout_ms
    }
    
    /// Update the last activity timestamp
    pub fn touch(&mut self, current_time: u64) {
        self.last_activity = current_time;
    }
    
    /// Extend the session expiration
    pub fn extend(&mut self, duration_ms: u64, current_time: u64) {
        self.expires_at = current_time + duration_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    
    #[test]
    fn test_packet_serialization() {
        // Auth packet
        let auth = PacketType::Auth {
            public_key: "ABC123".to_string(),
            version: "1.0.0".to_string(),
            features: vec!["chacha20poly1305".to_string()],
            nonce: "123456".to_string(),
        };
        
        let serialized = serde_json::to_string(&auth).unwrap();
        let deserialized: PacketType = serde_json::from_str(&serialized).unwrap();
        
        // Match on the deserialized value to verify the type and fields
        match deserialized {
            PacketType::Auth { public_key, version, features, nonce } => {
                assert_eq!(public_key, "ABC123");
                assert_eq!(version, "1.0.0");
                assert_eq!(features, vec!["chacha20poly1305"]);
                assert_eq!(nonce, "123456");
            }
            _ => panic!("Deserialized to wrong type"),
        }
    }
    
    #[test]
    fn test_session_methods() {
        let mut session = Session {
            id: "test-session".to_string(),
            client_key: "test-key".to_string(),
            ip_address: "10.0.0.1".to_string(),
            created_at: 1000,
            expires_at: 2000,
            last_activity: 1500,
        };
        
        // Test expiration
        assert!(session.is_expired(2001));
        assert!(!session.is_expired(1999));
        
        // Test inactivity
        assert!(session.is_inactive(2000, 300)); // 1500 + 300 < 2000
        assert!(!session.is_inactive(1700, 300)); // 1500 + 300 > 1700
        
        // Test touch
        session.touch(2500);
        assert_eq!(session.last_activity, 2500);
        
        // Test extend
        session.extend(1000, 3000);
        assert_eq!(session.expires_at, 4000);
    }
}
