// src/protocol/types.rs
//! Protocol message types for client-server communication.
//!
//! This module defines the message types used in the AeroNyx Privacy Network
//! protocol for authentication, key exchange, and data transfer.
//!
//! ## Key Changes for X25519 Support
//! - Added optional `x25519_key` field to Challenge packet
//! - Server now sends both Ed25519 (for signatures) and X25519 (for ECDH) public keys
//! - Maintains backward compatibility with clients that don't support X25519
//!
//! ## Why These Changes
//! - Clients need X25519 public key for ECDH key exchange
//! - Ed25519 keys cannot be directly used for X25519 operations
//! - Optional field ensures backward compatibility

use serde::{Deserialize, Serialize};
use thiserror::Error;
use serde_json::Value;

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

/// Data payload types for mixed mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum PayloadDataType {
    Json,
    Ip,
}

/// Envelope structure for encapsulating different payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataEnvelope {
    pub payload_type: PayloadDataType,
    pub payload: Value,
}

/// Packet types for client-server communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PacketType {
    /// Authentication request
    Auth {
        /// Client public key (Ed25519)
        public_key: String,
        /// Client version
        version: String,
        /// Supported features
        features: Vec<String>,
        /// Preferred encryption algorithm
        encryption_algorithm: Option<String>,
        /// Nonce for security
        nonce: String,
    },
    
    /// Challenge for authentication
    /// 
    /// ## X25519 Support
    /// Now includes optional `x25519_key` field for ECDH key exchange.
    /// - `server_key`: Ed25519 public key for signature verification
    /// - `x25519_key`: X25519 public key for ECDH (optional for backward compatibility)
    Challenge {
        /// Challenge data to sign
        data: Vec<u8>,
        /// Server's Ed25519 public key (for signature verification)
        server_key: String,
        /// Server's X25519 public key (for ECDH key exchange)
        /// This is optional to maintain backward compatibility
        #[serde(skip_serializing_if = "Option::is_none")]
        x25519_key: Option<String>,
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
        /// Selected encryption algorithm
        encryption_algorithm: String,
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
        /// Encryption algorithm used (optional for backward compatibility)
        encryption_algorithm: Option<String>,
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

pub mod encryption_algorithms {
    pub const CHACHA20_POLY1305: &str = "chacha20poly1305";
    pub const AES_256_GCM: &str = "aes256gcm";
    
    // Check if algorithm is supported
    pub fn is_supported(algorithm: &str) -> bool {
        match algorithm {
            CHACHA20_POLY1305 | AES_256_GCM => true,
            _ => false,
        }
    }
    
    // Get default algorithm
    pub fn default() -> &'static str {
        CHACHA20_POLY1305
    }
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
    fn test_challenge_with_x25519_key() {
        // Test with X25519 key
        let challenge = PacketType::Challenge {
            data: vec![1, 2, 3],
            server_key: "Ed25519PublicKey".to_string(),
            x25519_key: Some("X25519PublicKey".to_string()),
            expires_at: 1234567890,
            id: "challenge123".to_string(),
        };
        
        let serialized = serde_json::to_string(&challenge).unwrap();
        assert!(serialized.contains("x25519_key"));
        assert!(serialized.contains("X25519PublicKey"));
        
        let deserialized: PacketType = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            PacketType::Challenge { x25519_key, .. } => {
                assert_eq!(x25519_key, Some("X25519PublicKey".to_string()));
            }
            _ => panic!("Wrong packet type"),
        }
    }
    
    #[test]
    fn test_challenge_without_x25519_key() {
        // Test backward compatibility (no X25519 key)
        let json = r#"{
            "type": "Challenge",
            "data": [1, 2, 3],
            "server_key": "Ed25519PublicKey",
            "expires_at": 1234567890,
            "id": "challenge123"
        }"#;
        
        let deserialized: PacketType = serde_json::from_str(json).unwrap();
        match deserialized {
            PacketType::Challenge { x25519_key, .. } => {
                assert_eq!(x25519_key, None);
            }
            _ => panic!("Wrong packet type"),
        }
    }
    
    #[test]
    fn test_packet_serialization() {
        // Auth packet
        let auth = PacketType::Auth {
            public_key: "ABC123".to_string(),
            version: "1.0.0".to_string(),
            features: vec!["chacha20poly1305".to_string()],
            encryption_algorithm: Some("chacha20poly1305".to_string()),
            nonce: "123456".to_string(),
        };
        
        let serialized = serde_json::to_string(&auth).unwrap();
        let deserialized: PacketType = serde_json::from_str(&serialized).unwrap();
        
        match deserialized {
            PacketType::Auth { public_key, version, features, encryption_algorithm, nonce } => {
                assert_eq!(public_key, "ABC123");
                assert_eq!(version, "1.0.0");
                assert_eq!(features, vec!["chacha20poly1305"]);
                assert_eq!(encryption_algorithm, Some("chacha20poly1305".to_string()));
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
        assert!(session.is_inactive(2000, 300));
        assert!(!session.is_inactive(1700, 300));
        
        // Test touch
        session.touch(2500);
        assert_eq!(session.last_activity, 2500);
        
        // Test extend
        session.extend(1000, 3000);
        assert_eq!(session.expires_at, 4000);
    }
}
