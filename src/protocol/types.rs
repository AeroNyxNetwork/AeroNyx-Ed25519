// src/protocol/types.rs
//! Protocol message types for client-server communication.
//!
//! This module defines the message types used in the AeroNyx Privacy Network
//! protocol for authentication, key exchange, and data transfer.
//!
//! ## Phase 1: End-to-End Encryption Support (Blind Relay)
//! - Added X25519 public key exchange in chat messages
//! - Server acts as blind relay for E2E encrypted messages
//! - Maintains backward compatibility with legacy clients
//!
//! ## Key Changes
//! - `RequestChat`: Now includes sender's X25519 public key
//! - `AcceptChat`: Now includes recipient's X25519 public key
//! - `ChatMessage`: Supports both E2E encrypted and legacy modes
//! - Server never decrypts E2E messages (blind relay)
//!
//! ## Security Model
//! ```
//! Control Channel (Server-Client):
//!   - Authentication: Ed25519 signatures
//!   - Key Exchange: X25519 ECDH (server ↔ client)
//!   - Purpose: Session management, IP assignment
//!
//! Data Channel (Client-Client E2E):
//!   - Key Exchange: X25519 ECDH (client A ↔ client B)
//!   - Encryption: ChaCha20-Poly1305 or AES-256-GCM
//!   - Server: Blind relay (cannot decrypt)
//! ```

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
    /// JSON data (application messages)
    Json,
    /// IP packet data (VPN traffic)
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
        /// Encrypted session key (for control channel only)
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

/// Chat-related message types (embedded in DataEnvelope)
/// These are JSON payloads sent inside encrypted Data packets
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChatMessageType {
    /// Request to initiate a chat
    /// 
    /// ## Phase 1: E2E Key Exchange
    /// Sender includes their X25519 public key for end-to-end encryption
    #[serde(rename = "request-chat")]
    RequestChat {
        /// Target user's client ID
        target_user: String,
        /// Sender's client ID
        from_user: String,
        /// Sender's X25519 public key (Base58 encoded)
        /// Used for end-to-end ECDH key agreement
        x25519_public_key: String,
        /// Timestamp of request
        timestamp: u64,
    },
    
    /// Accept a chat request
    /// 
    /// ## Phase 1: E2E Key Exchange
    /// Recipient includes their X25519 public key to complete ECDH
    #[serde(rename = "accept-chat")]
    AcceptChat {
        /// Chat ID assigned by server
        chat_id: String,
        /// Accepting user's client ID
        from_user: String,
        /// Recipient's X25519 public key (Base58 encoded)
        /// Used for end-to-end ECDH key agreement
        x25519_public_key: String,
        /// Timestamp of acceptance
        timestamp: u64,
    },
    
    /// Reject a chat request
    #[serde(rename = "reject-chat")]
    RejectChat {
        /// Requesting user's client ID
        target_user: String,
        /// Rejecting user's client ID
        from_user: String,
        /// Optional rejection reason
        reason: Option<String>,
        /// Timestamp of rejection
        timestamp: u64,
    },
    
    /// Chat message
    /// 
    /// ## Phase 1: E2E Encryption
    /// Message content can be in two formats:
    /// 1. Legacy: Plain JSON (server can read) - DEPRECATED
    /// 2. E2E: Base64-encoded encrypted blob (server cannot read)
    #[serde(rename = "message")]
    Message {
        /// Chat ID
        chat_id: String,
        /// Sender's client ID
        from_user: String,
        /// Message content or encrypted payload
        /// 
        /// Format detection:
        /// - If starts with "e2e:", it's an encrypted payload
        /// - Otherwise, legacy plain text (deprecated)
        content: String,
        /// Message ID (for deduplication)
        message_id: String,
        /// Timestamp
        timestamp: u64,
        /// Indicates if this message is E2E encrypted
        #[serde(default)]
        is_encrypted: bool,
    },
    
    /// Request chat information
    #[serde(rename = "request-chat-info")]
    RequestChatInfo {
        /// Chat ID
        chat_id: String,
    },
    
    /// Request participant list
    #[serde(rename = "request-participants")]
    RequestParticipants {
        /// Chat ID (optional, uses current room if not specified)
        chat_id: Option<String>,
    },
    
    /// WebRTC signaling
    #[serde(rename = "webrtc-signal")]
    WebRtcSignal {
        /// Target peer's client ID
        peer_id: String,
        /// Sender's client ID
        from_user: String,
        /// Signal type (offer, answer, ice-candidate)
        signal_type: String,
        /// Signal payload
        payload: Value,
    },
    
    /// Leave chat
    #[serde(rename = "leave-chat")]
    LeaveChat {
        /// Chat ID
        chat_id: String,
    },
    
    /// Delete chat
    #[serde(rename = "delete-chat")]
    DeleteChat {
        /// Chat ID
        chat_id: String,
    },
}

/// Encryption algorithms supported
pub mod encryption_algorithms {
    pub const CHACHA20_POLY1305: &str = "chacha20poly1305";
    pub const AES_256_GCM: &str = "aes256gcm";
    
    /// Check if algorithm is supported
    pub fn is_supported(algorithm: &str) -> bool {
        matches!(algorithm, CHACHA20_POLY1305 | AES_256_GCM)
    }
    
    /// Get default algorithm
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
    
    #[test]
    fn test_request_chat_serialization() {
        let request = ChatMessageType::RequestChat {
            target_user: "user123".to_string(),
            from_user: "user456".to_string(),
            x25519_public_key: "5JJyqtqarra7ZQEP8LwFfRBvXyZhqEL6dYL6XaH5dZ2B".to_string(),
            timestamp: 1234567890,
        };
        
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("x25519_public_key"));
        assert!(json.contains("5JJyqtqarra7ZQEP8LwFfRBvXyZhqEL6dYL6XaH5dZ2B"));
        
        let deserialized: ChatMessageType = serde_json::from_str(&json).unwrap();
        match deserialized {
            ChatMessageType::RequestChat { x25519_public_key, .. } => {
                assert_eq!(x25519_public_key, "5JJyqtqarra7ZQEP8LwFfRBvXyZhqEL6dYL6XaH5dZ2B");
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_accept_chat_serialization() {
        let accept = ChatMessageType::AcceptChat {
            chat_id: "chat789".to_string(),
            from_user: "user123".to_string(),
            x25519_public_key: "3GGxvgsdfds8RTYU9MnGgGgCwaYaggfL9eM9YbI8eA3C".to_string(),
            timestamp: 1234567891,
        };
        
        let json = serde_json::to_string(&accept).unwrap();
        assert!(json.contains("x25519_public_key"));
        
        let deserialized: ChatMessageType = serde_json::from_str(&json).unwrap();
        match deserialized {
            ChatMessageType::AcceptChat { x25519_public_key, .. } => {
                assert_eq!(x25519_public_key, "3GGxvgsdfds8RTYU9MnGgGgCwaYaggfL9eM9YbI8eA3C");
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_encrypted_message_format() {
        let msg = ChatMessageType::Message {
            chat_id: "chat123".to_string(),
            from_user: "alice".to_string(),
            content: "e2e:SGVsbG8gV29ybGQh".to_string(),
            message_id: "msg001".to_string(),
            timestamp: 1234567890,
            is_encrypted: true,
        };
        
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("is_encrypted"));
        assert!(json.contains("true"));
        
        match msg {
            ChatMessageType::Message { content, is_encrypted, .. } => {
                assert!(content.starts_with("e2e:"));
                assert!(is_encrypted);
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_backward_compatibility_plain_message() {
        // Legacy message without is_encrypted field
        let json = r#"{
            "type": "message",
            "chat_id": "chat123",
            "from_user": "bob",
            "content": "Hello, this is plain text",
            "message_id": "msg002",
            "timestamp": 1234567890
        }"#;
        
        let msg: ChatMessageType = serde_json::from_str(json).unwrap();
        match msg {
            ChatMessageType::Message { is_encrypted, content, .. } => {
                assert!(!is_encrypted); // Default is false
                assert!(!content.starts_with("e2e:"));
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_challenge_with_x25519() {
        let challenge = PacketType::Challenge {
            data: vec![1, 2, 3],
            server_key: "Ed25519Key".to_string(),
            x25519_key: Some("X25519Key".to_string()),
            expires_at: 1234567890,
            id: "challenge123".to_string(),
        };
        
        let json = serde_json::to_string(&challenge).unwrap();
        assert!(json.contains("x25519_key"));
        
        let deserialized: PacketType = serde_json::from_str(&json).unwrap();
        match deserialized {
            PacketType::Challenge { x25519_key, .. } => {
                assert_eq!(x25519_key, Some("X25519Key".to_string()));
            }
            _ => panic!("Wrong packet type"),
        }
    }
}
