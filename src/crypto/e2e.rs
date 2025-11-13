// src/crypto/e2e.rs
//! End-to-End Encryption Utilities
//!
//! This module provides utilities for managing end-to-end encrypted communications
//! between clients. The server acts as a blind relay and cannot decrypt E2E messages.
//!
//! ## Architecture
//! ```
//! Client A                    Server (Blind Relay)              Client B
//!    |                               |                              |
//!    | 1. RequestChat                |                              |
//!    |    + X25519_Public_A          |                              |
//!    |------------------------------>|                              |
//!    |                               |  2. Forward Request          |
//!    |                               |    + X25519_Public_A         |
//!    |                               |----------------------------->|
//!    |                               |                              |
//!    |                               |  3. AcceptChat               |
//!    |                               |    + X25519_Public_B         |
//!    |  4. Forward Accept            |<-----------------------------|
//!    |    + X25519_Public_B          |                              |
//!    |<------------------------------|                              |
//!    |                               |                              |
//!    | 5. Both compute shared secret via ECDH                       |
//!    |    shared = DH(X25519_Private_A, X25519_Public_B)           |
//!    |    shared = DH(X25519_Private_B, X25519_Public_A)           |
//!    |                               |                              |
//!    | 6. Derive session key                                        |
//!    |    session_key = HKDF(shared, "AERONYX-E2E-CHAT-KEY")       |
//!    |                               |                              |
//!    | 7. Send encrypted message     |                              |
//!    |    encrypted = Encrypt(msg, session_key)                    |
//!    |------------------------------>|  8. Blind forward            |
//!    |                               |----------------------------->|
//!    |                               |    (Server cannot decrypt)   |
//! ```
//!
//! ## Security Properties
//! - **End-to-End Encryption**: Only clients can decrypt messages
//! - **Blind Relay**: Server cannot read message contents
//! - **Forward Secrecy**: Future messages safe if current key compromised (Phase 2)
//! - **Authentication**: X25519 keys signed by long-term Ed25519 keys (Phase 2)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// End-to-End encryption mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2EMode {
    /// Legacy mode: No E2E encryption (deprecated)
    Legacy,
    /// E2E mode: Client-to-client encryption
    EndToEnd,
}

/// E2E session state
#[derive(Debug, Clone)]
pub struct E2ESession {
    /// Chat ID
    pub chat_id: String,
    /// Participant A's client ID
    pub client_a: String,
    /// Participant B's client ID
    pub client_b: String,
    /// Participant A's X25519 public key (Base58)
    pub pubkey_a: Option<String>,
    /// Participant B's X25519 public key (Base58)
    pub pubkey_b: Option<String>,
    /// E2E mode
    pub mode: E2EMode,
    /// Creation timestamp
    pub created_at: u64,
}

impl E2ESession {
    /// Create a new E2E session
    pub fn new(chat_id: String, client_a: String, client_b: String) -> Self {
        Self {
            chat_id,
            client_a,
            client_b,
            pubkey_a: None,
            pubkey_b: None,
            mode: E2EMode::Legacy,
            created_at: crate::utils::current_timestamp_millis(),
        }
    }
    
    /// Set participant A's public key
    pub fn set_pubkey_a(&mut self, pubkey: String) {
        self.pubkey_a = Some(pubkey);
        self.update_mode();
    }
    
    /// Set participant B's public key
    pub fn set_pubkey_b(&mut self, pubkey: String) {
        self.pubkey_b = Some(pubkey);
        self.update_mode();
    }
    
    /// Update E2E mode based on available keys
    fn update_mode(&mut self) {
        if self.pubkey_a.is_some() && self.pubkey_b.is_some() {
            self.mode = E2EMode::EndToEnd;
            info!(
                "E2E mode enabled for chat {} ({} ↔ {})",
                self.chat_id, self.client_a, self.client_b
            );
        }
    }
    
    /// Check if E2E is fully established
    pub fn is_e2e_ready(&self) -> bool {
        self.mode == E2EMode::EndToEnd
    }
    
    /// Get the other participant's ID
    pub fn get_peer_id(&self, my_id: &str) -> Option<&str> {
        if self.client_a == my_id {
            Some(&self.client_b)
        } else if self.client_b == my_id {
            Some(&self.client_a)
        } else {
            None
        }
    }
}

/// E2E session manager
/// 
/// Tracks E2E sessions and manages public key exchange.
/// The server stores public keys but never stores derived session keys.
#[derive(Clone)]
pub struct E2ESessionManager {
    /// Map: chat_id -> E2ESession
    sessions: Arc<RwLock<HashMap<String, E2ESession>>>,
}

impl E2ESessionManager {
    /// Create a new E2E session manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create a new E2E session for a chat
    /// 
    /// # Arguments
    /// * `chat_id` - Unique chat identifier
    /// * `initiator` - Client ID of the user who initiated the chat
    /// * `recipient` - Client ID of the user who accepted the chat
    /// * `initiator_pubkey` - Initiator's X25519 public key (optional)
    pub async fn create_session(
        &self,
        chat_id: String,
        initiator: String,
        recipient: String,
        initiator_pubkey: Option<String>,
    ) -> E2ESession {
        let mut session = E2ESession::new(chat_id.clone(), initiator.clone(), recipient.clone());
        
        if let Some(pubkey) = initiator_pubkey {
            session.set_pubkey_a(pubkey);
        }
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(chat_id.clone(), session.clone());
        
        debug!("Created E2E session for chat {} ({} → {})", chat_id, initiator, recipient);
        
        session
    }
    
    /// Update a session with recipient's public key
    /// 
    /// # Arguments
    /// * `chat_id` - Chat identifier
    /// * `recipient_pubkey` - Recipient's X25519 public key
    pub async fn set_recipient_pubkey(&self, chat_id: &str, recipient_pubkey: String) -> bool {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(chat_id) {
            session.set_pubkey_b(recipient_pubkey);
            info!("E2E session established for chat {}", chat_id);
            true
        } else {
            warn!("Attempted to set recipient pubkey for non-existent chat {}", chat_id);
            false
        }
    }
    
    /// Get an E2E session by chat ID
    pub async fn get_session(&self, chat_id: &str) -> Option<E2ESession> {
        let sessions = self.sessions.read().await;
        sessions.get(chat_id).cloned()
    }
    
    /// Remove an E2E session
    pub async fn remove_session(&self, chat_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        sessions.remove(chat_id).is_some()
    }
    
    /// Check if a message is E2E encrypted
    /// 
    /// Messages are considered E2E encrypted if:
    /// 1. Content starts with "e2e:" prefix
    /// 2. The chat has an established E2E session
    pub async fn is_encrypted_message(&self, chat_id: &str, content: &str) -> bool {
        // Check content format
        if !content.starts_with("e2e:") {
            return false;
        }
        
        // Check if E2E session exists and is ready
        let sessions = self.sessions.read().await;
        sessions
            .get(chat_id)
            .map(|s| s.is_e2e_ready())
            .unwrap_or(false)
    }
    
    /// Get statistics about E2E sessions
    pub async fn get_stats(&self) -> E2EStats {
        let sessions = self.sessions.read().await;
        
        let total = sessions.len();
        let active = sessions.values().filter(|s| s.is_e2e_ready()).count();
        let legacy = total - active;
        
        E2EStats {
            total_sessions: total,
            e2e_sessions: active,
            legacy_sessions: legacy,
        }
    }
}

impl Default for E2ESessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// E2E session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2EStats {
    /// Total number of chat sessions
    pub total_sessions: usize,
    /// Number of E2E encrypted sessions
    pub e2e_sessions: usize,
    /// Number of legacy (unencrypted) sessions
    pub legacy_sessions: usize,
}

/// Encrypted message format
/// 
/// E2E encrypted messages follow this format:
/// ```text
/// e2e:<base64_encrypted_data>
/// ```
/// 
/// Where encrypted_data contains:
/// ```json
/// {
///   "content": "actual message content",
///   "timestamp": 1234567890,
///   "nonce": "base64_nonce"
/// }
/// ```
pub struct EncryptedMessageFormat;

impl EncryptedMessageFormat {
    /// E2E message prefix
    pub const PREFIX: &'static str = "e2e:";
    
    /// Check if a message is E2E encrypted
    pub fn is_encrypted(content: &str) -> bool {
        content.starts_with(Self::PREFIX)
    }
    
    /// Format an encrypted message
    /// 
    /// # Arguments
    /// * `encrypted_data` - Base64-encoded encrypted data
    /// 
    /// # Returns
    /// Formatted message string: "e2e:<encrypted_data>"
    pub fn format(encrypted_data: &str) -> String {
        format!("{}{}", Self::PREFIX, encrypted_data)
    }
    
    /// Extract encrypted data from a formatted message
    /// 
    /// # Arguments
    /// * `message` - Formatted message string
    /// 
    /// # Returns
    /// Base64-encoded encrypted data, or None if invalid format
    pub fn extract(message: &str) -> Option<&str> {
        message.strip_prefix(Self::PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_e2e_session_creation() {
        let manager = E2ESessionManager::new();
        
        let session = manager.create_session(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            Some("AliceX25519PubKey".to_string()),
        ).await;
        
        assert_eq!(session.chat_id, "chat123");
        assert_eq!(session.client_a, "alice");
        assert_eq!(session.client_b, "bob");
        assert_eq!(session.pubkey_a, Some("AliceX25519PubKey".to_string()));
        assert_eq!(session.pubkey_b, None);
        assert_eq!(session.mode, E2EMode::Legacy); // Not ready yet
    }
    
    #[tokio::test]
    async fn test_e2e_session_establishment() {
        let manager = E2ESessionManager::new();
        
        // Create session with Alice's key
        manager.create_session(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            Some("AliceX25519PubKey".to_string()),
        ).await;
        
        // Add Bob's key
        let success = manager.set_recipient_pubkey(
            "chat123",
            "BobX25519PubKey".to_string()
        ).await;
        
        assert!(success);
        
        // Check E2E is ready
        let session = manager.get_session("chat123").await.unwrap();
        assert!(session.is_e2e_ready());
        assert_eq!(session.mode, E2EMode::EndToEnd);
    }
    
    #[tokio::test]
    async fn test_get_peer_id() {
        let session = E2ESession::new(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
        );
        
        assert_eq!(session.get_peer_id("alice"), Some("bob"));
        assert_eq!(session.get_peer_id("bob"), Some("alice"));
        assert_eq!(session.get_peer_id("charlie"), None);
    }
    
    #[tokio::test]
    async fn test_encrypted_message_detection() {
        let manager = E2ESessionManager::new();
        
        // Create E2E session
        manager.create_session(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            Some("AlicePubKey".to_string()),
        ).await;
        
        manager.set_recipient_pubkey("chat123", "BobPubKey".to_string()).await;
        
        // Test encrypted message detection
        assert!(manager.is_encrypted_message("chat123", "e2e:SGVsbG8=").await);
        assert!(!manager.is_encrypted_message("chat123", "Plain text").await);
        assert!(!manager.is_encrypted_message("nonexistent", "e2e:SGVsbG8=").await);
    }
    
    #[tokio::test]
    async fn test_e2e_stats() {
        let manager = E2ESessionManager::new();
        
        // Create one E2E session
        manager.create_session(
            "chat1".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            Some("AliceKey".to_string()),
        ).await;
        manager.set_recipient_pubkey("chat1", "BobKey".to_string()).await;
        
        // Create one legacy session (no keys exchanged)
        manager.create_session(
            "chat2".to_string(),
            "charlie".to_string(),
            "david".to_string(),
            None,
        ).await;
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.total_sessions, 2);
        assert_eq!(stats.e2e_sessions, 1);
        assert_eq!(stats.legacy_sessions, 1);
    }
    
    #[test]
    fn test_encrypted_message_format() {
        assert!(EncryptedMessageFormat::is_encrypted("e2e:SGVsbG8gV29ybGQh"));
        assert!(!EncryptedMessageFormat::is_encrypted("Plain message"));
        
        let formatted = EncryptedMessageFormat::format("SGVsbG8gV29ybGQh");
        assert_eq!(formatted, "e2e:SGVsbG8gV29ybGQh");
        
        let extracted = EncryptedMessageFormat::extract("e2e:SGVsbG8gV29ybGQh");
        assert_eq!(extracted, Some("SGVsbG8gV29ybGQh"));
        
        let extracted_invalid = EncryptedMessageFormat::extract("Plain message");
        assert_eq!(extracted_invalid, None);
    }
    
    #[test]
    fn test_session_mode_transition() {
        let mut session = E2ESession::new(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
        );
        
        // Initially legacy
        assert_eq!(session.mode, E2EMode::Legacy);
        assert!(!session.is_e2e_ready());
        
        // Add Alice's key - still legacy
        session.set_pubkey_a("AliceKey".to_string());
        assert_eq!(session.mode, E2EMode::Legacy);
        assert!(!session.is_e2e_ready());
        
        // Add Bob's key - now E2E
        session.set_pubkey_b("BobKey".to_string());
        assert_eq!(session.mode, E2EMode::EndToEnd);
        assert!(session.is_e2e_ready());
    }
}
