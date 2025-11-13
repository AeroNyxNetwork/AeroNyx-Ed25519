// src/crypto/mod.rs
//! Cryptography module for the AeroNyx Privacy Network Server.
//!
//! This module provides cryptographic functions and utilities for
//! secure key management, encryption, and signatures.
//!
//! ## Architecture Overview
//!
//! ### Two-Layer Encryption Model (Phase 1: Blind Relay)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Layer 1: Control Channel (Server ↔ Client)                 │
//! │  - Purpose: Authentication, session management              │
//! │  - Keys: Server knows these (SessionKeyManager)             │
//! │  - Modules: keys, session, encryption                       │
//! └─────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Layer 2: Data Channel (Client ↔ Client E2E)                │
//! │  - Purpose: Chat messages, private data                     │
//! │  - Keys: Server NEVER knows these                           │
//! │  - Module: e2e (NEW)                                        │
//! │  - Server Role: Blind relay (forward only)                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Module Responsibilities
//!
//! - **encryption**: Core encryption primitives (AES-GCM, ChaCha20-Poly1305)
//! - **keys**: Server keypair management (Ed25519 + X25519)
//! - **session**: Control channel session key management
//! - **flexible_encryption**: Algorithm negotiation and unified interface
//! - **e2e**: End-to-end encryption session management (NEW in Phase 1)

pub mod encryption;
pub mod keys;
pub mod session;
pub mod flexible_encryption;
pub mod e2e; // Phase 1: End-to-End Encryption

// Re-export commonly used items for backward compatibility
pub use encryption::{encrypt_packet, decrypt_packet};
pub use keys::KeyManager;
pub use session::SessionKeyManager;
pub use flexible_encryption::{
    EncryptionAlgorithm, 
    encrypt_flexible, 
    decrypt_flexible,
    EncryptedPacket,
};

// Phase 1: Export E2E types
pub use e2e::{
    E2ESessionManager,
    E2ESession,
    E2EMode,
    E2EStats,
    EncryptedMessageFormat,
};

// Re-export additional encryption utilities for convenience
pub use encryption::{
    EncryptionError,
    encrypt_aes256_gcm,
    decrypt_aes256_gcm,
    encrypt_chacha20_poly1305,
    decrypt_chacha20_poly1305,
    encrypt_session_key_flexible,
    decrypt_session_key_flexible,
    generate_random_nonce,
    KEY_SIZE,
    NONCE_SIZE,
};

pub use keys::{
    KeyError,
    generate_shared_secret,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all expected types are exported
        let _ = std::any::type_name::<KeyManager>();
        let _ = std::any::type_name::<SessionKeyManager>();
        let _ = std::any::type_name::<EncryptionAlgorithm>();
        let _ = std::any::type_name::<E2ESessionManager>();
    }
    
    #[tokio::test]
    async fn test_integration_control_and_e2e() {
        // Test that control channel and E2E work together
        use std::time::Duration;
        
        // Control channel setup
        let session_mgr = SessionKeyManager::new(Duration::from_secs(3600));
        let session_key = SessionKeyManager::generate_key();
        session_mgr.store_key("alice", session_key).await;
        
        // E2E setup
        let e2e_mgr = E2ESessionManager::new();
        let e2e_session = e2e_mgr.create_session(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            Some("AliceX25519Key".to_string()),
        ).await;
        
        // Verify both systems coexist
        assert!(session_mgr.get_key("alice").await.is_some());
        assert_eq!(e2e_session.client_a, "alice");
        
        // Verify session key count
        assert_eq!(session_mgr.count().await, 1);
        
        // Verify E2E stats
        let stats = e2e_mgr.get_stats().await;
        assert_eq!(stats.total_sessions, 1);
    }
}
