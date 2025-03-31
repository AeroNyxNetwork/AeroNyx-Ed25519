// src/auth/manager.rs
//! Authentication manager for the server.
//!
//! This module provides a central manager for handling authentication
//! and authorization tasks.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::str::FromStr;
use thiserror::Error;
// Removed unused debug, info imports
use tracing::{error, warn};

use crate::auth::acl::{AccessControlEntry, AccessControlManager, AclError};
// Removed unused Challenge import
use crate::auth::challenge::{ChallengeError, ChallengeManager};
// Removed unused AUTH_CHALLENGE_TIMEOUT import
use crate::config::constants::MAX_AUTH_ATTEMPTS;
use crate::crypto::keys::KeyManager;
use crate::utils::security::StringValidator;

/// Error type for authentication operations
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Challenge error: {0}")]
    Challenge(#[from] ChallengeError),

    #[error("ACL error: {0}")]
    Acl(#[from] AclError),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Too many attempts")]
    TooManyAttempts,
}

/// Authentication manager
#[derive(Debug)]
pub struct AuthManager {
    /// ACL manager
    acl_manager: Arc<AccessControlManager>,
    /// Challenge manager
    challenge_manager: Arc<ChallengeManager>,
    /// Key manager (kept for potential future use)
    _key_manager: Arc<KeyManager>,
    /// Failed authentication attempts (client address -> count)
    failed_attempts: Arc<tokio::sync::Mutex<std::collections::HashMap<String, usize>>>,
}

impl AuthManager {
    /// Create a new authentication manager
    pub async fn new(
        acl_path: impl AsRef<Path>,
        key_manager: Arc<KeyManager>,
        challenge_timeout: Duration,
        max_challenges: usize,
    ) -> Result<Self, AuthError> {
        let acl_manager = Arc::new(AccessControlManager::new(acl_path).await
            .map_err(AuthError::Acl)?);

        let challenge_manager = Arc::new(ChallengeManager::new(
            key_manager.clone(), // Pass key manager to challenge manager
            challenge_timeout,
            max_challenges,
        ));

        Ok(Self {
            acl_manager,
            challenge_manager,
            _key_manager: key_manager, // Store but mark potentially unused
            failed_attempts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Get the ACL manager
    pub fn acl_manager(&self) -> Arc<AccessControlManager> {
        self.acl_manager.clone()
    }

    /// Get the challenge manager
    pub fn challenge_manager(&self) -> Arc<ChallengeManager> {
        self.challenge_manager.clone()
    }

    /// Generate a new authentication challenge for a client
    pub async fn generate_challenge(
        &self,
        client_addr: &str,
    ) -> Result<(String, Vec<u8>), AuthError> {
        // Check failed attempts
        let mut failed_attempts = self.failed_attempts.lock().await;
        let attempts = failed_attempts.entry(client_addr.to_string()).or_insert(0);

        if *attempts >= MAX_AUTH_ATTEMPTS {
            return Err(AuthError::TooManyAttempts);
        }

        // Convert string to SocketAddr for challenge manager
        let socket_addr = client_addr.parse::<SocketAddr>()
            .map_err(|_| AuthError::InvalidFormat(format!("Invalid address format: {}", client_addr)))?;

        // Generate challenge
        let challenge = self.challenge_manager.generate_challenge(socket_addr).await
            .map_err(AuthError::Challenge)?;

        Ok((challenge.id.clone(), challenge.data.clone()))
    }

    /// Verify a challenge response and authenticate the client
    /// This method verifies a signature against a challenge
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        signature: &str,
        public_key: &str,
        client_addr: &str,
    ) -> Result<(), AuthError> {
        // Validate input parameters
        if !StringValidator::is_valid_solana_pubkey(public_key) {
            return Err(AuthError::InvalidFormat(format!("Invalid public key format: {}", public_key)));
        }

        // Prefix unused variables _pubkey and _sig if they are not used later
        let _pubkey = Pubkey::from_str(public_key)
            .map_err(|_| AuthError::InvalidFormat(format!("Invalid public key: {}", public_key)))?;

        let _sig = Signature::from_str(signature)
            .map_err(|_| AuthError::InvalidFormat(format!("Invalid signature: {}", signature)))?;

        // Convert string to SocketAddr for challenge manager
        let socket_addr = client_addr.parse::<SocketAddr>()
            .map_err(|_| AuthError::InvalidFormat(format!("Invalid address format: {}", client_addr)))?;

        // Verify the challenge with the challenge manager
        let result = self.challenge_manager.verify_challenge(
            challenge_id,
            socket_addr,
            signature, // Pass original signature string
            public_key, // Pass original public key string
        ).await;

        // Handle the result
        if let Err(e) = &result {
            match e {
                ChallengeError::Expired | ChallengeError::SignatureVerificationFailed => {
                    self.record_failed_attempt(client_addr).await;
                }
                _ => {}
            }
        }

        // Propagate any verification errors
        result.map_err(AuthError::Challenge)?;

        // Reset failed attempts on successful verification
        self.reset_failed_attempts(client_addr).await;

        // Check if client is allowed in ACL
        if !self.acl_manager.is_allowed(public_key).await {
            return Err(AuthError::AccessDenied(format!("Access denied for {}", public_key)));
        }

        Ok(())
    }

    /// Record a failed authentication attempt
    async fn record_failed_attempt(&self, client_addr: &str) {
        let mut failed_attempts = self.failed_attempts.lock().await;
        let count = failed_attempts.entry(client_addr.to_string()).or_insert(0);
        *count += 1;

        if *count >= MAX_AUTH_ATTEMPTS {
            warn!(
                "Client {} reached maximum failed authentication attempts ({})",
                client_addr, MAX_AUTH_ATTEMPTS
            );
            // Consider adding client_addr to a temporary blocklist here
        }
    }

    /// Reset failed authentication attempts
    async fn reset_failed_attempts(&self, client_addr: &str) {
        let mut failed_attempts = self.failed_attempts.lock().await;
        failed_attempts.remove(client_addr);
    }

    /// Add a client to the ACL
    pub async fn add_client(&self, entry: AccessControlEntry) -> Result<(), AuthError> {
        self.acl_manager.add_entry(entry).await.map_err(AuthError::Acl)
    }

    /// Remove a client from the ACL
    pub async fn remove_client(&self, public_key: &str) -> Result<(), AuthError> {
        self.acl_manager.remove_entry(public_key).await.map_err(AuthError::Acl)
    }

    /// Check if a client is allowed to connect
    pub async fn is_client_allowed(&self, public_key: &str) -> bool {
        self.acl_manager.is_allowed(public_key).await
    }

    /// Get client information from the ACL
    pub async fn get_client_info(&self, public_key: &str) -> Option<AccessControlEntry> {
        self.acl_manager.get_entry(public_key).await
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self) -> usize {
        self.challenge_manager.cleanup_expired().await
    }

    /// Clean up failed attempts (e.g., periodically)
    pub async fn cleanup_failed_attempts(&self) {
        let mut failed_attempts = self.failed_attempts.lock().await;
        // Optionally implement time-based cleanup instead of just clearing all
        failed_attempts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use solana_sdk::signer::Signer; // Import Signer trait

    #[tokio::test]
    async fn test_auth_manager() {
        // Create temporary directories
        let dir = tempdir().unwrap();
        let acl_path = dir.path().join("test_acl.json");
        let key_path = dir.path().join("test_key.json");

        // Create key manager
        let key_manager = Arc::new(KeyManager::new(&key_path, Duration::from_secs(60), 100).await.unwrap());

        // Create auth manager
        let auth_manager = AuthManager::new(
            &acl_path,
            key_manager.clone(),
            Duration::from_secs(10),
            100,
        ).await.unwrap();

        // Test client address
        let client_addr_str = "127.0.0.1:12345";

        // Generate challenge
        let (challenge_id, challenge_data) = auth_manager.generate_challenge(client_addr_str).await.unwrap();

        // Create test client's keypair
        let client_keypair = solana_sdk::signature::Keypair::new();
        let client_pubkey = client_keypair.pubkey().to_string();

        // Sign the challenge
        let signature = client_keypair.sign_message(&challenge_data).to_string();

        // Verify challenge
        let result = auth_manager.verify_challenge(
            &challenge_id,
            &signature,
            &client_pubkey,
            client_addr_str,
        ).await;

        // Should fail since client is not in ACL yet
        assert!(result.is_err());
        if let Err(AuthError::Challenge(ChallengeError::NotFound(_))) = result {
            // Expected error if challenge was consumed by failed verification
        } else if let Err(AuthError::AccessDenied(_)) = result {
            // Expected error if challenge verification succeeded but ACL check failed
        }
         else {
            panic!("Expected ChallengeError::NotFound or AccessDenied, got {:?}", result);
        }


        // Add client to ACL
        let entry = AccessControlEntry {
            public_key: client_pubkey.clone(),
            access_level: 100,
            is_allowed: true,
            bandwidth_limit: 0,
            max_session_duration: 3600,
            static_ip: None,
            notes: None,
        };
        auth_manager.add_client(entry).await.unwrap();

        // Regenerate challenge (since previous one might have been consumed or expired)
        let (challenge_id, challenge_data) = auth_manager.generate_challenge(client_addr_str).await.unwrap();

        // Sign the challenge
        let signature = client_keypair.sign_message(&challenge_data).to_string();

        // Verify challenge again
        let result = auth_manager.verify_challenge(
            &challenge_id,
            &signature,
            &client_pubkey,
            client_addr_str,
        ).await;

        // Should succeed now
        assert!(result.is_ok());
    }
}
