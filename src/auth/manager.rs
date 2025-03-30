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
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::auth::acl::{AccessControlEntry, AccessControlManager, AclError};
use crate::auth::challenge::{Challenge, ChallengeError, ChallengeManager};
use crate::config::constants::{AUTH_CHALLENGE_TIMEOUT, MAX_AUTH_ATTEMPTS};
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
    /// Key manager
    key_manager: Arc<KeyManager>,
    /// Failed authentication attempts (client address -> count)
    failed_attempts: Arc<tokio::sync::Mutex<std::collections::HashMap<SocketAddr, usize>>>,
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
            key_manager.clone(),
            challenge_timeout,
            max_challenges,
        ));
        
        Ok(Self {
            acl_manager,
            challenge_manager,
            key_manager,
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
        client_addr: SocketAddr,
    ) -> Result<Challenge, AuthError> {
        // Check failed attempts
        let mut failed_attempts = self.failed_attempts.lock().await;
        let attempts = failed_attempts.entry(client_addr).or_insert(0);
        
        if *attempts >= MAX_AUTH_ATTEMPTS {
            return Err(AuthError::TooManyAttempts);
        }
        
        self.challenge_manager.generate_challenge(client_addr).await
            .map_err(AuthError::Challenge)
    }
    
    /// Verify a challenge response and authenticate the client
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        client_addr: SocketAddr,
        signature: &str,
        public_key: &str,
    ) -> Result<(), AuthError> {
        // Validate the public key format
        if !StringValidator::is_valid_solana_pubkey(public_key) {
            // Record failed attempt
            self.record_failed_attempt(client_addr).await;
            
            return Err(AuthError::InvalidFormat(format!(
                "Invalid public key format: {}", public_key
            )));
        }
        
        // Verify the challenge response
        match self.challenge_manager.verify_challenge(
            challenge_id,
            client_addr,
            signature,
            public_key,
        ).await {
            Ok(()) => {
                // Challenge verified, now check ACL
                if self.acl_manager.is_allowed(public_key).await {
                    // Reset failed attempts
                    self.reset_failed_attempts(client_addr).await;
                    
                    info!("Successfully authenticated client {} ({})", public_key, client_addr);
                    Ok(())
                } else {
                    // Record failed attempt
                    self.record_failed_attempt(client_addr).await;
                    
                    warn!("Access denied for client {} ({})", public_key, client_addr);
                    Err(AuthError::AccessDenied(format!(
                        "Client {} not allowed by ACL", public_key
                    )))
                }
            }
            Err(e) => {
                // Record failed attempt
                self.record_failed_attempt(client_addr).await;
                
                warn!("Challenge verification failed for client {}: {}", client_addr, e);
                Err(AuthError::Challenge(e))
            }
        }
    }
    
    /// Record a failed authentication attempt
    async fn record_failed_attempt(&self, client_addr: SocketAddr) {
        let mut failed_attempts = self.failed_attempts.lock().await;
        let count = failed_attempts.entry(client_addr).or_insert(0);
        *count += 1;
        
        if *count >= MAX_AUTH_ATTEMPTS {
            warn!(
                "Client {} reached maximum failed authentication attempts ({})",
                client_addr, MAX_AUTH_ATTEMPTS
            );
        }
    }
    
    /// Reset failed authentication attempts
    async fn reset_failed_attempts(&self, client_addr: SocketAddr) {
        let mut failed_attempts = self.failed_attempts.lock().await;
        failed_attempts.remove(&client_addr);
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
    
    /// Clean up failed attempts
    pub async fn cleanup_failed_attempts(&self) {
        let mut failed_attempts = self.failed_attempts.lock().await;
        failed_attempts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
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
        
        // Create test client
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let client_keypair = solana_sdk::signature::Keypair::new();
        let client_pubkey = client_keypair.pubkey().to_string();
        
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
        
        // Generate a challenge
        let challenge = auth_manager.generate_challenge(client_addr).await.unwrap();
        
        // Sign the challenge
        let signature = client_keypair.sign_message(&challenge.data);
        
        // Verify the challenge
        let result = auth_manager.verify_challenge(
            &challenge.id,
            client_addr,
            &signature.to_string(),
            &client_pubkey,
        ).await;
        
        // Should succeed
        assert!(result.is_ok());
        
        // Try with wrong signature
        let wrong_keypair = solana_sdk::signature::Keypair::new();
        let wrong_signature = wrong_keypair.sign_message(&challenge.data);
        
        // Generate a new challenge
        let challenge2 = auth_manager.generate_challenge(client_addr).await.unwrap();
        
        // Verify with wrong signature
        let result = auth_manager.verify_challenge(
            &challenge2.id,
            client_addr,
            &wrong_signature.to_string(),
            &client_pubkey,
        ).await;
        
        // Should fail
        assert!(result.is_err());
    }
}
