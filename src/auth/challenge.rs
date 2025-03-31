// src/auth/challenge.rs
//! Challenge-response authentication.
//!
//! This module implements challenge-response authentication using
//! cryptographic signatures for client verification.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

// Removed unused AUTH_CHALLENGE_TIMEOUT import (using constructor arg)
use crate::config::constants::CHALLENGE_SIZE;
use crate::crypto::encryption::generate_challenge as gen_challenge;
use crate::crypto::keys::KeyManager;
use crate::utils;
use std::str::FromStr; // Add FromStr import

/// Error type for challenge operations
#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("Challenge not found: {0}")]
    NotFound(String),

    #[error("Challenge expired")]
    Expired,

    #[error("Client address mismatch")]
    AddressMismatch,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Creation failed: {0}")]
    CreationFailed(String),

    #[error("Too many challenges")]
    TooManyChallenges,
}

/// Authentication challenge
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Unique challenge ID
    pub id: String,
    /// Challenge data to sign
    pub data: Vec<u8>,
    /// Challenge creation time
    pub created_at: Instant,
    /// Challenge expiration time
    pub expires_at: Instant,
    /// Client IP address
    pub client_addr: SocketAddr,
}

impl Challenge {
    /// Create a new challenge
    pub fn new(id: String, data: Vec<u8>, client_addr: SocketAddr, timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            id,
            data,
            created_at: now,
            expires_at: now + timeout,
            client_addr,
        }
    }

    /// Check if the challenge has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Get the remaining time until expiration
    pub fn time_remaining(&self) -> Duration {
        if self.is_expired() {
            Duration::from_secs(0)
        } else {
            self.expires_at.duration_since(Instant::now())
        }
    }
}

/// Manager for authentication challenges
#[derive(Debug)]
pub struct ChallengeManager {
    /// Active challenges
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
    /// Challenge timeout
    timeout: Duration,
    /// Key manager for crypto operations (unused field)
    _key_manager: Arc<KeyManager>, // Prefix if only used for creation, or remove if not needed
    /// Maximum number of active challenges
    max_challenges: usize,
}

impl ChallengeManager {
    /// Create a new challenge manager
    pub fn new(key_manager: Arc<KeyManager>, timeout: Duration, max_challenges: usize) -> Self {
        Self {
            challenges: Arc::new(Mutex::new(HashMap::new())),
            timeout,
            _key_manager: key_manager, // Assign to prefixed field if unused later
            max_challenges,
        }
    }

    /// Generate a new challenge for a client
    pub async fn generate_challenge(&self, client_addr: SocketAddr) -> Result<Challenge, ChallengeError> {
        let challenge_data = gen_challenge(CHALLENGE_SIZE);
        let challenge_id = utils::random_string(24);

        let challenge = Challenge::new(
            challenge_id.clone(),
            challenge_data,
            client_addr,
            self.timeout,
        );

        let mut challenges = self.challenges.lock().await;

        // Check if we have too many challenges
        if challenges.len() >= self.max_challenges {
            // Clean up expired challenges first
            self.cleanup_expired_challenges(&mut challenges);

            // If still too many, reject
            if challenges.len() >= self.max_challenges {
                return Err(ChallengeError::TooManyChallenges);
            }
        }

        // Store the challenge
        challenges.insert(challenge_id.clone(), challenge.clone());

        debug!("Generated challenge {} for client {}", challenge_id, client_addr);

        Ok(challenge)
    }

    /// Verify a challenge response
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        client_addr: SocketAddr,
        signature: &str,
        public_key: &str,
    ) -> Result<(), ChallengeError> {
        let mut challenges = self.challenges.lock().await;

        // Find the challenge
        let challenge = challenges.get(challenge_id)
            .ok_or_else(|| ChallengeError::NotFound(challenge_id.to_string()))?;

        // Verify client address
        if challenge.client_addr != client_addr {
            warn!("Challenge address mismatch: expected {}, got {}",
                 challenge.client_addr, client_addr);
            return Err(ChallengeError::AddressMismatch);
        }

        // Check if challenge has expired
        if challenge.is_expired() {
            warn!("Expired challenge: {}", challenge_id);
            // Remove expired challenge eagerly
            challenges.remove(challenge_id);
            return Err(ChallengeError::Expired);
        }

        // Clone the data before dropping the lock temporarily if needed, or keep lock
        let challenge_data = challenge.data.clone();

        // Drop the lock before potentially long-running crypto operations
        // drop(challenges); // Uncomment this if verify_signature is slow

        // Parse the client's public key
        let pubkey = solana_sdk::pubkey::Pubkey::from_str(public_key)
            .map_err(|_| ChallengeError::SignatureVerificationFailed)?;

        // Parse the signature
        let sig = solana_sdk::signature::Signature::from_str(signature)
            .map_err(|_| ChallengeError::SignatureVerificationFailed)?;

        // Verify the signature
        // KeyManager is no longer directly used here, assuming verify_signature is static or accessible
        if !KeyManager::verify_signature(&pubkey, &challenge_data, &sig) {
            warn!("Signature verification failed for challenge {}", challenge_id);
            // Re-acquire lock to potentially update failure counts if needed
            // let mut challenges = self.challenges.lock().await;
            // challenges.remove(challenge_id); // Optionally remove failed attempts
            return Err(ChallengeError::SignatureVerificationFailed);
        }

        // Re-acquire lock to remove the challenge
        // let mut challenges = self.challenges.lock().await; // Re-acquire lock if dropped
        challenges.remove(challenge_id);

        info!("Successfully verified challenge {} for client {}", challenge_id, client_addr);

        Ok(())
    }

    /// Clean up expired challenges (needs mutable access to map)
    fn cleanup_expired_challenges(&self, challenges: &mut HashMap<String, Challenge>) {
        let before_count = challenges.len();
        challenges.retain(|_, c| !c.is_expired());
        let removed = before_count - challenges.len();

        if removed > 0 {
            debug!("Cleaned up {} expired challenges", removed);
        }
    }

    /// Get the number of active challenges
    pub async fn challenge_count(&self) -> usize {
        let challenges = self.challenges.lock().await;
        challenges.len()
    }

    /// Clean up all expired challenges
    pub async fn cleanup_expired(&self) -> usize {
        let mut challenges = self.challenges.lock().await;
        let before_count = challenges.len();

        challenges.retain(|_, c| !c.is_expired());

        let removed = before_count - challenges.len();
        if removed > 0 {
            debug!("Cleaned up {} expired challenges", removed);
        }

        removed
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signer::Signer;

    #[tokio::test]
    async fn test_challenge_lifecycle() {
        // Create key manager
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("test_keypair.json");
        let key_manager = Arc::new(KeyManager::new(&key_path, Duration::from_secs(600), 100).await.unwrap());

        // Create challenge manager
        let challenge_manager = ChallengeManager::new(
            key_manager.clone(),
            Duration::from_secs(10),
            100,
        );

        // Generate a challenge
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let challenge = challenge_manager.generate_challenge(client_addr).await.unwrap();

        // Verify it was stored
        assert_eq!(challenge_manager.challenge_count().await, 1);

        // Create a keypair to sign the challenge
        let keypair = solana_sdk::signature::Keypair::new();
        let signature = keypair.sign_message(&challenge.data);

        // Verify the challenge with the correct keypair's public key
        let result = challenge_manager.verify_challenge(
            &challenge.id,
            client_addr,
            &signature.to_string(),
            &keypair.pubkey().to_string(), // Use the signing keypair's pubkey
        ).await;

        // Now it should succeed because the signature matches the public key
        assert!(result.is_ok());

        // Check that the challenge was removed after successful verification
        assert_eq!(challenge_manager.challenge_count().await, 0);


        // Test expiration cleanup
        let challenge2 = challenge_manager.generate_challenge(client_addr).await.unwrap();
        assert_eq!(challenge_manager.challenge_count().await, 1);


        // Simulate expiration
        tokio::time::sleep(Duration::from_secs(11)).await; // Wait longer than timeout
        let removed = challenge_manager.cleanup_expired().await;
        assert_eq!(removed, 1); // The challenge should be removed by cleanup

        // Final count should be 0
        assert_eq!(challenge_manager.challenge_count().await, 0);
    }

    #[test]
    fn test_challenge_expiration() {
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let challenge = Challenge::new(
            "test".to_string(),
            vec![1, 2, 3],
            client_addr,
            Duration::from_millis(10), // Very short timeout for testing
        );

        // Initially should not be expired
        assert!(!challenge.is_expired());

        // Sleep to ensure it expires
        std::thread::sleep(Duration::from_millis(15));

        // Now it should be expired
        assert!(challenge.is_expired());

        // Time remaining should be zero
        assert_eq!(challenge.time_remaining(), Duration::from_secs(0));
    }
}
