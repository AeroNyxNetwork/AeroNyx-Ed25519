// src/crypto/session.rs
//! Session key management for the server.
//!
//! This module manages the generation, storage, and rotation of
//! session keys used for encrypting network traffic.

use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
// Removed unused warn, info imports
use tracing::debug;

use crate::config::constants::SESSION_KEY_SIZE;
use crate::utils;

/// Session key entry with metadata
#[derive(Debug, Clone)]
pub struct SessionKeyEntry {
    /// Session key bytes
    pub key: Vec<u8>,
    /// When the key was created
    pub created_at: Instant,
    /// When the key was last used
    pub last_used: Instant,
    /// How many times the key has been used
    pub usage_count: u64,
}

impl SessionKeyEntry {
    /// Create a new session key entry
    fn new(key: Vec<u8>) -> Self {
        let now = Instant::now();
        Self {
            key,
            created_at: now,
            last_used: now,
            usage_count: 0,
        }
    }

    /// Update the last used timestamp and increment usage count
    fn touch(&mut self) {
        self.last_used = Instant::now();
        self.usage_count += 1;
    }

    /// Check if the key should be rotated based on age or usage
    fn should_rotate(&self, max_age: Duration, max_usage: u64) -> bool {
        self.created_at.elapsed() > max_age || (max_usage > 0 && self.usage_count > max_usage)
    }
}

/// Session key manager for the server
#[derive(Debug, Clone)]
pub struct SessionKeyManager {
    /// Current session keys by client ID
    session_keys: Arc<Mutex<HashMap<String, SessionKeyEntry>>>,
    /// Rotation interval
    rotation_interval: Duration,
    /// Maximum key usages before rotation
    max_key_usages: u64,
}

impl SessionKeyManager {
    /// Create a new session key manager
    pub fn new(rotation_interval: Duration, max_key_usages: u64) -> Self {
        Self {
            session_keys: Arc::new(Mutex::new(HashMap::new())),
            rotation_interval,
            max_key_usages,
        }
    }

    /// Generate a new random session key
    pub fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; SESSION_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Store a session key for a client
    pub async fn store_key(&self, client_id: &str, key: Vec<u8>) {
        let mut keys = self.session_keys.lock().await;
        let entry = SessionKeyEntry::new(key);
        keys.insert(client_id.to_string(), entry);
        debug!("Stored new session key for client {}", utils::security::StringValidator::sanitize_log(client_id));
    }

    /// Get a session key for a client, updating usage statistics
    pub async fn get_key(&self, client_id: &str) -> Option<Vec<u8>> {
        let mut keys = self.session_keys.lock().await;

        if let Some(entry) = keys.get_mut(client_id) {
            entry.touch();

            // Check if key needs rotation based on age or usage
            if entry.should_rotate(self.rotation_interval, self.max_key_usages) {
                // We don't rotate immediately here - return the current key
                // but log that it needs rotation. The rotation is done separately.
                debug!("Session key for client {} needs rotation", utils::security::StringValidator::sanitize_log(client_id));
            }

            Some(entry.key.clone())
        } else {
            None
        }
    }

    /// Check if a key needs to be rotated
    pub async fn needs_rotation(&self, client_id: &str) -> bool {
        let keys = self.session_keys.lock().await;

        if let Some(entry) = keys.get(client_id) {
            entry.should_rotate(self.rotation_interval, self.max_key_usages)
        } else {
            false
        }
    }

    /// Rotate a session key
    pub async fn rotate_key(&self, client_id: &str) -> Option<Vec<u8>> {
        let mut keys = self.session_keys.lock().await;

        // Only rotate if the client has an existing key
        if keys.contains_key(client_id) {
            let new_key = Self::generate_key();
            let entry = SessionKeyEntry::new(new_key.clone());
            keys.insert(client_id.to_string(), entry);

            debug!("Rotated session key for client {}", utils::security::StringValidator::sanitize_log(client_id));
            Some(new_key)
        } else {
            None
        }
    }

    /// Remove a client's session key
    pub async fn remove_key(&self, client_id: &str) {
        let mut keys = self.session_keys.lock().await;
        if keys.remove(client_id).is_some() {
            debug!("Removed session key for client {}", utils::security::StringValidator::sanitize_log(client_id));
        }
    }

    /// Get session key statistics
    pub async fn get_stats(&self) -> HashMap<String, (Duration, u64)> {
        let keys = self.session_keys.lock().await;
        let mut stats = HashMap::new();

        for (client_id, entry) in keys.iter() {
            stats.insert(
                client_id.clone(),
                (entry.created_at.elapsed(), entry.usage_count),
            );
        }

        stats
    }

    /// Clean up old unused sessions
    pub async fn cleanup_old_sessions(&self, inactive_timeout: Duration) -> usize {
        let mut keys = self.session_keys.lock().await;
        let before_count = keys.len();

        keys.retain(|client_id, entry| {
            let keep = entry.last_used.elapsed() <= inactive_timeout;
            if !keep {
                debug!("Cleaning up inactive session for client {}", utils::security::StringValidator::sanitize_log(client_id));
            }
            keep
        });

        let removed = before_count - keys.len();
        if removed > 0 {
            debug!("Cleaned up {} inactive sessions", removed);
        }

        removed
    }

    /// Get the number of active sessions
    pub async fn session_count(&self) -> usize {
        let keys = self.session_keys.lock().await;
        keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_key_lifecycle() {
        let manager = SessionKeyManager::new(Duration::from_secs(10), 100);
        let client_id = "test-client";

        // Initially no key
        assert!(manager.get_key(client_id).await.is_none());

        // Generate and store a key
        let key = SessionKeyManager::generate_key();
        manager.store_key(client_id, key.clone()).await;

        // Should be able to get the key
        let retrieved = manager.get_key(client_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), key);

        // Remove the key
        manager.remove_key(client_id).await;

        // Should be gone
        assert!(manager.get_key(client_id).await.is_none());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        // Set a short rotation interval for testing
        let manager = SessionKeyManager::new(Duration::from_millis(50), 5);
        let client_id = "test-client";

        // Generate and store a key
        let key = SessionKeyManager::generate_key();
        manager.store_key(client_id, key.clone()).await;

        // Get the key multiple times to increment usage
        for _ in 0..6 {
            manager.get_key(client_id).await;
        }

        // Should now need rotation due to usage
        assert!(manager.needs_rotation(client_id).await);

        // Alternatively, wait for age-based rotation
        let manager2 = SessionKeyManager::new(Duration::from_millis(10), 1000);
        let client_id2 = "test-client2";
        let key2_orig = SessionKeyManager::generate_key();
        manager2.store_key(client_id2, key2_orig.clone()).await; // Store key for client2

        // Wait for the key to expire
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(manager2.needs_rotation(client_id2).await);

        // Test actual rotation
        let new_key = manager2.rotate_key(client_id2).await.unwrap();

        // New key should be different from the original key for client2
        let retrieved = manager2.get_key(client_id2).await.unwrap();
        assert_eq!(retrieved, new_key);
        assert_ne!(retrieved, key2_orig); // Compare with the key stored for client2
    }

    #[tokio::test]
    async fn test_cleanup_old_sessions() {
        let manager = SessionKeyManager::new(Duration::from_secs(10), 100);

        // Add some clients
        manager.store_key("active-client", SessionKeyManager::generate_key()).await;
        manager.store_key("inactive-client", SessionKeyManager::generate_key()).await;

        // Wait a bit and touch only the active client
        tokio::time::sleep(Duration::from_millis(10)).await;
        manager.get_key("active-client").await;

        // Cleanup with a very short timeout
        let removed = manager.cleanup_old_sessions(Duration::from_millis(5)).await;

        // Should have removed the inactive client
        assert_eq!(removed, 1);
        assert_eq!(manager.session_count().await, 1);
        assert!(manager.get_key("active-client").await.is_some());
        assert!(manager.get_key("inactive-client").await.is_none());
    }

    #[test]
    fn test_generate_key() {
        // Generate two keys and make sure they're different
        let key1 = SessionKeyManager::generate_key();
        let key2 = SessionKeyManager::generate_key();

        assert_eq!(key1.len(), SESSION_KEY_SIZE);
        assert_eq!(key2.len(), SESSION_KEY_SIZE);
        assert_ne!(key1, key2);
    }
}
