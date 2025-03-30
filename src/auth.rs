use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::signer::Signer;
use tokio::sync::Mutex;
use crate::types::{AccessControlEntry, AccessControlList, Result, VpnError};
use crate::utils;
use crate::crypto;

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
    pub client_addr: String,
}

/// Authentication manager
#[derive(Debug)]
pub struct AuthManager {
    /// Active challenges
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
    /// Access control list
    access_control: Arc<Mutex<AccessControlList>>,
    /// Challenge timeout duration
    challenge_timeout: Duration,
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new(challenge_timeout: Duration) -> Self {
        Self {
            challenges: Arc::new(Mutex::new(HashMap::new())),
            access_control: Arc::new(Mutex::new(AccessControlList {
                default_policy: "deny".to_string(),
                entries: Vec::new(),
                updated_at: utils::current_timestamp_millis(),
            })),
            challenge_timeout,
        }
    }
    
    /// Load access control list from file
    pub async fn load_acl(&self, filename: &str) -> Result<bool> {
        match fs::read_to_string(filename) {
            Ok(content) => {
                let acl: AccessControlList = serde_json::from_str(&content)
                    .map_err(|e| VpnError::Json(e))?;
                let mut access_control = self.access_control.lock().await;
                *access_control = acl;
                Ok(true)
            }
            Err(e) => {
                // If file doesn't exist, create a default ACL
                if e.kind() == std::io::ErrorKind::NotFound {
                    let default_acl = AccessControlList {
                        default_policy: "deny".to_string(),
                        entries: Vec::new(),
                        updated_at: utils::current_timestamp_millis(),
                    };
                    let json = serde_json::to_string_pretty(&default_acl)?;
                    fs::write(filename, json)?;
                    let mut access_control = self.access_control.lock().await;
                    *access_control = default_acl;
                    Ok(false)
                } else {
                    Err(VpnError::Io(e))
                }
            }
        }
    }
    
    /// Save access control list to file
    pub async fn save_acl(&self, filename: &str) -> Result<()> {
        let access_control = self.access_control.lock().await;
        let json = serde_json::to_string_pretty(&*access_control)?;
        fs::write(filename, json)?;
        Ok(())
    }
    
    /// Add an entry to the access control list
    pub async fn add_acl_entry(&self, entry: AccessControlEntry) -> Result<()> {
        let mut access_control = self.access_control.lock().await;
        
        // Check if entry already exists
        for existing in &mut access_control.entries {
            if existing.public_key == entry.public_key {
                *existing = entry.clone();
                access_control.updated_at = utils::current_timestamp_millis();
                return Ok(());
            }
        }
        
        // Add new entry
        access_control.entries.push(entry);
        access_control.updated_at = utils::current_timestamp_millis();
        Ok(())
    }
    
    /// Remove an entry from the access control list
    pub async fn remove_acl_entry(&self, public_key: &str) -> Result<()> {
        let mut access_control = self.access_control.lock().await;
        let initial_len = access_control.entries.len();
        
        access_control.entries.retain(|e| e.public_key != public_key);
        
        if access_control.entries.len() < initial_len {
            access_control.updated_at = utils::current_timestamp_millis();
            Ok(())
        } else {
            Err(VpnError::AccessDenied(format!("Entry not found: {}", public_key)))
        }
    }
    
    /// Check if a public key is allowed to connect
    pub async fn is_allowed(&self, public_key: &Pubkey) -> Result<bool> {
        let access_control = self.access_control.lock().await;
        let pubkey_str = public_key.to_string();
        
        // Look for a specific entry for this public key
        for entry in &access_control.entries {
            if entry.public_key == pubkey_str {
                return Ok(entry.is_allowed);
            }
        }
        
        // Apply default policy
        match access_control.default_policy.as_str() {
            "allow" => Ok(true),
            "deny" => Err(VpnError::AccessDenied(format!("Public key not in ACL: {}", pubkey_str))),
            _ => Err(VpnError::AccessDenied("Invalid default policy".into())),
        }
    }
    
    /// Get access control entry for a public key
    pub async fn get_acl_entry(&self, public_key: &Pubkey) -> Result<AccessControlEntry> {
        let access_control = self.access_control.lock().await;
        let pubkey_str = public_key.to_string();
        
        for entry in &access_control.entries {
            if entry.public_key == pubkey_str {
                return Ok(entry.clone());
            }
        }
        
        Err(VpnError::AccessDenied(format!("Public key not in ACL: {}", pubkey_str)))
    }
    
    /// Generate a new challenge for a client
    pub async fn generate_challenge(&self, client_addr: &str) -> Result<(String, Vec<u8>)> {
        let challenge_data = crypto::generate_challenge();
        let challenge_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 24);
        
        let now = Instant::now();
        let expires_at = now + self.challenge_timeout;
        
        let challenge = Challenge {
            id: challenge_id.clone(),
            data: challenge_data.clone(),
            created_at: now,
            expires_at,
            client_addr: client_addr.to_string(),
        };
        
        let mut challenges = self.challenges.lock().await;
        challenges.insert(challenge_id.clone(), challenge);
        
        // Clean up expired challenges
        self.cleanup_challenges(&mut challenges);
        
        Ok((challenge_id, challenge_data))
    }
    
    /// Verify a challenge response
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        signature: &Signature,
        public_key: &Pubkey,
        client_addr: &str,
    ) -> Result<()> {
        let mut challenges = self.challenges.lock().await;
        
        // Find the challenge
        let challenge = challenges.get(challenge_id).ok_or_else(|| {
            VpnError::AuthenticationFailed(format!("Challenge not found: {}", challenge_id))
        })?;
        
        // Verify client address
        if challenge.client_addr != client_addr {
            return Err(VpnError::AuthenticationFailed(
                "Client address mismatch".into(),
            ));
        }
        
        // Check if challenge has expired
        if Instant::now() > challenge.expires_at {
            challenges.remove(challenge_id);
            return Err(VpnError::AuthenticationFailed("Challenge expired".into()));
        }
        
        // Verify signature
        if !crypto::verify_signature(public_key, &challenge.data, signature) {
            return Err(VpnError::SignatureVerificationFailed);
        }
        
        // Remove the used challenge
        challenges.remove(challenge_id);
        
        // Check access control
        self.is_allowed(public_key).await?;
        
        Ok(())
    }
    
    /// Clean up expired challenges
    fn cleanup_challenges(&self, challenges: &mut HashMap<String, Challenge>) {
        let now = Instant::now();
        challenges.retain(|_, challenge| challenge.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;
    
    #[tokio::test]
    async fn test_challenge_verification() {
        let auth_manager = AuthManager::new(Duration::from_secs(10));
        let client_addr = "127.0.0.1:12345";
        let keypair = Keypair::new();
        let public_key = keypair.pubkey();
        
        // Add the public key to the ACL
        let entry = AccessControlEntry {
            public_key: public_key.to_string(),
            access_level: 100,
            is_allowed: true,
            bandwidth_limit: 0,
            max_session_duration: 3600,
            static_ip: None,
            notes: None,
        };
        auth_manager.add_acl_entry(entry).await.unwrap();
        
        // Generate a challenge
        let (challenge_id, challenge_data) = auth_manager.generate_challenge(client_addr).await.unwrap();
        
        // Sign the challenge
        let signature = keypair.sign_message(&challenge_data);
        
        // Verify the challenge
        let result = auth_manager.verify_challenge(&challenge_id, &signature, &public_key, client_addr).await;
        assert!(result.is_ok());
        
        // Challenge should be consumed
        let challenges = auth_manager.challenges.lock().await;
        assert!(!challenges.contains_key(&challenge_id));
    }
    
    #[tokio::test]
    async fn test_acl_functionality() {
        let auth_manager = AuthManager::new(Duration::from_secs(10));
        let keypair = Keypair::new();
        let public_key = keypair.pubkey();
        
        // Public key should not be allowed initially
        let result = auth_manager.is_allowed(&public_key).await;
        assert!(result.is_err());
        
        // Add the public key to the ACL
        let entry = AccessControlEntry {
            public_key: public_key.to_string(),
            access_level: 100,
            is_allowed: true,
            bandwidth_limit: 0,
            max_session_duration: 3600,
            static_ip: None,
            notes: None,
        };
        auth_manager.add_acl_entry(entry.clone()).await.unwrap();
        
        // Now the public key should be allowed
        let result = auth_manager.is_allowed(&public_key).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Get the entry
        let retrieved_entry = auth_manager.get_acl_entry(&public_key).await.unwrap();
        assert_eq!(retrieved_entry.public_key, entry.public_key);
        
        // Remove the entry
        auth_manager.remove_acl_entry(&public_key.to_string()).await.unwrap();
        
        // Public key should no longer be allowed
        let result = auth_manager.is_allowed(&public_key).await;
        assert!(result.is_err());
    }
}
