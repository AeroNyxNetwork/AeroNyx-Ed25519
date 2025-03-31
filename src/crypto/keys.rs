// src/crypto/keys.rs
//! Key management for the server.
//!
//! This module handles the generation, storage, and management of
//! cryptographic keys used for authentication and encryption.

use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{info, debug, error, warn};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Error type for key-related operations
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Key format error: {0}")]
    Format(String),
    
    #[error("Key not found: {0}")]
    NotFound(String),
    
    #[error("Invalid key data: {0}")]
    InvalidData(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Signature verification failed")]
    SignatureVerification,
}

/// Cached secret key for performance optimization
#[derive(Debug)]
struct CachedSecretKey {
    /// Remote endpoint's public key
    pub public_key: Pubkey,
    /// Shared secret derived via ECDH
    pub shared_secret: Vec<u8>,
    /// Last time this key was used
    pub last_used: Instant,
}

impl CachedSecretKey {
    /// Create a new cached secret key
    fn new(public_key: Pubkey, shared_secret: Vec<u8>) -> Self {
        Self {
            public_key,
            shared_secret,
            last_used: Instant::now(),
        }
    }
    
    /// Check if this cached key has expired
    fn is_expired(&self, ttl: Duration) -> bool {
        self.last_used.elapsed() > ttl
    }
    
    /// Update the last used timestamp
    fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

/// Secret key cache manager
#[derive(Debug, Clone)]
pub struct SecretKeyCache {
    cache: Arc<Mutex<HashMap<Pubkey, CachedSecretKey>>>,
    ttl: Duration,
    max_size: usize,
}

impl SecretKeyCache {
    /// Create a new secret key cache
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            max_size,
        }
    }
    
    /// Get a cached secret key, or compute it if not cached
    pub async fn get_or_compute(
        &self,
        local_keypair: &Keypair,
        remote_public: &Pubkey,
    ) -> Result<Vec<u8>, KeyError> {
        let mut cache = self.cache.lock().await;
        
        // Check if we have a cached key
        if let Some(cached_key) = cache.get_mut(remote_public) {
            if !cached_key.is_expired(self.ttl) {
                cached_key.touch();
                return Ok(cached_key.shared_secret.clone());
            }
        }
        
        // Compute a new shared secret
        let shared_secret = generate_shared_secret(local_keypair, remote_public)?;
        
        // Add to cache
        cache.insert(
            *remote_public,
            CachedSecretKey::new(*remote_public, shared_secret.clone()),
        );
        
        // Clean up expired keys if cache is too large
        if cache.len() > self.max_size {
            self.cleanup_expired_keys(&mut cache);
        }
        
        Ok(shared_secret)
    }
    
    /// Remove expired keys from the cache
    fn cleanup_expired_keys(&self, cache: &mut HashMap<Pubkey, CachedSecretKey>) {
        cache.retain(|_, v| !v.is_expired(self.ttl));
    }
    
    /// Manually invalidate a cached key
    pub async fn invalidate(&self, remote_public: &Pubkey) {
        let mut cache = self.cache.lock().await;
        cache.remove(remote_public);
    }
    
    /// Clear the entire cache
    pub async fn clear(&self) {
        let mut cache = self.cache.lock().await;
        cache.clear();
    }
}

/// Key manager for the server
#[derive(Debug, Clone)]
pub struct KeyManager {
    /// Server key pair
    keypair: Arc<Mutex<Keypair>>,
    /// Path to the key file
    key_path: PathBuf,
    /// Secret key cache
    secret_cache: SecretKeyCache,
}

impl KeyManager {
    /// Create a new key manager
    pub async fn new(key_path: impl AsRef<Path>, ttl: Duration, max_cache: usize) -> Result<Self, KeyError> {
        let path = key_path.as_ref().to_path_buf();
        
        // Load or generate keypair
        let keypair = Self::load_or_generate_keypair(&path)?;
        
        info!("Server public key: {}", keypair.pubkey());
        
        // Create secret key cache
        let secret_cache = SecretKeyCache::new(ttl, max_cache);
        
        Ok(Self {
            keypair: Arc::new(Mutex::new(keypair)),
            key_path: path,
            secret_cache,
        })
    }
    
    /// Load a keypair from file or generate a new one if it doesn't exist
    fn load_or_generate_keypair(path: &Path) -> Result<Keypair, KeyError> {
        if path.exists() {
            Self::load_keypair(path)
        } else {
            // Generate new keypair
            let keypair = Keypair::new();
            Self::save_keypair(&keypair, path)?;
            
            info!("Generated new server keypair at {}", path.display());
            Ok(keypair)
        }
    }
    
    /// Load a keypair from file
    fn load_keypair(path: &Path) -> Result<Keypair, KeyError> {
        let mut file = fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        
        // Try to parse as JSON first
        if let Ok(json_str) = std::str::from_utf8(&bytes) {
            if let Ok(parsed) = serde_json::from_str::<Vec<u8>>(json_str) {
                if parsed.len() == 64 {
                    return Keypair::from_bytes(&parsed)
                        .map_err(|e| KeyError::Format(format!("Invalid keypair bytes: {}", e)));
                }
            }
        }
        
        // If JSON parsing fails, try direct bytes
        if bytes.len() == 64 {
            Keypair::from_bytes(&bytes)
                .map_err(|e| KeyError::Format(format!("Invalid keypair bytes: {}", e)))
        } else if bytes.len() == 32 {
            // Might be just a secret key
            let mut full_bytes = [0u8; 64];
            full_bytes[0..32].copy_from_slice(&bytes);
            Keypair::from_bytes(&full_bytes)
                .map_err(|e| KeyError::Format(format!("Invalid keypair bytes: {}", e)))
        } else {
            Err(KeyError::Format(format!(
                "Invalid keypair file size: {} bytes", bytes.len()
            )))
        }
    }
    
    /// Save a keypair to file
    fn save_keypair(keypair: &Keypair, path: &Path) -> Result<(), KeyError> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        
        // Write keypair bytes directly
        let mut file = fs::File::create(path)?;
        file.write_all(&keypair.to_bytes())?;
        
        // Set restrictive permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = file.metadata()?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600); // Read/write for owner only
            fs::set_permissions(path, perms)?;
        }
        
        Ok(())
    }
    
    /// Get the server's public key
    pub async fn public_key(&self) -> Pubkey {
        let keypair = self.keypair.lock().await;
        keypair.pubkey()
    }
    
    /// Sign a message with the server's private key
    pub async fn sign_message(&self, message: &[u8]) -> Signature {
        let keypair = self.keypair.lock().await;
        keypair.sign_message(message)
    }
    
    /// Verify a signature against a public key
    pub fn verify_signature(pubkey: &Pubkey, message: &[u8], signature: &Signature) -> bool {
        signature.verify(pubkey.as_ref(), message)
    }
    
    /// Get or compute a shared secret with a client
    pub async fn get_shared_secret(&self, client_pubkey: &Pubkey) -> Result<Vec<u8>, KeyError> {
        let keypair = self.keypair.lock().await;
        self.secret_cache.get_or_compute(&keypair, client_pubkey).await
    }
    
    /// Rotate the server keypair
    pub async fn rotate_keypair(&self) -> Result<(), KeyError> {
        let new_keypair = Keypair::new();
        
        // Save to disk before moving the keypair
        Self::save_keypair(&new_keypair, &self.key_path)?;
        
        // Get the new public key for logging before moving the keypair
        let new_pubkey = new_keypair.pubkey();
        
        // Update the keypair
        {
            let mut keypair = self.keypair.lock().await;
            *keypair = new_keypair;
        }
        
        // Clear the secret cache
        self.secret_cache.clear().await;
        
        info!("Server keypair rotated, new public key: {}", new_pubkey);
        Ok(())
    }
    
    /// Compute a key fingerprint (for logging/identification)
    pub fn compute_fingerprint(pubkey: &Pubkey) -> String {
        let bytes = pubkey.to_bytes();
        let hash = Sha256::digest(&bytes);
        hex::encode(&hash[0..4])
    }
}

/// Convert Ed25519 private key to X25519 for ECDH
fn ed25519_private_to_x25519(ed25519_secret: &[u8]) -> Result<X25519SecretKey, KeyError> {
    if ed25519_secret.len() != 32 {
        return Err(KeyError::InvalidData("Invalid Ed25519 private key length".into()));
    }
    
    // Hash the private key with SHA-512 as specified in the RFC
    let hash = Sha512::digest(ed25519_secret);
    
    // Extract the lower 32 bytes and clear bits according to the X25519 spec
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash[0..32]);
    
    // Clear bits according to RFC 7748
    key_bytes[0] &= 248;  // Clear bits 0, 1, 2
    key_bytes[31] &= 127; // Clear bit 255
    key_bytes[31] |= 64;  // Set bit 254
    
    Ok(X25519SecretKey::from(key_bytes))
}

/// Extract Solana secret key bytes
fn solana_keypair_to_bytes(keypair: &Keypair) -> Result<[u8; 32], KeyError> {
    let keypair_bytes = keypair.to_bytes();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&keypair_bytes[0..32]);
    Ok(secret)
}

/// Properly convert Ed25519 public key to X25519
fn ed25519_public_to_x25519(ed25519_public: &[u8]) -> Result<[u8; 32], KeyError> {
    if ed25519_public.len() != 32 {
        return Err(KeyError::InvalidData("Invalid Ed25519 public key length".into()));
    }
    
    // Create a compressed Edwards point from the public key bytes
    let compressed = CompressedEdwardsY::from_slice(ed25519_public);
    
    // Decompress the Edwards point from the Ed25519 public key
    let edwards_point = compressed.decompress()
        .ok_or_else(|| KeyError::InvalidData("Invalid Ed25519 point".into()))?;
    
    // Convert to Montgomery form using the correct method
    let montgomery_bytes = edwards_point.to_montgomery().to_bytes();
    
    Ok(montgomery_bytes)
}

/// Generate a shared secret using X25519 ECDH with converted Ed25519 keys
pub fn generate_shared_secret(local_private: &Keypair, remote_public: &Pubkey) -> Result<Vec<u8>, KeyError> {
    // Convert Solana keypair to Ed25519 secret key bytes
    let ed25519_private = solana_keypair_to_bytes(local_private)?;
    
    // Convert Ed25519 private key to X25519
    let x25519_private = ed25519_private_to_x25519(&ed25519_private)?;
    
    // Convert Ed25519 public key to X25519
    let ed25519_public = remote_public.to_bytes();
    let x25519_public_bytes = ed25519_public_to_x25519(&ed25519_public)?;
    let x25519_public = X25519PublicKey::from(x25519_public_bytes);
    
    // Perform X25519 ECDH
    let ecdh_output = x25519_private.diffie_hellman(&x25519_public);
    
    // Derive a key using HKDF for better security
    let hkdf = Hkdf::<Sha256>::new(None, ecdh_output.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"AERONYX-VPN-KEY", &mut output)
        .map_err(|_| KeyError::Crypto("HKDF expansion failed".into()))?;
    
    Ok(output.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_keypair_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_keypair.json");
        
        // Generate and save keypair
        let original = Keypair::new();
        KeyManager::save_keypair(&original, &path).unwrap();
        
        // Load the keypair
        let loaded = KeyManager::load_keypair(&path).unwrap();
        
        // Check that public keys match
        assert_eq!(original.pubkey(), loaded.pubkey());
    }
    
    #[tokio::test]
    async fn test_secret_key_cache() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        
        let cache = SecretKeyCache::new(Duration::from_secs(10), 100);
        
        // Get a shared secret
        let secret1 = cache.get_or_compute(&keypair1, &keypair2.pubkey()).await.unwrap();
        
        // Get it again - should be from cache
        let secret2 = cache.get_or_compute(&keypair1, &keypair2.pubkey()).await.unwrap();
        
        // Should be the same
        assert_eq!(secret1, secret2);
        
        // Clear cache
        cache.clear().await;
        
        // Get secret again - should recompute
        let secret3 = cache.get_or_compute(&keypair1, &keypair2.pubkey()).await.unwrap();
        
        // Still should be the same
        assert_eq!(secret1, secret3);
    }
    
    #[test]
    fn test_shared_secret() {
        // Create two keypairs
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        
        // Each party derives the shared secret
        let secret1 = generate_shared_secret(&keypair1, &keypair2.pubkey()).unwrap();
        let secret2 = generate_shared_secret(&keypair2, &keypair1.pubkey()).unwrap();
        
        // The shared secrets should be identical
        assert_eq!(secret1, secret2);
    }
    
    #[test]
    fn test_key_format_conversion() {
        // Create a keypair
        let keypair = Keypair::new();
        
        // Extract the private and public keys
        let ed25519_private = solana_keypair_to_bytes(&keypair).unwrap();
        let ed25519_public = keypair.pubkey().to_bytes();
        
        // Convert to X25519 format
        let x25519_private = ed25519_private_to_x25519(&ed25519_private).unwrap();
        let x25519_public = ed25519_public_to_x25519(&ed25519_public).unwrap();
        
        // Create X25519 structures
        let x_private = X25519SecretKey::from(x25519_private.to_bytes());
        let x_public = X25519PublicKey::from(x25519_public);
        
        // Check that ECDH produces a valid result
        let shared_secret = x_private.diffie_hellman(&x_public);
        assert_eq!(shared_secret.as_bytes().len(), 32);
    }
}
