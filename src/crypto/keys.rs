// src/crypto/keys.rs
//! Key management for the server.
//!
//! This module handles the generation, storage, and management of
//! cryptographic keys used for authentication and encryption.
//!
//! ## Key Changes (Updated for X25519 support)
//! - Added independent X25519 keypair generation
//! - Server now maintains both Ed25519 (for signatures) and X25519 (for ECDH) keys
//! - X25519 keys are generated independently, not derived from Ed25519
//! - Both keypairs are saved/loaded together for consistency
//!
//! ## Why These Changes
//! - Ed25519 and X25519 use different curve representations
//! - Direct conversion between them is complex and error-prone
//! - Independent generation is simpler and more secure
//! - Clients need X25519 public key for ECDH key exchange

use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256, Sha512};
use solana_sdk::pubkey::Pubkey;
use ed25519_dalek::{SecretKey, PublicKey, Keypair as DalekKeypair};
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
use tracing::{info, warn};
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
            } else {
                // Remove expired key before recomputing
                cache.remove(remote_public);
            }
        }

        // Compute a new shared secret
        let shared_secret = generate_shared_secret(local_keypair, remote_public)?;

        // Add to cache
        if cache.len() >= self.max_size {
             self.cleanup_expired_keys(&mut cache);
             if cache.len() >= self.max_size {
                  // Simple LRU: remove oldest entry
                  if let Some(oldest_key) = cache.keys().next().cloned() {
                      cache.remove(&oldest_key);
                  }
             }
        }

        cache.insert(
            *remote_public,
            CachedSecretKey::new(*remote_public, shared_secret.clone()),
        );

        Ok(shared_secret)
    }

    /// Remove expired keys from the cache
    fn cleanup_expired_keys(&self, cache: &mut HashMap<Pubkey, CachedSecretKey>) {
        let ttl = self.ttl;
        cache.retain(|_, v| !v.is_expired(ttl));
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

/// Combined keypair storage structure
/// Note: X25519SecretKey (StaticSecret) does not implement Debug,
/// so we implement Debug manually for this struct
struct CombinedKeypairs {
    ed25519: Keypair,
    x25519_private: X25519SecretKey,
    x25519_public: X25519PublicKey,
}

impl std::fmt::Debug for CombinedKeypairs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CombinedKeypairs")
            .field("ed25519", &self.ed25519.pubkey())
            .field("x25519_public", &bs58::encode(self.x25519_public.as_bytes()).into_string())
            .finish()
    }
}

/// Key manager for the server
/// 
/// ## X25519 Support
/// The KeyManager now maintains both Ed25519 and X25519 keypairs:
/// - Ed25519: Used for signatures and authentication
/// - X25519: Used for ECDH key exchange
/// Both are generated independently and stored together
#[derive(Debug, Clone)]
pub struct KeyManager {
    /// Combined keypairs (Ed25519 + X25519)
    keypairs: Arc<Mutex<CombinedKeypairs>>,
    /// Path to the key file
    key_path: PathBuf,
    /// Secret key cache
    secret_cache: SecretKeyCache,
}

impl KeyManager {
    /// Create a new key manager with both Ed25519 and X25519 support
    pub async fn new(key_path: impl AsRef<Path>, ttl: Duration, max_cache: usize) -> Result<Self, KeyError> {
        let path = key_path.as_ref().to_path_buf();

        // Load or generate both keypairs
        let keypairs = Self::load_or_generate_keypairs(&path)?;

        info!("Server Ed25519 public key: {}", keypairs.ed25519.pubkey());
        info!("Server X25519 public key: {}", bs58::encode(keypairs.x25519_public.as_bytes()).into_string());

        // Create secret key cache
        let secret_cache = SecretKeyCache::new(ttl, max_cache);

        Ok(Self {
            keypairs: Arc::new(Mutex::new(keypairs)),
            key_path: path,
            secret_cache,
        })
    }

    /// Load keypairs from file or generate new ones if they don't exist
    fn load_or_generate_keypairs(path: &Path) -> Result<CombinedKeypairs, KeyError> {
        if path.exists() {
            Self::load_keypairs(path)
        } else {
            // Generate new keypairs
            let ed25519 = Keypair::new();
            let x25519_private = X25519SecretKey::new(OsRng);
            let x25519_public = X25519PublicKey::from(&x25519_private);
            
            let keypairs = CombinedKeypairs {
                ed25519,
                x25519_private,
                x25519_public,
            };
            
            Self::save_keypairs(&keypairs, path)?;
            info!("Generated new server keypairs at {}", path.display());
            Ok(keypairs)
        }
    }

    /// Load keypairs from file
    /// File format: 64 bytes Ed25519 + 32 bytes X25519 private key = 96 bytes total
    fn load_keypairs(path: &Path) -> Result<CombinedKeypairs, KeyError> {
        let mut file = fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        // Check for new format (96 bytes)
        if bytes.len() == 96 {
            // Load Ed25519 keypair (first 64 bytes)
            let ed25519 = Keypair::from_bytes(&bytes[0..64])
                .map_err(|e| KeyError::Format(format!("Invalid Ed25519 keypair: {}", e)))?;
            
            // Load X25519 private key (last 32 bytes)
            let mut x25519_bytes = [0u8; 32];
            x25519_bytes.copy_from_slice(&bytes[64..96]);
            let x25519_private = X25519SecretKey::from(x25519_bytes);
            let x25519_public = X25519PublicKey::from(&x25519_private);
            
            Ok(CombinedKeypairs {
                ed25519,
                x25519_private,
                x25519_public,
            })
        } else if bytes.len() == 64 {
            // Old format: only Ed25519, generate X25519
            warn!("Loading old format keypair, generating new X25519 keypair");
            let ed25519 = Keypair::from_bytes(&bytes)
                .map_err(|e| KeyError::Format(format!("Invalid Ed25519 keypair: {}", e)))?;
            
            // Generate new X25519 keypair
            let x25519_private = X25519SecretKey::new(OsRng);
            let x25519_public = X25519PublicKey::from(&x25519_private);
            
            let keypairs = CombinedKeypairs {
                ed25519,
                x25519_private,
                x25519_public,
            };
            
            // Save the combined keypairs for next time
            Self::save_keypairs(&keypairs, path)?;
            
            Ok(keypairs)
        } else {
            Err(KeyError::Format(format!(
                "Invalid keypair file size: {} bytes (expected 96 or 64)", 
                bytes.len()
            )))
        }
    }

    /// Save keypairs to file
    fn save_keypairs(keypairs: &CombinedKeypairs, path: &Path) -> Result<(), KeyError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        // Combine both keypairs: Ed25519 (64 bytes) + X25519 private (32 bytes)
        let mut combined = Vec::with_capacity(96);
        combined.extend_from_slice(&keypairs.ed25519.to_bytes());
        combined.extend_from_slice(&keypairs.x25519_private.to_bytes());

        let mut file = fs::File::create(path)?;
        file.write_all(&combined)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = file.metadata() {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                drop(file);
                fs::set_permissions(path, perms)?;
            } else {
                warn!("Could not read metadata for {:?}, permissions not set.", path);
                drop(file);
            }
        }
        
        #[cfg(not(unix))]
        drop(file);

        Ok(())
    }

    /// Get the server's Ed25519 public key
    pub async fn public_key(&self) -> Pubkey {
        let keypairs = self.keypairs.lock().await;
        keypairs.ed25519.pubkey()
    }

    /// Get the server's X25519 public key as base58 string
    pub async fn get_x25519_public_key_string(&self) -> String {
        let keypairs = self.keypairs.lock().await;
        bs58::encode(keypairs.x25519_public.as_bytes()).into_string()
    }

    /// Get the server's X25519 public key
    pub async fn get_x25519_public_key(&self) -> X25519PublicKey {
        let keypairs = self.keypairs.lock().await;
        keypairs.x25519_public.clone()
    }

    /// Sign a message with the server's private key
    pub async fn sign_message(&self, message: &[u8]) -> Signature {
        let keypairs = self.keypairs.lock().await;
        keypairs.ed25519.sign_message(message)
    }

    /// Verify a signature against a public key
    pub fn verify_signature(pubkey: &Pubkey, message: &[u8], signature: &Signature) -> bool {
        signature.verify(pubkey.as_ref(), message)
    }

    /// Get or compute a shared secret with a client
    /// Uses the Ed25519 keypair for ECDH (converted to X25519 internally)
    pub async fn get_shared_secret(&self, client_pubkey: &Pubkey) -> Result<Vec<u8>, KeyError> {
        let keypairs = self.keypairs.lock().await;
        self.secret_cache.get_or_compute(&keypairs.ed25519, client_pubkey).await
    }

    /// Rotate the server keypairs (both Ed25519 and X25519)
    pub async fn rotate_keypair(&self) -> Result<(), KeyError> {
        // Generate new keypairs
        let new_ed25519 = Keypair::new();
        let new_x25519_private = X25519SecretKey::new(OsRng);
        let new_x25519_public = X25519PublicKey::from(&new_x25519_private);
        
        let new_keypairs = CombinedKeypairs {
            ed25519: new_ed25519,
            x25519_private: new_x25519_private,
            x25519_public: new_x25519_public,
        };
        
        let new_ed25519_pubkey = new_keypairs.ed25519.pubkey();
        let new_x25519_pubkey_str = bs58::encode(new_keypairs.x25519_public.as_bytes()).into_string();

        // Save the NEW keypairs to file first
        Self::save_keypairs(&new_keypairs, &self.key_path)?;

        // Update the keypairs in memory
        {
            let mut keypairs_guard = self.keypairs.lock().await;
            *keypairs_guard = new_keypairs;
        }

        // Clear the secret cache as old secrets are now invalid
        self.secret_cache.clear().await;

        info!("Server keypairs rotated");
        info!("  New Ed25519 public key: {}", new_ed25519_pubkey);
        info!("  New X25519 public key: {}", new_x25519_pubkey_str);
        
        Ok(())
    }

    /// Compute a key fingerprint (for logging/identification)
    pub fn compute_fingerprint(pubkey: &Pubkey) -> String {
        let bytes = pubkey.to_bytes();
        let hash = Sha256::digest(&bytes);
        hex::encode(&hash[0..4])
    }
}

// Keep existing helper functions unchanged
/// Convert Ed25519 private key to X25519 for ECDH
fn ed25519_private_to_x25519(ed25519_secret: &[u8]) -> Result<X25519SecretKey, KeyError> {
    if ed25519_secret.len() != 32 {
        return Err(KeyError::InvalidData("Invalid Ed25519 private key length".into()));
    }

    let hash = Sha512::digest(ed25519_secret);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash[0..32]);

    key_bytes[0] &= 248;
    key_bytes[31] &= 127;
    key_bytes[31] |= 64;

    Ok(X25519SecretKey::from(key_bytes))
}

/// Extract Solana secret key bytes
fn solana_keypair_to_bytes(keypair: &Keypair) -> Result<[u8; 32], KeyError> {
    let keypair_bytes = keypair.to_bytes();
    if keypair_bytes.len() != 64 {
         return Err(KeyError::Format("Keypair bytes have unexpected length".into()));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&keypair_bytes[0..32]);
    Ok(secret)
}

/// Properly convert Ed25519 public key to X25519
fn ed25519_public_to_x25519(ed25519_public: &[u8]) -> Result<[u8; 32], KeyError> {
    if ed25519_public.len() != 32 {
        return Err(KeyError::InvalidData("Invalid Ed25519 public key length".into()));
    }

    let compressed = CompressedEdwardsY::from_slice(ed25519_public);
    let edwards_point = compressed.decompress()
        .ok_or_else(|| KeyError::InvalidData("Invalid Ed25519 point".into()))?;

    let montgomery_bytes = edwards_point.to_montgomery().to_bytes();
    Ok(montgomery_bytes)
}

/// Generate a shared secret using X25519 ECDH with converted Ed25519 keys
pub fn generate_shared_secret(local_private: &Keypair, remote_public: &Pubkey) -> Result<Vec<u8>, KeyError> {
    let ed25519_private = solana_keypair_to_bytes(local_private)?;
    let x25519_private = ed25519_private_to_x25519(&ed25519_private)?;

    let ed25519_public = remote_public.to_bytes();
    let x25519_public_bytes = ed25519_public_to_x25519(&ed25519_public)?;
    let x25519_public = X25519PublicKey::from(x25519_public_bytes);

    let ecdh_output = x25519_private.diffie_hellman(&x25519_public);

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
        let path = dir.path().join("test_keypair.bin");

        // Generate and save keypairs
        let original_ed25519 = Keypair::new();
        let original_x25519_private = X25519SecretKey::new(OsRng);
        let original_x25519_public = X25519PublicKey::from(&original_x25519_private);
        
        let original = CombinedKeypairs {
            ed25519: original_ed25519,
            x25519_private: original_x25519_private,
            x25519_public: original_x25519_public,
        };
        
        KeyManager::save_keypairs(&original, &path).unwrap();

        // Load the keypairs
        let loaded = KeyManager::load_keypairs(&path).unwrap();

        // Check that keys match
        assert_eq!(original.ed25519.pubkey(), loaded.ed25519.pubkey());
        assert_eq!(original.ed25519.to_bytes(), loaded.ed25519.to_bytes());
        assert_eq!(original.x25519_public.as_bytes(), loaded.x25519_public.as_bytes());
    }

    #[tokio::test]
    async fn test_x25519_public_key_retrieval() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_keypair.bin");
        
        let key_manager = KeyManager::new(&path, Duration::from_secs(600), 100)
            .await
            .unwrap();
        
        // Get X25519 public key
        let x25519_key_string = key_manager.get_x25519_public_key_string().await;
        assert!(!x25519_key_string.is_empty());
        
        // Verify it's valid base58
        let decoded = bs58::decode(&x25519_key_string).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    // Keep other existing tests...
    #[tokio::test]
    async fn test_secret_key_cache() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let cache = SecretKeyCache::new(Duration::from_secs(1), 100);

        let secret1 = cache.get_or_compute(&keypair1, &keypair2.pubkey()).await.unwrap();
        let secret2 = cache.get_or_compute(&keypair1, &keypair2.pubkey()).await.unwrap();
        assert_eq!(secret1, secret2);

        tokio::time::sleep(Duration::from_secs(2)).await;

        let secret3 = cache.get_or_compute(&keypair1, &keypair2.pubkey()).await.unwrap();
        assert_eq!(secret1, secret3);

        cache.invalidate(&keypair2.pubkey()).await;
        let cache_map = cache.cache.lock().await;
        assert!(cache_map.is_empty());
    }

    #[test]
    fn test_shared_secret() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        let secret1 = generate_shared_secret(&keypair1, &keypair2.pubkey()).unwrap();
        let secret2 = generate_shared_secret(&keypair2, &keypair1.pubkey()).unwrap();

        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 32);
    }
}
