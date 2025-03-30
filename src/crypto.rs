use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Verifier};
use hmac::{Hmac, Mac, NewMac};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use hkdf::Hkdf;

use crate::config;
use crate::types::{Result, VpnError};
use crate::utils;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Cached secret key for performance optimization
#[derive(Debug)]
pub struct CachedSecretKey {
    /// Remote endpoint's public key
    pub public_key: Pubkey,
    /// Shared secret derived via ECDH
    pub shared_secret: [u8; 32],
    /// Last time this key was used
    pub last_used: Instant,
}

impl CachedSecretKey {
    /// Create a new cached secret key
    pub fn new(public_key: Pubkey, shared_secret: [u8; 32]) -> Self {
        Self {
            public_key,
            shared_secret,
            last_used: Instant::now(),
        }
    }
    
    /// Check if this cached key has expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        utils::is_expired(self.last_used, ttl)
    }
    
    /// Update the last used timestamp
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

/// Secret key cache manager
#[derive(Debug, Clone)]
pub struct SecretKeyCache {
    cache: Arc<Mutex<HashMap<Pubkey, CachedSecretKey>>>,
}

impl SecretKeyCache {
    /// Create a new secret key cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Get a cached secret key, or compute it if not cached
    pub async fn get_or_compute(
        &self,
        local_keypair: &Keypair,
        remote_public: &Pubkey,
    ) -> Result<[u8; 32]> {
        let mut cache = self.cache.lock().await;
        
        // Check if we have a cached key
        if let Some(cached_key) = cache.get_mut(remote_public) {
            if !cached_key.is_expired(Duration::from_secs(config::SECRET_CACHE_TTL.as_secs())) {
                cached_key.touch();
                return Ok(cached_key.shared_secret);
            }
        }
        
        // Compute a new shared secret
        let shared_secret = generate_shared_secret(local_keypair, remote_public)?;
        
        // Add to cache
        cache.insert(
            *remote_public,
            CachedSecretKey::new(*remote_public, shared_secret),
        );
        
        // Clean up expired keys if cache is too large
        if cache.len() > config::MAX_SECRET_CACHE_SIZE {
            self.cleanup_expired_keys(&mut cache);
        }
        
        Ok(shared_secret)
    }
    
    /// Remove expired keys from the cache
    fn cleanup_expired_keys(&self, cache: &mut HashMap<Pubkey, CachedSecretKey>) {
        let ttl = config::SECRET_CACHE_TTL;
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

/// Session key manager for perfect forward secrecy
#[derive(Debug, Clone)]
pub struct SessionKeyManager {
    /// Current session keys
    session_keys: Arc<Mutex<HashMap<String, (Vec<u8>, Instant)>>>,
}

impl SessionKeyManager {
    /// Create a new session key manager
    pub fn new() -> Self {
        Self {
            session_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Generate a new random session key
    pub fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; config::SESSION_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }
    
    /// Store a session key
    pub async fn store_key(&self, client_id: &str, key: Vec<u8>) {
        let mut keys = self.session_keys.lock().await;
        keys.insert(client_id.to_string(), (key, Instant::now()));
    }
    
    /// Get a session key
    pub async fn get_key(&self, client_id: &str) -> Option<Vec<u8>> {
        let mut keys = self.session_keys.lock().await;
        if let Some((key, created_at)) = keys.get(client_id) {
            // Check if key needs rotation
            if utils::is_expired(*created_at, config::KEY_ROTATION_INTERVAL) {
                return None;
            }
            Some(key.clone())
        } else {
            None
        }
    }
    
    /// Rotate a session key
    pub async fn rotate_key(&self, client_id: &str) -> Vec<u8> {
        let new_key = Self::generate_key();
        self.store_key(client_id, new_key.clone()).await;
        new_key
    }
    
    /// Remove a client's session key
    pub async fn remove_key(&self, client_id: &str) {
        let mut keys = self.session_keys.lock().await;
        keys.remove(client_id);
    }
}

/// Generate a new Solana keypair
pub fn generate_keypair() -> Keypair {
    Keypair::new()
}

/// Convert Ed25519 private key to X25519 for ECDH
pub fn ed25519_private_to_x25519(ed25519_secret: &[u8]) -> Result<X25519SecretKey> {
    if ed25519_secret.len() != 32 {
        return Err(VpnError::Crypto("Invalid Ed25519 private key length".into()));
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
pub fn solana_keypair_to_bytes(keypair: &Keypair) -> Result<[u8; 32]> {
    let keypair_bytes = keypair.to_bytes();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&keypair_bytes[0..32]);
    Ok(secret)
}

/// Properly convert Ed25519 public key to X25519
pub fn ed25519_public_to_x25519(ed25519_public: &[u8]) -> Result<[u8; 32]> {
    if ed25519_public.len() != 32 {
        return Err(VpnError::Crypto("Invalid Ed25519 public key length".into()));
    }
    
    // Decompress the Edwards point from the Ed25519 public key
    let compressed = CompressedEdwardsY::from_slice(ed25519_public)
        .map_err(|_| VpnError::Crypto("Invalid Ed25519 public key format".into()))?;
        
    let edwards_point = compressed.decompress()
        .ok_or_else(|| VpnError::Crypto("Invalid Ed25519 point".into()))?;
    
    // Convert to Montgomery form (X25519)
    let montgomery_point: MontgomeryPoint = edwards_point.into();
    
    Ok(montgomery_point.to_bytes())
}

/// Generate a shared secret using X25519 ECDH with converted Ed25519 keys
pub fn generate_shared_secret(local_private: &Keypair, remote_public: &Pubkey) -> Result<[u8; 32]> {
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
        .map_err(|_| VpnError::Crypto("HKDF expansion failed".into()))?;
    
    Ok(output)
}

/// Encrypt data using ChaCha20-Poly1305 AEAD with authentication
pub fn encrypt_chacha20(data: &[u8], key: &[u8], nonce_bytes: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != 32 {
        return Err(VpnError::Crypto("Invalid key length for ChaCha20-Poly1305".into()));
    }
    
    // Convert the key to an AEAD key
    let aead_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(aead_key);
    
    // Generate a random nonce or use the provided one
    let nonce = if let Some(nb) = nonce_bytes {
        if nb.len() != 12 {
            return Err(VpnError::Crypto("Invalid nonce length for ChaCha20-Poly1305".into()));
        }
        let mut n = [0u8; 12];
        n.copy_from_slice(nb);
        n
    } else {
        let mut n = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut n);
        n
    };
    
    // Encrypt the data
    let nonce = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| VpnError::Crypto(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?;
    
    Ok((ciphertext, nonce.to_vec()))
}

/// Decrypt data using ChaCha20-Poly1305 AEAD with authentication verification
pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(VpnError::Crypto("Invalid key length for ChaCha20-Poly1305".into()));
    }
    
    if nonce.len() != 12 {
        return Err(VpnError::Crypto("Invalid nonce length for ChaCha20-Poly1305".into()));
    }
    
    // Convert the key and nonce
    let aead_key = Key::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(aead_key);
    
    // Decrypt and verify the data
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| VpnError::Crypto(format!("ChaCha20-Poly1305 decryption failed: {}", e)))?;
    
    Ok(plaintext)
}

/// Encrypt data using AES-256-CBC with a shared secret and HMAC for authentication
pub fn encrypt(data: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
    // Generate a random 16-byte IV
    let mut iv = [0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    
    // Create AES-256-CBC encryptor
    let encryptor = Aes256CbcEnc::new_from_slices(shared_secret, &iv)
        .map_err(|e| VpnError::Crypto(format!("Encryption setup failed: {}", e)))?;
        
    // Encrypt the data
    let mut buffer = vec![0u8; data.len() + 32]; // Allow space for padding
    let ciphertext = encryptor.encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buffer)
        .map_err(|e| VpnError::Crypto(format!("Encryption failed: {}", e)))?;
    
    // Prepare encrypted data: IV + Encrypted data
    let mut result = Vec::with_capacity(iv.len() + ciphertext.len() + 32); // +32 for HMAC
    result.extend_from_slice(&iv);
    result.extend_from_slice(ciphertext);
    
    // Add HMAC for authentication
    let mut mac = HmacSha256::new_from_slice(shared_secret)
        .map_err(|_| VpnError::Crypto("Invalid key length for HMAC".into()))?;
    mac.update(&result);
    let hmac_result = mac.finalize();
    result.extend_from_slice(&hmac_result.into_bytes());
    
    Ok(result)
}

/// Decrypt data using AES-256-CBC with a shared secret and verify HMAC
pub fn decrypt(encrypted: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted.len() < 16 + 32 { // IV + HMAC
        return Err(VpnError::Crypto("Encrypted data too short".into()));
    }
    
    // Extract HMAC (last 32 bytes)
    let hmac_offset = encrypted.len() - 32;
    let hmac_received = &encrypted[hmac_offset..];
    let authenticated_part = &encrypted[..hmac_offset];
    
    // Verify HMAC in constant time
    let mut mac = HmacSha256::new_from_slice(shared_secret)
        .map_err(|_| VpnError::Crypto("Invalid key length for HMAC".into()))?;
    mac.update(authenticated_part);
    
    mac.verify(hmac_received)
        .map_err(|_| VpnError::Crypto("HMAC verification failed".into()))?;
    
    // Extract IV and encrypted data
    let iv = &encrypted[0..16];
    let ciphertext = &encrypted[16..hmac_offset];
    
    // Create AES-256-CBC decryptor
    let decryptor = Aes256CbcDec::new_from_slices(shared_secret, iv)
        .map_err(|e| VpnError::Crypto(format!("Decryption setup failed: {}", e)))?;
    
    // Decrypt the data
    let mut buffer = vec![0u8; ciphertext.len()];
    let plaintext = decryptor.decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buffer)
        .map_err(|e| VpnError::Crypto(format!("Decryption failed: {}", e)))?;
    
    Ok(plaintext.to_vec())
}

/// Encrypt a network packet with the latest cryptographic method (ChaCha20-Poly1305)
pub fn encrypt_packet(packet: &[u8], session_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    encrypt_chacha20(packet, session_key, None)
}

/// Decrypt a network packet with the latest cryptographic method (ChaCha20-Poly1305)
pub fn decrypt_packet(encrypted: &[u8], session_key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    decrypt_chacha20(encrypted, session_key, nonce)
}

/// Sign a message using Solana keypair
pub fn sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign_message(message)
}

/// Verify a signature using Solana public key
pub fn verify_signature(pubkey: &Pubkey, message: &[u8], signature: &Signature) -> bool {
    signature.verify(pubkey.as_ref(), message)
}

/// Generate a challenge for authentication
pub fn generate_challenge() -> Vec<u8> {
    let mut challenge = vec![0u8; config::CHALLENGE_SIZE];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Derive a session key from a shared secret
pub fn derive_session_key(shared_secret: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    // Use HKDF to derive a session key from the shared secret
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
    let mut session_key = vec![0u8; 32];
    hkdf.expand(b"AERONYX-SESSION-KEY", &mut session_key)
        .map_err(|_| VpnError::Crypto("Failed to derive session key".into()))?;
    Ok(session_key)
}

/// Encrypt a session key for transmission
pub fn encrypt_session_key(
    session_key: &[u8],
    shared_secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    encrypt_chacha20(session_key, shared_secret, None)
}

/// Decrypt a session key received from peer
pub fn decrypt_session_key(
    encrypted_key: &[u8],
    nonce: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>> {
    decrypt_chacha20(encrypted_key, shared_secret, nonce)
}

/// Compute a key fingerprint (for logging/identification)
pub fn compute_key_fingerprint(pubkey: &Pubkey) -> String {
    let bytes = pubkey.to_bytes();
    let hash = Sha256::digest(&bytes);
    format!("{:x}", &hash[0..4])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();
        assert_ne!(keypair.to_bytes().len(), 0);
        assert_eq!(keypair.pubkey().to_bytes().len(), 32);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let shared_secret = [0u8; 32]; // Use a zero key for testing
        let data = b"Hello, Military-Grade VPN!";
        
        let encrypted = encrypt(data, &shared_secret).unwrap();
        let decrypted = decrypt(&encrypted, &shared_secret).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }
    
    #[test]
    fn test_chacha20_encryption_decryption() {
        let key = [1u8; 32]; // Use a simple key for testing
        let data = b"ChaCha20-Poly1305 is fast and secure!";
        
        let (encrypted, nonce) = encrypt_chacha20(data, &key, None).unwrap();
        let decrypted = decrypt_chacha20(&encrypted, &key, &nonce).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }
    
    #[test]
    fn test_key_conversion() {
        let keypair = generate_keypair();
        let pubkey = keypair.pubkey();
        
        // Test private key conversion
        let secret_bytes = solana_keypair_to_bytes(&keypair).unwrap();
        let x25519_secret = ed25519_private_to_x25519(&secret_bytes).unwrap();
        
        // Test public key conversion
        let public_bytes = pubkey.to_bytes();
        let x25519_public = ed25519_public_to_x25519(&public_bytes).unwrap();
        
        // Ensure conversions yield keys of the right size
        assert_eq!(x25519_secret.to_bytes().len(), 32);
        assert_eq!(x25519_public.len(), 32);
    }
    
    #[test]
    fn test_shared_secret_derivation() {
        let alice_keypair = generate_keypair();
        let bob_keypair = generate_keypair();
        
        let alice_pubkey = alice_keypair.pubkey();
        let bob_pubkey = bob_keypair.pubkey();
        
        // Both parties should derive the same shared secret
        let shared_secret_alice = generate_shared_secret(&alice_keypair, &bob_pubkey).unwrap();
        let shared_secret_bob = generate_shared_secret(&bob_keypair, &alice_pubkey).unwrap();
        
        // With proper ECDH, the shared secrets should match
        assert_eq!(shared_secret_alice, shared_secret_bob);
    }
    
    #[test]
    fn test_signature_verification() {
        let keypair = generate_keypair();
        let message = b"Sign this message";
        
        let signature = sign_message(&keypair, message);
        assert!(verify_signature(&keypair.pubkey(), message, &signature));
        
        // Modify the message to verify signature fails
        let modified_message = b"Sign this modified message";
        assert!(!verify_signature(&keypair.pubkey(), modified_message, &signature));
    }
    
    #[test]
    fn test_session_key_derivation() {
        let shared_secret = [2u8; 32];
        let nonce = [3u8; 12];
        
        let session_key1 = derive_session_key(&shared_secret, &nonce).unwrap();
        let session_key2 = derive_session_key(&shared_secret, &nonce).unwrap();
        
        // Same inputs should produce same output
        assert_eq!(session_key1, session_key2);
        
        // Different nonce should produce different output
        let different_nonce = [4u8; 12];
        let session_key3 = derive_session_key(&shared_secret, &different_nonce).unwrap();
        assert_ne!(session_key1, session_key3);
    }
}
