// src/crypto/encryption.rs
//! Encryption utilities for secure communication.
//!
//! This module provides functions for encrypting and decrypting data
//! using various authenticated encryption schemes including ChaCha20-Poly1305
//! and AES-GCM with proper authentication.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use hmac::{Hmac, Mac}; // No NewMac, as it's accessed through the Mac trait
use rand::{Rng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, info, warn, error};

// Add AES-GCM imports
use aes_gcm::{
    aead::{Aead as AesGcmAead, KeyInit},
    Aes256Gcm, Nonce as AesGcmNonce
};
use generic_array::GenericArray;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Error type for encryption operations
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid padding: {0}")]
    InvalidPadding(String),

    #[error("Buffer too small")]
    BufferTooSmall,
}

/// Generate random bytes for a challenge
pub fn generate_challenge(size: usize) -> Vec<u8> {
    let mut challenge = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Encrypt data using ChaCha20-Poly1305 AEAD with authentication
pub fn encrypt_chacha20(data: &[u8], key: &[u8], nonce_bytes: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    if key.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength(key.len()));
    }

    // Convert the key to an AEAD key
    let aead_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(aead_key);

    // Generate a random nonce or use the provided one
    let nonce_val = if let Some(nb) = nonce_bytes {
        if nb.len() != 12 {
            return Err(EncryptionError::InvalidFormat(format!(
                "Invalid nonce length: {} (expected 12)",
                nb.len()
            )));
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
    let nonce = Nonce::from_slice(&nonce_val);
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| EncryptionError::EncryptionFailed(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?;

    Ok((ciphertext, nonce_val.to_vec()))
}

/// Decrypt data using ChaCha20-Poly1305 AEAD with authentication verification
pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if key.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength(key.len()));
    }

    if nonce.len() != 12 {
        return Err(EncryptionError::InvalidFormat(format!("Invalid nonce length: {} (expected 12)", nonce.len())));
    }

    // Convert the key and nonce
    let aead_key = Key::from_slice(key);
    let nonce_aead = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(aead_key);

    // Decrypt and verify the data
    let plaintext = cipher.decrypt(nonce_aead, ciphertext)
        .map_err(|e| {
            // Log authentication failures as they may indicate tampering
            debug!("ChaCha20-Poly1305 decryption failed: {}", e);
            EncryptionError::AuthenticationFailed
        })?;

    Ok(plaintext)
}

/// Encrypt data using AES-256-GCM with optional additional authenticated data (AAD)
/// 
/// # Parameters
/// - `plaintext`: The data to encrypt
/// - `key`: 32-byte AES-256 key
/// - `aad`: Optional additional authenticated data
///
/// # Returns
/// - Tuple of (ciphertext, nonce) where:
///   - ciphertext includes the authentication tag
///   - nonce is the 12-byte IV used for encryption
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    // Log the input parameters
    info!("AES-GCM Encryption: plaintext length={}, key length={}, aad={}",
         plaintext.len(), key.len(), aad.is_some());
    
    // For debugging, also log partial key and plaintext
    if !key.is_empty() {
        debug!("AES-GCM Key prefix: {:02x?}", &key[0..min(8, key.len())]);
    }
    if !plaintext.is_empty() {
        debug!("AES-GCM Plaintext prefix: {:02x?}", &plaintext[0..min(16, plaintext.len())]);
    }
    
    // Validate key length
    if key.len() != 32 {
        error!("AES-GCM encryption failed: Invalid key length {}", key.len());
        return Err(EncryptionError::InvalidKeyLength(key.len()));
    }

    // Initialize AES-GCM cipher with key
    debug!("Creating AES-GCM cipher with key");
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    
    // Generate a secure random 12-byte nonce (IV)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    debug!("Generated nonce: {:02x?}", nonce_bytes);
    
    let nonce = AesGcmNonce::from_slice(&nonce_bytes);
    
    // Encrypt plaintext, incorporating AAD if provided
    let ciphertext = match aad {
        Some(aad_data) => {
            debug!("Encrypting with AAD, AAD length={}", aad_data.len());
            
            // Version 1: Attempt to use AAD properly (adjust based on actual library implementation)
            cipher.encrypt(nonce, aad_data)
                .and_then(|_| cipher.encrypt(nonce, plaintext))
                .map_err(|e| {
                    error!("AES-GCM encryption failed with AAD: {}", e);
                    EncryptionError::EncryptionFailed(format!("AES-GCM encryption failed with AAD: {}", e))
                })?
        },
        None => {
            debug!("Encrypting without AAD");
            cipher.encrypt(nonce, plaintext)
                .map_err(|e| {
                    error!("AES-GCM encryption failed: {}", e);
                    EncryptionError::EncryptionFailed(format!("AES-GCM encryption failed: {}", e))
                })?
        },
    };
    
    info!("AES-GCM encryption successful: plaintext={} bytes, ciphertext={} bytes",
         plaintext.len(), ciphertext.len());
    debug!("Ciphertext prefix: {:02x?}", &ciphertext[0..min(16, ciphertext.len())]);
    
    Ok((ciphertext, nonce_bytes.to_vec()))
}


pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if key.len() != 32 {
        error!("ChaCha20 key length invalid: {} (expected 32)", key.len());
        return Err(EncryptionError::InvalidKeyLength(key.len()));
    }

    if nonce.len() != 12 {
        error!("ChaCha20 nonce length invalid: {} (expected 12)", nonce.len());
        return Err(EncryptionError::InvalidFormat(format!("Invalid nonce length: {} (expected 12)", nonce.len())));
    }

    // Print detailed debug information
    info!("ChaCha20-Poly1305 Decryption: ciphertext length={}, key length={}, nonce length={}",
         ciphertext.len(), key.len(), nonce.len());
    
    // Print key prefix (first 8 bytes or fewer)
    if !key.is_empty() {
        debug!("ChaCha20 Key prefix: {:02x?}", &key[0..min(8, key.len())]);
    }
    
    // Print full nonce (it's only 12 bytes)
    debug!("ChaCha20 Nonce: {:02x?}", nonce);
    
    // Print ciphertext prefix
    if !ciphertext.is_empty() {
        debug!("ChaCha20 Ciphertext prefix: {:02x?}", &ciphertext[0..min(16, ciphertext.len())]);
    }

    // Convert the key and nonce
    let aead_key = Key::from_slice(key);
    let nonce_aead = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(aead_key);

    debug!("ChaCha20 cipher created, attempting decryption");

    // Decrypt and verify the data
    let plaintext = match cipher.decrypt(nonce_aead, ciphertext) {
        Ok(plaintext) => {
            debug!("ChaCha20 decryption successful: {} bytes", plaintext.len());
            if !plaintext.is_empty() {
                debug!("ChaCha20 Plaintext prefix: {:02x?}", &plaintext[0..min(16, plaintext.len())]);
            }
            plaintext
        },
        Err(e) => {
            // Log authentication failures as they may indicate tampering
            error!("ChaCha20-Poly1305 decryption failed: {}", e);
            
            // Add more diagnostic info
            debug!("ChaCha20 Ciphertext full: {:02x?}", ciphertext);
            
            return Err(EncryptionError::AuthenticationFailed);
        }
    };

    Ok(plaintext)
}

/// Decrypt data using AES-256-GCM with optional additional authenticated data (AAD)
/// 
/// # Parameters
/// - `ciphertext`: The encrypted data including authentication tag
/// - `key`: 32-byte AES-256 key
/// - `nonce`: 12-byte IV used during encryption
/// - `aad`: Optional additional authenticated data (must match what was used for encryption)
///
/// # Returns
/// - Decrypted plaintext or error
pub fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8], nonce: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, EncryptionError> {
    // Log the input parameters
    info!("AES-GCM Decryption: ciphertext length={}, key length={}, nonce length={}, aad={}",
         ciphertext.len(), key.len(), nonce.len(), aad.is_some());
    
    // For debugging, also log partial key, nonce and ciphertext
    if !key.is_empty() {
        debug!("AES-GCM Key prefix: {:02x?}", &key[0..min(8, key.len())]);
    }
    if !nonce.is_empty() {
        debug!("AES-GCM Nonce: {:02x?}", nonce);
    }
    if !ciphertext.is_empty() {
        debug!("AES-GCM Ciphertext prefix: {:02x?}", &ciphertext[0..min(16, ciphertext.len())]);
    }
    
    // Validate key length
    if key.len() != 32 {
        error!("AES-GCM decryption failed: Invalid key length {}", key.len());
        return Err(EncryptionError::InvalidKeyLength(key.len()));
    }
    
    // Validate nonce length
    if nonce.len() != 12 {
        error!("AES-GCM decryption failed: Invalid nonce length {}", nonce.len());
        return Err(EncryptionError::InvalidFormat(format!(
            "Invalid nonce length: {} (expected 12)", nonce.len()
        )));
    }
    
    // Initialize AES-GCM cipher with key
    debug!("Creating AES-GCM cipher for decryption");
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    
    // Prepare nonce
    let nonce_array = AesGcmNonce::from_slice(nonce);
    
    // Decrypt ciphertext, verifying AAD if provided
    let plaintext = match aad {
        Some(aad_data) => {
            debug!("Decrypting with AAD, AAD length={}", aad_data.len());
            
            // Version 1: Attempt to verify AAD (adjust based on actual library implementation)
            cipher.decrypt(nonce_array, aad_data)
                .and_then(|_| cipher.decrypt(nonce_array, ciphertext))
                .map_err(|e| {
                    error!("AES-GCM decryption failed with AAD: {}", e);
                    EncryptionError::AuthenticationFailed
                })?
        },
        None => {
            debug!("Decrypting without AAD");
            cipher.decrypt(nonce_array, ciphertext)
                .map_err(|e| {
                    error!("AES-GCM decryption failed: {}", e);
                    EncryptionError::AuthenticationFailed
                })?
        },
    };
    
    info!("AES-GCM decryption successful: ciphertext={} bytes, plaintext={} bytes",
         ciphertext.len(), plaintext.len());
    if !plaintext.is_empty() {
        debug!("Plaintext prefix: {:02x?}", &plaintext[0..min(16, plaintext.len())]);
    }
    
    Ok(plaintext)
}

/// Encrypt data using AES-256-CBC with a shared secret and HMAC for authentication
pub fn encrypt_aes(data: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    // Check shared_secret length
    if shared_secret.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength(shared_secret.len()));
    }

    // Generate a random 16-byte IV
    let mut iv = [0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);

    // Extract 32 bytes for AES key
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&shared_secret[0..32]);

    // Create AES-256-CBC encryptor
    let encryptor = Aes256CbcEnc::new_from_slices(&key_bytes, &iv)
        .map_err(|e| EncryptionError::EncryptionFailed(format!("Encryption setup failed: {}", e)))?;

    // Encrypt the data
    let mut buffer = vec![0u8; data.len() + 16]; // Allow space for padding
    let ciphertext_len = encryptor.encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buffer)
        .map_err(|e| EncryptionError::EncryptionFailed(format!("Encryption failed: {}", e)))?
        .len();

    // Prepare encrypted data: IV + Encrypted data
    let ciphertext = &buffer[..ciphertext_len];
    let mut result = Vec::with_capacity(iv.len() + ciphertext.len() + 32); // +32 for HMAC
    result.extend_from_slice(&iv);
    result.extend_from_slice(ciphertext);

    // Add HMAC for authentication - using the correct API based on hmac 0.12
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key_bytes)
        .map_err(|_| EncryptionError::InvalidKeyLength(key_bytes.len()))?;
    mac.update(&result); // HMAC covers IV + Ciphertext
    let hmac_result = mac.finalize();
    let hmac_bytes = hmac_result.into_bytes();
    result.extend_from_slice(&hmac_bytes);

    Ok(result)
}

/// Decrypt data using AES-256-CBC with a shared secret and verify HMAC
pub fn decrypt_aes(encrypted: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    // Check shared_secret length
    if shared_secret.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength(shared_secret.len()));
    }

    // Check minimum length: 16 (IV) + 1 (min ciphertext block) + 32 (HMAC)
    if encrypted.len() < 16 + 1 + 32 {
        return Err(EncryptionError::InvalidFormat("Encrypted data too short".into()));
    }

    // Extract 32 bytes for AES key
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&shared_secret[0..32]);

    // Extract HMAC (last 32 bytes)
    let hmac_offset = encrypted.len() - 32;
    let hmac_received = &encrypted[hmac_offset..];
    let authenticated_part = &encrypted[..hmac_offset]; // Part to authenticate (IV + Ciphertext)

    // Verify HMAC using the correct API
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key_bytes)
        .map_err(|_| EncryptionError::InvalidKeyLength(key_bytes.len()))?;
    mac.update(authenticated_part);

    mac.verify_slice(hmac_received)
        .map_err(|_| EncryptionError::AuthenticationFailed)?;

    // Extract IV and encrypted data (ciphertext is between IV and HMAC)
    let iv = &encrypted[0..16];
    let ciphertext = &encrypted[16..hmac_offset];

    // Create AES-256-CBC decryptor
    let decryptor = Aes256CbcDec::new_from_slices(&key_bytes, iv)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Decryption setup failed: {}", e)))?;

    // Decrypt the data
    let mut buffer = vec![0u8; ciphertext.len()];
    let plaintext = decryptor.decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buffer)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Decryption failed: {}", e)))?;

    Ok(plaintext.to_vec())
}

/// Encrypt a network packet with ChaCha20-Poly1305
pub fn encrypt_packet(packet: &[u8], session_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    encrypt_chacha20(packet, session_key, None)
}

/// Decrypt a network packet with ChaCha20-Poly1305
pub fn decrypt_packet(encrypted: &[u8], session_key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    decrypt_chacha20(encrypted, session_key, nonce)
}

/// Derive a session key from a shared secret using HKDF
pub fn derive_session_key(shared_secret: &[u8], salt: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut session_key = vec![0u8; 32];

    hkdf.expand(b"AERONYX-SESSION-KEY", &mut session_key)
        .map_err(|_| EncryptionError::EncryptionFailed("Failed to derive session key".into()))?;

    Ok(session_key)
}

/// Add padding to a packet
pub fn add_padding(packet: &[u8], min_padding: usize, max_padding: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let padding_len = rng.gen_range(min_padding..=max_padding);

    let mut result = Vec::with_capacity(packet.len() + padding_len + 2);

    // Add padding length as two bytes (big-endian)
    result.extend_from_slice(&(padding_len as u16).to_be_bytes());

    // Add the original packet
    result.extend_from_slice(packet);

    // Add random padding
    for _ in 0..padding_len {
        result.push(rng.gen::<u8>());
    }

    result
}

/// Remove padding from a packet
pub fn remove_padding(packet: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if packet.len() < 2 {
        return Err(EncryptionError::InvalidFormat("Packet too short for padding".into()));
    }

    // Extract padding length (first two bytes)
    let mut padding_len_bytes = [0u8; 2];
    padding_len_bytes.copy_from_slice(&packet[0..2]);
    let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;

    // Validate packet length
    let expected_min_len = 2 + padding_len;
    if packet.len() < expected_min_len {
        return Err(EncryptionError::InvalidPadding(format!(
            "Invalid padding length {} for packet size {}", padding_len, packet.len()
        )));
    }

    // Extract the actual data (between header and padding)
    let data_len = packet.len() - 2 - padding_len;
    let data = &packet[2..(2 + data_len)];

    Ok(data.to_vec())
}

/// Encrypt a session key for transmission
pub fn encrypt_session_key(
    session_key: &[u8],
    shared_secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    encrypt_chacha20(session_key, shared_secret, None)
}

/// Decrypt a session key received from peer
pub fn decrypt_session_key(
    encrypted_key: &[u8],
    nonce: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    decrypt_chacha20(encrypted_key, shared_secret, nonce)
}

// Helper function for safe slicing
fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let key = [1u8; 32]; // Test key
        let data = b"Test message for encryption";

        // Encrypt with random nonce
        let (encrypted, nonce) = encrypt_chacha20(data, &key, None).unwrap();

        // Decrypt
        let decrypted = decrypt_chacha20(&encrypted, &key, &nonce).unwrap();

        // Check that decrypted data matches original
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_aes() {
        let key = [2u8; 32]; // Test key
        let data = b"Test message for AES encryption";

        // Encrypt
        let encrypted = encrypt_aes(data, &key).unwrap();

        // Decrypt
        let decrypted = decrypt_aes(&encrypted, &key).unwrap();

        // Check that decrypted data matches original
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm() {
        let key = [3u8; 32]; // Test key
        let data = b"Test message for AES-GCM encryption";
        let aad = b"Additional authenticated data";

        // Test without AAD
        let (encrypted1, nonce1) = encrypt_aes_gcm(data, &key, None).unwrap();
        let decrypted1 = decrypt_aes_gcm(&encrypted1, &key, &nonce1, None).unwrap();
        assert_eq!(data.to_vec(), decrypted1);

        // Test with AAD
        let (encrypted2, nonce2) = encrypt_aes_gcm(data, &key, Some(aad)).unwrap();
        let decrypted2 = decrypt_aes_gcm(&encrypted2, &key, &nonce2, Some(aad)).unwrap();
        assert_eq!(data.to_vec(), decrypted2);

        // Test authentication failure with wrong AAD
        let wrong_aad = b"Wrong additional data";
        let result = decrypt_aes_gcm(&encrypted2, &key, &nonce2, Some(wrong_aad));
        assert!(matches!(result.unwrap_err(), EncryptionError::AuthenticationFailed));

        // Test authentication failure with tampered ciphertext
        let mut tampered = encrypted2.clone();
        if !tampered.is_empty() {
            tampered[0] ^= 1; // Flip one bit
        }
        let result = decrypt_aes_gcm(&tampered, &key, &nonce2, Some(aad));
        assert!(matches!(result.unwrap_err(), EncryptionError::AuthenticationFailed));
    }

    #[test]
    fn test_aes_gcm_large_data() {
        // Test with larger data to ensure no buffer size issues
        let key = [4u8; 32];
        let large_data = vec![0xAA; 1024 * 1024]; // 1MB of data

        let (encrypted, nonce) = encrypt_aes_gcm(&large_data, &key, None).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key, &nonce, None).unwrap();
        
        assert_eq!(large_data, decrypted);
    }

    #[test]
    fn test_padding() {
        let data = b"Test data for padding";

        // Add padding
        let padded = add_padding(data, 10, 20);

        // Padding length should be within range
        let mut padding_len_bytes = [0u8; 2];
        padding_len_bytes.copy_from_slice(&padded[0..2]);
        let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
        assert!(padding_len >= 10 && padding_len <= 20);

        // Remove padding
        let unpadded = remove_padding(&padded).unwrap();

        // Check that unpadded data matches original
        assert_eq!(data.to_vec(), unpadded);
    }

    #[test]
    fn test_invalid_padding_length() {
        // Create packet where claimed padding length exceeds actual padding
        let original_data = b"original";
        let padding_len: u16 = 50; // Claim 50 bytes of padding
        let actual_padding = [0u8; 10]; // Provide only 10 bytes

        let mut packet = Vec::new();
        packet.extend_from_slice(&padding_len.to_be_bytes());
        packet.extend_from_slice(original_data);
        packet.extend_from_slice(&actual_padding); // Total length 2 + 8 + 10 = 20

        // Removing padding should fail because packet.len() (20) < 2 + padding_len (52)
        let result = remove_padding(&packet);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::InvalidPadding(_)));
    }

    #[test]
    fn test_padding_packet_too_short() {
        let packet = vec![0u8; 1]; // Less than 2 bytes needed for length field
        let result = remove_padding(&packet);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::InvalidFormat(_)));
    }

    #[test]
    fn test_derive_session_key() {
        let secret = [3u8; 32];
        let salt = [4u8; 16];

        // Derive session key
        let key = derive_session_key(&secret, &salt).unwrap();

        // Key should be correct length
        assert_eq!(key.len(), 32);

        // Deriving again with same inputs should give same key
        let key2 = derive_session_key(&secret, &salt).unwrap();
        assert_eq!(key, key2);

        // Different salt should give different key
        let salt2 = [5u8; 16];
        let key3 = derive_session_key(&secret, &salt2).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_generate_challenge() {
        // Generate two challenges
        let challenge1 = generate_challenge(32);
        let challenge2 = generate_challenge(32);

        // They should be different (extremely unlikely to be the same)
        assert_ne!(challenge1, challenge2);

        // Should be correct length
        assert_eq!(challenge1.len(), 32);
        assert_eq!(challenge2.len(), 32);
    }

    #[test]
    fn test_authentication_failure() {
        let key = [6u8; 32];
        let data = b"Test authentication";

        // Encrypt
        let (encrypted, nonce) = encrypt_chacha20(data, &key, None).unwrap();

        // Tamper with the encrypted data
        let mut tampered = encrypted.clone();
        if !tampered.is_empty() {
            tampered[0] ^= 1; // Flip one bit
        }

        // Decryption should fail due to authentication
        let result = decrypt_chacha20(&tampered, &key, &nonce);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EncryptionError::AuthenticationFailed));

        // Tamper with nonce
        let mut bad_nonce = nonce.clone();
        if !bad_nonce.is_empty() {
            bad_nonce[0] ^= 1;
        }
        let result_bad_nonce = decrypt_chacha20(&encrypted, &key, &bad_nonce);
        assert!(result_bad_nonce.is_err());
        assert!(matches!(result_bad_nonce.unwrap_err(), EncryptionError::AuthenticationFailed));

        // Use wrong key
        let wrong_key = [7u8; 32];
        let result_wrong_key = decrypt_chacha20(&encrypted, &wrong_key, &nonce);
        assert!(result_wrong_key.is_err());
        assert!(matches!(result_wrong_key.unwrap_err(), EncryptionError::AuthenticationFailed));
    }

    #[test]
    fn test_aes_authentication_failure() {
        let key = [8u8; 32];
        let data = b"Test AES authentication";

        // Encrypt
        let encrypted = encrypt_aes(data, &key).unwrap();

        // Tamper with encrypted data (before HMAC)
        let mut tampered_data = encrypted.clone();
        if tampered_data.len() > 33 { // Ensure there's data before HMAC
            tampered_data[20] ^= 1; // Flip a bit in ciphertext part
        }

        let result_tamper_data = decrypt_aes(&tampered_data, &key);
        assert!(result_tamper_data.is_err(), "Decryption should fail with tampered data");
        assert!(matches!(result_tamper_data.unwrap_err(), EncryptionError::AuthenticationFailed));

        // Tamper with HMAC
        let mut tampered_hmac = encrypted.clone();
        let hmac_start = tampered_hmac.len() - 1;
        tampered_hmac[hmac_start] ^= 1; // Flip last bit of HMAC

        let result_tamper_hmac = decrypt_aes(&tampered_hmac, &key);
        assert!(result_tamper_hmac.is_err(), "Decryption should fail with tampered HMAC");
        assert!(matches!(result_tamper_hmac.unwrap_err(), EncryptionError::AuthenticationFailed));

        // Use wrong key
        let wrong_key = [9u8; 32];
        let result_wrong_key = decrypt_aes(&encrypted, &wrong_key);
        assert!(result_wrong_key.is_err(), "Decryption should fail with wrong key");
        assert!(matches!(result_wrong_key.unwrap_err(), EncryptionError::AuthenticationFailed));
    }
}
