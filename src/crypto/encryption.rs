// src/crypto/encryption.rs
//! Encryption and decryption utilities for the server.
//!
//! This module provides functions for encrypting and decrypting data
//! using AES-256-GCM and ChaCha20-Poly1305 algorithms.
//!
//! ## CRITICAL FIX (2025-01-09)
//! - Enabled HKDF key derivation for session key encryption
//! - This matches what macOS/iOS clients expect
//! - Without this, clients fail to decrypt session keys
//!
//! ## Why This Fix Is Necessary
//! - Clients derive encryption keys using HKDF-SHA256 with "AERONYX-SESSION-KEY-ENCRYPTION" info
//! - Server was using shared_secret directly, causing decryption failures
//! - Now both use the same key derivation method

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{
    aead::{Aead as ChaChaAead, NewAead},
    ChaCha20Poly1305, Nonce as ChaNonce,
};
use generic_array::{GenericArray, typenum::U12};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use thiserror::Error;
use tracing::{debug, info, error};

use crate::crypto::flexible_encryption::{
    EncryptionAlgorithm, EncryptedPacket,
};

/// Size of the encryption key in bytes
pub const KEY_SIZE: usize = 32;

/// Size of the nonce in bytes (96 bits for both AES-GCM and ChaCha20-Poly1305)
pub const NONCE_SIZE: usize = 12;

/// Size of the authentication tag in bytes
pub const TAG_SIZE: usize = 16;

/// Error type for encryption operations
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Key derivation failed")]
    KeyDerivation,
    
    #[error("AEAD error: {0}")]
    Aead(String),
    
    #[error("Invalid algorithm")]
    InvalidAlgorithm,
    
    #[error("Invalid data")]
    InvalidData,
}

/// Generate a random nonce for encryption
pub fn generate_random_nonce() -> GenericArray<u8, U12> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    *GenericArray::from_slice(&nonce)
}

/// Generate a random challenge of specified size
pub fn generate_challenge(size: usize) -> Vec<u8> {
    let mut challenge = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

/// Encrypt data using AES-256-GCM
pub fn encrypt_aes256_gcm(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // Validate key length
    if key.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidNonceLength {
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    // Create nonce
    let nonce = AesNonce::from_slice(nonce);

    // Encrypt
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_aes256_gcm(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // Validate key length
    if key.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidNonceLength {
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    // Create nonce
    let nonce = AesNonce::from_slice(nonce);

    // Decrypt
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

/// Encrypt data using ChaCha20-Poly1305
pub fn encrypt_chacha20_poly1305(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // Validate key length
    if key.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidNonceLength {
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    // Create nonce
    let nonce = ChaNonce::from_slice(nonce);

    // Encrypt
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))
}

/// Decrypt data using ChaCha20-Poly1305
pub fn decrypt_chacha20_poly1305(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // Validate key length
    if key.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidNonceLength {
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| EncryptionError::InvalidKey(e.to_string()))?;

    // Create nonce
    let nonce = ChaNonce::from_slice(nonce);

    // Decrypt
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

/// Encrypt data with flexible algorithm support
pub fn encrypt_data_flexible(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>, EncryptionError> {
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            encrypt_chacha20_poly1305(plaintext, key, nonce)
        }
        EncryptionAlgorithm::Aes256Gcm => {
            encrypt_aes256_gcm(plaintext, key, nonce)
        }
    }
}

/// Decrypt data with flexible algorithm support
pub fn decrypt_data_flexible(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>, EncryptionError> {
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            decrypt_chacha20_poly1305(ciphertext, key, nonce)
        }
        EncryptionAlgorithm::Aes256Gcm => {
            decrypt_aes256_gcm(ciphertext, key, nonce)
        }
    }
}

/// Encrypt session key with flexible algorithm support
/// 
/// ## FIXED IMPLEMENTATION (2025-01-09)
/// Now uses HKDF-SHA256 to derive encryption key from shared secret
/// This matches the client implementation exactly
pub fn encrypt_session_key_flexible(
    session_key: &[u8],
    shared_secret: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<EncryptedPacket, EncryptionError> {
    // Validate shared secret length
    if shared_secret.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: shared_secret.len(),
        });
    }
    
    // HKDF key derivation
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(b"AERONYX-SESSION-KEY-ENCRYPTION", &mut derived_key)
        .map_err(|_| EncryptionError::KeyDerivation)?;
    
    // 添加调试日志
    debug!("Shared secret (first 8 bytes): {:02x?}", &shared_secret[..8]);
    debug!("Derived key (first 8 bytes): {:02x?}", &derived_key[..8]);
    
    let encryption_key = &derived_key;
    
    debug!("Encrypting session key with {:?} algorithm using HKDF-derived key", algorithm);
    
    // Generate nonce
    let nonce = generate_random_nonce();
    debug!("Generated nonce (first 8 bytes): {:02x?}", &nonce.as_slice()[..8]);
    
    // Encrypt based on algorithm
    let encrypted = match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            encrypt_chacha20_poly1305(session_key, encryption_key, nonce.as_slice())?
        }
        EncryptionAlgorithm::Aes256Gcm => {
            encrypt_aes256_gcm(session_key, encryption_key, nonce.as_slice())?
        }
    };
    
    info!("Session key encrypted successfully with {:?}", algorithm);
    
    Ok(EncryptedPacket {
        algorithm,
        data: encrypted,
        nonce: nonce.to_vec(),
    })
}

/// Decrypt session key with flexible algorithm support
pub fn decrypt_session_key_flexible(
    encrypted_data: &[u8],
    nonce: &[u8],
    shared_secret: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>, EncryptionError> {
    // Validate shared secret length
    if shared_secret.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: shared_secret.len(),
        });
    }
    
    // Use HKDF to derive decryption key (same as encryption)
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(b"AERONYX-SESSION-KEY-ENCRYPTION", &mut derived_key)
        .map_err(|_| EncryptionError::KeyDerivation)?;
    let decryption_key = &derived_key;
    
    debug!("Decrypting session key with {:?} algorithm using HKDF-derived key", algorithm);
    
    // Decrypt based on algorithm
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            decrypt_chacha20_poly1305(encrypted_data, decryption_key, nonce)
        }
        EncryptionAlgorithm::Aes256Gcm => {
            decrypt_aes256_gcm(encrypted_data, decryption_key, nonce)
        }
    }
}

/// Legacy packet encryption (for backward compatibility)
pub fn encrypt_packet(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // Default to ChaCha20-Poly1305 for legacy support
    encrypt_chacha20_poly1305(plaintext, key, nonce)
}

/// Legacy packet decryption (for backward compatibility)
pub fn decrypt_packet(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // Default to ChaCha20-Poly1305 for legacy support
    decrypt_chacha20_poly1305(ciphertext, key, nonce)
}

/// Parse encrypted packet from raw data
pub fn parse_encrypted_packet(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    if data.len() < NONCE_SIZE + TAG_SIZE {
        return Err(EncryptionError::InvalidData);
    }
    
    let nonce = data[..NONCE_SIZE].to_vec();
    let ciphertext = data[NONCE_SIZE..].to_vec();
    
    Ok((nonce, ciphertext))
}

/// Build encrypted packet with nonce prepended
pub fn build_encrypted_packet(nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(nonce.len() + ciphertext.len());
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(ciphertext);
    packet
}

/// Decrypt with automatic algorithm detection (tries both algorithms)
pub fn decrypt_auto(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // Try ChaCha20-Poly1305 first (default)
    if let Ok(plaintext) = decrypt_chacha20_poly1305(ciphertext, key, nonce) {
        return Ok(plaintext);
    }
    
    // Try AES-256-GCM
    if let Ok(plaintext) = decrypt_aes256_gcm(ciphertext, key, nonce) {
        return Ok(plaintext);
    }
    
    Err(EncryptionError::DecryptionFailed("Failed with both algorithms".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = vec![0x42; KEY_SIZE];
        let nonce = vec![0x24; NONCE_SIZE];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt_aes256_gcm(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt_aes256_gcm(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = vec![0x42; KEY_SIZE];
        let nonce = vec![0x24; NONCE_SIZE];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt_chacha20_poly1305(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt_chacha20_poly1305(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = vec![0x42; 16]; // Wrong size
        let nonce = vec![0x24; NONCE_SIZE];
        let plaintext = b"Hello, World!";

        let result = encrypt_aes256_gcm(plaintext, &key, &nonce);
        assert!(matches!(result, Err(EncryptionError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = vec![0x42; KEY_SIZE];
        let nonce = vec![0x24; 8]; // Wrong size
        let plaintext = b"Hello, World!";

        let result = encrypt_aes256_gcm(plaintext, &key, &nonce);
        assert!(matches!(result, Err(EncryptionError::InvalidNonceLength { .. })));
    }

    #[test]
    fn test_session_key_encryption_with_hkdf() {
        let session_key = vec![0x55; 32];
        let shared_secret = vec![0x66; 32];
        
        // Test AES-256-GCM with HKDF
        let encrypted = encrypt_session_key_flexible(
            &session_key,
            &shared_secret,
            EncryptionAlgorithm::Aes256Gcm,
        ).unwrap();
        
        assert_eq!(encrypted.algorithm, EncryptionAlgorithm::Aes256Gcm);
        assert_eq!(encrypted.nonce.len(), NONCE_SIZE);
        assert!(encrypted.data.len() > session_key.len()); // Has tag
        
        // Test decryption with HKDF
        let decrypted = decrypt_session_key_flexible(
            &encrypted.data,
            &encrypted.nonce,
            &shared_secret,
            EncryptionAlgorithm::Aes256Gcm,
        ).unwrap();
        
        assert_eq!(decrypted, session_key);
    }
    
    #[test]
    fn test_hkdf_key_derivation() {
        // Test that HKDF produces consistent results
        let shared_secret = vec![0x42; 32];
        
        // Derive key multiple times
        let hkdf1 = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key1 = [0u8; 32];
        hkdf1.expand(b"AERONYX-SESSION-KEY-ENCRYPTION", &mut key1).unwrap();
        
        let hkdf2 = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key2 = [0u8; 32];
        hkdf2.expand(b"AERONYX-SESSION-KEY-ENCRYPTION", &mut key2).unwrap();
        
        // Keys should be identical
        assert_eq!(key1, key2);
        
        // Key should be different from shared secret
        assert_ne!(key1.to_vec(), shared_secret);
    }

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge(32);
        let challenge2 = generate_challenge(32);
        
        assert_eq!(challenge1.len(), 32);
        assert_eq!(challenge2.len(), 32);
        assert_ne!(challenge1, challenge2); // Should be random
    }
    
    #[test]
    fn test_auto_decrypt() {
        let key = vec![0x42; KEY_SIZE];
        let nonce = vec![0x24; NONCE_SIZE];
        let plaintext = b"Test auto decrypt";
        
        // Test with ChaCha20
        let ciphertext_chacha = encrypt_chacha20_poly1305(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt_auto(&ciphertext_chacha, &key, &nonce).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
        
        // Test with AES
        let ciphertext_aes = encrypt_aes256_gcm(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt_auto(&ciphertext_aes, &key, &nonce).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
