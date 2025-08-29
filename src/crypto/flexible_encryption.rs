// src/crypto/flexible_encryption.rs
//! Flexible encryption support for multiple algorithms
//!
//! This module provides a unified interface for different encryption algorithms,
//! allowing the server to negotiate and use the best available algorithm with each client.

use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::error;

// Import encryption functions from the main encryption module
use crate::crypto::encryption::{
    encrypt_chacha20_poly1305,
    decrypt_chacha20_poly1305,
    encrypt_aes256_gcm,
    decrypt_aes256_gcm,
    generate_random_nonce,
    EncryptionError,
    KEY_SIZE,
    NONCE_SIZE,
};

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    #[serde(rename = "chacha20poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "aes256gcm")]
    Aes256Gcm,
}

impl EncryptionAlgorithm {
    /// Get string representation for protocol messages
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20poly1305",
            Self::Aes256Gcm => "aes256gcm",
        }
    }
    
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chacha20poly1305" | "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            "aes256gcm" | "aes-256-gcm" | "aes256-gcm" => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
    
    /// Get the default algorithm
    pub fn default() -> Self {
        Self::ChaCha20Poly1305
    }
    
    /// Check if algorithm is supported
    pub fn is_supported(&self) -> bool {
        true // Both algorithms are supported
    }
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::ChaCha20Poly1305
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Encrypted packet with algorithm information
#[derive(Debug, Clone)]
pub struct EncryptedPacket {
    pub algorithm: EncryptionAlgorithm,
    pub data: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Encrypt data with specified algorithm
pub fn encrypt_flexible(
    plaintext: &[u8],
    key: &[u8],
    algorithm: EncryptionAlgorithm,
    nonce: Option<Vec<u8>>,
) -> Result<EncryptedPacket, EncryptionError> {
    // Validate key
    if key.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }
    
    // Generate or use provided nonce
    let nonce = nonce.unwrap_or_else(|| generate_random_nonce().to_vec());
    
    if nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidNonceLength {
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    
    // Encrypt based on algorithm
    let encrypted_data = match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            encrypt_chacha20_poly1305(plaintext, key, &nonce)?
        }
        EncryptionAlgorithm::Aes256Gcm => {
            encrypt_aes256_gcm(plaintext, key, &nonce)?
        }
    };
    
    Ok(EncryptedPacket {
        algorithm,
        data: encrypted_data,
        nonce,
    })
}

/// Decrypt data with specified algorithm
pub fn decrypt_flexible(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<Vec<u8>, EncryptionError> {
    // Validate key
    if key.len() != KEY_SIZE {
        return Err(EncryptionError::InvalidKeyLength {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }
    
    // Validate nonce
    if nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidNonceLength {
            expected: NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    
    // Decrypt based on algorithm
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            decrypt_chacha20_poly1305(ciphertext, key, nonce)
        }
        EncryptionAlgorithm::Aes256Gcm => {
            decrypt_aes256_gcm(ciphertext, key, nonce)
        }
    }
}

/// Negotiate best algorithm between client and server preferences
pub fn negotiate_algorithm(
    client_pref: Option<EncryptionAlgorithm>,
    server_pref: EncryptionAlgorithm,
) -> EncryptionAlgorithm {
    // If client has a preference and it's supported, use it
    if let Some(client_algo) = client_pref {
        if client_algo.is_supported() {
            return client_algo;
        }
    }
    
    // Otherwise use server preference
    server_pref
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(
            EncryptionAlgorithm::from_str("chacha20poly1305"),
            Some(EncryptionAlgorithm::ChaCha20Poly1305)
        );
        assert_eq!(
            EncryptionAlgorithm::from_str("aes256gcm"),
            Some(EncryptionAlgorithm::Aes256Gcm)
        );
        assert_eq!(
            EncryptionAlgorithm::from_str("aes-256-gcm"),
            Some(EncryptionAlgorithm::Aes256Gcm)
        );
        assert_eq!(
            EncryptionAlgorithm::from_str("invalid"),
            None
        );
    }
    
    #[test]
    fn test_encrypt_decrypt_flexible() {
        let key = vec![0x42; KEY_SIZE];
        let plaintext = b"Hello, flexible encryption!";
        
        // Test ChaCha20-Poly1305
        let encrypted = encrypt_flexible(
            plaintext,
            &key,
            EncryptionAlgorithm::ChaCha20Poly1305,
            None,
        ).unwrap();
        
        assert_eq!(encrypted.algorithm, EncryptionAlgorithm::ChaCha20Poly1305);
        assert_eq!(encrypted.nonce.len(), NONCE_SIZE);
        
        let decrypted = decrypt_flexible(
            &encrypted.data,
            &key,
            &encrypted.nonce,
            encrypted.algorithm,
        ).unwrap();
        
        assert_eq!(decrypted, plaintext);
        
        // Test AES-256-GCM
        let encrypted = encrypt_flexible(
            plaintext,
            &key,
            EncryptionAlgorithm::Aes256Gcm,
            None,
        ).unwrap();
        
        assert_eq!(encrypted.algorithm, EncryptionAlgorithm::Aes256Gcm);
        
        let decrypted = decrypt_flexible(
            &encrypted.data,
            &key,
            &encrypted.nonce,
            encrypted.algorithm,
        ).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_algorithm_negotiation() {
        // Client prefers AES, server prefers ChaCha
        let result = negotiate_algorithm(
            Some(EncryptionAlgorithm::Aes256Gcm),
            EncryptionAlgorithm::ChaCha20Poly1305,
        );
        assert_eq!(result, EncryptionAlgorithm::Aes256Gcm);
        
        // Client has no preference
        let result = negotiate_algorithm(
            None,
            EncryptionAlgorithm::ChaCha20Poly1305,
        );
        assert_eq!(result, EncryptionAlgorithm::ChaCha20Poly1305);
    }
}
