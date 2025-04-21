// src/crypto/flexible_encryption.rs
//! Flexible encryption module supporting multiple encryption algorithms.
//!
//! This module provides a unified interface for encrypting and decrypting data
//! using different algorithms (ChaCha20-Poly1305 or AES-GCM) based on client preference.

use crate::crypto::encryption::{encrypt_chacha20, decrypt_chacha20, encrypt_aes_gcm, decrypt_aes_gcm};
use thiserror::Error;

/// Encryption algorithms supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// ChaCha20-Poly1305 AEAD
    ChaCha20Poly1305,
    /// AES-256-GCM AEAD
    Aes256Gcm,
}

impl EncryptionAlgorithm {
    /// Parse algorithm from string identifier
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chacha20poly1305" | "chacha" => Some(Self::ChaCha20Poly1305),
            "aes256gcm" | "aes" | "aesgcm" => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
    
    /// Get string identifier for algorithm
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20poly1305",
            Self::Aes256Gcm => "aes256gcm",
        }
    }
}

/// Default to ChaCha20-Poly1305 for compatibility with existing clients
impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::ChaCha20Poly1305
    }
}

/// Error type for flexible encryption operations
#[derive(Debug, Error)]
pub enum FlexibleEncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    
    #[error("Algorithm mismatch")]
    AlgorithmMismatch,
}

/// Encrypted data with metadata about the encryption algorithm
#[derive(Debug, Clone)]
pub struct EncryptedPacket {
    /// Encrypted data
    pub data: Vec<u8>,
    /// Nonce/IV used for encryption
    pub nonce: Vec<u8>,
    /// Algorithm used for encryption
    pub algorithm: EncryptionAlgorithm,
}

/// Encrypt data using the specified algorithm
pub fn encrypt_flexible(
    data: &[u8], 
    key: &[u8], 
    algorithm: EncryptionAlgorithm,
    aad: Option<&[u8]>,
) -> Result<EncryptedPacket, FlexibleEncryptionError> {
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let (encrypted, nonce) = encrypt_chacha20(data, key, None)
                .map_err(|e| FlexibleEncryptionError::EncryptionFailed(e.to_string()))?;
                
            Ok(EncryptedPacket {
                data: encrypted,
                nonce,
                algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            })
        },
        EncryptionAlgorithm::Aes256Gcm => {
            let (encrypted, nonce) = encrypt_aes_gcm(data, key, aad)
                .map_err(|e| FlexibleEncryptionError::EncryptionFailed(e.to_string()))?;
                
            Ok(EncryptedPacket {
                data: encrypted,
                nonce,
                algorithm: EncryptionAlgorithm::Aes256Gcm,
            })
        }
    }
}


pub fn decrypt_flexible(
    encrypted: &[u8],
    nonce: &[u8],
    key: &[u8],
    algorithm: EncryptionAlgorithm,
    aad: Option<&[u8]>,
    fallback: bool,
) -> Result<Vec<u8>, FlexibleEncryptionError> {
    // Log the decryption attempt
    info!("Attempting to decrypt with {:?}, fallback={}", algorithm, fallback);
    debug!("Decryption details: ciphertext={} bytes, nonce={} bytes, key={} bytes",
         encrypted.len(), nonce.len(), key.len());
    
    // First attempt with specified algorithm
    info!("Primary decryption with {:?}", algorithm);
    let primary_result = match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            debug!("Trying ChaCha20-Poly1305 decryption...");
            let result = decrypt_chacha20(encrypted, key, nonce);
            if let Err(ref e) = result {
                warn!("ChaCha20-Poly1305 decryption failed: {}", e);
            } else {
                info!("ChaCha20-Poly1305 decryption succeeded!");
            }
            result.map_err(|e| FlexibleEncryptionError::DecryptionFailed(e.to_string()))
        },
        EncryptionAlgorithm::Aes256Gcm => {
            debug!("Trying AES-GCM decryption...");
            let result = decrypt_aes_gcm(encrypted, key, nonce, aad);
            if let Err(ref e) = result {
                warn!("AES-GCM decryption failed: {}", e);
            } else {
                info!("AES-GCM decryption succeeded!");
            }
            result.map_err(|e| FlexibleEncryptionError::DecryptionFailed(e.to_string()))
        }
    };
    
    // If primary algorithm succeeded or fallback is disabled, return the result
    if primary_result.is_ok() || !fallback {
        return primary_result;
    }
    
    // If the primary algorithm failed and fallback is enabled, try the other algorithm
    info!("Primary decryption failed, attempting fallback");
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            // Fallback to AES-GCM
            debug!("Fallback to AES-GCM decryption...");
            let result = decrypt_aes_gcm(encrypted, key, nonce, aad);
            if let Err(ref e) = result {
                error!("Fallback AES-GCM decryption also failed: {}", e);
            } else {
                info!("Fallback AES-GCM decryption succeeded!");
            }
            result.map_err(|e| FlexibleEncryptionError::DecryptionFailed(format!("Both algorithms failed: {}", e)))
        },
        EncryptionAlgorithm::Aes256Gcm => {
            // Fallback to ChaCha20-Poly1305
            debug!("Fallback to ChaCha20-Poly1305 decryption...");
            let result = decrypt_chacha20(encrypted, key, nonce);
            if let Err(ref e) = result {
                error!("Fallback ChaCha20-Poly1305 decryption also failed: {}", e);
            } else {
                info!("Fallback ChaCha20-Poly1305 decryption succeeded!");
            }
            result.map_err(|e| FlexibleEncryptionError::DecryptionFailed(format!("Both algorithms failed: {}", e)))
        }
    }
}

/// Decrypt data, attempting the specified algorithm first, then falling back if it fails
pub fn decrypt_flexible(
    encrypted: &[u8],
    nonce: &[u8],
    key: &[u8],
    algorithm: EncryptionAlgorithm,
    aad: Option<&[u8]>,
    fallback: bool,
) -> Result<Vec<u8>, FlexibleEncryptionError> {
    // First attempt with specified algorithm
    let primary_result = match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            decrypt_chacha20(encrypted, key, nonce)
                .map_err(|e| FlexibleEncryptionError::DecryptionFailed(e.to_string()))
        },
        EncryptionAlgorithm::Aes256Gcm => {
            decrypt_aes_gcm(encrypted, key, nonce, aad)
                .map_err(|e| FlexibleEncryptionError::DecryptionFailed(e.to_string()))
        }
    };
    
    // If primary algorithm succeeded or fallback is disabled, return the result
    if primary_result.is_ok() || !fallback {
        return primary_result;
    }
    
    // If the primary algorithm failed and fallback is enabled, try the other algorithm
    match algorithm {
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            // Fallback to AES-GCM
            decrypt_aes_gcm(encrypted, key, nonce, aad)
                .map_err(|e| FlexibleEncryptionError::DecryptionFailed(format!("Both algorithms failed: {}", e)))
        },
        EncryptionAlgorithm::Aes256Gcm => {
            // Fallback to ChaCha20-Poly1305
            decrypt_chacha20(encrypted, key, nonce)
                .map_err(|e| FlexibleEncryptionError::DecryptionFailed(format!("Both algorithms failed: {}", e)))
        }
    }
}

/// Encrypt a network packet with the specified or default algorithm
pub fn encrypt_packet(
    packet: &[u8], 
    session_key: &[u8],
    algorithm: Option<EncryptionAlgorithm>,
) -> Result<EncryptedPacket, FlexibleEncryptionError> {
    let algo = algorithm.unwrap_or_default();
    encrypt_flexible(packet, session_key, algo, None)
}

/// Decrypt a network packet with the specified algorithm and optional fallback
pub fn decrypt_packet(
    encrypted: &[u8], 
    session_key: &[u8], 
    nonce: &[u8],
    algorithm: EncryptionAlgorithm,
    enable_fallback: bool,
) -> Result<Vec<u8>, FlexibleEncryptionError> {
    decrypt_flexible(encrypted, nonce, session_key, algorithm, None, enable_fallback)
}

// Session info structure with encryption algorithm preference
#[derive(Debug, Clone)]
pub struct SessionEncryptionInfo {
    /// Client's preferred encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Whether to enable fallback decryption
    pub enable_fallback: bool,
}

impl Default for SessionEncryptionInfo {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            enable_fallback: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_algorithm_parsing() {
        assert_eq!(EncryptionAlgorithm::from_str("chacha"), Some(EncryptionAlgorithm::ChaCha20Poly1305));
        assert_eq!(EncryptionAlgorithm::from_str("aes"), Some(EncryptionAlgorithm::Aes256Gcm));
        assert_eq!(EncryptionAlgorithm::from_str("unknown"), None);
    }
    
    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let data = b"Test data for ChaCha20-Poly1305";
        let key = [1u8; 32]; // Test key
        
        let encrypted = encrypt_flexible(data, &key, EncryptionAlgorithm::ChaCha20Poly1305, None).unwrap();
        
        // Decrypt with correct algorithm
        let decrypted = decrypt_flexible(
            &encrypted.data, 
            &encrypted.nonce, 
            &key, 
            EncryptionAlgorithm::ChaCha20Poly1305, 
            None, 
            false
        ).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_encrypt_decrypt_aes_gcm() {
        let data = b"Test data for AES-GCM";
        let key = [2u8; 32]; // Test key
        
        let encrypted = encrypt_flexible(data, &key, EncryptionAlgorithm::Aes256Gcm, None).unwrap();
        
        // Decrypt with correct algorithm
        let decrypted = decrypt_flexible(
            &encrypted.data, 
            &encrypted.nonce, 
            &key, 
            EncryptionAlgorithm::Aes256Gcm, 
            None, 
            false
        ).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_fallback_decryption() {
        let data = b"Test data for fallback decryption";
        let key = [3u8; 32]; // Test key
        
        // Encrypt with ChaCha20-Poly1305
        let encrypted = encrypt_flexible(data, &key, EncryptionAlgorithm::ChaCha20Poly1305, None).unwrap();
        
        // Try to decrypt with AES-GCM first, then fallback to ChaCha20-Poly1305
        let decrypted = decrypt_flexible(
            &encrypted.data, 
            &encrypted.nonce, 
            &key, 
            EncryptionAlgorithm::Aes256Gcm, 
            None, 
            true // Enable fallback
        ).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
        
        // Without fallback, it should fail
        let result = decrypt_flexible(
            &encrypted.data, 
            &encrypted.nonce, 
            &key, 
            EncryptionAlgorithm::Aes256Gcm, 
            None, 
            false // Disable fallback
        );
        
        assert!(result.is_err());
    }
}
