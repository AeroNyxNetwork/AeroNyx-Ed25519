// src/crypto/encryption.rs
//! Encryption utilities for secure communication.
//!
//! This module provides functions for encrypting and decrypting data
//! using ChaCha20-Poly1305 AEAD with authentication.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use thiserror::Error;
// Removed unused warn import
use tracing::debug;

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
    let nonce_vec = if let Some(nb) = nonce_bytes {
        if nb.len() != 12 {
            return Err(EncryptionError::InvalidFormat(format!(
                "Invalid nonce length: {} (expected 12)",
                nb.len()
            )));
        }
        nb.to_vec() // Convert to Vec<u8>
    } else {
        let mut n = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut n);
        n.to_vec() // Convert to Vec<u8>
    };

    // Encrypt the data
    let nonce = Nonce::from_slice(&nonce_vec); // Create Nonce from slice
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| EncryptionError::EncryptionFailed(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?;

    Ok((ciphertext, nonce_vec)) // Return the Vec<u8> nonce
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
    let nonce = Nonce::from_slice(nonce);
    let cipher = ChaCha20Poly1305::new(aead_key);

    // Decrypt and verify the data
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| {
            // Log authentication failures as they may indicate tampering
            debug!("ChaCha20-Poly1305 decryption failed: {}", e);
            EncryptionError::AuthenticationFailed
        })?;

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
    // Allow buffer to be potentially larger than needed for padding
    let mut buffer = vec![0u8; data.len() + 16]; // data len + one block for padding max
    let ciphertext = encryptor.encrypt_padded_b2b_mut::<Pkcs7>(data, &mut buffer)
        .map_err(|e| EncryptionError::EncryptionFailed(format!("Encryption failed: {}", e)))?;

    // Prepare encrypted data: IV + Encrypted data
    // Use exact length for HMAC calculation
    let encrypted_len = ciphertext.len();
    let mut result = Vec::with_capacity(iv.len() + encrypted_len + 32); // +32 for HMAC
    result.extend_from_slice(&iv);
    result.extend_from_slice(ciphertext);


    // Add HMAC for authentication
    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|_| EncryptionError::InvalidKeyLength(key_bytes.len()))?;
    mac.update(&result); // HMAC over IV + ciphertext
    let hmac_result = mac.finalize();
    let hmac_bytes = hmac_result.into_bytes();
    result.extend_from_slice(hmac_bytes.as_slice());

    Ok(result)
}

/// Decrypt data using AES-256-CBC with a shared secret and verify HMAC
pub fn decrypt_aes(encrypted: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    // Check shared_secret length
    if shared_secret.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength(shared_secret.len()));
    }

    if encrypted.len() < 16 + 32 { // IV + HMAC minimum size
        return Err(EncryptionError::InvalidFormat("Encrypted data too short".into()));
    }

    // Extract 32 bytes for AES key
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&shared_secret[0..32]);

    // Extract HMAC (last 32 bytes)
    let hmac_offset = encrypted.len() - 32;
    let hmac_received = &encrypted[hmac_offset..];
    let authenticated_part = &encrypted[..hmac_offset]; // IV + ciphertext

    // Verify HMAC
    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|_| EncryptionError::InvalidKeyLength(key_bytes.len()))?;
    mac.update(authenticated_part);

    mac.verify_slice(hmac_received)
        .map_err(|_| EncryptionError::AuthenticationFailed)?;

    // Extract IV and encrypted data
    let iv = &encrypted[0..16];
    let ciphertext = &encrypted[16..hmac_offset];

    // Create AES-256-CBC decryptor
    let decryptor = Aes256CbcDec::new_from_slices(&key_bytes, iv)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Decryption setup failed: {}", e)))?;

    // Decrypt the data
    // Provide a buffer large enough for the original ciphertext, decryption might shrink it
    let mut buffer = vec![0u8; ciphertext.len()];
    let plaintext = decryptor.decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buffer)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Decryption failed (check padding): {}", e)))?;

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
    if packet.len() < 2 + padding_len {
        return Err(EncryptionError::InvalidPadding(format!(
             "Invalid padding length: specified {}, available {}",
             padding_len, packet.len() - 2
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
    }
}
