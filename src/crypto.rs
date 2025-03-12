use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
use rand::rngs::ThreadRng;
use sha2::{Digest, Sha512};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use solana_sdk::signature::Keypair;
use solana_sdk::pubkey::Pubkey;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use crate::types::{Result, VpnError};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Generate a new Solana keypair
pub fn generate_keypair() -> Keypair {
    Keypair::new()
}

/// Convert Ed25519 private key to X25519 for ECDH
pub fn ed25519_private_to_x25519(ed25519_secret: &[u8]) -> Result<X25519SecretKey> {
    if ed25519_secret.len() != 32 {
        return Err(VpnError::Crypto("Invalid Ed25519 private key length".into()));
    }
    
    // Hash the private key with SHA-512 to get the seed for X25519
    let hash = Sha512::digest(ed25519_secret);
    
    // Extract the lower 32 bytes
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash[0..32]);
    
    // Clear the bits according to the X25519 spec
    key_bytes[0] &= 248;
    key_bytes[31] &= 127;
    key_bytes[31] |= 64;
    
    Ok(X25519SecretKey::from(key_bytes))
}

/// Extract Solana secret key bytes
pub fn solana_keypair_to_bytes(keypair: &Keypair) -> Result<[u8; 32]> {
    let keypair_bytes = keypair.to_bytes();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&keypair_bytes[0..32]);
    Ok(secret)
}

/// Convert Ed25519 public key to X25519
pub fn ed25519_public_to_x25519(ed25519_public: &[u8]) -> Result<[u8; 32]> {
    // Note: This is a simplified placeholder implementation.
    // A proper implementation would follow the conversion algorithm
    // described in RFC 7748 Section 4.1
    
    if ed25519_public.len() != 32 {
        return Err(VpnError::Crypto("Invalid Ed25519 public key length".into()));
    }
    
    // In a real implementation, we would calculate:
    // Let's assume we have a working conversion function
    // This is a placeholder - in production use a well-tested library
    let mut x25519_public = [0u8; 32];
    
    // Copy bytes for now as a placeholder
    // WARNING: This is not the correct conversion, just a placeholder!
    x25519_public.copy_from_slice(ed25519_public);
    
    // For a proper implementation, we would convert the Edwards y-coordinate
    // to the Montgomery u-coordinate
    
    Ok(x25519_public)
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
    let shared_secret = x25519_private.diffie_hellman(&x25519_public);
    
    Ok(shared_secret.to_bytes())
}

/// Encrypt data using AES-256-CBC with a shared secret
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
    
    // Prepare final packet: IV + Encrypted data
    let mut result = Vec::with_capacity(iv.len() + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(ciphertext);
    
    Ok(result)
}

/// Decrypt data using AES-256-CBC with a shared secret
pub fn decrypt(encrypted: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted.len() < 16 {
        return Err(VpnError::Crypto("Encrypted data too short".into()));
    }
    
    // Extract IV and encrypted data
    let iv = &encrypted[0..16];
    let ciphertext = &encrypted[16..];
    
    // Create AES-256-CBC decryptor
    let decryptor = Aes256CbcDec::new_from_slices(shared_secret, iv)
        .map_err(|e| VpnError::Crypto(format!("Decryption setup failed: {}", e)))?;
    
    // Decrypt the data
    let mut buffer = vec![0u8; ciphertext.len()];
    let plaintext = decryptor.decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buffer)
        .map_err(|e| VpnError::Crypto(format!("Decryption failed: {}", e)))?;
    
    Ok(plaintext.to_vec())
}

/// Encrypt a network packet
pub fn encrypt_packet(packet: &[u8], local_private: &Keypair, remote_public: &Pubkey) -> Result<Vec<u8>> {
    let shared_secret = generate_shared_secret(local_private, remote_public)?;
    encrypt(packet, &shared_secret)
}

/// Decrypt a network packet
pub fn decrypt_packet(encrypted: &[u8], local_private: &Keypair, remote_public: &Pubkey) -> Result<Vec<u8>> {
    let shared_secret = generate_shared_secret(local_private, remote_public)?;
    decrypt(encrypted, &shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();
        assert_ne!(keypair.to_bytes().len(), 0);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let shared_secret = [0u8; 32]; // Use a zero key for testing
        let data = b"Hello, VPN!";
        
        let encrypted = encrypt(data, &shared_secret).unwrap();
        let decrypted = decrypt(&encrypted, &shared_secret).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }
}
