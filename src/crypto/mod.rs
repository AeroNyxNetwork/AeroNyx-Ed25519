// src/crypto/mod.rs
//! Cryptography module for the AeroNyx Privacy Network Server.
//!
//! This module provides cryptographic functions and utilities for
//! secure key management, encryption, and signatures.

pub mod encryption;
pub mod keys;
pub mod session;
pub mod flexible_encryption; // Add the new module

// Re-export commonly used items
pub use encryption::{encrypt_packet, decrypt_packet};
pub use keys::KeyManager;
pub use session::SessionKeyManager;
pub use flexible_encryption::{EncryptionAlgorithm, encrypt_flexible, decrypt_flexible}; // Export flexible encryption
