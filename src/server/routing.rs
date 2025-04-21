// src/server/routing.rs
//! Network packet routing.
//!
//! This module handles routing of network packets between clients
//! and the TUN device.

// Removed unused io import
use std::io::Write;
// Removed unused IpAddr, Ipv4Addr imports
use std::sync::Arc;
use rand::{Rng, thread_rng};
use tokio::sync::Mutex;
// Removed unused debug import
use tracing::{debug, error, trace, warn};

use crate::config::constants::{MIN_PADDING_SIZE, MAX_PADDING_SIZE, PAD_PROBABILITY};
use crate::crypto::{encrypt_packet, decrypt_packet};
use crate::protocol::{PacketType, MessageError};
// Removed unused packet_to_ws_message import
use crate::server::session::ClientSession;
use crate::utils::security::detect_attack_patterns;
use crate::crypto::flexible_encryption::EncryptionAlgorithm;

/// Error type for packet routing operations
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Packet processing error: {0}")]
    Processing(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("TUN write error: {0}")]
    TunWrite(String),

    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("Protocol error: {0}")]
    Protocol(#[from] MessageError),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Potential attack detected: {0}")]
    SecurityRisk(String),
}

/// Handles routing of packets between clients and the TUN device
pub struct PacketRouter {
    /// Maximum packet size
    max_packet_size: usize,
    /// Whether to enable padding
    enable_padding: bool,
    /// Packet counter to prevent replay attacks
    packet_counter: Arc<Mutex<u64>>,
}

impl PacketRouter {
    /// Create a new packet router
    pub fn new(max_packet_size: usize, enable_padding: bool) -> Self {
        Self {
            max_packet_size,
            enable_padding,
            packet_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Process an IP packet and extract routing information
    pub fn process_packet<'a>(&self, packet: &'a [u8]) -> Option<(String, Vec<u8>)> {
        // Check minimum IPv4 header size
        if packet.len() < 20 {
            trace!("Packet too small for IPv4: {} bytes", packet.len());
            return None;
        }

        // Check if it's an IPv4 packet (version field in the first 4 bits)
        let version = packet[0] >> 4;
        if version != 4 {
            trace!("Not an IPv4 packet: version {}", version);
            return None;
        }

        // Extract destination IP from bytes 16-19
        let dest_ip = format!(
            "{}.{}.{}.{}",
            packet[16], packet[17], packet[18], packet[19]
        );

        trace!("Processed packet for destination IP: {}", dest_ip);

        // Return destination IP and the full packet
        Some((dest_ip, packet.to_vec()))
    }

    /// Route a packet from the TUN device to a client
    pub async fn route_outbound_packet(
        &self,
        packet: &[u8],
        session_key: &[u8],
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Check packet size
        if packet.len() > self.max_packet_size {
            return Err(RoutingError::InvalidPacket(format!(
                "Packet size {} exceeds maximum {}",
                packet.len(), self.max_packet_size
            )));
        }

        // Apply padding if enabled
        let packet_data = if self.enable_padding && self.should_add_padding() {
            self.add_padding(packet)
        } else {
            packet.to_vec()
        };

        // Get the session's encryption algorithm
        let algorithm = EncryptionAlgorithm::from_str(
            &session.encryption_algorithm
        ).unwrap_or_default();
        
        // Use flexible encryption
        let encrypted_packet = crate::crypto::flexible_encryption::encrypt_packet(
            &packet_data, session_key, Some(algorithm)
        ).map_err(|e| RoutingError::Encryption(e.to_string()))?;

        // Get next packet counter
        let counter = {
            let mut counter = self.packet_counter.lock().await;
            let value = *counter;
            *counter = value.wrapping_add(1);
            value
        };

        // Create data packet with algorithm info
        let data_packet = PacketType::Data {
            encrypted: encrypted_packet.data,
            nonce: encrypted_packet.nonce,
            counter,
            padding: None,
            encryption_algorithm: Some(encrypted_packet.algorithm.as_str().to_string()),
        };

        // Send to client
        session.send_packet(&data_packet)
            .await
            .map_err(|e| RoutingError::Protocol(MessageError::InvalidFormat(e.to_string())))?;

        Ok(())
    }

    /// Handle an inbound packet from a client
    pub async fn handle_inbound_packet(
        &self,
        encrypted: &[u8],
        nonce: &[u8],
        session_key: &[u8],
        session: &ClientSession,
        encryption_algorithm: Option<&str>, // New parameter from Data packet
    ) -> Result<usize, RoutingError> {
        // Determine which algorithm to use
        let algorithm = if let Some(algo) = encryption_algorithm {
            debug!("Using packet-specified algorithm: {}", algo);
            crate::crypto::flexible_encryption::EncryptionAlgorithm::from_str(algo)
                .unwrap_or_else(|| {
                    debug!("Packet algorithm not recognized, using session algorithm: {}", session.encryption_algorithm);
                    crate::crypto::flexible_encryption::EncryptionAlgorithm::from_str(
                        &session.encryption_algorithm
                    ).unwrap_or_default()
                })
        } else {
            debug!("No algorithm specified in packet, using session algorithm: {}", session.encryption_algorithm);
            crate::crypto::flexible_encryption::EncryptionAlgorithm::from_str(
                &session.encryption_algorithm
            ).unwrap_or_default()
        };
        
        debug!("Attempting to decrypt packet (size={} bytes, nonce={} bytes) with {:?} algorithm", 
               encrypted.len(), nonce.len(), algorithm);
        
        // Log session key
        if !session_key.is_empty() {
            debug!("Session key prefix: {:02x?}", &session_key[0..std::cmp::min(8, session_key.len())]);
        }
        
        // Decrypt using flexible decryption with fallback
        let decrypted = match crate::crypto::flexible_encryption::decrypt_packet(
            encrypted, session_key, nonce, algorithm, session.enable_fallback
        ) {
            Ok(data) => {
                debug!("Packet decryption successful, received {} bytes", data.len());
                data
            },
            Err(e) => {
                error!("Packet decryption failed: {}", e);
                error!("Packet details: algo={:?}, encrypted={} bytes, nonce={:?}, enable_fallback={}", 
                       algorithm, encrypted.len(), nonce, session.enable_fallback);
                return Err(RoutingError::Decryption(e.to_string()));
            }
        };
    
        // Check packet size
        if decrypted.len() > self.max_packet_size {
            return Err(RoutingError::InvalidPacket(format!(
                "Decrypted packet size {} exceeds maximum {}",
                decrypted.len(), self.max_packet_size
            )));
        }
    
        // Check for attack patterns
        if let Some(reason) = detect_attack_patterns(&decrypted) {
            warn!("Security risk in packet from {}: {}", session.client_id, reason);
            return Err(RoutingError::SecurityRisk(reason));
        }
    
        // Remove padding if necessary
        let packet_data = if self.enable_padding {
            match self.remove_padding(&decrypted) {
                Ok(data) => {
                    debug!("Padding removed, packet size reduced from {} to {} bytes", 
                          decrypted.len(), data.len());
                    data
                },
                Err(e) => {
                    warn!("Failed to remove padding from packet: {}", e);
                    decrypted
                }
            }
        } else {
            decrypted
        };
    
        debug!("Processed packet, ready to write {} bytes to TUN device", packet_data.len());
    
        // Get the TUN device from the global reference
        if let Some(tun_device) = crate::server::globals::SERVER_TUN_DEVICE.get() {
            // Write the packet to the TUN device
            let written = {
                let mut device = tun_device.lock().await;
                match device.write(&packet_data) {
                    Ok(bytes) => {
                        debug!("Successfully wrote {} bytes to TUN device", bytes);
                        bytes
                    },
                    Err(e) => {
                        error!("Failed to write to TUN device: {}", e);
                        return Err(RoutingError::TunWrite(e.to_string()));
                    }
                }
            };
    
            Ok(written)
        } else {
            error!("TUN device not initialized");
            Err(RoutingError::TunWrite("TUN device not initialized".to_string()))
        }
    }

    /// Check if padding should be added based on probability
    fn should_add_padding(&self) -> bool {
        thread_rng().gen::<f32>() < PAD_PROBABILITY
    }

    /// Add random padding to a packet
    fn add_padding(&self, packet: &[u8]) -> Vec<u8> {
        let mut rng = thread_rng();
        let padding_len = rng.gen_range(MIN_PADDING_SIZE..=MAX_PADDING_SIZE);

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
    fn remove_padding(&self, packet: &[u8]) -> Result<Vec<u8>, RoutingError> {
        if packet.len() < 2 {
            return Err(RoutingError::InvalidPacket("Packet too short for padding".to_string()));
        }

        // Extract padding length (first two bytes)
        let mut padding_len_bytes = [0u8; 2];
        padding_len_bytes.copy_from_slice(&packet[0..2]);
        let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;

        // Validate packet length
        if packet.len() < 2 + padding_len {
            return Err(RoutingError::InvalidPacket(format!(
                "Invalid padding length: {} exceeds packet size {}",
                padding_len, packet.len() - 2
            )));
        }

        // Extract the actual data (between header and padding)
        let data_len = packet.len() - 2 - padding_len;
        let data = &packet[2..(2 + data_len)];

        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused Message import
    // Removed unused ClientSession import (was implicitly unused) // Corrected line 261
    use std::net::SocketAddr;
    // Removed unused WebSocketStream, TlsStream, TcpStream, FromStr imports

    // Mock implementation for tests (simplified)
    #[derive(Clone)]
    struct MockClientSession {
        pub id: String,
        pub client_id: String,
        pub ip_address: String,
        pub address: SocketAddr,
    }

    impl MockClientSession {
        async fn send_packet(&self, _packet: &PacketType) -> Result<(), crate::server::core::ServerError> {
            Ok(())
        }
    }

    #[test]
    fn test_process_packet() {
        let router = PacketRouter::new(2048, false);

        // Create a mock IPv4 packet
        let mut packet = vec![0u8; 20]; // Minimum IPv4 header size
        packet[0] = 0x45; // IPv4, header length 5 words
        packet[16] = 10;  // Destination IP: 10.7.0.5
        packet[17] = 7;
        packet[18] = 0;
        packet[19] = 5;

        let result = router.process_packet(&packet);
        assert!(result.is_some());

        let (dest_ip, processed) = result.unwrap();
        assert_eq!(dest_ip, "10.7.0.5");
        assert_eq!(processed, packet);
    }

    #[test]
    fn test_non_ipv4_packet() {
        let router = PacketRouter::new(2048, false);

        // Mock IPv6 packet (version 6)
        let mut packet = vec![0u8; 40]; // IPv6 header
        packet[0] = 0x60; // IPv6 version

        let result = router.process_packet(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_packet_too_small() {
        let router = PacketRouter::new(2048, false);

        // Packet smaller than IPv4 header
        let packet = vec![0u8; 10];

        let result = router.process_packet(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_padding() {
        let router = PacketRouter::new(2048, true);
        let data = b"Test data for padding";

        // Add padding
        let padded = router.add_padding(data);

        // Padding length should be at least the minimum size
        let mut padding_len_bytes = [0u8; 2];
        padding_len_bytes.copy_from_slice(&padded[0..2]);
        let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
        assert!(padding_len >= MIN_PADDING_SIZE && padding_len <= MAX_PADDING_SIZE);

        // Remove padding
        let unpadded = router.remove_padding(&padded).unwrap();

        // Check that unpadded data matches original
        assert_eq!(data.to_vec(), unpadded);
    }

    #[test]
    fn test_invalid_padding() {
        let router = PacketRouter::new(2048, true);

        // Create invalid packet with padding length larger than data
        let mut invalid_packet = vec![0u8; 10];
        // Set padding length to 20 (larger than available data)
        invalid_packet[0] = 0;
        invalid_packet[1] = 20;

        let result = router.remove_padding(&invalid_packet);
        assert!(result.is_err());

        if let Err(RoutingError::InvalidPacket(msg)) = result {
            assert!(msg.contains("Invalid padding length"));
        } else {
            panic!("Expected InvalidPacket error");
        }
    }
    
    #[test]
    fn test_algorithm_compatibility() {
        // Test compatibility between different encryption algorithms
        let key = [1u8; 32];
        let data = b"Test data for algorithm compatibility";
        
        // Test ChaCha20-Poly1305 encryption
        let chacha_result = crate::crypto::flexible_encryption::encrypt_packet(
            data, &key, Some(EncryptionAlgorithm::ChaCha20Poly1305)
        ).unwrap();
        
        // Test AES-GCM encryption
        let aes_result = crate::crypto::flexible_encryption::encrypt_packet(
            data, &key, Some(EncryptionAlgorithm::Aes256Gcm)
        ).unwrap();
        
        // Verify both algorithms produce different ciphertexts
        assert_ne!(chacha_result.data, aes_result.data);
        
        // Verify ChaCha20-Poly1305 encryption can be decrypted
        let decrypted1 = crate::crypto::flexible_encryption::decrypt_packet(
            &chacha_result.data, &key, &chacha_result.nonce,
            EncryptionAlgorithm::ChaCha20Poly1305, false
        ).unwrap();
        assert_eq!(data.to_vec(), decrypted1);
        
        // Verify AES-GCM encryption can be decrypted
        let decrypted2 = crate::crypto::flexible_encryption::decrypt_packet(
            &aes_result.data, &key, &aes_result.nonce,
            EncryptionAlgorithm::Aes256Gcm, false
        ).unwrap();
        assert_eq!(data.to_vec(), decrypted2);
        
        // Test fallback mechanism (decrypt ChaCha20 with AES algorithm + fallback)
        let decrypted_fallback = crate::crypto::flexible_encryption::decrypt_packet(
            &chacha_result.data, &key, &chacha_result.nonce,
            EncryptionAlgorithm::Aes256Gcm, true
        ).unwrap();
        assert_eq!(data.to_vec(), decrypted_fallback);
    }
}
