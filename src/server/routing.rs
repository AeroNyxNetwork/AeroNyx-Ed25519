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

use serde::{Serialize, Deserialize};
// Removed unused debug import
use tracing::{debug, error, trace, warn};

use crate::config::constants::{MIN_PADDING_SIZE, MAX_PADDING_SIZE, PAD_PROBABILITY};
// Removed: use crate::crypto::{encrypt_packet, decrypt_packet};
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

/// Data envelope for mixed-mode packet handling
#[derive(Debug, Serialize, Deserialize)]
pub struct DataEnvelope {
    pub payload_type: PayloadDataType,
    pub payload: serde_json::Value,
}

/// Payload data types supported in envelopes
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PayloadDataType {
    /// JSON data (application messages)
    Json,
    /// IP packet data (encoded as Base64 string)
    Ip,
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

    /// Handle an inbound packet from a client with mixed mode support
    pub async fn handle_inbound_packet(
        &self,
        encrypted: &[u8],
        nonce: &[u8],
        session_key: &[u8],
        session: &ClientSession,
        encryption_algorithm: Option<&str>,
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
        
        // Get enable_fallback boolean
        let enable_fallback = session.is_fallback_enabled().await;
        
        // Decrypt using flexible decryption with fallback
        let decrypted = match crate::crypto::flexible_encryption::decrypt_packet(
            encrypted, session_key, nonce, algorithm, enable_fallback
        ) {
            Ok(data) => {
                debug!("Packet decryption successful, received {} bytes", data.len());
                data
            },
            Err(e) => {
                error!("Packet decryption failed: {}", e);
                error!("Packet details: algo={:?}, encrypted={} bytes, nonce={:?}, enable_fallback={}", 
                       algorithm, encrypted.len(), nonce, enable_fallback);
                return Err(RoutingError::Decryption(e.to_string()));
            }
        };

        // Try to parse as a DataEnvelope
        match serde_json::from_slice::<DataEnvelope>(&decrypted) {
            Ok(envelope) => {
                match envelope.payload_type {
                    PayloadDataType::Json => {
                        // Handle JSON payload (application messages)
                        debug!("Processing JSON payload from client {}", session.client_id);
                        self.process_json_payload(envelope.payload, session).await
                    },
                    PayloadDataType::Ip => {
                        // Handle IP payload (VPN packets)
                        debug!("Processing IP packet payload from client {}", session.client_id);
                        self.process_ip_payload(envelope.payload, session).await
                    }
                }
            },
            Err(e) => {
                // Legacy mode: Try direct IP packet (without envelope)
                debug!("Failed to parse as DataEnvelope: {}. Trying legacy mode as direct IP packet.", e);
                return self.write_to_tun_device(&decrypted).await;
            }
        }
    }

    /// Process JSON payload from client
    async fn process_json_payload(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<usize, RoutingError> {
        // Extract message type from the JSON payload
        let msg_type = payload.get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing 'type' field in JSON payload".to_string()))?;
        
        match msg_type {
            "message" => {
                // Handle the message and return the processed size
                self.handle_chat_message(payload, session).await?;
                // Return the size of the processed JSON (or estimated size)
                Ok(payload.to_string().len())
            },
            "participants_request" => {
                // Handle the request and return the processed size
                self.handle_participants_request(session).await?;
                // Return the size of the processed JSON (or estimated size)
                Ok(payload.to_string().len())
            },
            "webrtc_signal" => {
                // Handle the signal and return the processed size
                self.handle_webrtc_signal(payload, session).await?;
                // Return the size of the processed JSON (or estimated size)
                Ok(payload.to_string().len())
            },
            _ => {
                warn!("Unknown JSON message type: {}", msg_type);
                Err(RoutingError::InvalidPacket(format!("Unknown message type: {}", msg_type)))
            }
        }
    }

    /// Process IP payload from client
    async fn process_ip_payload(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<usize, RoutingError> {
        // Extract Base64 string from the payload
        let base64_ip = payload.as_str()
            .ok_or_else(|| RoutingError::InvalidPacket("IP payload is not a string".to_string()))?;
        
        // Decode Base64 to get IP packet bytes
        let ip_packet_bytes = base64::decode(base64_ip)
            .map_err(|e| RoutingError::InvalidPacket(format!("Invalid Base64 IP payload: {}", e)))?;
        
        // Write the IP packet to the TUN device
        self.write_to_tun_device(&ip_packet_bytes).await
    }
    
    /// Helper method to write data to the TUN device
    async fn write_to_tun_device(&self, data: &[u8]) -> Result<usize, RoutingError> {
        // Check packet size
        if data.len() > self.max_packet_size {
            return Err(RoutingError::InvalidPacket(format!(
                "Packet size {} exceeds maximum {}",
                data.len(), self.max_packet_size
            )));
        }
    
        // Check for attack patterns
        if let Some(reason) = detect_attack_patterns(data) {
            warn!("Security risk in packet: {}", reason);
            return Err(RoutingError::SecurityRisk(reason));
        }
    
        // Remove padding if necessary
        let packet_data = if self.enable_padding {
            match self.remove_padding(data) {
                Ok(clean_data) => {
                    debug!("Padding removed, packet size reduced from {} to {} bytes", 
                          data.len(), clean_data.len());
                    clean_data
                },
                Err(e) => {
                    warn!("Failed to remove padding from packet: {}", e);
                    data.to_vec()
                }
            }
        } else {
            data.to_vec()
        };
        
        // Get the TUN device
        if let Some(tun_device) = crate::server::globals::get_tun_device() {
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

    /// Handle a chat message
    async fn handle_chat_message(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Extract required fields
        let chat_id = payload.get("chatId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing chatId in message".to_string()))?;

        // Get session manager
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        // Update session's current room if changed
        let current_room = session.get_current_room().await;
        if current_room.as_deref() != Some(chat_id) {
            session.set_current_room(Some(chat_id.to_string())).await;
        }
        
        // Get all sessions in the same chat room
        let sessions = session_manager.get_sessions_by_room(chat_id).await;
        
        // Forward message to all other sessions in the room
        for target_session in sessions {
            if target_session.id != session.id {
                // Create envelope for the target session
                let envelope = DataEnvelope {
                    payload_type: PayloadDataType::Json,
                    payload: payload.clone(),
                };
                
                // Try to get target session's encryption key
                if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
                    if let Some(target_key) = session_key_manager.get_key(&target_session.client_id).await {
                        // Create encrypted message packet
                        if let Err(e) = self.forward_envelope_to_session(&envelope, &target_key, &target_session).await {
                            warn!("Failed to forward message to {}: {}", target_session.client_id, e);
                            // Continue with other sessions - don't fail entire operation for one recipient
                        }
                    } else {
                        warn!("No session key found for {}", target_session.client_id);
                    }
                } else {
                    warn!("Session key manager not available");
                }
            }
        }
        
        Ok(())
    }

    /// Forward an envelope to a session
    async fn forward_envelope_to_session(
        &self,
        envelope: &DataEnvelope,
        target_key: &[u8],
        target_session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Serialize the envelope
        let envelope_data = serde_json::to_vec(envelope)
            .map_err(|e| RoutingError::Processing(format!("Failed to serialize envelope: {}", e)))?;
        
        // Get target's encryption algorithm
        let algorithm = crate::crypto::flexible_encryption::EncryptionAlgorithm::from_str(
            &target_session.encryption_algorithm
        ).unwrap_or_default();
        
        // Encrypt the envelope
        let encrypted_packet = crate::crypto::flexible_encryption::encrypt_packet(
            &envelope_data,
            target_key,
            Some(algorithm),
        ).map_err(|e| RoutingError::Encryption(e.to_string()))?;
        
        // Get next packet counter (should be atomic)
        let counter = {
            let mut counter = self.packet_counter.lock().await;
            let value = *counter;
            *counter = value.wrapping_add(1);
            value
        };
        
        // Create Data packet
        let data_packet = crate::protocol::types::PacketType::Data {
            encrypted: encrypted_packet.data,
            nonce: encrypted_packet.nonce,
            counter,
            padding: None,
            encryption_algorithm: Some(encrypted_packet.algorithm.as_str().to_string()),
        };
        
        // Send to target client
        target_session.send_packet(&data_packet).await
            .map_err(|e| RoutingError::Protocol(MessageError::InvalidFormat(e.to_string())))?;
        
        Ok(())
    }

    /// Handle request for participants in a room
    async fn handle_participants_request(
        &self,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Get current room
        let room_id = session.get_current_room().await
            .ok_or_else(|| RoutingError::InvalidPacket("Client not in a room".to_string()))?;
        
        // Get session manager
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        // Get all sessions in the room
        let sessions = session_manager.get_sessions_by_room(&room_id).await;
        
        // Create participants list
        let participants: Vec<serde_json::Value> = sessions.iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.client_id,
                    "name": s.get_display_name().unwrap_or_else(|| s.client_id.clone()),
                    "online": true
                })
            })
            .collect();
        
        // Create response
        let response = serde_json::json!({
            "type": "participants_response",
            "roomId": room_id,
            "participants": participants
        });
        
        // Create envelope
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: response,
        };
        
        // Get session key
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(session_key) = session_key_manager.get_key(&session.client_id).await {
                // Forward to requesting client
                self.forward_envelope_to_session(&envelope, &session_key, session).await?;
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
    }

    /// Handle WebRTC signaling message
    async fn handle_webrtc_signal(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Extract required fields
        let peer_id = payload.get("peerId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing peerId in WebRTC signal".to_string()))?;
        
        // Get session manager
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        // Find target session
        let target_session = session_manager.get_session_by_client_id(peer_id).await
            .ok_or_else(|| RoutingError::Processing(format!("Peer {} not found", peer_id)))?;
        
        // Create envelope
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: payload.clone(),
        };
        
        // Get session key manager
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            // Get target session key
            if let Some(target_key) = session_key_manager.get_key(&target_session.client_id).await {
                // Forward signal
                self.forward_envelope_to_session(&envelope, &target_key, &target_session).await?;
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", target_session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
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
    
    #[test]
    fn test_data_envelope_serialization() {
        // Test creation and serialization of data envelopes
        let json_envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: serde_json::json!({ "type": "message", "text": "Hello" }),
        };
        
        // Serialize
        let serialized = serde_json::to_string(&json_envelope).unwrap();
        
        // Deserialize
        let deserialized: DataEnvelope = serde_json::from_str(&serialized).unwrap();
        
        // Verify payload type
        assert_eq!(deserialized.payload_type, PayloadDataType::Json);
        
        // Verify payload data
        assert_eq!(
            deserialized.payload.get("type").and_then(|v| v.as_str()),
            Some("message")
        );
        assert_eq!(
            deserialized.payload.get("text").and_then(|v| v.as_str()),
            Some("Hello")
        );
    }

    #[test]
    fn test_base64_ip_envelope() {
        // Create mock IP packet
        let ip_data = vec![0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 
                           0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                           0x0A, 0x07, 0x00, 0x05];
        
        // Create Base64 representation
        let base64_ip = base64::encode(&ip_data);
        
        // Create envelope
        let ip_envelope = DataEnvelope {
            payload_type: PayloadDataType::Ip,
            payload: serde_json::Value::String(base64_ip.clone()),
        };
        
        // Serialize and deserialize
        let serialized = serde_json::to_string(&ip_envelope).unwrap();
        let deserialized: DataEnvelope = serde_json::from_str(&serialized).unwrap();
        
        // Verify payload type
        assert_eq!(deserialized.payload_type, PayloadDataType::Ip);
        
        // Verify we can extract the base64 string
        let extracted_base64 = deserialized.payload.as_str().unwrap();
        assert_eq!(extracted_base64, base64_ip);
        
        // Verify we can decode back to original data
        let decoded = base64::decode(extracted_base64).unwrap();
        assert_eq!(decoded, ip_data);
    }
}
