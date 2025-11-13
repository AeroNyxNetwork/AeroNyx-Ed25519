// src/server/routing.rs
//! Network packet routing with blind relay support for end-to-end encryption.
//!
//! ## Phase 1: Blind Relay Architecture
//!
//! This module implements a blind relay system where the server forwards encrypted
//! messages between clients without being able to decrypt them.
//!
//! ### Message Flow
//! ```
//! Client A                    Server (Blind Relay)              Client B
//!    |                               |                              |
//!    | Encrypt with E2E key          |                              |
//!    | (Server doesn't know this key)|                              |
//!    |------------------------------>|                              |
//!    |                               | Forward encrypted packet     |
//!    |                               | (Server cannot decrypt)      |
//!    |                               |----------------------------->|
//!    |                               |                              |
//!    |                               |                              | Decrypt with E2E key
//! ```
//!
//! ### Security Model
//! - **Control Channel**: Server-Client ECDH encryption
//!   - Used for: Authentication, session management, IP assignment
//!   - Server can decrypt: Control messages only
//!
//! - **Data Channel**: Client-Client E2E encryption (for chat messages)
//!   - Used for: Chat messages, file transfers
//!   - Server cannot decrypt: Message contents
//!   - Server can see: Metadata (sender, receiver, timestamp, size)
//!
//! ### Backward Compatibility
//! - Legacy clients (no E2E): Messages are not encrypted, server can read
//! - Modern clients (with E2E): Messages are encrypted, server cannot read
//! - Detection: Check for "e2e:" prefix and is_encrypted flag

use std::io::Write;
use std::sync::Arc;
use rand::{Rng, thread_rng};
use tokio::sync::Mutex;

use serde::{Serialize, Deserialize};
use tracing::{debug, error, info, trace, warn};

use crate::config::constants::{MIN_PADDING_SIZE, MAX_PADDING_SIZE, PAD_PROBABILITY};
use crate::protocol::{PacketType, MessageError, ChatMessageType};
use crate::server::session::ClientSession;
use crate::utils::security::detect_attack_patterns;
use crate::crypto::flexible_encryption::{
    EncryptionAlgorithm, 
    encrypt_flexible, 
    decrypt_flexible,
    EncryptedPacket
};
use crate::crypto::e2e::{E2ESessionManager, EncryptedMessageFormat};

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
    /// E2E session manager for blind relay
    e2e_manager: E2ESessionManager,
}

impl PacketRouter {
    /// Create a new packet router
    pub fn new(max_packet_size: usize, enable_padding: bool) -> Self {
        Self {
            max_packet_size,
            enable_padding,
            packet_counter: Arc::new(Mutex::new(0)),
            e2e_manager: E2ESessionManager::new(),
        }
    }

    /// Get reference to E2E session manager
    pub fn e2e_manager(&self) -> &E2ESessionManager {
        &self.e2e_manager
    }

    /// Process an IP packet and extract routing information
    pub fn process_packet<'a>(&self, packet: &'a [u8]) -> Option<(String, Vec<u8>)> {
        // Check minimum IPv4 header size
        if packet.len() < 20 {
            trace!("Packet too small for IPv4: {} bytes", packet.len());
            return None;
        }

        // Check if it's an IPv4 packet (version field in the top 4 bits)
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
        
        // Use flexible encryption with the correct function
        let encrypted_packet = encrypt_flexible(
            &packet_data, 
            session_key, 
            algorithm,
            None  // Let the function generate nonce
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
    /// 
    /// ## Phase 1: Blind Relay Logic
    /// 
    /// This function implements smart packet handling:
    /// 1. Decrypt the outer layer (control channel encryption)
    /// 2. Parse the payload to determine if it's chat or VPN data
    /// 3. For chat messages:
    ///    - Check if it's E2E encrypted (starts with "e2e:")
    ///    - If E2E: Blind relay without decryption
    ///    - If legacy: Process normally (backward compatibility)
    /// 4. For VPN data: Process normally (always requires server decryption)
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
            EncryptionAlgorithm::from_str(algo)
                .unwrap_or_else(|| {
                    debug!("Packet algorithm not recognized, using session algorithm: {}", session.encryption_algorithm);
                    EncryptionAlgorithm::from_str(
                        &session.encryption_algorithm
                    ).unwrap_or_default()
                })
        } else {
            debug!("No algorithm specified in packet, using session algorithm: {}", session.encryption_algorithm);
            EncryptionAlgorithm::from_str(
                &session.encryption_algorithm
            ).unwrap_or_default()
        };
        
        // Step 1: Decrypt the control channel layer
        // This is the Server-Client ECDH encryption
        let decrypted = match decrypt_flexible(
            encrypted, 
            session_key, 
            nonce, 
            algorithm
        ) {
            Ok(data) => {
                debug!("Control channel decryption successful, received {} bytes", data.len());
                data
            },
            Err(e) => {
                error!("Control channel decryption failed for packet from {}", session.client_id);
                error!("  Algorithm used: {:?}", algorithm);
                error!("  Error: {}", e);
                
                // Try fallback if enabled
                if session.is_fallback_enabled().await {
                    debug!("Primary decryption failed, trying fallback algorithms");
                    
                    let fallback_algo = match algorithm {
                        EncryptionAlgorithm::ChaCha20Poly1305 => EncryptionAlgorithm::Aes256Gcm,
                        EncryptionAlgorithm::Aes256Gcm => EncryptionAlgorithm::ChaCha20Poly1305,
                    };
                    
                    match decrypt_flexible(encrypted, session_key, nonce, fallback_algo) {
                        Ok(data) => {
                            debug!("Fallback decryption successful with {:?}", fallback_algo);
                            data
                        },
                        Err(_) => {
                            error!("All decryption attempts failed");
                            return Err(RoutingError::Decryption(e.to_string()));
                        }
                    }
                } else {
                    error!("Packet decryption failed: {}", e);
                    return Err(RoutingError::Decryption(e.to_string()));
                }
            }
        };

        // Step 2: Parse the payload to determine type
        match serde_json::from_slice::<DataEnvelope>(&decrypted) {
            Ok(envelope) => {
                match envelope.payload_type {
                    PayloadDataType::Json => {
                        // Handle JSON payload (chat messages)
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
                self.write_to_tun_device(&decrypted).await
            }
        }
    }

    /// Process JSON payload from client
    /// 
    /// ## Phase 1: Smart Routing
    /// 
    /// This function parses the JSON payload and routes it appropriately:
    /// - For E2E encrypted messages: Use blind relay (forward without decryption)
    /// - For legacy messages: Process normally (backward compatibility)
    async fn process_json_payload(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<usize, RoutingError> {
        // Extract message type from the JSON payload
        let msg_type = payload.get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing 'type' field in JSON payload".to_string()))?;
        
        // Store payload size for return value
        let payload_size = payload.to_string().len();
        
        match msg_type {
            "request-chat" => {
                self.handle_request_chat(payload.clone(), session).await?;
                Ok(payload_size)
            },
            "accept-chat" => {
                self.handle_accept_chat(payload.clone(), session).await?;
                Ok(payload_size)
            },
            "message" => {
                // Check if this is an E2E encrypted message
                let is_encrypted = payload.get("is_encrypted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                
                let content = payload.get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                
                if is_encrypted && EncryptedMessageFormat::is_encrypted(content) {
                    // E2E encrypted message - use blind relay
                    info!("Routing E2E encrypted message via blind relay");
                    self.handle_e2e_message_blind_relay(payload.clone(), session).await?;
                } else {
                    // Legacy message - process normally
                    warn!("Routing legacy (unencrypted) message - E2E not enabled");
                    self.handle_chat_message_legacy(payload.clone(), session).await?;
                }
                Ok(payload_size)
            },
            "request-chat-info" | "chat_info_request" => {
                self.handle_chat_info_request(payload.clone(), session).await?;
                Ok(payload_size)
            },
            "request-participants" | "participants_request" => {
                self.handle_participants_request(session).await?;
                Ok(payload_size)
            },
            "webrtc-signal" | "webrtc_signal" => {
                self.handle_webrtc_signal(payload.clone(), session).await?;
                Ok(payload_size)
            },
            "leave-chat" => {
                self.handle_leave_chat_request(payload.clone(), session).await?;
                Ok(payload_size)
            },
            "delete-chat" => {
                self.handle_delete_chat_request(payload.clone(), session).await?;
                Ok(payload_size)
            },
            _ => {
                debug!("Unknown JSON message type: {}", msg_type);
                Ok(payload_size)
            }
        }
    }

    /// Handle request-chat message
    /// 
    /// ## Phase 1: E2E Key Exchange Initiation
    /// 
    /// When Alice requests a chat with Bob:
    /// 1. Extract Alice's X25519 public key
    /// 2. Create an E2E session with Alice's key
    /// 3. Forward the request to Bob (including Alice's public key)
    async fn handle_request_chat(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Parse the request
        let msg: ChatMessageType = serde_json::from_value(payload.clone())
            .map_err(|e| RoutingError::InvalidPacket(format!("Invalid request-chat: {}", e)))?;
        
        let (target_user, from_user, x25519_pubkey) = match msg {
            ChatMessageType::RequestChat { target_user, from_user, x25519_public_key, .. } => {
                (target_user, from_user, x25519_public_key)
            },
            _ => return Err(RoutingError::InvalidPacket("Expected request-chat".to_string())),
        };
        
        // Generate chat ID
        let chat_id = format!("chat_{}", crate::utils::random_string(16));
        
        // Create E2E session with initiator's public key
        self.e2e_manager.create_session(
            chat_id.clone(),
            from_user.clone(),
            target_user.clone(),
            Some(x25519_pubkey.clone()),
        ).await;
        
        info!(
            "E2E session created for chat {} ({} → {}), awaiting recipient's key",
            chat_id, from_user, target_user
        );
        
        // Get session manager
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        // Find target session
        let target_session = session_manager.get_session_by_client_id(&target_user).await
            .ok_or_else(|| RoutingError::Processing(format!("Target user {} not found", target_user)))?;
        
        // Forward request to target (including chat_id and initiator's X25519 key)
        let forward_payload = serde_json::json!({
            "type": "request-chat",
            "chat_id": chat_id,
            "target_user": target_user,
            "from_user": from_user,
            "x25519_public_key": x25519_pubkey,
            "timestamp": crate::utils::current_timestamp_millis(),
        });
        
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: forward_payload,
        };
        
        // Get session key manager
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(target_key) = session_key_manager.get_key(&target_session.client_id).await {
                self.forward_envelope_to_session(&envelope, &target_key, &target_session).await?;
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", target_session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
    }

    /// Handle accept-chat message
    /// 
    /// ## Phase 1: E2E Key Exchange Completion
    /// 
    /// When Bob accepts Alice's chat request:
    /// 1. Extract Bob's X25519 public key
    /// 2. Update the E2E session with Bob's key
    /// 3. Forward the acceptance to Alice (including Bob's public key)
    /// 4. E2E session is now complete (both public keys exchanged)
    async fn handle_accept_chat(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Parse the acceptance
        let msg: ChatMessageType = serde_json::from_value(payload.clone())
            .map_err(|e| RoutingError::InvalidPacket(format!("Invalid accept-chat: {}", e)))?;
        
        let (chat_id, from_user, x25519_pubkey) = match msg {
            ChatMessageType::AcceptChat { chat_id, from_user, x25519_public_key, .. } => {
                (chat_id, from_user, x25519_public_key)
            },
            _ => return Err(RoutingError::InvalidPacket("Expected accept-chat".to_string())),
        };
        
        // Update E2E session with recipient's public key
        let updated = self.e2e_manager.set_recipient_pubkey(&chat_id, x25519_pubkey.clone()).await;
        
        if !updated {
            warn!("Failed to update E2E session for chat {}", chat_id);
        }
        
        // Get the E2E session to find the initiator
        let e2e_session = self.e2e_manager.get_session(&chat_id).await
            .ok_or_else(|| RoutingError::Processing(format!("E2E session not found for chat {}", chat_id)))?;
        
        let initiator = if e2e_session.client_a == from_user {
            &e2e_session.client_b
        } else {
            &e2e_session.client_a
        };
        
        info!(
            "E2E session established for chat {} - both keys exchanged",
            chat_id
        );
        
        // Get session manager
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        // Find initiator's session
        let initiator_session = session_manager.get_session_by_client_id(initiator).await
            .ok_or_else(|| RoutingError::Processing(format!("Initiator {} not found", initiator)))?;
        
        // Forward acceptance to initiator (including recipient's X25519 key)
        let forward_payload = serde_json::json!({
            "type": "accept-chat",
            "chat_id": chat_id,
            "from_user": from_user,
            "x25519_public_key": x25519_pubkey,
            "timestamp": crate::utils::current_timestamp_millis(),
        });
        
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: forward_payload,
        };
        
        // Get session key manager
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(initiator_key) = session_key_manager.get_key(&initiator_session.client_id).await {
                self.forward_envelope_to_session(&envelope, &initiator_key, &initiator_session).await?;
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", initiator_session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
    }

    /// Handle E2E encrypted message using blind relay
    /// 
    /// ## Phase 1: Blind Relay Implementation
    /// 
    /// This is the core of blind relay:
    /// 1. Server receives encrypted message (outer layer: control channel)
    /// 2. Server decrypts outer layer to see metadata (sender, receiver, chat_id)
    /// 3. Server reads the E2E encrypted content (inner layer: client-client)
    /// 4. Server CANNOT decrypt the inner layer (no E2E key)
    /// 5. Server forwards the E2E encrypted content to recipient
    /// 6. Recipient decrypts inner layer with E2E key
    /// 
    /// Security: Server sees metadata but not message content
    async fn handle_e2e_message_blind_relay(
        &self,
        payload: serde_json::Value,
        _sender_session: &ClientSession,
    ) -> Result<(), RoutingError> {
        // Extract message fields
        let chat_id = payload.get("chat_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing chat_id in E2E message".to_string()))?;
        
        let from_user = payload.get("from_user")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing from_user in E2E message".to_string()))?;
        
        let encrypted_content = payload.get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing content in E2E message".to_string()))?;
        
        // Verify it's actually E2E encrypted
        if !EncryptedMessageFormat::is_encrypted(encrypted_content) {
            return Err(RoutingError::InvalidPacket("Content not E2E encrypted".to_string()));
        }
        
        // Get E2E session to find recipient
        let e2e_session = self.e2e_manager.get_session(chat_id).await
            .ok_or_else(|| RoutingError::Processing(format!("E2E session not found for chat {}", chat_id)))?;
        
        if !e2e_session.is_e2e_ready() {
            return Err(RoutingError::Processing("E2E session not fully established".to_string()));
        }
        
        // Find recipient (the other participant)
        let recipient = e2e_session.get_peer_id(from_user)
            .ok_or_else(|| RoutingError::Processing(format!("{} is not a participant in chat {}", from_user, chat_id)))?;
        
        debug!(
            "Blind relay: Forwarding E2E encrypted message from {} to {} (chat {})",
            from_user, recipient, chat_id
        );
        
        // Get session manager
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        // Find recipient's session
        let recipient_session = session_manager.get_session_by_client_id(recipient).await
            .ok_or_else(|| RoutingError::Processing(format!("Recipient {} not found", recipient)))?;
        
        // Forward the E2E encrypted message (server cannot decrypt inner layer)
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: payload.clone(),
        };
        
        // Get session key manager
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(recipient_key) = session_key_manager.get_key(&recipient_session.client_id).await {
                self.forward_envelope_to_session(&envelope, &recipient_key, &recipient_session).await?;
                
                // Log metadata only (server cannot see message content)
                info!(
                    "Blind relay: Message forwarded ({} → {}, {} bytes)",
                    from_user,
                    recipient,
                    encrypted_content.len()
                );
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", recipient_session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
    }

    /// Handle legacy chat message (backward compatibility)
    /// 
    /// This function handles messages from clients that don't support E2E encryption.
    /// Server can decrypt and read these messages.
    /// 
    /// **DEPRECATED**: New clients should use E2E encryption
    async fn handle_chat_message_legacy(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        warn!("Processing legacy (unencrypted) chat message - consider upgrading client to support E2E");
        
        // Extract required fields
        let chat_id = payload.get("chat_id" )
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing chat_id in message".to_string()))?;

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
                let envelope = DataEnvelope {
                    payload_type: PayloadDataType::Json,
                    payload: payload.clone(),
                };
                
                if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
                    if let Some(target_key) = session_key_manager.get_key(&target_session.client_id).await {
                        if let Err(e) = self.forward_envelope_to_session(&envelope, &target_key, &target_session).await {
                            warn!("Failed to forward legacy message to {}: {}", target_session.client_id, e);
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

    // ... (rest of the helper functions remain the same)
    // I'll include them for completeness

    async fn handle_chat_info_request(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        let chat_id = payload.get("chatId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing chatId in chat info request".to_string()))?;
        
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        session.set_current_room(Some(chat_id.to_string())).await;
        
        let chat_info = serde_json::json!({
            "type": "chat-info",
            "chatId": chat_id,
            "name": format!("Chat {}", chat_id),
            "created_at": crate::utils::current_timestamp_millis(),
            "participant_count": session_manager.get_sessions_by_room(chat_id).await.len(),
            "encryption": "end-to-end"
        });
        
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: chat_info,
        };
        
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(session_key) = session_key_manager.get_key(&session.client_id).await {
                self.forward_envelope_to_session(&envelope, &session_key, session).await?;
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
    }

    async fn handle_leave_chat_request(
        &self,
        payload: serde_json::Value,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        let chat_id = payload.get("chatId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing chatId in leave chat request".to_string()))?;
        
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        session.set_current_room(None).await;
        
        let leave_notification = serde_json::json!({
            "type": "participant-leave",
            "chatId": chat_id,
            "participantId": session.client_id,
            "timestamp": crate::utils::current_timestamp_millis()
        });
        
        let sessions = session_manager.get_sessions_by_room(chat_id).await;
        
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            for target_session in sessions {
                if target_session.id != session.id {
                    let envelope = DataEnvelope {
                        payload_type: PayloadDataType::Json,
                        payload: leave_notification.clone(),
                    };
                    
                    if let Some(target_key) = session_key_manager.get_key(&target_session.client_id).await {
                        if let Err(e) = self.forward_envelope_to_session(&envelope, &target_key, &target_session).await {
                            debug!("Failed to forward leave notification to {}: {}", target_session.client_id, e);
                        }
                    }
                }
            }
        }
        
        let confirmation = serde_json::json!({
            "type": "leave-chat-confirm",
            "chatId": chat_id,
            "success": true
        });
        
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: confirmation,
        };
        
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(session_key) = session_key_manager.get_key(&session.client_id).await {
                self.forward_envelope_to_session(&envelope, &session_key, session).await?;
            }
        }
        
        Ok(())
    }

    async fn handle_delete_chat_request(
        &self,
        payload: serde_json::Value,
        _session: &ClientSession,
    ) -> Result<(), RoutingError> {
        let chat_id = payload.get("chatId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing chatId in delete chat request".to_string()))?;
        
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        let is_authorized = true; // TODO: Implement proper authorization
        
        if !is_authorized {
            let error_response = serde_json::json!({
                "type": "delete-chat-response",
                "chatId": chat_id,
                "success": false,
                "error": "Not authorized to delete this chat"
            });
            
            let envelope = DataEnvelope {
                payload_type: PayloadDataType::Json,
                payload: error_response,
            };
            
            if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
                if let Some(session_key) = session_key_manager.get_key(&_session.client_id).await {
                    self.forward_envelope_to_session(&envelope, &session_key, _session).await?;
                }
            }
            
            return Err(RoutingError::SecurityRisk("Unauthorized chat deletion attempt".to_string()));
        }
        
        let delete_notification = serde_json::json!({
            "type": "chat-deleted",
            "chatId": chat_id,
            "timestamp": crate::utils::current_timestamp_millis()
        });
        
        let sessions = session_manager.get_sessions_by_room(chat_id).await;
        
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            for target_session in sessions {
                let envelope = DataEnvelope {
                    payload_type: PayloadDataType::Json,
                    payload: delete_notification.clone(),
                };
                
                if let Some(target_key) = session_key_manager.get_key(&target_session.client_id).await {
                    if let Some(current_room) = target_session.get_current_room().await {
                        if current_room == chat_id {
                            target_session.set_current_room(None).await;
                        }
                    }
                    
                    if let Err(e) = self.forward_envelope_to_session(&envelope, &target_key, &target_session).await {
                        debug!("Failed to forward deletion notification to {}: {}", target_session.client_id, e);
                    }
                }
            }
        }
        
        // Remove E2E session
        self.e2e_manager.remove_session(chat_id).await;
        
        Ok(())
    }

    /// Process IP payload from client
    async fn process_ip_payload(
        &self,
        payload: serde_json::Value,
        _session: &ClientSession,
    ) -> Result<usize, RoutingError> {
        let base64_ip = payload.as_str()
            .ok_or_else(|| RoutingError::InvalidPacket("IP payload is not a string".to_string()))?;
        
        let ip_packet_bytes = base64::decode(base64_ip)
            .map_err(|e| RoutingError::InvalidPacket(format!("Invalid Base64 IP payload: {}", e)))?;
        
        self.write_to_tun_device(&ip_packet_bytes).await
    }
    
    async fn write_to_tun_device(&self, data: &[u8]) -> Result<usize, RoutingError> {
        if data.len() > self.max_packet_size {
            return Err(RoutingError::InvalidPacket(format!(
                "Packet size {} exceeds maximum {}",
                data.len(), self.max_packet_size
            )));
        }
    
        if let Some(reason) = detect_attack_patterns(data) {
            warn!("Security risk in packet: {}", reason);
            return Err(RoutingError::SecurityRisk(reason));
        }
    
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
        
        if let Some(tun_device) = crate::server::globals::get_tun_device() {
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

    async fn forward_envelope_to_session(
        &self,
        envelope: &DataEnvelope,
        target_key: &[u8],
        target_session: &ClientSession,
    ) -> Result<(), RoutingError> {
        let envelope_data = serde_json::to_vec(envelope)
            .map_err(|e| RoutingError::Processing(format!("Failed to serialize envelope: {}", e)))?;
        
        let algorithm = EncryptionAlgorithm::from_str(
            &target_session.encryption_algorithm
        ).unwrap_or_default();
        
        let encrypted_packet = encrypt_flexible(
            &envelope_data,
            target_key,
            algorithm,
            None
        ).map_err(|e| RoutingError::Encryption(e.to_string()))?;
        
        let counter = {
            let mut counter = self.packet_counter.lock().await;
            let value = *counter;
            *counter = value.wrapping_add(1);
            value
        };
        
        let data_packet = crate::protocol::types::PacketType::Data {
            encrypted: encrypted_packet.data,
            nonce: encrypted_packet.nonce,
            counter,
            padding: None,
            encryption_algorithm: Some(encrypted_packet.algorithm.as_str().to_string()),
        };
        
        target_session.send_packet(&data_packet).await
            .map_err(|e| RoutingError::Protocol(MessageError::InvalidFormat(e.to_string())))?;
        
        Ok(())
    }

    async fn handle_participants_request(
        &self,
        session: &ClientSession,
    ) -> Result<(), RoutingError> {
        let room_id = session.get_current_room().await
            .ok_or_else(|| RoutingError::InvalidPacket("Client not in a room".to_string()))?;
        
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        let sessions = session_manager.get_sessions_by_room(&room_id).await;
        
        let participants: Vec<serde_json::Value> = sessions.iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.client_id,
                    "name": s.get_display_name().unwrap_or_else(|| s.client_id.clone()),
                    "online": true
                })
            })
            .collect();
        
        let response = serde_json::json!({
            "type": "participants_response",
            "roomId": room_id,
            "participants": participants
        });
        
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: response,
        };
        
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(session_key) = session_key_manager.get_key(&session.client_id).await {
                self.forward_envelope_to_session(&envelope, &session_key, session).await?;
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
    }

    async fn handle_webrtc_signal(
        &self,
        payload: serde_json::Value,
        _session: &ClientSession,
    ) -> Result<(), RoutingError> {
        let peer_id = payload.get("peerId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RoutingError::InvalidPacket("Missing peerId in WebRTC signal".to_string()))?;
        
        let session_manager = crate::server::globals::get_session_manager()
            .ok_or_else(|| RoutingError::Processing("Session manager not available".to_string()))?;
        
        let target_session = session_manager.get_session_by_client_id(peer_id).await
            .ok_or_else(|| RoutingError::Processing(format!("Peer {} not found", peer_id)))?;
        
        let envelope = DataEnvelope {
            payload_type: PayloadDataType::Json,
            payload: payload.clone(),
        };
        
        if let Some(session_key_manager) = crate::server::globals::get_session_key_manager() {
            if let Some(target_key) = session_key_manager.get_key(&target_session.client_id).await {
                self.forward_envelope_to_session(&envelope, &target_key, &target_session).await?;
            } else {
                return Err(RoutingError::Processing(format!("No session key found for {}", target_session.client_id)));
            }
        } else {
            return Err(RoutingError::Processing("Session key manager not available".to_string()));
        }
        
        Ok(())
    }

    fn should_add_padding(&self) -> bool {
        thread_rng().gen::<f32>() < PAD_PROBABILITY
    }

    fn add_padding(&self, packet: &[u8]) -> Vec<u8> {
        let mut rng = thread_rng();
        let padding_len = rng.gen_range(MIN_PADDING_SIZE..=MAX_PADDING_SIZE);

        let mut result = Vec::with_capacity(packet.len() + padding_len + 2);
        result.extend_from_slice(&(padding_len as u16).to_be_bytes());
        result.extend_from_slice(packet);

        for _ in 0..padding_len {
            result.push(rng.gen::<u8>());
        }

        result
    }

    fn remove_padding(&self, packet: &[u8]) -> Result<Vec<u8>, RoutingError> {
        if packet.len() < 2 {
            return Err(RoutingError::InvalidPacket("Packet too short for padding".to_string()));
        }

        let mut padding_len_bytes = [0u8; 2];
        padding_len_bytes.copy_from_slice(&packet[0..2]);
        let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;

        if packet.len() < 2 + padding_len {
            return Err(RoutingError::InvalidPacket(format!(
                "Invalid padding length: {} exceeds packet size {}",
                padding_len, packet.len() - 2
            )));
        }

        let data_len = packet.len() - 2 - padding_len;
        let data = &packet[2..(2 + data_len)];

        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_e2e_session_workflow() {
        let router = PacketRouter::new(2048, false);
        
        // Step 1: Create session when Alice requests chat
        let session = router.e2e_manager.create_session(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            Some("AliceX25519Key".to_string()),
        ).await;
        
        assert!(!session.is_e2e_ready());
        
        // Step 2: Update with Bob's key when he accepts
        router.e2e_manager.set_recipient_pubkey(
            "chat123",
            "BobX25519Key".to_string()
        ).await;
        
        // Step 3: Verify E2E is now ready
        let updated_session = router.e2e_manager.get_session("chat123").await.unwrap();
        assert!(updated_session.is_e2e_ready());
    }
    
    #[tokio::test]
    async fn test_encrypted_message_detection() {
        let router = PacketRouter::new(2048, false);
        
        // Create E2E session
        router.e2e_manager.create_session(
            "chat123".to_string(),
            "alice".to_string(),
            "bob".to_string(),
            Some("AliceKey".to_string()),
        ).await;
        
        router.e2e_manager.set_recipient_pubkey("chat123", "BobKey".to_string()).await;
        
        // Test detection
        assert!(router.e2e_manager.is_encrypted_message("chat123", "e2e:SGVsbG8=").await);
        assert!(!router.e2e_manager.is_encrypted_message("chat123", "Plain text").await);
    }
    
    #[test]
    fn test_encrypted_message_format() {
        let formatted = EncryptedMessageFormat::format("SGVsbG8gV29ybGQh");
        assert_eq!(formatted, "e2e:SGVsbG8gV29ybGQh");
        
        let extracted = EncryptedMessageFormat::extract(&formatted);
        assert_eq!(extracted, Some("SGVsbG8gV29ybGQh"));
    }
}
