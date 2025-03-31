// src/protocol/serialization.rs
//! Protocol message serialization and deserialization.
//!
//! This module provides functions for serializing and deserializing
//! protocol messages with proper error handling and validation.

use serde_json;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{trace, debug, warn};

use crate::protocol::types::{MessageError, PacketType};
use crate::protocol::validation::validate_message;

/// Maximum allowed message size (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Serialize a packet to a JSON string
pub fn serialize_packet(packet: &PacketType) -> Result<String, MessageError> {
    // Validate the packet before serializing
    validate_message(packet)?;
    
    let json = serde_json::to_string(packet)
        .map_err(|e| MessageError::Serialization(e))?;
    
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(MessageError::MessageTooLarge);
    }
    
    trace!("Serialized {} packet, size: {} bytes", get_packet_type_name(packet), json.len());
    
    Ok(json)
}

/// Serialize a packet to a WebSocket message
pub fn packet_to_ws_message(packet: &PacketType) -> Result<WsMessage, MessageError> {
    let json = serialize_packet(packet)?;
    Ok(WsMessage::Text(json))
}

/// Deserialize a JSON string to a packet
pub fn deserialize_packet(json: &str) -> Result<PacketType, MessageError> {
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(MessageError::MessageTooLarge);
    }
    
    let packet: PacketType = serde_json::from_str(json)
        .map_err(|e| MessageError::Serialization(e))?;
    
    // Validate the deserialized packet
    validate_message(&packet)?;
    
    trace!("Deserialized {} packet, size: {} bytes", get_packet_type_name(&packet), json.len());
    
    Ok(packet)
}

/// Parse a WebSocket message to a packet
pub fn ws_message_to_packet(message: &WsMessage) -> Result<PacketType, MessageError> {
    match message {
        WsMessage::Text(text) => {
            deserialize_packet(text)
        }
        WsMessage::Binary(_) => {
            // We don't handle binary messages, but could implement a binary protocol here
            Err(MessageError::InvalidFormat("Binary messages not supported".into()))
        }
        _ => {
            Err(MessageError::InvalidFormat("Unsupported message type".into()))
        }
    }
}

/// Create a standard error packet
pub fn create_error_packet(code: u16, message: &str) -> PacketType {
    PacketType::Error {
        code,
        message: message.to_string(),
    }
}

/// Create a disconnect packet
pub fn create_disconnect_packet(reason: u16, message: &str) -> PacketType {
    PacketType::Disconnect {
        reason,
        message: message.to_string(),
    }
}

/// Get the name of a packet type for logging
pub fn get_packet_type_name(packet: &PacketType) -> &'static str {
    match packet {
        PacketType::Auth { .. } => "Auth",
        PacketType::Challenge { .. } => "Challenge",
        PacketType::ChallengeResponse { .. } => "ChallengeResponse",
        PacketType::IpAssign { .. } => "IpAssign",
        PacketType::Data { .. } => "Data",
        PacketType::Ping { .. } => "Ping",
        PacketType::Pong { .. } => "Pong",
        PacketType::KeyRotation { .. } => "KeyRotation",
        PacketType::IpRenewal { .. } => "IpRenewal",
        PacketType::IpRenewalResponse { .. } => "IpRenewalResponse",
        PacketType::Disconnect { .. } => "Disconnect",
        PacketType::Error { .. } => "Error",
    }
}

/// Log packet information (non-sensitive parts only)
pub fn log_packet_info(packet: &PacketType, is_incoming: bool) {
    let direction = if is_incoming { "Received" } else { "Sending" };
    
    match packet {
        PacketType::Auth { public_key, version, features, .. } => {
            debug!(
                "{} Auth packet from {}, version: {}, features: {:?}",
                direction, public_key, version, features
            );
        }
        PacketType::Challenge { id, expires_at, .. } => {
            debug!(
                "{} Challenge packet, id: {}, expires: {}",
                direction, id, expires_at
            );
        }
        PacketType::ChallengeResponse { public_key, challenge_id, .. } => {
            debug!(
                "{} ChallengeResponse packet from {}, challenge_id: {}",
                direction, public_key, challenge_id
            );
        }
        PacketType::IpAssign { ip_address, lease_duration, session_id, .. } => {
            debug!(
                "{} IpAssign packet, ip: {}, lease: {}s, session: {}",
                direction, ip_address, lease_duration, session_id
            );
        }
        PacketType::Data { counter, .. } => {
            trace!(
                "{} Data packet, counter: {}",
                direction, counter
            );
        }
        PacketType::Ping { sequence, .. } => {
            trace!(
                "{} Ping packet, sequence: {}",
                direction, sequence
            );
        }
        PacketType::Pong { sequence, .. } => {
            trace!(
                "{} Pong packet, sequence: {}",
                direction, sequence
            );
        }
        PacketType::KeyRotation { key_id, .. } => {
            debug!(
                "{} KeyRotation packet, key_id: {}",
                direction, key_id
            );
        }
        PacketType::IpRenewal { session_id, ip_address } => {
            debug!(
                "{} IpRenewal packet, session: {}, ip: {}",
                direction, session_id, ip_address
            );
        }
        PacketType::IpRenewalResponse { session_id, expires_at, success } => {
            debug!(
                "{} IpRenewalResponse packet, session: {}, success: {}, expires: {}",
                direction, session_id, success, expires_at
            );
        }
        PacketType::Disconnect { reason, message } => {
            debug!(
                "{} Disconnect packet, reason: {}, message: {}",
                direction, reason, message
            );
        }
        PacketType::Error { code, message } => {
            warn!(
                "{} Error packet, code: {}, message: {}",
                direction, code, message
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_serialize_deserialize() {
        // Create a packet
        let original = PacketType::Ping {
            timestamp: 123456789,
            sequence: 42,
        };
        
        // Serialize
        let json = serialize_packet(&original).unwrap();
        
        // Deserialize
        let deserialized = deserialize_packet(&json).unwrap();
        
        // Compare using pattern matching
        match deserialized {
            PacketType::Ping { timestamp, sequence } => {
                assert_eq!(timestamp, 123456789);
                assert_eq!(sequence, 42);
            }
            _ => panic!("Deserialized to wrong type"),
        }
    }
    
    #[test]
    fn test_packet_to_ws_message() {
        let packet = PacketType::Ping {
            timestamp: 123456789,
            sequence: 42,
        };
        
        let message = packet_to_ws_message(&packet).unwrap();
        
        match message {
            WsMessage::Text(text) => {
                // Should be valid JSON
                assert!(serde_json::from_str::<serde_json::Value>(&text).is_ok());
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_ws_message_to_packet() {
        // Create a text message
        let json = r#"{"type":"Ping","timestamp":123456789,"sequence":42}"#;
        let message = WsMessage::Text(json.to_string());
        
        // Parse it
        let packet = ws_message_to_packet(&message).unwrap();
        
        // Verify
        match packet {
            PacketType::Ping { timestamp, sequence } => {
                assert_eq!(timestamp, 123456789);
                assert_eq!(sequence, 42);
            }
            _ => panic!("Parsed to wrong type"),
        }
        
        // Binary messages should fail
        let binary = WsMessage::Binary(vec![1, 2, 3]);
        assert!(ws_message_to_packet(&binary).is_err());
    }
    
    #[test]
    fn test_create_error_packet() {
        let error = create_error_packet(1001, "Test error");
        
        match error {
            PacketType::Error { code, message } => {
                assert_eq!(code, 1001);
                assert_eq!(message, "Test error");
            }
            _ => panic!("Wrong packet type"),
        }
    }
    
    #[test]
    fn test_create_disconnect_packet() {
        let disconnect = create_disconnect_packet(2, "Goodbye");
        
        match disconnect {
            PacketType::Disconnect { reason, message } => {
                assert_eq!(reason, 2);
                assert_eq!(message, "Goodbye");
            }
            _ => panic!("Wrong packet type"),
        }
    }
    
    #[test]
    fn test_get_packet_type_name() {
        let auth = PacketType::Auth {
            public_key: "test".to_string(),
            version: "1.0".to_string(),
            features: vec![],
            nonce: "nonce".to_string(),
        };
        
        assert_eq!(get_packet_type_name(&auth), "Auth");
        
        let ping = PacketType::Ping {
            timestamp: 123,
            sequence: 1,
        };
        
        assert_eq!(get_packet_type_name(&ping), "Ping");
    }
}
