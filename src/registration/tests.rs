// src/registration/tests.rs
// AeroNyx Privacy Network - Registration Module Tests
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT

use super::*;
use crate::websocket_protocol::{ClientMessage, ServerMessage, HeartbeatMetrics as WsHeartbeatMetrics};

#[test]
fn test_client_message_serialization() {
    // Test auth message
    let auth = ClientMessage::Auth {
        code: "AERO-12345".to_string(),
    };
    
    let json = serde_json::to_string(&auth).unwrap();
    assert!(json.contains("\"type\":\"auth\""));
    assert!(json.contains("AERO-12345"));
    
    // Test heartbeat message
    let heartbeat = ClientMessage::Heartbeat {
        metrics: WsHeartbeatMetrics {
            cpu: 25.5,
            memory: 45.2,
            disk: 60.1,
            network: 10.3,
        },
        timestamp: Some(1234567890),
    };
    
    let json = serde_json::to_string(&heartbeat).unwrap();
    assert!(json.contains("\"type\":\"heartbeat\""));
    assert!(json.contains("\"cpu\":25.5"));
}

#[test]
fn test_server_message_deserialization() {
    // Test connection established
    let json = r#"{"type":"connection_established"}"#;
    let msg: ServerMessage = serde_json::from_str(json).unwrap();
    assert!(matches!(msg, ServerMessage::ConnectionEstablished));
    
    // Test auth success
    let json = r#"{"type":"auth_success","heartbeat_interval":60}"#;
    let msg: ServerMessage = serde_json::from_str(json).unwrap();
    match msg {
        ServerMessage::AuthSuccess { heartbeat_interval, .. } => {
            assert_eq!(heartbeat_interval, Some(60));
        }
        _ => panic!("Wrong message type"),
    }
    
    // Test challenge request
    let json = r#"{"type":"challenge_request","challenge_id":"test-123"}"#;
    let msg: ServerMessage = serde_json::from_str(json).unwrap();
    match msg {
        ServerMessage::ChallengeRequest { challenge_id, .. } => {
            assert_eq!(challenge_id, "test-123");
        }
        _ => panic!("Wrong message type"),
    }
}

#[tokio::test]
async fn test_registration_manager_creation() {
    let manager = RegistrationManager::new("https://api.aeronyx.com");
    assert!(manager.reference_code.is_none());
    assert!(manager.wallet_address.is_none());
    assert!(!manager.is_connected().await);
    assert_eq!(manager.api_url, "https://api.aeronyx.com");
    assert!(!manager.has_zkp_enabled());
}
