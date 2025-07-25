// src/registration/types.rs
// AeroNyx Privacy Network - Registration Type Definitions
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Type definitions for the registration module including API responses,
// WebSocket messages, and configuration structures.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use crate::remote_management::CommandResponse;
use crate::remote_command_handler::{RemoteCommandData, RemoteCommandResponse};

/// Generic API response wrapper
#[derive(Debug, Deserialize, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
    pub errors: Option<serde_json::Value>,
}

/// Registration confirmation response structure
#[derive(Debug, Deserialize)]
pub struct RegistrationConfirmResponse {
    pub success: bool,
    pub result_code: String,
    pub node: NodeInfo,
    pub security: SecurityInfo,
    pub next_steps: Vec<String>,
}

/// Node information returned from registration
#[derive(Debug, Deserialize)]
pub struct NodeInfo {
    pub id: u64,
    pub reference_code: String,
    pub name: String,
    pub status: String,
    pub node_type: String,
    pub registration_confirmed_at: String,
    pub wallet_address: String,
}

/// Security information for the registered node
#[derive(Debug, Deserialize)]
pub struct SecurityInfo {
    pub hardware_fingerprint_generated: bool,
    pub fingerprint_preview: String,
    pub security_level: String,
    pub registration_ip: String,
}

/// WebSocket message types for node communication
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    /// Authentication message sent after connection
    #[serde(rename = "auth")]
    Auth {
        reference_code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        registration_code: Option<String>,
    },

    #[serde(rename = "remote_command")]
    RemoteCommand {
        request_id: String,
        from_session: String,
        command: RemoteCommandData,  
    },
    
    /// Remote command response to server
    #[serde(rename = "remote_command_response")]
    RemoteCommandResponse {
        #[serde(flatten)]  
        response: RemoteCommandResponse,
    },
    
    /// Periodic heartbeat with system metrics
    #[serde(rename = "heartbeat")]
    Heartbeat {
        status: String,
        uptime_seconds: u64,
        metrics: LegacyHeartbeatMetrics,
    },
    
    /// Status update notification
    #[serde(rename = "status_update")]
    StatusUpdate {
        status: String,
    },
    
    /// Ping message for connection health
    #[serde(rename = "ping")]
    Ping {
        timestamp: u64,
    },
    
    /// Response to remote command execution
    #[serde(rename = "command_response")]
    CommandResponse {
        request_id: String,
        response: CommandResponse,
    },
    
    /// Hardware change notification
    #[serde(rename = "hardware_change")]
    HardwareChange {
        old_fingerprint: String,
        new_fingerprint: String,
        changed_components: Vec<String>,
        reason: String,
    },
    
    /// Request for hardware attestation proof
    #[serde(rename = "hardware_attestation_request")]
    HardwareAttestationRequest {
        challenge: Vec<u8>,
        nonce: String,
    },
    
    /// Hardware attestation proof response
    #[serde(rename = "hardware_attestation_proof")]
    HardwareAttestationProof {
        commitment: String,
        proof: Vec<u8>,
        nonce: String,
    },
}

/// System metrics included in heartbeat messages
#[derive(Debug, Serialize, Deserialize)]
pub struct LegacyHeartbeatMetrics {
    pub cpu: f64,
    pub mem: f64,
    pub disk: f64,
    pub net: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<u32>,
}

/// Stored registration data for persistence
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredRegistration {
    pub reference_code: String,
    pub wallet_address: String,
    pub hardware_fingerprint: String,
    pub registered_at: String,
    pub node_type: String,
    #[serde(default)]
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_components: Option<HardwareComponents>,
    /// Zero-knowledge proof commitment (added for ZKP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_commitment: Option<String>,
}

/// Individual hardware components for granular tracking
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HardwareComponents {
    pub mac_addresses: HashSet<String>,
    pub system_uuid: Option<String>,
    pub machine_id: Option<String>,
    pub cpu_model: String,
    pub bios_info: Option<String>,
}

/// Configuration for hardware change tolerance
#[derive(Debug, Clone)]
pub struct HardwareToleranceConfig {
    /// Allow minor hardware changes (e.g., network interface additions)
    pub allow_minor_changes: bool,
    /// Require at least one original MAC address to remain
    pub require_mac_match: bool,
    /// Allow CPU model changes (for cloud provider upgrades)
    pub allow_cpu_change: bool,
    /// Maximum percentage of components that can change
    pub max_change_percentage: f32,
}

impl Default for HardwareToleranceConfig {
    fn default() -> Self {
        Self {
            allow_minor_changes: true,
            require_mac_match: true,
            allow_cpu_change: false,
            max_change_percentage: 0.3, // Allow up to 30% change
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_websocket_message_serialization() {
        // Test auth message
        let auth = WebSocketMessage::Auth {
            reference_code: "AERO-12345".to_string(),
            registration_code: Some("AERO-REG123".to_string()),
        };
        
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"auth\""));
        assert!(json.contains("AERO-12345"));
        assert!(json.contains("AERO-REG123"));
        
        // Test heartbeat message
        let heartbeat = WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds: 3600,
            metrics: LegacyHeartbeatMetrics {
                cpu: 25.5,
                mem: 45.2,
                disk: 60.1,
                net: 10.3,
                temperature: Some(65.0),
                processes: Some(150),
            },
        };
        
        let json = serde_json::to_string(&heartbeat).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
        assert!(json.contains("\"cpu\":25.5"));
        assert!(json.contains("\"temperature\":65.0"));
        
        // Test ZKP attestation message
        let attestation = WebSocketMessage::HardwareAttestationProof {
            commitment: "abc123".to_string(),
            proof: vec![1, 2, 3, 4],
            nonce: "nonce123".to_string(),
        };
        
        let json = serde_json::to_string(&attestation).unwrap();
        assert!(json.contains("\"type\":\"hardware_attestation_proof\""));
        assert!(json.contains("\"commitment\":\"abc123\""));
    }
    
    #[test]
    fn test_tolerance_config() {
        let config = HardwareToleranceConfig::default();
        assert!(config.allow_minor_changes);
        assert!(config.require_mac_match);
        assert!(!config.allow_cpu_change);
        assert_eq!(config.max_change_percentage, 0.3);
    }
}
