// src/registration/types.rs
// AeroNyx Privacy Network - Registration Type Definitions
// Version: 1.1.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Type definitions for the registration module including API responses,
// WebSocket messages, and configuration structures.
//
// ============================================
// File Creation/Modification Notes
// ============================================
// Creation Reason: Define types for registration and WebSocket communication
// Modification Reason: Fixed heartbeat metrics field names to match Django backend
// Main Functionality: Type definitions for API/WebSocket communication
// Dependencies: Used by registration/websocket.rs and registration module
//
// Main Logical Flow:
// 1. Define API response structures
// 2. Define WebSocket message types
// 3. Define heartbeat metrics with correct field names
// 4. Support hardware tracking and ZKP attestation
//
// ⚠️ Important Note for Next Developer:
// - Field names in LegacyHeartbeatMetrics MUST match Django backend expectations
// - Do not change "memory" and "network" field names without updating Django
// - The WebSocket message format is critical for server communication
//
// Last Modified: v1.1.0 - Fixed field names for Django compatibility
// ============================================

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

    /// Remote command from server
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
/// 
/// IMPORTANT: Field names MUST match Django backend expectations:
/// - "cpu" for CPU usage percentage
/// - "memory" for memory usage percentage (not "mem")
/// - "disk" for disk usage percentage  
/// - "network" for network usage percentage (not "net")
/// - "temperature" for CPU temperature (optional)
/// - "processes" for process count (optional)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LegacyHeartbeatMetrics {
    /// CPU usage percentage (0-100)
    pub cpu: f64,
    
    /// Memory usage percentage (0-100)
    /// NOTE: This field is serialized as "memory" for Django compatibility
    pub memory: f64,
    
    /// Disk usage percentage (0-100)
    pub disk: f64,
    
    /// Network usage percentage (0-100)
    /// NOTE: This field is serialized as "network" for Django compatibility
    pub network: f64,
    
    /// CPU temperature in Celsius (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    
    /// Number of running processes (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<u32>,
}

impl LegacyHeartbeatMetrics {
    /// Create new metrics with all required fields
    pub fn new(cpu: f64, memory: f64, disk: f64, network: f64) -> Self {
        Self {
            cpu: cpu.min(100.0).max(0.0),
            memory: memory.min(100.0).max(0.0),
            disk: disk.min(100.0).max(0.0),
            network: network.min(100.0).max(0.0),
            temperature: None,
            processes: None,
        }
    }
    
    /// Set optional temperature field
    pub fn with_temperature(mut self, temp: f64) -> Self {
        self.temperature = Some(temp);
        self
    }
    
    /// Set optional process count field
    pub fn with_processes(mut self, count: u32) -> Self {
        self.processes = Some(count);
        self
    }
    
    /// Format metrics for display
    pub fn format_display(&self) -> String {
        format!(
            "CPU: {:.1}%, Memory: {:.1}%, Disk: {:.1}%, Network: {:.1}%{}{}",
            self.cpu,
            self.memory,
            self.disk,
            self.network,
            self.temperature
                .map(|t| format!(", Temp: {:.1}°C", t))
                .unwrap_or_default(),
            self.processes
                .map(|p| format!(", Processes: {}", p))
                .unwrap_or_default()
        )
    }
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
        
        // Test heartbeat message with correct field names
        let heartbeat = WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds: 3600,
            metrics: LegacyHeartbeatMetrics {
                cpu: 25.5,
                memory: 45.2,  // Changed from 'mem'
                disk: 60.1,
                network: 10.3,  // Changed from 'net'
                temperature: Some(65.0),
                processes: Some(150),
            },
        };
        
        let json = serde_json::to_string(&heartbeat).unwrap();
        println!("Heartbeat JSON: {}", json); // Debug output
        
        // Verify correct field names in JSON
        assert!(json.contains("\"type\":\"heartbeat\""));
        assert!(json.contains("\"cpu\":25.5"));
        assert!(json.contains("\"memory\":45.2"));  // Must be "memory" not "mem"
        assert!(json.contains("\"network\":10.3"));  // Must be "network" not "net"
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
    fn test_heartbeat_metrics_builder() {
        let metrics = LegacyHeartbeatMetrics::new(50.0, 75.0, 30.0, 15.5)
            .with_temperature(65.5)
            .with_processes(234);
        
        assert_eq!(metrics.cpu, 50.0);
        assert_eq!(metrics.memory, 75.0);
        assert_eq!(metrics.disk, 30.0);
        assert_eq!(metrics.network, 15.5);
        assert_eq!(metrics.temperature, Some(65.5));
        assert_eq!(metrics.processes, Some(234));
        
        // Test boundary conditions
        let bounded = LegacyHeartbeatMetrics::new(150.0, -10.0, 50.0, 200.0);
        assert_eq!(bounded.cpu, 100.0);  // Capped at 100
        assert_eq!(bounded.memory, 0.0);  // Floored at 0
        assert_eq!(bounded.disk, 50.0);
        assert_eq!(bounded.network, 100.0);  // Capped at 100
    }
    
    #[test]
    fn test_metrics_display_format() {
        let metrics = LegacyHeartbeatMetrics::new(25.5, 45.2, 60.1, 10.3)
            .with_temperature(65.0)
            .with_processes(150);
        
        let display = metrics.format_display();
        assert!(display.contains("CPU: 25.5%"));
        assert!(display.contains("Memory: 45.2%"));
        assert!(display.contains("Disk: 60.1%"));
        assert!(display.contains("Network: 10.3%"));
        assert!(display.contains("Temp: 65.0°C"));
        assert!(display.contains("Processes: 150"));
    }
    
    #[test]
    fn test_tolerance_config() {
        let config = HardwareToleranceConfig::default();
        assert!(config.allow_minor_changes);
        assert!(config.require_mac_match);
        assert!(!config.allow_cpu_change);
        assert_eq!(config.max_change_percentage, 0.3);
    }
    
    #[test]
    fn test_json_field_names() {
        // Critical test: Ensure JSON uses correct field names for Django
        let metrics = LegacyHeartbeatMetrics::new(10.0, 20.0, 30.0, 40.0);
        let json = serde_json::to_string(&metrics).unwrap();
        
        // These exact field names are required by Django backend
        assert!(json.contains("\"memory\":"));  // NOT "mem"
        assert!(json.contains("\"network\":"));  // NOT "net"
        assert!(!json.contains("\"mem\":"));
        assert!(!json.contains("\"net\":"));
    }
}
