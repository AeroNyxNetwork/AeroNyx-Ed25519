// src/registration/websocket.rs
// ============================================
// AeroNyx Privacy Network - WebSocket Communication Module
// Version: 1.0.3 - Complete implementation with proper heartbeat handling
// ============================================
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Creation Reason: WebSocket connection management for node communication
// Modification Reason: Fixed heartbeat implementation and field naming consistency
// Main Functionality:
// - WebSocket connection establishment and maintenance
// - Message handling and routing
// - Heartbeat and metrics reporting with correct field names
// Dependencies:
// - connection.rs: Connection lifecycle management
// - handlers.rs: Message processing
// - terminal.rs: Terminal-specific handlers
// - ../registration.rs: Provides get_terminal_manager
// - terminal.rs (local): Provides start_terminal_output_reader
//
// Main Logical Flow:
// 1. Establish WebSocket connection with retry logic
// 2. Handle authentication and heartbeat
// 3. Process incoming messages (commands, terminal, etc.)
// 4. Terminal output reader spawning handled by terminal.rs
//
// ⚠️ Important Note for Next Developer:
// - DO NOT add duplicate definitions of get_terminal_manager or start_terminal_output_reader
// - get_terminal_manager is defined in src/registration.rs
// - start_terminal_output_reader is defined in src/registration/websocket/terminal.rs
// - WebSocket reconnection logic is critical for reliability
// - Heartbeat messages maintain connection alive status
// - CRITICAL: Use 'memory' and 'network' field names in heartbeat metrics for Django compatibility
//
// Last Modified: v1.0.3 - Fixed heartbeat field naming for Django compatibility
// ============================================

use super::{RegistrationManager, WebSocketMessage, LegacyHeartbeatMetrics};
use crate::hardware::HardwareInfo;
use crate::zkp_halo2::SetupParams;
use crate::websocket_protocol::{
    HeartbeatMetrics as WsHeartbeatMetrics, ClientMessage,
};
use crate::server::metrics::ServerMetricsCollector;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn, error, debug};
use std::error::Error;

// Sub-modules
mod connection;
mod handlers;
mod terminal;

// Re-export for backward compatibility
pub use connection::*;
pub use handlers::*;
pub use terminal::*;

impl RegistrationManager {
    /// Start WebSocket connection for real-time communication (original version for compatibility)
    pub async fn start_websocket_connection(
        &mut self,
        reference_code: String,
        registration_code: Option<String>,
    ) -> Result<(), String> {
        // Collect hardware info if not already cached
        let hardware_info = if let Some(ref hw_info) = self.hardware_info {
            hw_info.clone()
        } else {
            HardwareInfo::collect().await
                .map_err(|e| format!("Failed to collect hardware info: {}", e))?
        };
        
        // Initialize ZKP if not already done
        let setup_params = if let Some(ref params) = self.zkp_params {
            params.as_ref().clone()
        } else {
            let params = self.initialize_zkp().await?;
            self.set_zkp_params(params.clone());
            params
        };
        
        self.start_websocket_connection_with_params(
            reference_code,
            registration_code,
            &hardware_info,
            &setup_params,
        ).await
    }

    /// Start WebSocket connection with explicit hardware info and ZKP params
    pub async fn start_websocket_connection_with_params(
        &mut self,
        reference_code: String,
        registration_code: Option<String>,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        self.reference_code = Some(reference_code.clone());
        if let Some(code) = registration_code {
            self.registration_code = Some(code);
        }

        // Build WebSocket URL
        let ws_url = self.api_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let ws_url = format!("{}/ws/aeronyx/node/", ws_url.trim_end_matches('/'));
        
        info!("Connecting to WebSocket: {}", ws_url);

        // For registration setup, only do a single connection attempt
        let is_setup_mode = self.registration_code.is_some();
        let max_retries = if is_setup_mode { 1 } else { 5 };
        
        // Connect with retry logic
        let mut retry_count = 0;
        let mut backoff = Duration::from_secs(1);
        
        // Clone for the async task
        let hw_info = hardware_info.clone();
        let params = setup_params.clone();
        
        loop {
            match self.connect_and_run_websocket_v2(&ws_url, &hw_info, &params).await {
                Ok(_) => {
                    info!("WebSocket connection closed normally");
                    
                    if is_setup_mode {
                        // During setup, successful connection is enough
                        return Ok(());
                    }
                    
                    // For normal operation, wait before reconnecting
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    retry_count = 0;
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    retry_count += 1;
                    
                    if retry_count >= max_retries {
                        if is_setup_mode {
                            // During setup, connection failure is not critical
                            warn!("WebSocket test failed, but registration may still be valid");
                            return Ok(());
                        } else {
                            return Err(format!("Failed to establish WebSocket connection after {} attempts", max_retries));
                        }
                    }
                    
                    warn!("Retrying WebSocket connection in {:?} (attempt {}/{})", 
                          backoff, retry_count, max_retries);
                    tokio::time::sleep(backoff).await;
                    
                    // Exponential backoff with jitter
                    backoff = backoff.mul_f32(1.5).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// Send periodic heartbeat messages with Django-compatible field names
    pub async fn send_heartbeat(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        use crate::registration::types::LegacyHeartbeatMetrics;
        use crate::utils;
        
        // Get system metrics
        let cpu_usage = self.get_cpu_usage().await;
        let mem_usage = self.get_memory_usage().await;
        let disk_usage = self.get_disk_usage().await;
        let net_usage = self.get_network_usage().await;
        let temperature = self.get_cpu_temperature().await;
        let processes = self.get_process_count().await;
        
        // Get system uptime
        let uptime_seconds = match tokio::task::spawn_blocking(|| {
            utils::system::get_system_uptime().unwrap_or(0)
        }).await {
            Ok(uptime) => uptime,
            Err(_) => 0,
        };
        
        // Create metrics with CORRECT field names for Django
        // IMPORTANT: Django expects 'memory' and 'network', not 'mem' and 'net'
        let metrics = LegacyHeartbeatMetrics {
            cpu: cpu_usage,
            memory: mem_usage,      // ✅ CRITICAL: Use 'memory' for Django compatibility
            disk: disk_usage,
            network: net_usage,     // ✅ CRITICAL: Use 'network' for Django compatibility
            temperature,
            processes,
        };
        
        // Log the metrics for debugging
        info!("Sending heartbeat - CPU: {:.1}%, Memory: {:.1}%, Disk: {:.1}%, Network: {:.1} KB/s",
              metrics.cpu, metrics.memory, metrics.disk, metrics.network);
        
        // Debug: Verify JSON format has correct field names
        #[cfg(debug_assertions)]
        {
            let json_metrics = serde_json::to_string(&metrics)?;
            debug!("Heartbeat metrics JSON: {}", json_metrics);
            
            // Verify correct field names
            if !json_metrics.contains("\"memory\":") || !json_metrics.contains("\"network\":") {
                error!("CRITICAL: Heartbeat metrics have wrong field names!");
                error!("JSON: {}", json_metrics);
                return Err("Invalid heartbeat field names".into());
            }
        }
        
        // Create and send heartbeat message
        let message = WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds,
            metrics,
        };
        
        // Send the message
        self.send_message(message).await?;
        
        Ok(())
    }

    /// Create heartbeat message with system metrics (legacy format)
    /// This method ensures backward compatibility while using correct field names
    pub(crate) async fn create_heartbeat_message(&self, _metrics_collector: &ServerMetricsCollector) -> WebSocketMessage {
        let uptime_seconds = self.start_time.elapsed().as_secs();
        
        let (cpu_usage, mem_usage, disk_usage, net_usage) = tokio::join!(
            self.get_cpu_usage(),
            self.get_memory_usage(),
            self.get_disk_usage(),
            self.get_network_usage()
        );
        
        let temperature = self.get_cpu_temperature().await;
        let processes = self.get_process_count().await;
        
        WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds,
            metrics: LegacyHeartbeatMetrics {
                cpu: cpu_usage,
                memory: mem_usage,      // Use 'memory' not 'mem'
                disk: disk_usage,
                network: net_usage,     // Use 'network' not 'net'
                temperature,
                processes,
            },
        }
    }

    /// Create heartbeat with metrics (new format) for WebSocket protocol
    pub(crate) async fn create_client_heartbeat_message(&self, _metrics_collector: &ServerMetricsCollector) -> ClientMessage {
        let (cpu_usage, mem_usage, disk_usage, net_usage) = tokio::join!(
            self.get_cpu_usage(),
            self.get_memory_usage(),
            self.get_disk_usage(),
            self.get_network_usage()
        );
        
        // Use the websocket_protocol HeartbeatMetrics directly
        ClientMessage::Heartbeat {
            metrics: WsHeartbeatMetrics {
                cpu: cpu_usage,
                memory: mem_usage,
                disk: disk_usage,
                network: net_usage,
            },
            timestamp: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        }
    }
    
    // ============================================
    // IMPORTANT: DO NOT ADD THESE METHODS HERE
    // ============================================
    // get_terminal_manager() is defined in src/registration.rs
    // start_terminal_output_reader() is defined in src/registration/websocket/terminal.rs
    //
    // Adding duplicate definitions will cause compilation errors.
    // If you need to use these methods, they are already available
    // through the RegistrationManager impl in their respective files.
    //
    // Example usage from this file:
    // let terminal_mgr = self.get_terminal_manager();
    // self.start_terminal_output_reader(session_id, tx).await;
    // ============================================
    
    /// Helper method to validate heartbeat metrics before sending
    #[cfg(debug_assertions)]
    fn validate_heartbeat_metrics(&self, metrics: &LegacyHeartbeatMetrics) -> bool {
        // Ensure all values are within reasonable ranges
        if metrics.cpu < 0.0 || metrics.cpu > 100.0 {
            error!("Invalid CPU usage: {}", metrics.cpu);
            return false;
        }
        if metrics.memory < 0.0 || metrics.memory > 100.0 {
            error!("Invalid memory usage: {}", metrics.memory);
            return false;
        }
        if metrics.disk < 0.0 || metrics.disk > 100.0 {
            error!("Invalid disk usage: {}", metrics.disk);
            return false;
        }
        if metrics.network < 0.0 {
            error!("Invalid network usage: {}", metrics.network);
            return false;
        }
        true
    }
}

// ============================================
// Module Tests
// ============================================
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_heartbeat_field_names() {
        // Test that heartbeat metrics serialize with correct field names
        let metrics = LegacyHeartbeatMetrics {
            cpu: 50.0,
            memory: 60.0,  // Must be 'memory' not 'mem'
            disk: 70.0,
            network: 80.0, // Must be 'network' not 'net'
            temperature: Some(45.0),
            processes: Some(150),
        };
        
        let json = serde_json::to_string(&metrics).unwrap();
        
        // Verify correct field names for Django
        assert!(json.contains("\"memory\":60.0"), "Should use 'memory' field name");
        assert!(json.contains("\"network\":80.0"), "Should use 'network' field name");
        assert!(!json.contains("\"mem\":"), "Should NOT use 'mem' field name");
        assert!(!json.contains("\"net\":"), "Should NOT use 'net' field name");
    }
    
    #[tokio::test]
    async fn test_websocket_url_construction() {
        let mut manager = RegistrationManager::new("https://api.example.com".to_string());
        
        // Test HTTPS to WSS conversion
        manager.api_url = "https://api.example.com".to_string();
        let ws_url = manager.api_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let ws_url = format!("{}/ws/aeronyx/node/", ws_url.trim_end_matches('/'));
        assert_eq!(ws_url, "wss://api.example.com/ws/aeronyx/node/");
        
        // Test HTTP to WS conversion
        manager.api_url = "http://localhost:8000".to_string();
        let ws_url = manager.api_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let ws_url = format!("{}/ws/aeronyx/node/", ws_url.trim_end_matches('/'));
        assert_eq!(ws_url, "ws://localhost:8000/ws/aeronyx/node/");
    }
}
