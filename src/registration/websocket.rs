// src/registration/websocket.rs
// ============================================
// AeroNyx Privacy Network - WebSocket Communication Module
// Version: 1.0.2 - Fixed duplicate definitions
// ============================================
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Creation Reason: WebSocket connection management for node communication
// Modification Reason: Removed duplicate method definitions
// Main Functionality:
// - WebSocket connection establishment and maintenance
// - Message handling and routing
// - Heartbeat and metrics reporting
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
//
// Last Modified: v1.0.2 - Removed duplicate method definitions
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
use tracing::{info, warn, error};

// Sub-modules
mod connection;
mod handlers;
mod terminal;

// Re-export for backward compatibility (even if not used, to maintain API)
#[allow(unused_imports)]
pub use connection::*;
#[allow(unused_imports)]
pub use handlers::*;
#[allow(unused_imports)]
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

    /// Create heartbeat message with system metrics (legacy format)
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
                mem: mem_usage,
                disk: disk_usage,
                net: net_usage,
                temperature,
                processes,
            },
        }
    }

    /// Create heartbeat with metrics (new format)
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
    // ============================================
}
