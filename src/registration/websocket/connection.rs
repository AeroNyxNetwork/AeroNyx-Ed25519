// src/registration/websocket/connection.rs
// WebSocket connection management and lifecycle

use crate::registration::{RegistrationManager, WebSocketMessage};
use crate::hardware::HardwareInfo;
use crate::zkp_halo2::SetupParams;
use crate::websocket_protocol::{ServerMessage, ClientMessage};
use crate::terminal::{TerminalMessage, TerminalSessionManager};
use crate::server::metrics::ServerMetricsCollector;
use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream, MaybeTlsStream};
use tracing::{debug, error, info, warn};

pub type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, Message>;
pub type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;

impl RegistrationManager {
    /// Internal WebSocket connection handler (original version)
    pub(crate) async fn connect_and_run_websocket(&self, ws_url: &str) -> Result<(), String> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| format!("WebSocket connection failed: {}", e))?;
        
        info!("WebSocket connected successfully");
        *self.websocket_connected.write().await = true;
        
        let (mut write, mut read) = ws_stream.split();
        
        // Set up heartbeat interval
        let mut heartbeat_interval = time::interval(Duration::from_secs(60));
        let mut authenticated = false;
        let _metrics_collector = Arc::new(ServerMetricsCollector::new(
            Duration::from_secs(60),
            60,
        ));
        
        // Track last heartbeat time for connection health
        let mut last_heartbeat_ack = std::time::Instant::now();
        let heartbeat_timeout = Duration::from_secs(180); // 3 minutes
        
        // Terminal output channels
        let mut terminal_output_channels: HashMap<String, mpsc::Receiver<TerminalMessage>> = HashMap::new();
        
        loop {
            tokio::select! {
                Some(message) = read.next() => {
                    match message {
                        Ok(Message::Text(text)) => {
                            if let Err(e) = self.handle_websocket_message_v1(
                                &text, 
                                &mut write, 
                                &mut authenticated, 
                                &mut heartbeat_interval, 
                                &mut last_heartbeat_ack,
                                &mut terminal_output_channels
                            ).await {
                                error!("Failed to handle WebSocket message: {}", e);
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("WebSocket closed by server");
                            break;
                        }
                        Ok(Message::Ping(data)) => {
                            debug!("Received ping, sending pong");
                            write.send(Message::Pong(data)).await
                                .map_err(|e| format!("Failed to send pong: {}", e))?;
                        }
                        Ok(Message::Pong(_)) => {
                            debug!("Received pong");
                            last_heartbeat_ack = std::time::Instant::now();
                        }
                        Err(e) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
                
                // Check terminal output channels
                Some((session_id, msg)) = async {
                    for (id, rx) in terminal_output_channels.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some((id.clone(), msg));
                        }
                    }
                    None
                } => {
                    if let Ok(json) = serde_json::to_string(&msg) {
                        if let Err(e) = write.send(Message::Text(json)).await {
                            error!("Failed to send terminal output: {}", e);
                            // Remove the channel if send failed
                            terminal_output_channels.remove(&session_id);
                        }
                    }
                }
                
                _ = heartbeat_interval.tick() => {
                    if authenticated {
                        // Check heartbeat timeout
                        if last_heartbeat_ack.elapsed() > heartbeat_timeout {
                            error!("Heartbeat timeout - no response from server");
                            break;
                        }
                        
                        let heartbeat = self.create_heartbeat_message(&_metrics_collector).await;
                        let heartbeat_json = serde_json::to_string(&heartbeat)
                            .map_err(|e| format!("Failed to serialize heartbeat: {}", e))?;
                        
                        if let Err(e) = write.send(Message::Text(heartbeat_json)).await {
                            error!("Failed to send heartbeat: {}", e);
                            break;
                        }
                        debug!("Heartbeat sent via WebSocket");
                    }
                }
            }
        }
        
        *self.websocket_connected.write().await = false;
        
        if !authenticated {
            Err("Failed to authenticate with WebSocket server".to_string())
        } else {
            Ok(())
        }
    }

    /// Updated WebSocket connection handler that properly handles initial messages
    pub(crate) async fn connect_and_run_websocket_v2(
        &self,
        ws_url: &str,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| format!("WebSocket connection failed: {}", e))?;
        
        info!("WebSocket TCP connection established, waiting for server handshake");
        *self.websocket_connected.write().await = true;
        
        let (mut write, mut read) = ws_stream.split();
        
        // Set up heartbeat interval (30 seconds to match test script)
        let mut heartbeat_interval = time::interval(Duration::from_secs(30));
        heartbeat_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        let mut authenticated = false;
        let mut auth_sent = false;
        let _metrics_collector = Arc::new(ServerMetricsCollector::new(
            Duration::from_secs(60),
            60,
        ));
        
        // Track last heartbeat acknowledgment
        let mut last_heartbeat_ack = std::time::Instant::now();
        let heartbeat_timeout = Duration::from_secs(90); // 3 missed heartbeats
        
        // Terminal output channels
        let mut terminal_output_channels: HashMap<String, mpsc::Receiver<TerminalMessage>> = HashMap::new();
        
        loop {
            tokio::select! {
                Some(message) = read.next() => {
                    match message {
                        Ok(Message::Text(text)) => {
                            // Add debug logging for ALL messages
                            info!("=== WEBSOCKET MESSAGE RECEIVED ===");
                            info!("Raw message: {}", if text.len() > 500 { 
                                format!("{}... (truncated, total length: {})", &text[..500], text.len()) 
                            } else { 
                                text.clone() 
                            });
                            
                            // First try to parse as structured ServerMessage
                            let handled = if let Ok(server_msg) = serde_json::from_str::<ServerMessage>(&text) {
                                info!("Parsed as ServerMessage");
                                
                                // Check if this is a heartbeat ack before handling
                                let is_heartbeat_ack = matches!(server_msg, ServerMessage::HeartbeatAck { .. });
                                
                                let result = self.handle_server_message(
                                    server_msg,
                                    &mut write,
                                    &mut authenticated,
                                    hardware_info,
                                    setup_params,
                                ).await;
                                
                                // Update timestamp for heartbeat ack
                                if is_heartbeat_ack && result.is_ok() {
                                    last_heartbeat_ack = std::time::Instant::now();
                                }
                                
                                result.is_ok()
                            } else {
                                false
                            };
                            
                            // If structured parsing failed, try generic JSON handling
                            if !handled {
                                self.handle_generic_message(
                                    &text,
                                    &mut write,
                                    &mut authenticated,
                                    &mut auth_sent,
                                    &mut heartbeat_interval,
                                    &mut last_heartbeat_ack,
                                    &mut terminal_output_channels,
                                    hardware_info,
                                    setup_params,
                                ).await?;
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("WebSocket closed by server");
                            break;
                        }
                        Ok(Message::Ping(data)) => {
                            debug!("Received ping, sending pong");
                            if let Err(e) = write.send(Message::Pong(data)).await {
                                error!("Failed to send pong: {}", e);
                                break;
                            }
                        }
                        Ok(Message::Pong(_)) => {
                            debug!("Received pong");
                            last_heartbeat_ack = std::time::Instant::now();
                        }
                        Err(e) => {
                            error!("WebSocket read error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
                
                // Check terminal output channels
                Some((session_id, msg)) = async {
                    for (id, rx) in terminal_output_channels.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some((id.clone(), msg));
                        }
                    }
                    None
                } => {
                    if let Ok(json) = serde_json::to_string(&msg) {
                        if let Err(e) = write.send(Message::Text(json)).await {
                            error!("Failed to send terminal output: {}", e);
                            // Remove the channel if send failed
                            terminal_output_channels.remove(&session_id);
                        }
                    }
                }
                
                _ = heartbeat_interval.tick() => {
                    if authenticated {
                        // Check heartbeat timeout
                        if last_heartbeat_ack.elapsed() > heartbeat_timeout {
                            error!("Heartbeat timeout - no response from server for {:?}", 
                                   last_heartbeat_ack.elapsed());
                            break;
                        }
                        
                        // Log remote management status with heartbeat
                        let remote_enabled = *self.remote_management_enabled.read().await;
                        info!("Sending heartbeat - Remote management enabled: {}", remote_enabled);
                        
                        // Send heartbeat in simple format
                        let heartbeat = serde_json::json!({
                            "type": "heartbeat",
                            "metrics": {
                                "cpu": self.get_cpu_usage().await,
                                "memory": self.get_memory_usage().await,
                                "disk": self.get_disk_usage().await,
                                "network": self.get_network_usage().await
                            }
                        });
                        
                        if let Err(e) = write.send(Message::Text(heartbeat.to_string())).await {
                            error!("Failed to send heartbeat: {}", e);
                            break;
                        }
                        
                        info!("Sent heartbeat at {}", std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs());
                    } else if auth_sent && self.start_time.elapsed() > Duration::from_secs(25) {
                        warn!("Not authenticated after 25 seconds despite sending auth");
                    }
                }
                
                // Timeout for initial connection/auth sequence
                _ = tokio::time::sleep(Duration::from_secs(35)) => {
                    if !authenticated && !auth_sent {
                        error!("No server message received within 35 seconds of connection");
                        break;
                    }
                }
            }
        }
        
        *self.websocket_connected.write().await = false;
        
        // Clean up terminal sessions
        for (session_id, _) in terminal_output_channels {
            if let Err(e) = self.terminal_manager.close_session(&session_id).await {
                warn!("Failed to close terminal session {}: {}", session_id, e);
            }
        }
        
        // Return more accurate error messages
        if authenticated && last_heartbeat_ack.elapsed() > heartbeat_timeout {
            Err("Connection lost: heartbeat timeout".to_string())
        } else if !authenticated && auth_sent {
            Err("WebSocket connection closed without successful authentication".to_string())
        } else if !auth_sent {
            Err("Server did not send initial connection message".to_string())
        } else {
            Ok(())
        }
    }
}
