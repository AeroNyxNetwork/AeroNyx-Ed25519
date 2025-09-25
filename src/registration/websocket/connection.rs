// src/registration/websocket/connection.rs
// WebSocket connection management and lifecycle - Fixed version with terminal output support

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
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream, MaybeTlsStream};
use tracing::{debug, error, info, warn};

pub type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, Message>;
pub type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;

// 心跳配置
#[derive(Clone)]
struct HeartbeatConfig {
    interval: Duration,
    timeout: Duration,
    max_missed: u32,
    grace_period: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(180),     // 6分钟基础超时
            max_missed: 3,                        // 允许错过3次
            grace_period: Duration::from_secs(30), // 额外宽限期
        }
    }
}

// 终端会话管理器
struct TerminalSessionTracker {
    channels: HashMap<String, mpsc::Receiver<TerminalMessage>>,
    last_cleanup: std::time::Instant,
}

impl TerminalSessionTracker {
    fn new() -> Self {
        Self {
            channels: HashMap::new(),
            last_cleanup: std::time::Instant::now(),
        }
    }
    
    fn insert(&mut self, session_id: String, rx: mpsc::Receiver<TerminalMessage>) {
        self.channels.insert(session_id, rx);
    }
    
    fn remove(&mut self, session_id: &str) -> Option<mpsc::Receiver<TerminalMessage>> {
        self.channels.remove(session_id)
    }
    
    fn cleanup_closed(&mut self) {
        let closed_sessions: Vec<String> = self.channels
            .iter()
            .filter(|(_, rx)| rx.is_closed())
            .map(|(id, _)| id.clone())
            .collect();
            
        for session_id in closed_sessions {
            self.channels.remove(&session_id);
            info!("Cleaned up closed terminal channel: {}", session_id);
        }
    }
    
    async fn check_for_output(&mut self) -> Option<(String, TerminalMessage)> {
        for (id, rx) in self.channels.iter_mut() {
            if let Ok(msg) = rx.try_recv() {
                return Some((id.clone(), msg));
            }
        }
        None
    }
    
    fn should_cleanup(&self) -> bool {
        self.last_cleanup.elapsed() > Duration::from_secs(60)
    }
    
    fn mark_cleanup(&mut self) {
        self.last_cleanup = std::time::Instant::now();
    }
}

// Connection state management
struct ConnectionState {
    authenticated: bool,
    auth_sent: bool,
    last_heartbeat_ack: std::time::Instant,
    missed_heartbeats: u32,
    heartbeat_interval: time::Interval,
}

impl ConnectionState {
    fn new() -> Self {
        let mut heartbeat_interval = time::interval(Duration::from_secs(30));
        heartbeat_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        Self {
            authenticated: false,
            auth_sent: false,
            last_heartbeat_ack: std::time::Instant::now(),
            missed_heartbeats: 0,
            heartbeat_interval,
        }
    }
}

impl RegistrationManager {
    /// Optimized WebSocket connection handler with improved error handling and resource management
    pub(crate) async fn connect_and_run_websocket_v2(
        &self,
        ws_url: &str,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        // Establish connection with retry logic
        let ws_stream = self.connect_with_retry(ws_url, 3).await?;
        
        info!("WebSocket TCP connection established, waiting for server handshake");
        *self.websocket_connected.write().await = true;
        
        let (mut write, mut read) = ws_stream.split();
        
        // Initialize connection state
        let mut connection_state = ConnectionState::new();
        let heartbeat_config = HeartbeatConfig::default();
        let _metrics_collector = Arc::new(ServerMetricsCollector::new(
            Duration::from_secs(60),
            60,
        ));
        
        // Terminal session tracking
        let mut terminal_tracker = TerminalSessionTracker::new();
        
        // Main event loop
        let result = self.run_event_loop(
            &mut write,
            &mut read,
            &mut connection_state,
            &heartbeat_config,
            &_metrics_collector,
            &mut terminal_tracker,
            hardware_info,
            setup_params,
        ).await;
        
        // Cleanup
        *self.websocket_connected.write().await = false;
        self.cleanup_resources(&mut terminal_tracker).await;
        
        result
    }
    
    /// Connect with retry logic
    async fn connect_with_retry(&self, ws_url: &str, max_retries: u32) -> Result<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, String> {
        let mut retry_count = 0;
        let mut backoff = Duration::from_secs(1);
        
        loop {
            match connect_async(ws_url).await {
                Ok((stream, _)) => return Ok(stream),
                Err(e) if retry_count < max_retries => {
                    retry_count += 1;
                    warn!("WebSocket connection attempt {} failed: {}. Retrying in {:?}...", 
                          retry_count, e, backoff);
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.mul_f32(1.5).min(Duration::from_secs(10));
                }
                Err(e) => {
                    return Err(format!("WebSocket connection failed after {} attempts: {}", max_retries, e));
                }
            }
        }
    }
    
    /// Main event loop
    async fn run_event_loop(
        &self,
        write: &mut WsSink,
        read: &mut WsStream,
        state: &mut ConnectionState,
        heartbeat_config: &HeartbeatConfig,
        metrics_collector: &Arc<ServerMetricsCollector>,
        terminal_tracker: &mut TerminalSessionTracker,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        // Set up intervals
        let mut heartbeat_interval = time::interval(heartbeat_config.interval);
        heartbeat_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        let mut cleanup_interval = time::interval(Duration::from_secs(60));
        cleanup_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        // Authentication timeout
        let auth_timeout = time::sleep(Duration::from_secs(35));
        tokio::pin!(auth_timeout);
        
        loop {
            tokio::select! {
                // Handle incoming messages
                Some(message) = read.next() => {
                    match self.handle_incoming_message(
                        message, 
                        write, 
                        state, 
                        terminal_tracker,
                        hardware_info,
                        setup_params,
                    ).await {
                        Ok(should_continue) => {
                            if !should_continue {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error handling message: {}", e);
                            return Err(e);
                        }
                    }
                }
                
                // Check terminal outputs
                Some((session_id, msg)) = terminal_tracker.check_for_output() => {
                    if let Err(e) = self.send_terminal_output(write, &session_id, msg).await {
                        error!("Failed to send terminal output: {}", e);
                        terminal_tracker.remove(&session_id);
                    }
                }
                
                // Heartbeat
                _ = heartbeat_interval.tick() => {
                    if state.authenticated {
                        if let Err(e) = self.handle_heartbeat(
                            write, 
                            state, 
                            &heartbeat_config,
                            metrics_collector,
                        ).await {
                            error!("Heartbeat error: {}", e);
                            break;
                        }
                    }
                }
                
                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    if terminal_tracker.should_cleanup() {
                        terminal_tracker.cleanup_closed();
                        terminal_tracker.mark_cleanup();
                    }
                }
                
                // Authentication timeout
                _ = &mut auth_timeout, if !state.authenticated => {
                    error!("Authentication timeout - no server response within 35 seconds");
                    return Err("Authentication timeout".to_string());
                }
            }
        }
        
        // Determine exit reason
        self.determine_exit_reason(state, &heartbeat_config)
    }
    
    /// Handle incoming WebSocket message
    async fn handle_incoming_message(
        &self,
        message: Result<Message, tokio_tungstenite::tungstenite::Error>,
        write: &mut WsSink,
        state: &mut ConnectionState,
        terminal_tracker: &mut TerminalSessionTracker,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<bool, String> {
        match message {
            Ok(Message::Text(text)) => {
                debug!("Received message: {} bytes", text.len());
                
                // Try structured message first
                if let Ok(server_msg) = serde_json::from_str::<ServerMessage>(&text) {
                    // Update heartbeat ack for relevant messages
                    if matches!(server_msg, ServerMessage::HeartbeatAck { .. }) {
                        state.last_heartbeat_ack = std::time::Instant::now();
                        state.missed_heartbeats = 0;
                    }
                    
                    // ✅ FIX: Pass terminal_tracker as mutable HashMap
                    self.handle_server_message(
                        server_msg,
                        write,
                        &mut state.authenticated,
                        hardware_info,
                        setup_params,
                        &mut terminal_tracker.channels,  // Pass the HashMap directly
                    ).await?;
                } else {
                    // Handle generic message
                    self.handle_generic_message(
                        &text,
                        write,
                        &mut state.authenticated,
                        &mut state.auth_sent,
                        &mut state.heartbeat_interval,
                        &mut state.last_heartbeat_ack,
                        &mut terminal_tracker.channels,  // Pass the HashMap directly
                        hardware_info,
                        setup_params,
                    ).await?;
                }
                Ok(true)
            }
            Ok(Message::Close(_)) => {
                info!("WebSocket closed by server");
                Ok(false)
            }
            Ok(Message::Ping(data)) => {
                debug!("Received ping, sending pong");
                write.send(Message::Pong(data)).await
                    .map_err(|e| format!("Failed to send pong: {}", e))?;
                Ok(true)
            }
            Ok(Message::Pong(_)) => {
                debug!("Received pong");
                state.last_heartbeat_ack = std::time::Instant::now();
                state.missed_heartbeats = 0;
                Ok(true)
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                Err(format!("WebSocket error: {}", e))
            }
            _ => Ok(true)
        }
    }
    
    /// Handle heartbeat logic
    async fn handle_heartbeat(
        &self,
        write: &mut WsSink,
        state: &mut ConnectionState,
        config: &HeartbeatConfig,
        metrics_collector: &Arc<ServerMetricsCollector>,
    ) -> Result<(), String> {
        let elapsed = state.last_heartbeat_ack.elapsed();
        
        // Check for timeout
        if elapsed > config.timeout {
            state.missed_heartbeats += 1;
            
            if state.missed_heartbeats >= config.max_missed {
                if elapsed > config.timeout + config.grace_period {
                    return Err(format!(
                        "Heartbeat timeout after {} missed beats, elapsed: {:?}", 
                        state.missed_heartbeats, elapsed
                    ));
                } else {
                    // In grace period, send urgent ping
                    warn!("In heartbeat grace period, sending urgent ping");
                    write.send(Message::Ping(vec![])).await.ok();
                }
            }
        }
        
        // Send regular heartbeat
        let heartbeat = self.create_heartbeat_message(metrics_collector).await;
        let heartbeat_json = serde_json::to_string(&heartbeat)
            .map_err(|e| format!("Failed to serialize heartbeat: {}", e))?;
        
        write.send(Message::Text(heartbeat_json)).await
            .map_err(|e| format!("Failed to send heartbeat: {}", e))?;
        
        debug!("Heartbeat sent");
        Ok(())
    }
    
    /// Send terminal output
    async fn send_terminal_output(
        &self,
        write: &mut WsSink,
        _session_id: &str,
        msg: TerminalMessage,
    ) -> Result<(), String> {
        let json = serde_json::to_string(&msg)
            .map_err(|e| format!("Failed to serialize terminal message: {}", e))?;
        
        write.send(Message::Text(json)).await
            .map_err(|e| format!("Failed to send terminal output: {}", e))
    }
    
    /// Clean up resources
    async fn cleanup_resources(&self, terminal_tracker: &mut TerminalSessionTracker) {
        // Close all terminal sessions
        let session_ids: Vec<String> = terminal_tracker.channels.keys().cloned().collect();
        
        for session_id in session_ids {
            if let Some(mut rx) = terminal_tracker.remove(&session_id) {
                rx.close();
                
                // terminal_manager is Arc<TerminalSessionManager>, not Option
                if let Err(e) = self.terminal_manager.close_session(&session_id).await {
                    warn!("Failed to close terminal session {}: {}", session_id, e);
                }
            }
        }
        
        info!("Cleaned up {} terminal sessions", terminal_tracker.channels.len());
    }
    
    /// Determine exit reason
    fn determine_exit_reason(&self, state: &ConnectionState, config: &HeartbeatConfig) -> Result<(), String> {
        if state.authenticated && state.last_heartbeat_ack.elapsed() > config.timeout {
            Err("Connection lost: heartbeat timeout".to_string())
        } else if !state.authenticated && state.auth_sent {
            Err("WebSocket connection closed without successful authentication".to_string())
        } else if !state.auth_sent {
            Err("Server did not send initial connection message".to_string())
        } else {
            Ok(())
        }
    }
}
