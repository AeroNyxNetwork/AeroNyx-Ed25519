// src/registration/websocket/connection.rs
// ============================================
// WebSocket connection management and lifecycle
// Version: 1.2.0 - Fixed terminal input message routing
// ============================================
// Creation Reason: Manages WebSocket connections between node and backend
// Modification Reason: Fixed terminal input messages being incorrectly parsed as ServerMessage::Unknown
// Main Functionality:
// - WebSocket connection establishment with retry logic
// - Message routing and processing
// - Terminal session management
// - Heartbeat mechanism
// - Ping/pong handling
//
// Main Logical Flow:
// 1. Establish WebSocket connection with retry
// 2. Authenticate with backend
// 3. Check message type BEFORE parsing to ServerMessage enum
// 4. Route terminal messages directly to terminal handler
// 5. Process other messages through appropriate handlers
// 6. Maintain heartbeat for connection health
//
// ⚠️ Important Note for Next Developer:
// - Terminal messages (term_input, term_resize, term_close) must be checked BEFORE ServerMessage parsing
// - The ServerMessage::Unknown variant will catch ANY unmatched type due to #[serde(other)]
// - Terminal output check MUST be rate-limited to prevent blocking
// - WebSocket ping/pong messages have priority over terminal output
// - Never remove the terminal_check_interval - it prevents connection drops
//
// Last Modified: v1.2.0 - Fixed message routing for terminal input
// ============================================

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

// Heartbeat configuration
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
            interval: Duration::from_secs(30),      // Send heartbeat every 30 seconds
            timeout: Duration::from_secs(180),      // Timeout after 180 seconds (3 minutes)
            max_missed: 3,                          // Allow 3 missed heartbeats
            grace_period: Duration::from_secs(30),  // Additional grace period before disconnect
        }
    }
}

// Terminal session tracker - manages terminal output channels
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
    
    // Add a new terminal session channel
    fn insert(&mut self, session_id: String, rx: mpsc::Receiver<TerminalMessage>) {
        self.channels.insert(session_id, rx);
    }
    
    // Remove a terminal session channel
    fn remove(&mut self, session_id: &str) -> Option<mpsc::Receiver<TerminalMessage>> {
        self.channels.remove(session_id)
    }
    
    // Clean up closed channels
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
    
    // Check for output from any terminal session (non-blocking)
    async fn check_for_output(&mut self) -> Option<(String, TerminalMessage)> {
        // Iterate through all channels and try to receive without blocking
        for (id, rx) in self.channels.iter_mut() {
            if let Ok(msg) = rx.try_recv() {
                return Some((id.clone(), msg));
            }
        }
        None
    }
    
    // Check if cleanup is needed (every 60 seconds)
    fn should_cleanup(&self) -> bool {
        self.last_cleanup.elapsed() > Duration::from_secs(60)
    }
    
    // Mark cleanup as done
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
    /// Main WebSocket connection handler with retry logic and resource management
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
    
    /// Connect to WebSocket with exponential backoff retry
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
                    // Exponential backoff with cap at 10 seconds
                    backoff = backoff.mul_f32(1.5).min(Duration::from_secs(10));
                }
                Err(e) => {
                    return Err(format!("WebSocket connection failed after {} attempts: {}", max_retries, e));
                }
            }
        }
    }
    
    /// Main event loop - processes all WebSocket events with proper priority
    /// CRITICAL: Terminal output checking is rate-limited to prevent blocking ping/pong
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
        // Set up intervals for various periodic tasks
        let mut heartbeat_interval = time::interval(heartbeat_config.interval);
        heartbeat_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        let mut cleanup_interval = time::interval(Duration::from_secs(60));
        cleanup_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        // CRITICAL: Terminal output check interval - increased to 100ms to reduce CPU usage
        // and prevent blocking of ping/pong processing
        let mut terminal_check_interval = time::interval(Duration::from_millis(100));
        terminal_check_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        // Authentication timeout
        let auth_timeout = time::sleep(Duration::from_secs(35));
        tokio::pin!(auth_timeout);
        
        // Flag to skip terminal checks when processing important messages
        let mut skip_terminal_check = false;
        
        // Main event loop using tokio::select! for concurrent event handling
        loop {
            tokio::select! {
                // Priority 1: Handle incoming WebSocket messages (including ping/pong)
                // This branch has implicit priority by being listed first
                Some(message) = read.next() => {
                    // Set flag to skip terminal check on next tick if we're processing messages
                    skip_terminal_check = true;
                    
                    // CRITICAL: Handle ping messages immediately without going through the full handler
                    if let Ok(Message::Ping(data)) = &message {
                        info!("Received ping with {} bytes, sending pong IMMEDIATELY", data.len());
                        // Send pong directly here for fastest response
                        if let Err(e) = write.send(Message::Pong(data.clone())).await {
                            error!("Failed to send pong: {}", e);
                            break;
                        }
                        info!("Pong sent successfully, continuing loop");
                        continue; // Skip the rest of processing for ping messages
                    }
                    
                    // Handle all other messages normally
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
                
                // Priority 2: Send heartbeat messages (must be timely)
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
                
                // Priority 3: Check terminal output (rate-limited and conditional)
                // Skip this if we just processed a WebSocket message
                _ = terminal_check_interval.tick(), if !skip_terminal_check => {
                    // Only check if we have active terminal sessions
                    if !terminal_tracker.channels.is_empty() {
                        // Non-blocking check, process only one message per tick
                        if let Some((session_id, msg)) = terminal_tracker.check_for_output().await {
                            debug!("Sending terminal output for session {}", session_id);
                            if let Err(e) = self.send_terminal_output(write, &session_id, msg).await {
                                error!("Failed to send terminal output: {}", e);
                                terminal_tracker.remove(&session_id);
                            }
                        }
                    }
                    skip_terminal_check = false; // Reset the flag
                }
                
                // Priority 4: Periodic cleanup of closed channels
                _ = cleanup_interval.tick() => {
                    if terminal_tracker.should_cleanup() {
                        terminal_tracker.cleanup_closed();
                        terminal_tracker.mark_cleanup();
                    }
                }
                
                // Authentication timeout check (only active before authentication)
                _ = &mut auth_timeout, if !state.authenticated => {
                    error!("Authentication timeout - no server response within 35 seconds");
                    return Err("Authentication timeout".to_string());
                }
            }
            
            // Reset skip flag if it wasn't reset in the terminal check branch
            if skip_terminal_check {
                skip_terminal_check = false;
            }
        }
        
        // Determine exit reason
        self.determine_exit_reason(state, &heartbeat_config)
    }
    
    /// Handle incoming WebSocket messages
    /// FIXED: Check for terminal messages BEFORE attempting to parse as ServerMessage
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
                debug!("Received text message: {} bytes", text.len());
                
                // CRITICAL FIX: Check for terminal messages FIRST
                // This prevents them from being caught by ServerMessage::Unknown
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(msg_type) = json.get("type").and_then(|t| t.as_str()) {
                        // Check if this is a client-to-server terminal message
                        if matches!(msg_type, "term_input" | "term_resize" | "term_close") {
                            info!("Processing terminal message type: {}", msg_type);
                            
                            // Handle terminal message directly
                            self.handle_terminal_message_json(&json, write, terminal_tracker).await?;
                            return Ok(true);
                        }
                    }
                }
                
                // Now try to parse as ServerMessage for server-to-client messages
                if let Ok(server_msg) = serde_json::from_str::<ServerMessage>(&text) {
                    // Update heartbeat acknowledgment for relevant messages
                    if matches!(server_msg, ServerMessage::HeartbeatAck { .. }) {
                        state.last_heartbeat_ack = std::time::Instant::now();
                        state.missed_heartbeats = 0;
                    }
                    
                    // Handle structured server message
                    self.handle_server_message(
                        server_msg,
                        write,
                        &mut state.authenticated,
                        hardware_info,
                        setup_params,
                        &mut terminal_tracker.channels,
                    ).await?;
                } else {
                    // Handle generic/unstructured message
                    self.handle_generic_message_v2(
                        &text,
                        write,
                        &mut state.authenticated,
                        &mut state.auth_sent,
                        &mut state.heartbeat_interval,
                        &mut state.last_heartbeat_ack,
                        terminal_tracker,
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
                // CRITICAL: Respond to ping immediately to maintain connection
                info!("Received ping with {} bytes, sending pong immediately", data.len());
                write.send(Message::Pong(data)).await
                    .map_err(|e| format!("Failed to send pong: {}", e))?;
                info!("Pong sent successfully");
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
    
    /// Handle heartbeat logic - sends heartbeat and checks for timeout
    async fn handle_heartbeat(
        &self,
        write: &mut WsSink,
        state: &mut ConnectionState,
        config: &HeartbeatConfig,
        metrics_collector: &Arc<ServerMetricsCollector>,
    ) -> Result<(), String> {
        let elapsed = state.last_heartbeat_ack.elapsed();
        
        // Check for heartbeat timeout
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
        
        // Send regular heartbeat message
        let heartbeat = self.create_heartbeat_message(metrics_collector).await;
        let heartbeat_json = serde_json::to_string(&heartbeat)
            .map_err(|e| format!("Failed to serialize heartbeat: {}", e))?;
        
        write.send(Message::Text(heartbeat_json)).await
            .map_err(|e| format!("Failed to send heartbeat: {}", e))?;
        
        debug!("Heartbeat sent");
        Ok(())
    }
    
    /// Send terminal output to WebSocket
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
    
    /// Clean up resources on disconnect
    async fn cleanup_resources(&self, terminal_tracker: &mut TerminalSessionTracker) {
        // Close all terminal sessions
        let session_ids: Vec<String> = terminal_tracker.channels.keys().cloned().collect();
        
        for session_id in session_ids {
            if let Some(mut rx) = terminal_tracker.remove(&session_id) {
                rx.close();
                
                // Close the actual terminal session
                if let Err(e) = self.terminal_manager.close_session(&session_id).await {
                    warn!("Failed to close terminal session {}: {}", session_id, e);
                }
            }
        }
        
        info!("Cleaned up {} terminal sessions", terminal_tracker.channels.len());
    }
    
    /// Determine exit reason based on connection state
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
    
    /// Handle generic/unstructured messages with terminal support
    async fn handle_generic_message_v2(
        &self,
        text: &str,
        write: &mut WsSink,
        authenticated: &mut bool,
        auth_sent: &mut bool,
        heartbeat_interval: &mut time::Interval,
        last_heartbeat_ack: &mut std::time::Instant,
        terminal_tracker: &mut TerminalSessionTracker,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(msg_type) = json.get("type").and_then(|t| t.as_str()) {
                match msg_type {
                    // NOTE: Terminal input messages are now handled in handle_incoming_message
                    // before reaching here, so we don't need these cases anymore
                    
                    // Terminal ready response
                    "term_ready" => {
                        if let Ok(msg) = serde_json::from_value::<TerminalMessage>(json) {
                            if let TerminalMessage::Ready { session_id } = msg {
                                // Create channel for terminal output
                                let (tx, rx) = mpsc::channel::<TerminalMessage>(100);
                                terminal_tracker.insert(session_id.clone(), rx);
                                
                                // Start output reader task
                                self.start_terminal_output_reader(
                                    self.terminal_manager.clone(),
                                    session_id,
                                    tx
                                ).await;
                            }
                        }
                    }
                    
                    // All other messages - delegate to main handler
                    _ => {
                        return self.handle_generic_message(
                            text,
                            write,
                            authenticated,
                            auth_sent,
                            heartbeat_interval,
                            last_heartbeat_ack,
                            &mut terminal_tracker.channels,
                            hardware_info,
                            setup_params,
                        ).await;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle terminal-specific messages
    /// This function is called for client-to-server terminal messages
    async fn handle_terminal_message_json(
        &self,
        json: &serde_json::Value,
        write: &mut WsSink,
        terminal_tracker: &mut TerminalSessionTracker,
    ) -> Result<(), String> {
        info!("Processing terminal message: {}", json);
        
        // Check if remote management is enabled
        if !*self.remote_management_enabled.read().await {
            let session_id = json.get("session_id")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");
            
            let error_response = serde_json::json!({
                "type": "term_error",
                "session_id": session_id,
                "error": "Remote management is disabled"
            });
            
            write.send(Message::Text(error_response.to_string())).await
                .map_err(|e| format!("Failed to send error response: {}", e))?;
            return Ok(());
        }
        
        // Parse and handle terminal message
        match serde_json::from_value::<TerminalMessage>(json.clone()) {
            Ok(term_msg) => {
                info!("Successfully parsed terminal message: {:?}", term_msg);
                
                let terminal_manager = self.get_terminal_manager();
                
                match super::terminal::handle_terminal_message(&terminal_manager, term_msg).await {
                    Ok(Some(response)) => {
                        let response_json = serde_json::to_string(&response)
                            .unwrap_or_else(|_| "{}".to_string());
                        
                        write.send(Message::Text(response_json)).await
                            .map_err(|e| format!("Failed to send terminal response: {}", e))?;
                        
                        // Handle special responses
                        if let TerminalMessage::Ready { session_id } = response {
                            // Create output channel
                            let (tx, rx) = mpsc::channel::<TerminalMessage>(100);
                            terminal_tracker.insert(session_id.clone(), rx);
                            
                            // Start output reader
                            self.start_terminal_output_reader(
                                terminal_manager.clone(),
                                session_id,
                                tx
                            ).await;
                        }
                    }
                    Ok(None) => {
                        info!("Terminal message processed successfully, no response needed");
                    }
                    Err(e) => {
                        error!("Terminal message handling error: {}", e);
                        
                        let session_id = json.get("session_id")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown");
                        
                        let error_response = serde_json::json!({
                            "type": "term_error",
                            "session_id": session_id,
                            "error": e.to_string()
                        });
                        
                        write.send(Message::Text(error_response.to_string())).await
                            .map_err(|e| format!("Failed to send error response: {}", e))?;
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse terminal message: {}, JSON was: {}", e, json);
                
                let session_id = json.get("session_id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                
                let error_response = serde_json::json!({
                    "type": "term_error",
                    "session_id": session_id,
                    "error": format!("Failed to parse message: {}", e)
                });
                
                write.send(Message::Text(error_response.to_string())).await
                    .map_err(|e| format!("Failed to send error response: {}", e))?;
            }
        }
        
        Ok(())
    }
}
