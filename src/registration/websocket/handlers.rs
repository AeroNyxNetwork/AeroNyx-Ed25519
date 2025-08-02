// src/registration/websocket/handlers.rs
// WebSocket message handling logic

use crate::registration::{RegistrationManager, WebSocketMessage};
use crate::hardware::HardwareInfo;
use crate::zkp_halo2::SetupParams;
use crate::websocket_protocol::{ServerMessage, ClientMessage, ProofData};
use crate::terminal::TerminalMessage;
use crate::remote_command_handler::{RemoteCommandData, RemoteCommandError, log_remote_command};
use super::connection::WsSink;
use super::terminal::handle_terminal_message;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

// Import SinkExt to enable the send method on WsSink
use futures_util::sink::SinkExt;

impl RegistrationManager {
    /// Handle incoming WebSocket messages (legacy version with terminal support)
    pub(super) async fn handle_websocket_message_v1(
        &self,
        text: &str,
        write: &mut WsSink,
        authenticated: &mut bool,
        heartbeat_interval: &mut time::Interval,
        last_heartbeat_ack: &mut std::time::Instant,
        terminal_output_channels: &mut HashMap<String, mpsc::Receiver<TerminalMessage>>,
    ) -> Result<(), String> {
        debug!("Received WebSocket message: {}", text);
        
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            match json.get("type").and_then(|t| t.as_str()) {
                Some("term_init") | Some("term_input") | Some("term_resize") | Some("term_close") => {
                    info!("=== TERMINAL MESSAGE DETECTED ===");
                    
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
                    
                    // Parse terminal message
                    if let Ok(term_msg) = serde_json::from_str::<TerminalMessage>(text) {
                        let terminal_manager = self.get_terminal_manager();
                        
                        match handle_terminal_message(&terminal_manager, term_msg).await {
                            Ok(Some(response)) => {
                                let response_json = serde_json::to_string(&response)
                                    .unwrap_or_else(|_| "{}".to_string());
                                
                                write.send(Message::Text(response_json)).await
                                    .map_err(|e| format!("Failed to send terminal response: {}", e))?;
                                
                                // If this was an init message, start output reader
                                if let TerminalMessage::Ready { session_id } = response {
                                    let (tx, rx) = mpsc::channel::<TerminalMessage>(100);
                                    terminal_output_channels.insert(session_id.clone(), rx);
                                    
                                    self.start_terminal_output_reader(
                                        terminal_manager.clone(),
                                        session_id,
                                        tx
                                    ).await;
                                }
                            }
                            Ok(None) => {
                                // No response needed
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
                    } else {
                        error!("Failed to parse terminal message");
                    }
                    
                    return Ok(());
                }
                _ => {
                    // Call the original handler for non-terminal messages
                    return self.handle_websocket_message(
                        text,
                        write,
                        authenticated,
                        heartbeat_interval,
                        last_heartbeat_ack
                    ).await;
                }
            }
        }
        
        // If not JSON, still call original handler
        self.handle_websocket_message(
            text,
            write,
            authenticated,
            heartbeat_interval,
            last_heartbeat_ack
        ).await
    }

    /// Handle incoming WebSocket messages (legacy version)
    pub(super) async fn handle_websocket_message(
        &self,
        text: &str,
        write: &mut WsSink,
        authenticated: &mut bool,
        heartbeat_interval: &mut time::Interval,
        last_heartbeat_ack: &mut std::time::Instant,
    ) -> Result<(), String> {
        debug!("Received WebSocket message: {}", text);
        
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            match json.get("type").and_then(|t| t.as_str()) {
                Some("connection_established") => {
                    info!("WebSocket connection established, sending authentication");
                    
                    let auth_msg = WebSocketMessage::Auth {
                        reference_code: self.reference_code.clone().unwrap(),
                        registration_code: self.registration_code.clone(),
                    };
                    
                    let auth_json = serde_json::to_string(&auth_msg)
                        .map_err(|e| format!("Failed to serialize auth: {}", e))?;
                    
                    write.send(Message::Text(auth_json)).await
                        .map_err(|e| format!("Failed to send auth: {}", e))?;
                }
                
                Some("auth_success") => {
                    info!("WebSocket authentication successful");
                    *authenticated = true;
                    *last_heartbeat_ack = std::time::Instant::now();
                    
                    // Get heartbeat interval from server
                    if let Some(interval_secs) = json.get("heartbeat_interval").and_then(|v| v.as_u64()) {
                        *heartbeat_interval = time::interval(Duration::from_secs(interval_secs));
                        info!("Heartbeat interval set to {} seconds", interval_secs);
                    }
                    
                    // Check for additional auth info
                    if let Some(node_info) = json.get("node_info") {
                        if let Some(status) = node_info.get("status").and_then(|s| s.as_str()) {
                            info!("Node status: {}", status);
                        }
                    }
                }
                
                Some("heartbeat_ack") => {
                    debug!("Heartbeat acknowledged by server");
                    *last_heartbeat_ack = std::time::Instant::now();
                    
                    // Update next heartbeat interval if provided
                    if let Some(next_interval) = json.get("next_interval").and_then(|v| v.as_u64()) {
                        *heartbeat_interval = time::interval(Duration::from_secs(next_interval));
                    }
                }
                
                Some("hardware_attestation_request") => {
                    // Handle ZKP attestation request
                    if self.zkp_params.is_some() {
                        info!("Received hardware attestation request");
                        
                        let challenge = json.get("challenge")
                            .and_then(|c| c.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<u8>>())
                            .unwrap_or_default();
                        
                        let nonce = json.get("nonce")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        
                        match self.handle_attestation_request(challenge, nonce).await {
                            Ok(response_msg) => {
                                let response_json = serde_json::to_string(&response_msg)
                                    .map_err(|e| format!("Failed to serialize attestation response: {}", e))?;
                                
                                write.send(Message::Text(response_json)).await
                                    .map_err(|e| format!("Failed to send attestation proof: {}", e))?;
                                
                                info!("Hardware attestation proof sent successfully");
                            }
                            Err(e) => {
                                error!("Failed to generate attestation proof: {}", e);
                            }
                        }
                    } else {
                        warn!("Received hardware attestation request but ZKP is not enabled");
                    }
                }
                
                Some("error") => {
                    let error_code = json.get("error_code").and_then(|c| c.as_str()).unwrap_or("unknown");
                    let message = json.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                    error!("Server error [{}]: {}", error_code, message);
                    
                    // Handle specific errors
                    match error_code {
                        "hardware_fingerprint_conflict" => {
                            error!("This hardware is already registered with another node");
                            error!("Each physical device can only run one AeroNyx node");
                            return Err("Hardware already registered".to_string());
                        }
                        "auth_failed" => {
                            error!("Authentication failed - invalid reference code");
                            return Err("Authentication failed".to_string());
                        }
                        "node_suspended" => {
                            error!("This node has been suspended");
                            error!("Please contact support for more information");
                            return Err("Node suspended".to_string());
                        }
                        "node_not_found" => {
                            error!("Node not found - registration may have been deleted");
                            return Err("Node not found".to_string());
                        }
                        _ => {}
                    }
                }
                
                Some("command") => {
                    // Handle remote commands if enabled
                    if *self.remote_management_enabled.read().await {
                        self.handle_remote_command(&json, write).await?;
                    } else {
                        warn!("Received remote command but remote management is disabled");
                        
                        // Send error response
                        if let Some(request_id) = json.get("request_id").and_then(|id| id.as_str()) {
                            let error_response = crate::remote_management::CommandResponse {
                                success: false,
                                message: "Remote management is disabled".to_string(),
                                data: None,
                                error_code: Some("REMOTE_MANAGEMENT_DISABLED".to_string()),
                                execution_time_ms: None,
                            };
                            
                            let response_msg = WebSocketMessage::CommandResponse {
                                request_id: request_id.to_string(),
                                response: error_response,
                            };
                            
                            let response_json = serde_json::to_string(&response_msg)
                                .map_err(|e| format!("Failed to serialize error response: {}", e))?;
                            
                            write.send(Message::Text(response_json)).await
                                .map_err(|e| format!("Failed to send error response: {}", e))?;
                        }
                    }
                }
                
                Some("ping") => {
                    // Respond to server ping
                    if let Some(timestamp) = json.get("timestamp").and_then(|t| t.as_u64()) {
                        let pong = WebSocketMessage::Ping { timestamp };
                        let pong_json = serde_json::to_string(&pong)
                            .map_err(|e| format!("Failed to serialize pong: {}", e))?;
                        
                        write.send(Message::Text(pong_json)).await
                            .map_err(|e| format!("Failed to send pong: {}", e))?;
                    }
                }
                
                Some("config_update") => {
                    // Handle configuration updates from server
                    info!("Received configuration update from server");
                    if let Some(config) = json.get("config") {
                        debug!("New configuration: {:?}", config);
                        // TODO: Apply configuration updates
                    }
                }
                
                Some("remote_command") => {
                    info!("=== REMOTE COMMAND RECEIVED ===");
                    info!("Raw message: {}", text);
                    
                    if *self.remote_management_enabled.read().await {
                        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(text) {
                            // Extract fields
                            let request_id = json_value.get("request_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let from_session = json_value.get("from_session")
                                .and_then(|v| v.as_str());
                            
                            info!("Request ID: {}", request_id);
                            info!("From session: {:?}", from_session);
                            
                            // NOTE: Backend doesn't send node_reference, so we don't check it
                            // The node is already authenticated, so we trust the command
                            
                            if let Some(command_json) = json_value.get("command") {
                                info!("Command JSON: {:?}", command_json);
                                
                                match serde_json::from_value::<RemoteCommandData>(command_json.clone()) {
                                    Ok(command_data) => {
                                        info!("Processing remote command: type={}", command_data.command_type);
                                        
                                        // Log the command execution
                                        if let Some(session_id) = from_session {
                                            log_remote_command(
                                                session_id,
                                                &command_data.command_type,
                                                true,
                                                &format!("request_id={}", request_id)
                                            );
                                        }
                                        
                                        // Execute command
                                        let handler = self.remote_command_handler.clone();
                                        let response = handler.handle_command(
                                            request_id.to_string(), 
                                            command_data
                                        ).await;
                                        
                                        // Build response message
                                        let response_msg = if response.success {
                                            serde_json::json!({
                                                "type": "remote_command_response",
                                                "request_id": request_id,
                                                "success": true,
                                                "result": response.result,
                                                "executed_at": response.executed_at
                                            })
                                        } else {
                                            serde_json::json!({
                                                "type": "remote_command_response",
                                                "request_id": request_id,
                                                "success": false,
                                                "error": response.error,
                                                "executed_at": response.executed_at
                                            })
                                        };
                                        
                                        // Send response
                                        info!("Sending remote command response for request_id: {}", request_id);
                                        let response_json = response_msg.to_string();
                                        
                                        match write.send(Message::Text(response_json)).await {
                                            Ok(_) => info!("Response sent successfully"),
                                            Err(e) => error!("Failed to send response: {}", e),
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse remote command: {}", e);
                                        error!("Command JSON was: {:?}", command_json);
                                        
                                        // Log failed command
                                        if let Some(session_id) = from_session {
                                            log_remote_command(
                                                session_id,
                                                "unknown",
                                                false,
                                                &format!("parse_error={}", e)
                                            );
                                        }
                                        
                                        // Send error response
                                        let error_response = serde_json::json!({
                                            "type": "remote_command_response",
                                            "request_id": request_id,
                                            "success": false,
                                            "error": {
                                                "code": "INVALID_COMMAND",
                                                "message": format!("Failed to parse command: {}", e)
                                            }
                                        });
                                        
                                        let _ = write.send(Message::Text(error_response.to_string())).await;
                                    }
                                }
                            } else {
                                error!("No 'command' field in message");
                                
                                // Send error response
                                let error_response = serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": false,
                                    "error": {
                                        "code": "MISSING_COMMAND",
                                        "message": "Command field is missing"
                                    }
                                });
                                
                                let _ = write.send(Message::Text(error_response.to_string())).await;
                            }
                        } else {
                            error!("Failed to parse JSON message");
                        }
                    } else {
                        warn!("Remote management is disabled");
                        
                        // If remote management is disabled, also send response
                        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(text) {
                            if let Some(request_id) = json_value.get("request_id").and_then(|v| v.as_str()) {
                                let error_response = serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": false,
                                    "error": {
                                        "code": "REMOTE_MANAGEMENT_DISABLED",
                                        "message": "Remote management is disabled on this node"
                                    }
                                });
                                
                                let _ = write.send(Message::Text(error_response.to_string())).await;
                            }
                        }
                    }
                    
                    info!("=== REMOTE COMMAND PROCESSING COMPLETE ===");
                }

                Some("remote_auth") => {
                    info!("Received remote_auth message");
                    
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(text) {
                        let jwt_token = json_value.get("jwt_token")
                            .and_then(|v| v.as_str());
                        
                        if let Some(token) = jwt_token {
                            info!("Remote auth JWT token received, length: {}", token.len());
                            
                            // TODO: In production, you should verify the JWT token here
                            // For now, we'll accept it and enable remote management
                            
                            // Enable remote management for this session
                            *self.remote_management_enabled.write().await = true;
                            
                            // Send success response
                            let success_response = serde_json::json!({
                                "type": "remote_auth_success",
                                "message": "Remote authentication successful"
                            });
                            
                            write.send(Message::Text(success_response.to_string())).await
                                .map_err(|e| format!("Failed to send remote auth response: {}", e))?;
                            
                            info!("Remote auth success response sent, remote management enabled");
                        } else {
                            // JWT token missing
                            let error_response = serde_json::json!({
                                "type": "error",
                                "error_code": "MISSING_JWT",
                                "message": "JWT token is required for remote authentication"
                            });
                            
                            write.send(Message::Text(error_response.to_string())).await
                                .map_err(|e| format!("Failed to send error response: {}", e))?;
                        }
                    }
                }
                
                Some("status_request") => {
                    // Server requesting current status
                    let status_update = WebSocketMessage::StatusUpdate {
                        status: "active".to_string(),
                    };
                    
                    let status_json = serde_json::to_string(&status_update)
                        .map_err(|e| format!("Failed to serialize status: {}", e))?;
                    
                    write.send(Message::Text(status_json)).await
                        .map_err(|e| format!("Failed to send status update: {}", e))?;
                }
                
                _ => {
                    debug!("Unknown message type: {:?}", json.get("type"));
                }
            }
        } else {
            warn!("Received non-JSON WebSocket message: {}", text);
        }
        
        Ok(())
    }

    /// Handle remote command execution
    async fn handle_remote_command(
        &self,
        json: &serde_json::Value,
        write: &mut WsSink,
    ) -> Result<(), String> {
        let request_id = json.get("request_id")
            .and_then(|id| id.as_str())
            .unwrap_or("unknown")
            .to_string();
        
        info!("Processing remote command with request ID: {}", request_id);
        
        // Parse remote command data from the command field instead of parameters
        if let Some(command_data) = json.get("command") {
            match serde_json::from_value::<RemoteCommandData>(command_data.clone()) {
                Ok(remote_cmd_data) => {
                    info!("Executing remote command: {:?}", remote_cmd_data);
                    
                    // Use the new remote command handler
                    let handler = self.remote_command_handler.clone();
                    let response = handler.handle_command(
                        request_id.clone(),
                        remote_cmd_data
                    ).await;
                    
                    // Send response back using RemoteCommandResponse
                    let response_msg = WebSocketMessage::RemoteCommandResponse {
                        response,
                    };
                    
                    let response_json = serde_json::to_string(&response_msg)
                        .map_err(|e| format!("Failed to serialize response: {}", e))?;
                    
                    write.send(Message::Text(response_json)).await
                        .map_err(|e| format!("Failed to send command response: {}", e))?;
                }
                Err(e) => {
                    warn!("Invalid remote command format: {}", e);
                    
                    // Send error response
                    let error_response = crate::remote_command_handler::RemoteCommandResponse {
                        request_id,
                        success: false,
                        result: None,
                        error: Some(RemoteCommandError {
                            code: "INVALID_COMMAND".to_string(),
                            message: format!("Invalid command format: {}", e),
                            details: None,
                        }),
                        executed_at: chrono::Utc::now().to_rfc3339(),
                    };
                    
                    let response_msg = WebSocketMessage::RemoteCommandResponse {
                        response: error_response,
                    };
                    
                    let response_json = serde_json::to_string(&response_msg)
                        .map_err(|e| format!("Failed to serialize error response: {}", e))?;
                    
                    write.send(Message::Text(response_json)).await
                        .map_err(|e| format!("Failed to send error response: {}", e))?;
                }
            }
        } else {
            warn!("Remote command missing command data");
            
            // Send error response
            let error_response = crate::remote_command_handler::RemoteCommandResponse {
                request_id,
                success: false,
                result: None,
                error: Some(RemoteCommandError {
                    code: "INVALID_COMMAND".to_string(),
                    message: "Missing command data".to_string(),
                    details: None,
                }),
                executed_at: chrono::Utc::now().to_rfc3339(),
            };
            
            let response_msg = WebSocketMessage::RemoteCommandResponse {
                response: error_response,
            };
            
            let response_json = serde_json::to_string(&response_msg)
                .map_err(|e| format!("Failed to serialize error response: {}", e))?;
            
            write.send(Message::Text(response_json)).await
                .map_err(|e| format!("Failed to send error response: {}", e))?;
        }
        
        Ok(())
    }

    /// Handle ZKP challenge
    pub(super) async fn handle_zkp_challenge(
        &self,
        challenge_id: &str,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
        write: &mut WsSink,
    ) -> Result<(), String> {
        use crate::zkp_halo2;
        
        info!("Generating ZKP proof for challenge ID: {}", challenge_id);
        
        // Generate commitment
        let commitment = hardware_info.generate_zkp_commitment();
        
        // Generate proof
        let proof = zkp_halo2::generate_hardware_proof(hardware_info, &commitment, setup_params)
            .await
            .map_err(|e| format!("Failed to generate proof: {}", e))?;
        
        // Send response in the expected format
        let response = serde_json::json!({
            "type": "challenge_response",
            "challenge_id": challenge_id,
            "proof": {
                "data": hex::encode(&proof.data),
                "public_inputs": hex::encode(&proof.public_inputs),
                "timestamp": proof.timestamp,
            }
        });
        
        write.send(Message::Text(response.to_string())).await
            .map_err(|e| format!("Failed to send challenge response: {}", e))?;
        
        info!("Successfully sent ZKP proof for challenge {}", challenge_id);
        Ok(())
    }

    /// Handle server messages with ZKP support
    pub(super) async fn handle_server_message(
        &self,
        message: ServerMessage,
        write: &mut WsSink,
        authenticated: &mut bool,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        use crate::zkp_halo2;
        
        match message {
            ServerMessage::ConnectionEstablished | ServerMessage::Connected { .. } => {
                info!("Connection established, sending authentication");
                
                let auth_code = self.reference_code.clone()
                    .or_else(|| self.registration_code.clone())
                    .ok_or("No authentication code available")?;
                
                let auth_msg = ClientMessage::Auth {
                    code: auth_code,
                };
                
                let auth_json = serde_json::to_string(&auth_msg)
                    .map_err(|e| format!("Failed to serialize auth: {}", e))?;
                write.send(Message::Text(auth_json)).await
                    .map_err(|e| format!("Failed to send auth: {}", e))?;
            }
            
            ServerMessage::AuthSuccess { heartbeat_interval, node_info: _ } => {
                info!("Authentication successful");
                *authenticated = true;
                
                if let Some(interval) = heartbeat_interval {
                    info!("Heartbeat interval: {} seconds", interval);
                }
            }
            
            ServerMessage::AuthResponse { success, message, node_info: _ } => {
                if success {
                    info!("Authentication successful");
                    *authenticated = true;
                } else {
                    let err_msg = message.unwrap_or_else(|| "Authentication failed".to_string());
                    error!("Authentication failed: {}", err_msg);
                    return Err(format!("Authentication failed: {}", err_msg));
                }
            }
            
            ServerMessage::RemoteCommand { request_id, command, from_session } => {
                info!("=== REMOTE COMMAND RECEIVED (ServerMessage) ===");
                info!("Request ID: {}", request_id);
                info!("From session: {}", from_session);
                info!("Command: {:?}", command);
                
                if *self.remote_management_enabled.read().await {
                    match serde_json::from_value::<RemoteCommandData>(command.clone()) {
                        Ok(command_data) => {
                            info!("Processing remote command: type={}", command_data.command_type);
                            
                            // Log the command execution
                            log_remote_command(
                                &from_session,
                                &command_data.command_type,
                                true,
                                &format!("request_id={}", request_id)
                            );
                            
                            // Execute command
                            let handler = self.remote_command_handler.clone();
                            let response = handler.handle_command(
                                request_id.clone(), 
                                command_data
                            ).await;
                            
                            // Build response message
                            let response_msg = if response.success {
                                serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": true,
                                    "result": response.result,
                                    "executed_at": response.executed_at
                                })
                            } else {
                                serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": false,
                                    "error": response.error,
                                    "executed_at": response.executed_at
                                })
                            };
                            
                            // Send response
                            info!("Sending remote command response for request_id: {}", request_id);
                            let response_json = response_msg.to_string();
                            
                            write.send(Message::Text(response_json)).await
                                .map_err(|e| format!("Failed to send response: {}", e))?;
                            
                            info!("Response sent successfully");
                        }
                        Err(e) => {
                            error!("Failed to parse remote command: {}", e);
                            
                            // Send error response
                            let error_response = serde_json::json!({
                                "type": "remote_command_response",
                                "request_id": request_id,
                                "success": false,
                                "error": {
                                    "code": "INVALID_COMMAND",
                                    "message": format!("Failed to parse command: {}", e)
                                }
                            });
                            
                            write.send(Message::Text(error_response.to_string())).await
                                .map_err(|e| format!("Failed to send error response: {}", e))?;
                        }
                    }
                } else {
                    warn!("Remote management is disabled");
                    
                    let error_response = serde_json::json!({
                        "type": "remote_command_response",
                        "request_id": request_id,
                        "success": false,
                        "error": {
                            "code": "REMOTE_MANAGEMENT_DISABLED",
                            "message": "Remote management is disabled on this node"
                        }
                    });
                    
                    write.send(Message::Text(error_response.to_string())).await
                        .map_err(|e| format!("Failed to send error response: {}", e))?;
                }
            }
            
            ServerMessage::RemoteAuth { jwt_token } => {
                info!("Received remote_auth message");
                info!("Remote auth JWT token received, length: {}", jwt_token.len());
                
                // Enable remote management for this session
                *self.remote_management_enabled.write().await = true;
                
                // Send success response
                let success_response = serde_json::json!({
                    "type": "remote_auth_success",
                    "message": "Remote authentication successful"
                });
                
                write.send(Message::Text(success_response.to_string())).await
                    .map_err(|e| format!("Failed to send remote auth response: {}", e))?;
                
                info!("Remote auth success response sent, remote management enabled");
            }
            
            ServerMessage::ChallengeRequest { challenge_id, nonce: _ } => {
                info!("✅ Received ZKP challenge request with ID: {}", challenge_id);
                
                let commitment = hardware_info.generate_zkp_commitment();
                
                match zkp_halo2::generate_hardware_proof(hardware_info, &commitment, setup_params).await {
                    Ok(proof) => {
                        let response = ClientMessage::ChallengeResponse {
                            challenge_id: challenge_id.clone(),
                            proof: ProofData::from(&proof),
                        };
                        
                        let response_json = serde_json::to_string(&response)
                            .map_err(|e| format!("Failed to serialize response: {}", e))?;
                        write.send(Message::Text(response_json)).await
                            .map_err(|e| format!("Failed to send challenge response: {}", e))?;
                        
                        info!("🚀 Successfully sent proof for challenge {}", challenge_id);
                    }
                    Err(e) => {
                        error!("❌ Failed to generate proof: {}", e);
                    }
                }
            }
            
            ServerMessage::ChallengeResponseAck { challenge_id, status, message: _ } => {
                info!("Server acknowledged proof for challenge {}: {}", challenge_id, status);
            }
            
            ServerMessage::HeartbeatAck { received_at: _, next_interval: _ } => {
                debug!("Heartbeat acknowledged");
                // Don't update timestamp here - it needs to be updated in the caller
            }
            
            ServerMessage::Error { error_code, message } => {
                error!("Server error [{}]: {}", error_code, message);
            }
            
            ServerMessage::Unknown => {
                debug!("Received unknown message type");
            }
        }
        
        Ok(())
    }

    /// Handle generic JSON messages (for messages not matching ServerMessage enum)
    pub(super) async fn handle_generic_message(
        &self,
        text: &str,
        write: &mut WsSink,
        authenticated: &mut bool,
        auth_sent: &mut bool,
        heartbeat_interval: &mut time::Interval,
        last_heartbeat_ack: &mut std::time::Instant,
        terminal_output_channels: &mut HashMap<String, mpsc::Receiver<TerminalMessage>>,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(msg_type) = json.get("type").and_then(|t| t.as_str()) {
                info!("Processing generic message type: {}", msg_type);
                
                match msg_type {
                    "connected" | "connection_established" => {
                        info!("Received connection confirmation from server");
                        
                        if !*auth_sent {
                            // Send authentication using the simplified format
                            let auth_code = self.reference_code.clone()
                                .or_else(|| self.registration_code.clone())
                                .ok_or("No authentication code available")?;
                            
                            let auth_msg = serde_json::json!({
                                "type": "auth",
                                "code": auth_code
                            });
                            
                            info!("Sending authentication with code: {}...", 
                                  &auth_code[..8.min(auth_code.len())]);
                            
                            write.send(Message::Text(auth_msg.to_string())).await
                                .map_err(|e| format!("Failed to send auth: {}", e))?;
                            
                            *auth_sent = true;
                        }
                    }
                    
                    "auth_success" | "auth_response" => {
                        let success = json.get("success")
                            .and_then(|s| s.as_bool())
                            .unwrap_or(true); // Default to true for "auth_success"
                        
                        if success {
                            info!("Authentication successful");
                            *authenticated = true;
                            *last_heartbeat_ack = std::time::Instant::now();
                            
                            // Update heartbeat interval if provided
                            if let Some(interval) = json.get("heartbeat_interval")
                                .and_then(|v| v.as_u64()) {
                                *heartbeat_interval = time::interval(Duration::from_secs(interval));
                                info!("Heartbeat interval set to {} seconds", interval);
                            }
                        } else {
                            let message = json.get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Authentication failed");
                            error!("Authentication failed: {}", message);
                            return Err(format!("Authentication failed: {}", message));
                        }
                    }
                    
                    "heartbeat_ack" | "heartbeat_response" => {
                        debug!("Heartbeat acknowledged");
                        *last_heartbeat_ack = std::time::Instant::now();
                    }
                    
                    "challenge_request" | "CHALLENGE_REQUEST" => {
                        info!("Received ZKP challenge request");
                        
                        let challenge_id = json.get("challenge_id")
                            .or_else(|| json.get("payload")
                                .and_then(|p| p.get("challenge_id")))
                            .and_then(|id| id.as_str())
                            .unwrap_or("unknown");
                        
                        // Generate and send ZKP proof
                        if let Err(e) = self.handle_zkp_challenge(
                            challenge_id,
                            hardware_info,
                            setup_params,
                            write
                        ).await {
                            error!("Failed to handle ZKP challenge: {}", e);
                        }
                    }
                    
                    "term_init" | "term_input" | "term_resize" | "term_close" => {
                        info!("=== TERMINAL MESSAGE DETECTED ===");
                        
                        // Check if remote management is enabled
                        if !*self.remote_management_enabled.read().await {
                            let error_response = serde_json::json!({
                                "type": "term_error",
                                "session_id": json.get("session_id").and_then(|s| s.as_str()).unwrap_or("unknown"),
                                "error": "Remote management is disabled"
                            });
                            
                            if let Err(e) = write.send(Message::Text(error_response.to_string())).await {
                                error!("Failed to send error response: {}", e);
                            }
                            return Ok(());
                        }
                        
                        // Parse terminal message
                        if let Ok(term_msg) = serde_json::from_str::<TerminalMessage>(text) {
                            // Get or create terminal manager
                            let terminal_manager = self.get_terminal_manager();
                            
                            match handle_terminal_message(&terminal_manager, term_msg).await {
                                Ok(Some(response)) => {
                                    let response_json = serde_json::to_string(&response)
                                        .unwrap_or_else(|_| "{}".to_string());
                                    
                                    if let Err(e) = write.send(Message::Text(response_json)).await {
                                        error!("Failed to send terminal response: {}", e);
                                    }
                                    
                                    // If this was an init message, start output reader
                                    if let TerminalMessage::Ready { session_id } = response {
                                        // Create channel for terminal output
                                        let (tx, rx) = mpsc::channel::<TerminalMessage>(100);
                                        
                                        // Store the receiver
                                        terminal_output_channels.insert(session_id.clone(), rx);
                                        
                                        // Start output reader
                                        self.start_terminal_output_reader(
                                            terminal_manager.clone(),
                                            session_id,
                                            tx
                                        ).await;
                                    }
                                }
                                Ok(None) => {
                                    // No response needed
                                }
                                Err(e) => {
                                    error!("Terminal message handling error: {}", e);
                                    
                                    let error_response = serde_json::json!({
                                        "type": "term_error",
                                        "error": e.to_string()
                                    });
                                    
                                    let _ = write.send(Message::Text(error_response.to_string())).await;
                                }
                            }
                        } else {
                            error!("Failed to parse terminal message");
                        }
                    }
                    
                    "remote_command" => {
                        info!("=== REMOTE COMMAND DETECTED ===");
                        info!("Full remote command JSON: {}", serde_json::to_string_pretty(&json).unwrap_or_default());
                        
                        // Call the existing handler
                        if let Err(e) = self.handle_websocket_message(
                            text,
                            write,
                            authenticated,
                            heartbeat_interval,
                            last_heartbeat_ack
                        ).await {
                            error!("Failed to handle remote command: {}", e);
                        }
                    }
                    
                    "remote_auth" => {
                        info!("=== REMOTE AUTH DETECTED ===");
                        
                        // Also handle remote_auth through the legacy handler
                        if let Err(e) = self.handle_websocket_message(
                            text,
                            write,
                            authenticated,
                            heartbeat_interval,
                            last_heartbeat_ack
                        ).await {
                            error!("Failed to handle remote auth: {}", e);
                        }
                    }
                    
                    "error" => {
                        let error_code = json.get("error_code")
                            .and_then(|c| c.as_str())
                            .unwrap_or("unknown");
                        let message = json.get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Unknown error");
                        
                        error!("Server error [{}]: {}", error_code, message);
                        
                        // Handle specific errors
                        if message.contains("Message too large") {
                            warn!("Command output exceeded size limit. Consider using pagination or filtering.");
                        }
                        
                        if error_code == "AUTH_TIMEOUT" || 
                           error_code == "INVALID_CODE" || 
                           error_code == "auth_failed" {
                            return Err(format!("Authentication error: {}", message));
                        }
                    }
                    
                    _ => {
                        info!("Unhandled message type: {}, trying legacy handler", msg_type);
                        
                        // For any other message type, try the legacy handler
                        if let Err(e) = self.handle_websocket_message(
                            text,
                            write,
                            authenticated,
                            heartbeat_interval,
                            last_heartbeat_ack
                        ).await {
                            error!("Legacy handler failed: {}", e);
                        }
                    }
                }
            } else {
                warn!("Message without type field: {:?}", json);
            }
        } else {
            warn!("Non-JSON message: {}", text);
        }
        
        Ok(())
    }
}
