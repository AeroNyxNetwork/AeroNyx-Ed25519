// src/server/client.rs
//! Client connection handling.
//!
//! This module handles individual client connections, including authentication,
//! session setup, and message processing.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use futures::{SinkExt, StreamExt};
use tokio::sync::RwLock;
use tokio::time;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, trace, warn};

use crate::auth::AuthManager;
use crate::crypto::{KeyManager, SessionKeyManager};
use crate::network::{IpPoolManager, NetworkMonitor};
use crate::protocol::PacketType;
use crate::protocol::serialization::{packet_to_ws_message, ws_message_to_packet, create_error_packet, create_disconnect_packet, log_packet_info};
use crate::server::session::{ClientSession, SessionManager, SessionError};
use crate::server::routing::PacketRouter;
use crate::server::metrics::ServerMetricsCollector;
use crate::server::core::{ServerError, ServerState};
use crate::utils::{current_timestamp_millis, random_string};
use crate::utils::security::StringValidator;
use solana_sdk::pubkey::Pubkey;

/// Handle a client connection
pub async fn handle_client(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    tls_acceptor: Arc<TlsAcceptor>,
    key_manager: Arc<KeyManager>,
    auth_manager: Arc<AuthManager>,
    ip_pool: Arc<IpPoolManager>,
    session_manager: Arc<SessionManager>,
    session_key_manager: Arc<SessionKeyManager>,
    network_monitor: Arc<NetworkMonitor>,
    packet_router: Arc<PacketRouter>,
    metrics: Arc<ServerMetricsCollector>,
    server_state: Arc<RwLock<ServerState>>,
) -> Result<(), ServerError> {
    // Record TLS handshake start in metrics
    metrics.record_handshake_start().await;
    
    // Perform TLS handshake
    let tls_stream = match tls_acceptor.accept(stream).await {
        Ok(stream) => {
            // Record successful handshake
            metrics.record_handshake_complete().await;
            debug!("TLS handshake successful with {}", addr);
            stream
        }
        Err(e) => {
            // Record failed handshake
            metrics.record_handshake_complete().await;
            return Err(ServerError::Tls(format!("TLS handshake failed: {}", e)));
        }
    };
    
    // Upgrade connection to WebSocket
    let ws_stream = match tokio_tungstenite::accept_async(tls_stream).await {
        Ok(stream) => {
            debug!("WebSocket connection established with {}", addr);
            stream
        }
        Err(e) => {
            return Err(ServerError::WebSocket(e));
        }
    };
    
    // Split the WebSocket stream
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    
    // Wait for authentication
    let public_key_string = match ws_receiver.next().await {
        Some(Ok(msg)) => {
            match ws_message_to_packet(&msg) {
                Ok(PacketType::Auth { public_key, version, features, nonce }) => {
                    debug!("Auth request from {}, version: {}, features: {:?}", public_key, version, features);
                    
                    // Verify public key format
                    if !StringValidator::is_valid_solana_pubkey(&public_key) {
                        // Send error response
                        let error = create_error_packet(1001, "Invalid public key format");
                        ws_sender.send(packet_to_ws_message(&error)?).await?;
                        
                        metrics.record_auth_failure().await;
                        return Err(ServerError::Authentication("Invalid public key format".to_string()));
                    }
                    
                    // Generate challenge
                    let challenge = match auth_manager.generate_challenge(&addr.to_string()).await {
                        Ok(challenge) => challenge,
                        Err(e) => {
                            let error = create_error_packet(1001, &format!("Failed to generate challenge: {}", e));
                            ws_sender.send(packet_to_ws_message(&error)?).await?;
                            
                            metrics.record_auth_failure().await;
                            return Err(ServerError::Challenge(e));
                        }
                    };
                    
                    // Get server public key
                    let server_pubkey = key_manager.public_key().await.to_string();
                    
                    // Create challenge packet
                    let challenge_packet = PacketType::Challenge {
                        data: challenge.1.clone(),
                        server_key: server_pubkey,
                        expires_at: current_timestamp_millis() + 30000, // 30 seconds
                        id: challenge.0.clone(),
                    };
                    
                    // Send challenge
                    ws_sender.send(packet_to_ws_message(&challenge_packet)?).await?;
                    
                    // Wait for challenge response
                    match ws_receiver.next().await {
                        Some(Ok(msg)) => {
                            match ws_message_to_packet(&msg) {
                                Ok(PacketType::ChallengeResponse { signature, public_key: resp_pubkey, challenge_id }) => {
                                    // Verify it's the same public key
                                    if resp_pubkey != public_key {
                                        let error = create_error_packet(1001, "Public key mismatch");
                                        ws_sender.send(packet_to_ws_message(&error)?).await?;
                                        
                                        metrics.record_auth_failure().await;
                                        return Err(ServerError::Authentication("Public key mismatch".to_string()));
                                    }
                                    
                                    // Verify the challenge
                                    match auth_manager.verify_challenge(
                                        &challenge_id,
                                        &signature,
                                        &public_key,
                                        &addr.to_string(),
                                    ).await {
                                        Ok(_) => {
                                            debug!("Challenge successfully verified for {}", public_key);
                                            
                                            // Verify access is allowed
                                            if !auth_manager.is_client_allowed(&public_key).await {
                                                let error = create_error_packet(1005, "Access denied by ACL");
                                                ws_sender.send(packet_to_ws_message(&error)?).await?;
                                                
                                                metrics.record_auth_failure().await;
                                                return Err(ServerError::Authentication("Access denied by ACL".to_string()));
                                            }
                                            
                                            // Authentication successful
                                            metrics.record_auth_success().await;
                                            info!("Client {} authenticated successfully", public_key);
                                            
                                            // Return the public key for session creation
                                            public_key
                                        }
                                        Err(e) => {
                                            let error = create_error_packet(1001, &format!("Challenge verification failed: {}", e));
                                            ws_sender.send(packet_to_ws_message(&error)?).await?;
                                            
                                            metrics.record_auth_failure().await;
                                            return Err(ServerError::Challenge(e));
                                        }
                                    }
                                }
                                Ok(_) => {
                                    let error = create_error_packet(1002, "Expected challenge response");
                                    ws_sender.send(packet_to_ws_message(&error)?).await?;
                                    
                                    metrics.record_auth_failure().await;
                                    return Err(ServerError::Authentication("Expected challenge response".to_string()));
                                }
                                Err(e) => {
                                    let error = create_error_packet(1002, &format!("Invalid message: {}", e));
                                    ws_sender.send(packet_to_ws_message(&error)?).await?;
                                    
                                    metrics.record_auth_failure().await;
                                    return Err(ServerError::Protocol(e));
                                }
                            }
                        }
                        Some(Err(e)) => {
                            metrics.record_auth_failure().await;
                            return Err(ServerError::WebSocket(e));
                        }
                        None => {
                            metrics.record_auth_failure().await;
                            return Err(ServerError::Authentication("WebSocket closed during authentication".to_string()));
                        }
                    }
                }
                Ok(_) => {
                    let error = create_error_packet(1002, "Expected authentication message");
                    ws_sender.send(packet_to_ws_message(&error)?).await?;
                    
                    metrics.record_auth_failure().await;
                    return Err(ServerError::Authentication("Expected authentication message".to_string()));
                }
                Err(e) => {
                    let error = create_error_packet(1002, &format!("Invalid message: {}", e));
                    ws_sender.send(packet_to_ws_message(&error)?).await?;
                    
                    metrics.record_auth_failure().await;
                    return Err(ServerError::Protocol(e));
                }
            }
        }
        Some(Err(e)) => {
            metrics.record_auth_failure().await;
            return Err(ServerError::WebSocket(e));
        }
        None => {
            metrics.record_auth_failure().await;
            return Err(ServerError::Authentication("WebSocket closed before authentication".to_string()));
        }
    };
    
    // Reunite the WebSocket stream for easier handling
    let ws_stream = ws_sender.reunite(ws_receiver)
        .map_err(|_| ServerError::Internal("Failed to reunite WebSocket stream".to_string()))?;
        
    // Assign IP address
    let ip_address = match ip_pool.allocate_ip(&public_key_string).await {
        Ok(ip) => {
            debug!("Assigned IP {} to client {}", ip, public_key_string);
            ip
        }
        Err(e) => {
            let error = create_error_packet(1007, &format!("Failed to allocate IP: {}", e));
            let mut stream = ws_stream;
            stream.send(packet_to_ws_message(&error)?).await?;
            
            return Err(ServerError::Network(format!("IP allocation failed: {}", e)));
        }
    };
    
    // Generate session ID
    let session_id = format!("session_{}", random_string(16));
    
    // Generate session key
    let session_key = SessionKeyManager::generate_key();
    
    // Store session key
    session_key_manager.store_key(&public_key_string, session_key.clone()).await;
    
    // Get shared secret for encrypting session key
    let pubkey = Pubkey::from_str(&public_key_string)
        .map_err(|e| ServerError::KeyError(format!("Invalid public key: {}", e)))?;
    let shared_secret = match key_manager.get_shared_secret(&pubkey).await {
        Ok(secret) => secret,
        Err(e) => {
            let error = create_error_packet(1006, &format!("Failed to derive shared secret: {}", e));
            let mut stream = ws_stream;
            stream.send(packet_to_ws_message(&error)?).await?;
            
            // Release the IP
            if let Err(e) = ip_pool.release_ip(&ip_address).await {
                warn!("Failed to release IP {}: {}", ip_address, e);
            }
            
            return Err(ServerError::KeyError(format!("Failed to derive shared secret: {}", e)));
        }
    };
    
    // Encrypt session key
    let (encrypted_key, key_nonce) = match crate::crypto::encryption::encrypt_session_key(
        &session_key,
        &shared_secret,
    ) {
        Ok((encrypted, nonce)) => (encrypted, nonce),
        Err(e) => {
            let error = create_error_packet(1006, &format!("Encryption failed: {}", e));
            let mut stream = ws_stream;
            stream.send(packet_to_ws_message(&error)?).await?;
            
            // Release the IP
            if let Err(e) = ip_pool.release_ip(&ip_address).await {
                warn!("Failed to release IP {}: {}", ip_address, e);
            }
            
            return Err(ServerError::Internal(format!("Failed to encrypt session key: {}", e)));
        }
    };
    
    // Create IP assignment packet
    let ip_assign = PacketType::IpAssign {
        ip_address: ip_address.clone(),
        lease_duration: ip_pool.get_default_lease_duration().as_secs(),
        session_id: session_id.clone(),
        encrypted_session_key: encrypted_key,
        key_nonce,
    };
    
    // Send IP assignment
    {
        let mut stream = ws_stream;
        stream.send(packet_to_ws_message(&ip_assign)?).await?;
    }
    
    // Create client session
    let session = match ClientSession::new(
        session_id.clone(),
        public_key_string.clone(),
        ip_address.clone(),
        addr,
        ws_stream,
    ) {
        Ok(session) => session,
        Err(e) => {
            // Release the IP
            if let Err(ip_err) = ip_pool.release_ip(&ip_address).await {
                warn!("Failed to release IP {}: {}", ip_address, ip_err);
            }
            
            return Err(ServerError::Session(e));
        }
    };
    
    // Register the session
    session_manager.add_session(session.clone()).await;
    
    // Process client messages
    process_client_session(
        session,
        key_manager,
        session_key_manager,
        packet_router,
        network_monitor,
        ip_pool,
        session_manager,
        server_state,
    ).await?;
    
    Ok(())
}

/// Process messages from an authenticated client session
async fn process_client_session(
    session: ClientSession,
    key_manager: Arc<KeyManager>,
    session_key_manager: Arc<SessionKeyManager>,
    packet_router: Arc<PacketRouter>,
    network_monitor: Arc<NetworkMonitor>,
    ip_pool: Arc<IpPoolManager>,
    session_manager: Arc<SessionManager>,
    server_state: Arc<RwLock<ServerState>>,
) -> Result<(), ServerError> {
    let client_id = session.client_id.clone();
    let session_id = session.id.clone();
    let ip_address = session.ip_address.clone();
    let _address = session.address;
    
    // Setup heartbeat task
    let heartbeat_interval = Duration::from_secs(30);
    let session_clone = session.clone();
    let client_id_for_heartbeat = client_id.clone();
    
    // Start heartbeat task
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = time::interval(heartbeat_interval);
        let mut sequence: u64 = 0;
        
        loop {
            interval.tick().await;
            
            // Create ping packet
            let ping = PacketType::Ping {
                timestamp: current_timestamp_millis(),
                sequence,
            };
            
            // Send ping
            if let Err(e) = session_clone.send_packet(&ping).await {
                warn!("Failed to send heartbeat to {}: {}", client_id_for_heartbeat, e);
                break;
            }
            
            sequence += 1;
        }
    });
    
    // Setup key rotation task
    let rotation_interval = Duration::from_secs(3600); // 1 hour
    let session_clone = session.clone();
    let session_key_manager_clone = session_key_manager.clone();
    let key_manager_clone = key_manager.clone();
    let client_id_for_rotation = client_id.clone();
    
    // Start key rotation task
    let key_rotation_handle = tokio::spawn(async move {
        let mut interval = time::interval(rotation_interval);
        
        loop {
            interval.tick().await;
            
            // Skip if not needed
            if !session_key_manager_clone.needs_rotation(&client_id_for_rotation).await {
                continue;
            }
            
            debug!("Rotating session key for client {}", client_id_for_rotation);
            
            // Generate new key
            let new_key = SessionKeyManager::generate_key();
            
            // Get current session key
            if let Some(current_key) = session_key_manager_clone.get_key(&client_id_for_rotation).await {
                // Encrypt the new key with the current key
                match crate::crypto::encryption::encrypt_chacha20(&new_key, &current_key, None) {
                    Ok((encrypted_key, nonce)) => {
                        // Create a key ID for verification
                        let key_id = random_string(16);
                        
                        // Create signature data
                        let mut sign_data = key_id.clone().into_bytes();
                        sign_data.extend_from_slice(&nonce);
                        
                        // Sign with server key
                        let signature = key_manager_clone.sign_message(&sign_data).await;
                        
                        // Create key rotation packet
                        let rotation = PacketType::KeyRotation {
                            encrypted_new_key: encrypted_key,
                            nonce,
                            key_id,
                            signature: signature.to_string(),
                        };
                        
                        // Send key rotation
                        if let Err(e) = session_clone.send_packet(&rotation).await {
                            warn!("Failed to send key rotation to {}: {}", client_id_for_rotation, e);
                            break;
                        }
                        
                        // Update the key
                        session_key_manager_clone.store_key(&client_id_for_rotation, new_key).await;
                        debug!("Session key rotated for client {}", client_id_for_rotation);
                    }
                    Err(e) => {
                        warn!("Failed to encrypt new session key: {}", e);
                    }
                }
            }
        }
    });
    
    // Get stream for processing
    let mut stream = match session.take_stream().await {
        Ok(stream) => stream,
        Err(e) => {
            // Clean up background tasks
            heartbeat_handle.abort();
            key_rotation_handle.abort();
            
            // Remove session
            session_manager.remove_session(&session_id).await;
            
            // Release IP
            if let Err(ip_err) = ip_pool.release_ip(&ip_address).await {
                warn!("Failed to release IP {}: {}", ip_address, ip_err);
            }
            
            return match e {
                SessionError::StreamConsumed => Err(ServerError::Internal("Stream already consumed".to_string())),
                _ => Err(ServerError::Session(e)),
            };
        }
    };
    
    let mut last_counter: Option<u64> = None;
    
    while let Some(result) = stream.next().await {
        // Check server state
        let current_state = *server_state.read().await;
        if current_state != ServerState::Running {
            // Send disconnect notification
            let disconnect = create_disconnect_packet(2, "Server shutting down");
            stream.send(packet_to_ws_message(&disconnect)?).await.ok();
            break;
        }
        
        match result {
            Ok(msg) => {
                // Update session activity
                session_manager.touch_session(&session_id).await?;
                
                match ws_message_to_packet(&msg) {
                    Ok(packet) => {
                        // Log packet (security filtered)
                        log_packet_info(&packet, true);
                        
                        match packet {
                            PacketType::Data { encrypted, nonce, counter, padding: _ } => {
                                // Check for replay attacks
                                if let Some(last) = last_counter {
                                    if counter <= last && counter != 0 { // Allow wrap-around
                                        warn!("Potential replay attack detected from {}: counter {} <= {}", client_id, counter, last);
                                        continue;
                                    }
                                }
                                last_counter = Some(counter);
                                
                                // Get session key
                                if let Some(key) = session_key_manager.get_key(&client_id).await {
                                    // Decrypt and process the packet
                                    match packet_router.handle_inbound_packet(
                                        &encrypted,
                                        &nonce,
                                        &key,
                                        &session,
                                    ).await {
                                        Ok(bytes_written) => {
                                            // Record traffic
                                            network_monitor.record_client_traffic(&client_id, 0, bytes_written as u64).await;
                                            network_monitor.record_sent(bytes_written as u64).await;
                                        }
                                        Err(e) => {
                                            trace!("Failed to process inbound packet from {}: {}", client_id, e);
                                        }
                                    }
                                } else {
                                    warn!("No session key found for client {}", client_id);
                                }
                            }
                            PacketType::Ping { timestamp, sequence } => {
                                // Respond with pong
                                let pong = PacketType::Pong {
                                    echo_timestamp: timestamp,
                                    server_timestamp: current_timestamp_millis(),
                                    sequence,
                                };
                                
                                if let Err(e) = session.send_packet(&pong).await {
                                    warn!("Failed to send pong to {}: {}", client_id, e);
                                }
                            }
                            PacketType::Pong { echo_timestamp, server_timestamp: _, sequence: _ } => {
                                // Calculate RTT
                                let now = current_timestamp_millis();
                                let rtt = now - echo_timestamp;
                                
                                // Record latency
                                network_monitor.record_latency(&client_id, rtt as f64).await;
                            }
                            PacketType::IpRenewal { session_id: renewal_id, ip_address: renewal_ip } => {
                                // Verify session ID
                                if renewal_id != session_id {
                                    warn!("IP renewal with mismatched session ID from {}", client_id);
                                    continue;
                                }
                                
                                // Verify IP address
                                if renewal_ip != ip_address {
                                    warn!("IP renewal with mismatched IP from {}", client_id);
                                    continue;
                                }
                                
                                // Renew IP lease
                                match ip_pool.renew_ip(&ip_address).await {
                                    Ok(expires_at) => {
                                        debug!("Renewed IP lease for {} until {}", client_id, expires_at);
                                        
                                        // Send renewal response
                                        let response = PacketType::IpRenewalResponse {
                                            session_id: session_id.clone(),
                                            expires_at,
                                            success: true,
                                        };
                                        
                                        if let Err(e) = session.send_packet(&response).await {
                                            warn!("Failed to send IP renewal response to {}: {}", client_id, e);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to renew IP lease for {}: {}", client_id, e);
                                        
                                        // Send failure response
                                        let response = PacketType::IpRenewalResponse {
                                            session_id: session_id.clone(),
                                            expires_at: 0,
                                            success: false,
                                        };
                                        
                                        if let Err(e) = session.send_packet(&response).await {
                                            warn!("Failed to send IP renewal response to {}: {}", client_id, e);
                                        }
                                    }
                                }
                            }
                            PacketType::Disconnect { reason, message } => {
                                info!("Client {} disconnecting: {} (reason {})", client_id, message, reason);
                                break;
                            }
                            _ => {
                                warn!("Received unexpected packet type from {}", client_id);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse message from {}: {}", client_id, e);
                    }
                }
            }
            Err(e) => {
                // Normal close or connection error
                debug!("WebSocket connection closed with {}: {}", client_id, e);
                break;
            }
        }
    }
    
    // Abort background tasks
    heartbeat_handle.abort();
    key_rotation_handle.abort();
    
    // Clean up the session
    info!("Client {} disconnected", client_id);
    
    // Remove session
    session_manager.remove_session(&session_id).await;
    
    // Release IP address
    if let Err(e) = ip_pool.release_ip(&ip_address).await {
        warn!("Failed to release IP {}: {}", ip_address, e);
    }
    
    // Remove session key
    session_key_manager.remove_key(&client_id).await;
    
    Ok(())
}
