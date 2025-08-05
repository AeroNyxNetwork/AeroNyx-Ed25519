// src/server/client.rs
//! Client connection handling.
//!
//! This module handles individual client connections, including authentication,
//! session setup, and message processing.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use futures::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, trace, warn};

use crate::auth::AuthManager;
use crate::crypto::{KeyManager, SessionKeyManager};
use crate::crypto::flexible_encryption::EncryptionAlgorithm;
use crate::crypto::encryption::encrypt_session_key_flexible;
use crate::network::{IpPoolManager, NetworkMonitor};
use crate::protocol::types::PacketType;
use crate::protocol::serialization::{packet_to_ws_message, ws_message_to_packet, create_error_packet, create_disconnect_packet, log_packet_info};
use crate::server::session::{ClientSession, SessionManager};
use crate::server::routing::PacketRouter;
use crate::server::metrics::ServerMetricsCollector;
use crate::server::core::{ServerError, ServerState};
use crate::utils::{current_timestamp_millis, random_string};
use crate::utils::security::StringValidator;
use solana_sdk::pubkey::Pubkey;

/// Handle a RAW (non-TLS) client connection
pub async fn handle_client_raw(
    stream: TcpStream,
    addr: SocketAddr,
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
    // Directly upgrade TCP connection to WebSocket
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(stream) => {
            debug!("RAW WebSocket connection established with {}", addr);
            stream
        }
        Err(e) => {
            return Err(ServerError::WebSocket(e));
        }
    };

    // Split the WebSocket stream and process the session
    let (ws_sender, ws_receiver) = ws_stream.split();
    
    process_websocket_session(
        ws_sender,
        ws_receiver,
        addr,
        key_manager,
        auth_manager,
        ip_pool,
        session_manager,
        session_key_manager,
        network_monitor,
        packet_router,
        metrics,
        server_state,
    ).await
}

/// Handle a client connection
pub async fn handle_client(
    stream: TcpStream,
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
    let tls_stream : TlsStream<TcpStream> = match tls_acceptor.accept(stream).await {
        Ok(stream) => {
            // Record successful handshake
            metrics.record_handshake_complete().await;
            debug!("TLS handshake successful with {}", addr);
            stream
        }
        Err(e) => {
            // Record failed handshake (consider if this metric makes sense on failure)
            // metrics.record_handshake_failure().await; // Or a dedicated failure metric
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
            return Err(ServerError::WebSocket(e)); // Use the From trait
        }
    };

    // Split the WebSocket stream and process the session
    let (ws_sender, ws_receiver) = ws_stream.split();
    
    process_websocket_session(
        ws_sender,
        ws_receiver,
        addr,
        key_manager,
        auth_manager,
        ip_pool,
        session_manager,
        session_key_manager,
        network_monitor,
        packet_router,
        metrics,
        server_state,
    ).await
}

/// Process a WebSocket session after the connection is established
async fn process_websocket_session<S>(
    mut ws_sender: SplitSink<WebSocketStream<S>, tokio_tungstenite::tungstenite::Message>,
    mut ws_receiver: SplitStream<WebSocketStream<S>>,
    addr: SocketAddr,
    key_manager: Arc<KeyManager>,
    auth_manager: Arc<AuthManager>,
    ip_pool: Arc<IpPoolManager>,
    session_manager: Arc<SessionManager>,
    session_key_manager: Arc<SessionKeyManager>,
    network_monitor: Arc<NetworkMonitor>,
    packet_router: Arc<PacketRouter>,
    metrics: Arc<ServerMetricsCollector>,
    server_state: Arc<RwLock<ServerState>>,
) -> Result<(), ServerError> 
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // --- Authentication Phase ---
    let (public_key_string, client_encryption_preference) = match time::timeout(Duration::from_secs(30), ws_receiver.next()).await {
        Ok(Some(Ok(msg))) => {
             match ws_message_to_packet(&msg) {
                Ok(PacketType::Auth { 
                    public_key, 
                    version, 
                    features, 
                    encryption_algorithm,
                    nonce: _nonce 
                }) => {
                    debug!(
                        "Auth request from {}, version: {}, features: {:?}, encryption: {:?}", 
                        public_key, version, features, encryption_algorithm
                    );

                    // Verify public key format
                    if !StringValidator::is_valid_solana_pubkey(&public_key) {
                        let error_packet = create_error_packet(1001, "Invalid public key format");
                        let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                        metrics.record_auth_failure().await;
                        return Err(ServerError::Authentication("Invalid public key format".to_string()));
                    }

                    // Store the client's algorithm preference string for later parsing
                    let client_algo_pref_str = encryption_algorithm;

                    // Generate challenge
                    let challenge = match auth_manager.generate_challenge(&addr.to_string()).await {
                        Ok(challenge) => challenge,
                        Err(e) => {
                             let error_packet = create_error_packet(1001, &format!("Failed to generate challenge: {}", e));
                            let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                            metrics.record_auth_failure().await;
                            return Err(ServerError::Authentication(format!("Challenge generation failed: {}", e)));
                        }
                    };

                    // Get server public key
                    let server_pubkey = key_manager.public_key().await.to_string();

                    // Create challenge packet
                    let challenge_packet = PacketType::Challenge {
                        data: challenge.1.clone(), // Challenge data
                        server_key: server_pubkey,
                        expires_at: current_timestamp_millis() + crate::config::constants::AUTH_CHALLENGE_TIMEOUT.as_millis() as u64,
                        id: challenge.0.clone(), // Challenge ID
                    };

                    // Send challenge
                    if ws_sender.send(packet_to_ws_message(&challenge_packet)?).await.is_err() {
                        return Err(ServerError::Network("Failed to send challenge".to_string()));
                    }

                    // Wait for challenge response
                    match time::timeout(Duration::from_secs(30), ws_receiver.next()).await {
                         Ok(Some(Ok(resp_msg))) => {
                             match ws_message_to_packet(&resp_msg) {
                                Ok(PacketType::ChallengeResponse { signature, public_key: resp_pubkey, challenge_id }) => {
                                    if resp_pubkey != public_key {
                                        let error_packet = create_error_packet(1001, "Public key mismatch");
                                        let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                                        metrics.record_auth_failure().await;
                                        return Err(ServerError::Authentication("Public key mismatch".to_string()));
                                    }

                                    // Verify the challenge
                                    match auth_manager.verify_challenge(&challenge_id, &signature, &public_key, &addr.to_string()).await {
                                        Ok(_) => {
                                            debug!("Challenge successfully verified for {}", public_key);
                                            if !auth_manager.is_client_allowed(&public_key).await {
                                                 let error_packet = create_error_packet(1005, "Access denied by ACL");
                                                let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                                                metrics.record_auth_failure().await;
                                                return Err(ServerError::Authentication("Access denied by ACL".to_string()));
                                            }
                                            metrics.record_auth_success().await;
                                            info!("Client {} authenticated successfully", public_key);
                                            
                                            // Parse client's preferred algorithm, if invalid/unsupported use default
                                            let client_preferred_algo = client_algo_pref_str
                                                .as_deref() // Option<String> -> Option<&str>
                                                .and_then(EncryptionAlgorithm::from_str) // Option<&str> -> Option<EncryptionAlgorithm>
                                                .unwrap_or_else(|| {
                                                    if client_algo_pref_str.is_some() {
                                                        warn!(
                                                            "Client {} provided unsupported/invalid algorithm {:?}, using default.", 
                                                            public_key, client_algo_pref_str
                                                        );
                                                    }
                                                    EncryptionAlgorithm::default() // Use server default algorithm
                                                });
                                            
                                            (public_key, client_preferred_algo) // Return the verified public key and parsed algorithm
                                        }
                                        Err(e) => {
                                             let error_packet = create_error_packet(1001, &format!("Challenge verification failed: {}", e));
                                            let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                                            metrics.record_auth_failure().await;
                                            return Err(ServerError::Authentication(format!("Challenge verification failed: {}", e)));
                                        }
                                    }
                                }
                                Ok(_) => {
                                    let error_packet = create_error_packet(1002, "Expected challenge response");
                                    let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                                    metrics.record_auth_failure().await;
                                    return Err(ServerError::Authentication("Expected challenge response".to_string()));
                                }
                                Err(e) => {
                                    let error_packet = create_error_packet(1002, &format!("Invalid challenge response message: {}", e));
                                     let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                                    metrics.record_auth_failure().await;
                                    return Err(ServerError::Protocol(e));
                                }
                            }
                        }
                        Ok(Some(Err(e))) => { // Handle specific websocket error
                            metrics.record_auth_failure().await;
                            return Err(ServerError::WebSocket(e)); // Map error
                        }
                        Err(_) => { // Handle timeout
                            metrics.record_auth_failure().await;
                            return Err(ServerError::Authentication("Timed out waiting for challenge response".to_string()));
                        }
                        Ok(None) => { // Handle stream closed
                             metrics.record_auth_failure().await;
                             return Err(ServerError::Authentication("WebSocket closed during challenge response".to_string()));
                        }
                    }
                }
                 Ok(_) => { // Wrong initial packet type
                     let error_packet = create_error_packet(1002, "Expected authentication message");
                     let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                     metrics.record_auth_failure().await;
                     return Err(ServerError::Authentication("Expected authentication message".to_string()));
                 }
                 Err(e) => { // Deserialization error
                     let error_packet = create_error_packet(1002, &format!("Invalid auth message: {}", e));
                     let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
                     metrics.record_auth_failure().await;
                     return Err(ServerError::Protocol(e));
                 }
             }
        }
        Ok(Some(Err(e))) => { // Handle specific websocket error
            metrics.record_auth_failure().await;
            return Err(ServerError::WebSocket(e)); // Map error
        }
        Err(_) => { // Handle timeout
            metrics.record_auth_failure().await;
            return Err(ServerError::Authentication("Timed out waiting for auth message".to_string()));
        }
         Ok(None) => { // Handle stream closed
             metrics.record_auth_failure().await;
             return Err(ServerError::Authentication("WebSocket closed before authentication".to_string()));
         }
    };
    // --- Authentication Phase End ---

    // Assign IP address
    let ip_address = match ip_pool.allocate_ip(&public_key_string).await {
        Ok(ip) => {
            debug!("Assigned IP {} to client {}", ip, public_key_string);
            ip
        }
        Err(e) => {
            let error_packet = create_error_packet(1007, &format!("Failed to allocate IP: {}", e));
            let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
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
            let error_packet = create_error_packet(1006, &format!("Failed to derive shared secret: {}", e));
            let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
            if let Err(release_err) = ip_pool.release_ip(&ip_address).await {
                warn!("Failed to release IP {}: {}", ip_address, release_err);
            }
            return Err(ServerError::KeyError(format!("Failed to derive shared secret: {}", e)));
        }
    };

    // Encrypt session key using the flexible encryption method with negotiated algorithm
    let encrypted_key_packet = match encrypt_session_key_flexible(
        &session_key,
        &shared_secret,
        client_encryption_preference, // Use negotiated algorithm
    ) {
        Ok(packet) => packet,
        Err(e) => {
            let error_packet = create_error_packet(1006, &format!("Encryption failed: {}", e));
            let _ = ws_sender.send(packet_to_ws_message(&error_packet)?).await;
            if let Err(release_err) = ip_pool.release_ip(&ip_address).await {
                warn!("Failed to release IP {}: {}", ip_address, release_err);
            }
            return Err(ServerError::Internal(format!("Failed to encrypt session key: {}", e)));
        }
    };

    let ws_sender_mutex = Arc::new(Mutex::new(ws_sender));
    let ws_receiver_mutex = Arc::new(Mutex::new(ws_receiver));

    // Create the ClientSession with encryption algorithm from the encrypted packet
    let session = ClientSession::new(
        session_id.clone(),
        public_key_string.clone(),
        ip_address.clone(),
        addr,
        ws_sender_mutex.clone(),
        ws_receiver_mutex.clone(),
        Some(encrypted_key_packet.algorithm.as_str().to_string()),
    )?;

    // Create IP assignment packet with encryption algorithm info
    let ip_assign = PacketType::IpAssign {
        ip_address: ip_address.clone(),
        lease_duration: ip_pool.get_default_lease_duration().as_secs(),
        session_id: session_id.clone(),
        encrypted_session_key: encrypted_key_packet.data,
        key_nonce: encrypted_key_packet.nonce,
        encryption_algorithm: encrypted_key_packet.algorithm.as_str().to_string(),
    };

    // Send IP assignment
    if session.send_packet(&ip_assign).await.is_err() {
        if let Err(release_err) = ip_pool.release_ip(&ip_address).await {
             warn!("Failed to release IP {}: {}", ip_address, release_err);
        }
        return Err(ServerError::Network("Failed to send IP assignment".to_string()));
    }
    
    // Register the session
    session_manager.add_session(session.clone()).await;

    // Process client messages
    let result = process_client_session(
        session,
        key_manager, // Keep original Arc
        session_key_manager.clone(), // Clone Arc for the async function
        packet_router, // Keep original Arc
        network_monitor, // Keep original Arc
        ip_pool.clone(), // Clone Arc for cleanup logic within or after process_client_session
        session_manager.clone(), // Clone Arc for cleanup logic within or after process_client_session
        server_state,
    ).await;

    // Cleanup after process_client_session finishes or errors
    info!("Cleaning up session for client {}", public_key_string);
    session_manager.remove_session(&session_id).await; // Use cloned session_manager
    if let Err(e) = ip_pool.release_ip(&ip_address).await { // Use cloned ip_pool
        warn!("Failed to release IP {} during cleanup: {}", ip_address, e);
    }
    // Use original session_key_manager (which still holds a valid Arc reference)
    session_key_manager.remove_key(&public_key_string).await;

    result // Return the result from process_client_session
}


/// Process messages from an authenticated client session
async fn process_client_session(
    session: ClientSession,
    key_manager: Arc<KeyManager>, // Keep original Arc
    session_key_manager: Arc<SessionKeyManager>, // Now receives a clone
    packet_router: Arc<PacketRouter>, // Keep original Arc
    network_monitor: Arc<NetworkMonitor>, // Keep original Arc
    _ip_pool: Arc<IpPoolManager>, // Mark unused if cleanup is outside
    _session_manager: Arc<SessionManager>, // Mark unused if cleanup is outside
    server_state: Arc<RwLock<ServerState>>,
) -> Result<(), ServerError> {
    let client_id = session.client_id.clone();
    let session_id = session.id.clone();
    let ip_address = session.ip_address.clone();
    // let _address = session.address; // Marked unused

    // --- Heartbeat Task ---
    let heartbeat_interval = Duration::from_secs(30);
    let session_hb = session.clone(); // Clone session for heartbeat task
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = time::interval(heartbeat_interval);
        let mut sequence: u64 = 0;
        loop {
            interval.tick().await;
            // Check if session is closing - Remove dereference (*)
            if session_hb.is_stream_taken().await {
                 break;
            }
            let ping = PacketType::Ping {
                timestamp: current_timestamp_millis(),
                sequence,
            };
            if session_hb.send_packet(&ping).await.is_err() {
                warn!("Failed to send heartbeat to {}: channel closed", session_hb.client_id);
                break;
            }
            sequence = sequence.wrapping_add(1);
        }
    });

    // --- Key Rotation Task ---
    let rotation_interval = Duration::from_secs(3600); // 1 hour
    let session_rot = session.clone(); // Clone session for rotation task
    let session_key_manager_clone = session_key_manager.clone();
    let key_manager_clone = key_manager.clone();
    let key_rotation_handle = tokio::spawn(async move {
        let mut interval = time::interval(rotation_interval);
        loop {
            interval.tick().await;
            // Check if session is closing - Remove dereference (*)
            if session_rot.is_stream_taken().await {
                break;
            }

            if !session_key_manager_clone.needs_rotation(&session_rot.client_id).await {
                continue;
            }

            debug!("Rotating session key for client {}", session_rot.client_id);

            let new_key = SessionKeyManager::generate_key();

             if let Some(current_key) = session_key_manager_clone.get_key(&session_rot.client_id).await {
                 // Use the session's encryption algorithm for key rotation
                 // Unwrap the Option<String> to get &str, then parse algorithm
                 let algorithm = EncryptionAlgorithm::from_str(&session_rot.encryption_algorithm)
                .unwrap_or_default(); // Default if None or parsing fails

                 let encrypted_packet = match crate::crypto::flexible_encryption::encrypt_flexible(
                     &new_key,
                     &current_key,
                     algorithm,
                     None,
                 ) {
                     Ok(packet) => packet,
                     Err(e) => {
                         warn!("Failed to encrypt new session key for {}: {}", session_rot.client_id, e);
                         continue;
                     }
                 };

                 let key_id = random_string(16);
                 let mut sign_data = key_id.clone().into_bytes();
                 sign_data.extend_from_slice(&encrypted_packet.nonce);
                 let signature = key_manager_clone.sign_message(&sign_data).await;

                 let rotation = PacketType::KeyRotation {
                     encrypted_new_key: encrypted_packet.data,
                     nonce: encrypted_packet.nonce,
                     key_id,
                     signature: signature.to_string(),
                 };

                if session_rot.send_packet(&rotation).await.is_err() {
                     warn!("Failed to send key rotation to {}: channel closed", session_rot.client_id);
                     break;
                 }

                session_key_manager_clone.store_key(&session_rot.client_id, new_key).await;
                 debug!("Session key rotated for client {}", session_rot.client_id);
             } else {
                 warn!("Could not get current session key for rotation for client {}", session_rot.client_id);
             }
        }
    });


    let mut last_counter: Option<u64> = None;

    // Main message processing loop
     loop {
         // Check server state first
         let current_state = *server_state.read().await;
         if current_state != ServerState::Running {
             let disconnect = create_disconnect_packet(2, "Server shutting down");
             let _ = session.send_packet(&disconnect).await; // Attempt to notify client
             return Err(ServerError::Internal("Server shutting down".to_string()));
         }

         match session.next_message().await {
             Some(Ok(msg)) => {
                 session.update_activity().await;

                 match ws_message_to_packet(&msg) {
                     Ok(packet) => {
                         log_packet_info(&packet, true);

                         match packet {
                            PacketType::Data { encrypted, nonce, counter, padding: _, encryption_algorithm } => {
                                 if let Some(last) = last_counter {
                                     if counter <= last && counter != 0 {
                                         warn!("Potential replay attack detected from {}: counter {} <= {}", client_id, counter, last);
                                         continue;
                                     }
                                 }
                                 last_counter = Some(counter);

                                 if let Some(key) = session_key_manager.get_key(&client_id).await {
                                     // session对象直接传递给handle_inbound_packet，由函数内部正确处理
                                     match packet_router.handle_inbound_packet(
                                         &encrypted, 
                                         &nonce, 
                                         &key, 
                                         &session,
                                         encryption_algorithm.as_deref(),
                                     ).await {
                                         Ok(bytes_written) => {
                                             network_monitor.record_client_traffic(&client_id, 0, bytes_written as u64).await;
                                             network_monitor.record_sent(bytes_written as u64).await;
                                         }
                                         Err(e) => {
                                             trace!("Failed to process inbound packet from {}: {}", client_id, e);
                                         }
                                     }
                                 } else {
                                     warn!("No session key found for client {}, dropping packet", client_id);
                                 }
                             }
                             PacketType::Ping { timestamp, sequence } => {
                                 let pong = PacketType::Pong {
                                     echo_timestamp: timestamp,
                                     server_timestamp: current_timestamp_millis(),
                                     sequence,
                                 };
                                 if session.send_packet(&pong).await.is_err() {
                                     warn!("Failed to send pong to {}: channel closed", client_id);
                                     return Err(ServerError::Network("Pong send failed".to_string()));
                                 }
                             }
                             PacketType::Pong { echo_timestamp, server_timestamp: _, sequence: _ } => {
                                 let now = current_timestamp_millis();
                                 if now >= echo_timestamp {
                                     let rtt = now - echo_timestamp;
                                     network_monitor.record_latency(&client_id, rtt as f64).await;
                                 } else {
                                      warn!("Received Pong with future timestamp from {}", client_id);
                                 }
                             }
                             PacketType::IpRenewal { session_id: renewal_id, ip_address: renewal_ip } => {
                                 if renewal_id != session_id {
                                     warn!("IP renewal with mismatched session ID from {}", client_id);
                                     continue;
                                 }
                                 if renewal_ip != ip_address {
                                     warn!("IP renewal with mismatched IP from {}", client_id);
                                     continue;
                                 }
                                 // Get the IP pool from the session_manager or pass it in
                                 // Assuming IP Pool is accessible (e.g., passed into process_client_session)
                                 // let ip_pool = ...; // Get access to IP Pool
                                 // match ip_pool.renew_ip(&ip_address).await { ... }

                                 // Placeholder: Need access to ip_pool here
                                 warn!("IP Renewal requested but IP pool access not implemented here");
                                 let response = PacketType::IpRenewalResponse {
                                      session_id: session_id.clone(),
                                      expires_at: 0, // Indicate failure
                                      success: false,
                                  };
                                  if session.send_packet(&response).await.is_err() {
                                      warn!("Failed to send failed IP renewal response to {}: channel closed", client_id);
                                      return Err(ServerError::Network("Failed IP renewal response send failed".to_string()));
                                  }

                             }
                             PacketType::Disconnect { reason, message } => {
                                 info!("Client {} disconnecting: {} (reason {})", client_id, message, reason);
                                 break; // Break loop for graceful disconnect
                             }
                             _ => {
                                 warn!("Received unexpected packet type from {} during session", client_id);
                             }
                         }
                     }
                     Err(e) => {
                         warn!("Failed to parse message from {}: {}", client_id, e);
                         // Maybe disconnect on parse error?
                         // return Err(ServerError::Protocol(e));
                     }
                 }
             }
             Some(Err(e)) => { // WebSocket error
                 debug!("WebSocket error for client {}: {}", client_id, e);
                 // Use explicit From conversion
                 return Err(ServerError::from(e));
             }
             None => { // WebSocket stream closed
                 debug!("WebSocket connection closed for client {}", client_id);
                 break; // Break loop for normal closure
             }
         }
     }

    // Abort background tasks associated with this session
    heartbeat_handle.abort();
    key_rotation_handle.abort();
    session.mark_stream_taken().await; // Mark session as closing

    Ok(()) // Return Ok(()) if loop finishes normally
}
