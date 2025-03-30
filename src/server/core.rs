// src/server/core.rs
//! Core server implementation for the AeroNyx Privacy Network.
//!
//! This module contains the main VPN server implementation that handles
//! client connections, authentication, and network routing.

use std::io::{self, Result as IoResult};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, trace, warn};
use tun::platform::Device;

use crate::auth::{AuthManager, Challenge, ChallengeError};
use crate::config::settings::ServerConfig;
use crate::crypto::{KeyManager, SessionKeyManager};
use crate::network::{IpPoolManager, NetworkMonitor, setup_tun_device, configure_nat};
use crate::protocol::{PacketType, MessageError, validate_message};
use crate::protocol::serialization::{packet_to_ws_message, ws_message_to_packet, create_error_packet, create_disconnect_packet, log_packet_info};
use crate::server::session::{ClientSession, SessionManager, SessionError};
use crate::server::routing::PacketRouter;
use crate::server::metrics::ServerMetricsCollector;
use crate::utils::{current_timestamp_millis, random_string};
use crate::utils::security::{RateLimiter, StringValidator};

/// Error type for VPN server operations
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("TLS error: {0}")]
    Tls(String),
    
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Protocol error: {0}")]
    Protocol(#[from] MessageError),
    
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
    
    #[error("Challenge error: {0}")]
    Challenge(#[from] ChallengeError),
    
    #[error("Key error: {0}")]
    KeyError(String),
    
    #[error("TUN setup error: {0}")]
    TunSetup(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// VPN server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Initial state
    Created,
    /// Server is starting up
    Starting,
    /// Server is running
    Running,
    /// Server is shutting down
    ShuttingDown,
    /// Server has stopped
    Stopped,
}

/// Main VPN server for the AeroNyx Privacy Network
pub struct VpnServer {
    /// Server configuration
    config: ServerConfig,
    /// TLS acceptor for secure connections
    tls_acceptor: Arc<TlsAcceptor>,
    /// TUN device for packet routing
    tun_device: Arc<Mutex<Device>>,
    /// Key manager for the server
    key_manager: Arc<KeyManager>,
    /// Authentication manager
    auth_manager: Arc<AuthManager>,
    /// IP address pool manager
    ip_pool: Arc<IpPoolManager>,
    /// Session manager for client sessions
    session_manager: Arc<SessionManager>,
    /// Session key manager
    session_key_manager: Arc<SessionKeyManager>,
    /// Network monitor for traffic statistics
    network_monitor: Arc<NetworkMonitor>,
    /// Packet router for network traffic
    packet_router: Arc<PacketRouter>,
    /// Server metrics collector
    metrics: Arc<ServerMetricsCollector>,
    /// Rate limiter for connections
    rate_limiter: Arc<RateLimiter>,
    /// Server state
    state: Arc<RwLock<ServerState>>,
    /// Server task handles
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl VpnServer {
    /// Create a new VPN server instance
    pub async fn new(mut config: ServerConfig) -> Result<Self, ServerError> {
        info!("Initializing AeroNyx Privacy Network Server");
        
        // Initialize key manager
        let key_manager = Arc::new(KeyManager::new(
            &config.server_key_file,
            Duration::from_secs(config.key_rotation_interval.as_secs()),
            1000, // Cache size
        ).await.map_err(|e| ServerError::KeyError(e.to_string()))?);
        
        // Set the key manager in config for easier access
        config.key_manager = Some(key_manager.clone());
        
        // Setup TUN device
        info!("Setting up TUN device: {}", config.tun_name);
        let tun_config = tun::Configuration::default()
            .name(&config.tun_name)
            .up();
            
        let tun_device = tun::create(&tun_config)
            .map_err(|e| ServerError::TunSetup(format!("Failed to create TUN device: {}", e)))?;
        
        // Parse TLS certificates
        let tls_config = Self::setup_tls(&config)?;
        let tls_acceptor = Arc::new(TlsAcceptor::from(tls_config));
        
        // Initialize auth manager
        let auth_manager = Arc::new(AuthManager::new(
            config.acl_file.clone(),
            key_manager.clone(),
            Duration::from_secs(30), // Challenge timeout
            100, // Max challenges
        ).await.map_err(|e| ServerError::Authentication(e.to_string()))?);
        
        // Initialize IP pool manager
        let ip_pool = Arc::new(IpPoolManager::new(
            &config.subnet,
            config.session_timeout.as_secs(),
        ).await.map_err(|e| ServerError::Network(format!("Failed to initialize IP pool: {}", e)))?);
        
        // Initialize session manager
        let session_manager = Arc::new(SessionManager::new(
            config.max_connections_per_ip,
            config.session_timeout,
        ));
        
        // Initialize session key manager
        let session_key_manager = Arc::new(SessionKeyManager::new(
            Duration::from_secs(config.key_rotation_interval.as_secs()),
            1000, // Max key usages before rotation
        ));
        
        // Initialize network monitor
        let network_monitor = Arc::new(NetworkMonitor::new(
            Duration::from_secs(1),
            1000, // History size
        ));
        
        // Initialize packet router
        let packet_router = Arc::new(PacketRouter::new(
            tun_device.mtu().unwrap_or(1500) as usize,
            config.enable_padding,
        ));
        
        // Initialize metrics collector
        let metrics = Arc::new(ServerMetricsCollector::new(
            Duration::from_secs(30),
            100, // History size
        ));
        
        // Initialize rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(
            config.max_connections_per_ip,
            Duration::from_secs(60),
        ));
        
        // Configure NAT if requested
        if let Err(e) = configure_nat(&config.tun_name, &config.subnet) {
            warn!("Failed to configure NAT: {}. VPN routing may not work correctly.", e);
        }
        
        Ok(Self {
            config,
            tls_acceptor,
            tun_device: Arc::new(Mutex::new(tun_device)),
            key_manager,
            auth_manager,
            ip_pool,
            session_manager,
            session_key_manager,
            network_monitor,
            packet_router,
            metrics,
            rate_limiter,
            state: Arc::new(RwLock::new(ServerState::Created)),
            task_handles: Arc::new(Mutex::new(Vec::new())),
        })
    }
    
    /// Set up TLS configuration
    fn setup_tls(config: &ServerConfig) -> Result<Arc<rustls::ServerConfig>, ServerError> {
        debug!("Setting up TLS with certificates from {:?} and {:?}", 
               config.cert_file, config.key_file);
        
        // Read certificate file
        let cert_file = std::fs::File::open(&config.cert_file)
            .map_err(|e| ServerError::Tls(format!("Failed to open certificate file: {}", e)))?;
        let mut reader = std::io::BufReader::new(cert_file);
        
        // Load certificates
        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| ServerError::Tls(format!("Failed to parse certificates: {}", e)))?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
            
        // Read key file
        let key_file = std::fs::File::open(&config.key_file)
            .map_err(|e| ServerError::Tls(format!("Failed to open key file: {}", e)))?;
        let mut reader = std::io::BufReader::new(key_file);
        
        // Load private key
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .map_err(|e| ServerError::Tls(format!("Failed to parse private key: {}", e)))?;
            
        if keys.is_empty() {
            // Try rsa key format if pkcs8 fails
            let key_file = std::fs::File::open(&config.key_file)
                .map_err(|e| ServerError::Tls(format!("Failed to open key file: {}", e)))?;
            let mut reader = std::io::BufReader::new(key_file);
            
            keys = rustls_pemfile::rsa_private_keys(&mut reader)
                .map_err(|e| ServerError::Tls(format!("Failed to parse RSA private key: {}", e)))?;
        }
        
        if keys.is_empty() {
            return Err(ServerError::Tls("No private keys found".to_string()));
        }
        
        let key = rustls::PrivateKey(keys.remove(0));
        
        // Create server config
        let server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(format!("TLS configuration error: {}", e)))?;
            
        Ok(Arc::new(server_config))
    }
    
    /// Start the VPN server
    pub async fn start(&self) -> Result<JoinHandle<()>, ServerError> {
        {
            let mut state = self.state.write().await;
            if *state != ServerState::Created && *state != ServerState::Stopped {
                return Err(ServerError::Internal(format!("Cannot start server in state {:?}", *state)));
            }
            *state = ServerState::Starting;
        }
        
        info!("Starting AeroNyx Privacy Network Server on {}", self.config.listen_addr);
        
        // Start the network monitor
        self.network_monitor.start().await;
        
        // Start metrics collector
        self.metrics.start().await;
        
        // Start background tasks
        self.start_background_tasks().await;
        
        // Start TUN reading task
        let tun_router_handle = self.start_tun_reader().await?;
        
        // Add the TUN task to our handles
        {
            let mut handles = self.task_handles.lock().await;
            handles.push(tun_router_handle);
        }
        
        // Get components needed for the main server loop
        let tls_acceptor = self.tls_acceptor.clone();
        let key_manager = self.key_manager.clone();
        let auth_manager = self.auth_manager.clone();
        let ip_pool = self.ip_pool.clone();
        let session_manager = self.session_manager.clone();
        let session_key_manager = self.session_key_manager.clone();
        let network_monitor = self.network_monitor.clone();
        let packet_router = self.packet_router.clone();
        let metrics = self.metrics.clone();
        let rate_limiter = self.rate_limiter.clone();
        let state = self.state.clone();
        let listen_addr = self.config.listen_addr.clone();
        
        // Create the main server loop
        let server_handle = tokio::spawn(async move {
            // Update server state
            {
                let mut state_guard = state.write().await;
                *state_guard = ServerState::Running;
            }
            
            // Bind to the listening address
            match TcpListener::bind(&listen_addr).await {
                Ok(listener) => {
                    info!("Server listening on {}", listen_addr);
                    
                    // Accept incoming connections
                    while let Ok((stream, addr)) = listener.accept().await {
                        trace!("Accepted connection from {}", addr);
                        
                        // Check rate limit
                        if !rate_limiter.check_rate_limit(&addr.ip()).await {
                            warn!("Rate limit exceeded for {}, rejecting connection", addr);
                            continue;
                        }
                        
                        // Record new connection in metrics
                        metrics.record_new_connection().await;
                        
                        // Clone needed components for the handler
                        let tls_acceptor = tls_acceptor.clone();
                        let key_manager = key_manager.clone();
                        let auth_manager = auth_manager.clone();
                        let ip_pool = ip_pool.clone();
                        let session_manager = session_manager.clone();
                        let session_key_manager = session_key_manager.clone();
                        let network_monitor = network_monitor.clone();
                        let packet_router = packet_router.clone();
                        let metrics = metrics.clone();
                        let server_state = state.clone();
                        
                        // Spawn a task to handle the connection
                        tokio::spawn(async move {
                            // Handle the client
                            if let Err(e) = Self::handle_client(
                                stream,
                                addr,
                                tls_acceptor,
                                key_manager,
                                auth_manager,
                                ip_pool,
                                session_manager,
                                session_key_manager,
                                network_monitor,
                                packet_router,
                                metrics,
                                server_state,
                            ).await {
                                match e {
                                    ServerError::WebSocket(e) => {
                                        // WebSocket errors are common, especially on disconnection
                                        trace!("WebSocket error for {}: {}", addr, e);
                                    }
                                    ServerError::Authentication(e) => {
                                        // Authentication failures are logged at higher level
                                        warn!("Authentication failed for {}: {}", addr, e);
                                    }
                                    _ => {
                                        // Log other errors at error level
                                        error!("Error handling client {}: {}", addr, e);
                                    }
                                }
                            }
                            
                            // Record connection close in metrics
                            metrics.record_connection_close().await;
                        });
                        
                        // Check if we should still be running
                        let current_state = *state.read().await;
                        if current_state != ServerState::Running {
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind to {}: {}", listen_addr, e);
                    
                    // Update server state
                    let mut state_guard = state.write().await;
                    *state_guard = ServerState::Stopped;
                }
            }
        });
        
        // Add the main server handle to our task handles
        {
            let mut handles = self.task_handles.lock().await;
            handles.push(server_handle.clone());
        }
        
        // Return the main server handle
        Ok(server_handle)
    }
    
    /// Shutdown the server gracefully
    pub async fn shutdown(&self) -> Result<(), ServerError> {
        info!("Shutting down AeroNyx Privacy Network Server");
        
        {
            let mut state = self.state.write().await;
            if *state != ServerState::Running {
                return Err(ServerError::Internal(format!("Cannot shut down server in state {:?}", *state)));
            }
            *state = ServerState::ShuttingDown;
        }
        
        // Stop the network monitor
        self.network_monitor.stop().await;
        
        // Stop the metrics collector
        self.metrics.stop().await;
        
        // Abort all background tasks
        {
            let mut handles = self.task_handles.lock().await;
            for handle in handles.iter_mut() {
                handle.abort();
            }
            handles.clear();
        }
        
        // Close all client sessions
        self.session_manager.close_all_sessions("Server shutdown").await;
        
        // Update server state
        {
            let mut state = self.state.write().await;
            *state = ServerState::Stopped;
        }
        
        info!("Server shutdown complete");
        
        Ok(())
    }
    
    /// Start background maintenance tasks
    async fn start_background_tasks(&self) {
        // Clone needed components
        let session_manager = self.session_manager.clone();
        let ip_pool = self.ip_pool.clone();
        let session_key_manager = self.session_key_manager.clone();
        let auth_manager = self.auth_manager.clone();
        let metrics = self.metrics.clone();
        let state = self.state.clone();
        let task_handles = self.task_handles.clone();
        
        // Session cleanup task
        let session_cleanup_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check server state
                let current_state = *state.read().await;
                if current_state != ServerState::Running {
                    break;
                }
                
                // Clean up expired sessions
                let removed = session_manager.cleanup_expired_sessions().await;
                if removed > 0 {
                    debug!("Cleaned up {} expired sessions", removed);
                }
            }
        });
        
        // IP pool cleanup task
        let ip_pool_cleanup_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(300)); // 5 minutes
            
            loop {
                interval.tick().await;
                
                // Check server state
                let current_state = *state.read().await;
                if current_state != ServerState::Running {
                    break;
                }
                
                // Clean up expired IP leases
                match ip_pool.cleanup_expired().await {
                    Ok(removed) => {
                        if !removed.is_empty() {
                            debug!("Released {} expired IP leases", removed.len());
                        }
                    }
                    Err(e) => {
                        warn!("Error cleaning up IP pool: {}", e);
                    }
                }
            }
        });
        
        // Session key cleanup task
        let session_key_cleanup_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(600)); // 10 minutes
            
            loop {
                interval.tick().await;
                
                // Check server state
                let current_state = *state.read().await;
                if current_state != ServerState::Running {
                    break;
                }
                
                // Clean up old unused session keys
                let removed = session_key_manager.cleanup_old_sessions(Duration::from_secs(3600)).await;
                if removed > 0 {
                    debug!("Cleaned up {} unused session keys", removed);
                }
            }
        });
        
        // Authentication challenge cleanup task
        let auth_cleanup_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check server state
                let current_state = *state.read().await;
                if current_state != ServerState::Running {
                    break;
                }
                
                // Clean up expired authentication challenges
                let removed = auth_manager.cleanup_expired_challenges().await;
                if removed > 0 {
                    debug!("Cleaned up {} expired authentication challenges", removed);
                }
            }
        });
        
        // Metrics reporting task
        let metrics_report_handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(3600)); // 1 hour
            
            loop {
                interval.tick().await;
                
                // Check server state
                let current_state = *state.read().await;
                if current_state != ServerState::Running {
                    break;
                }
                
                // Generate and log metrics report
                let report = metrics.generate_report().await;
                info!("Server metrics report:\n{}", report);
            }
        });
        
        // Add task handles to our collection
        {
            let mut handles = task_handles.lock().await;
            handles.push(session_cleanup_handle);
            handles.push(ip_pool_cleanup_handle);
            handles.push(session_key_cleanup_handle);
            handles.push(auth_cleanup_handle);
            handles.push(metrics_report_handle);
        }
    }
    
    /// Start TUN reader task to process packets from the TUN device
    async fn start_tun_reader(&self) -> Result<JoinHandle<()>, ServerError> {
        // Clone needed components
        let tun_device = self.tun_device.clone();
        let session_manager = self.session_manager.clone();
        let session_key_manager = self.session_key_manager.clone();
        let packet_router = self.packet_router.clone();
        let network_monitor = self.network_monitor.clone();
        let state = self.state.clone();
        
        // Spawn the TUN reader task
        let handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            
            loop {
                // Read from TUN device
                let bytes_read = {
                    let mut device = tun_device.lock().await;
                    match device.read(&mut buffer) {
                        Ok(n) => n,
                        Err(e) => {
                            // Handle non-blocking errors
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                time::sleep(Duration::from_millis(1)).await;
                                continue;
                            }
                            
                            // Log other errors
                            error!("Error reading from TUN device: {}", e);
                            time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                };
                
                if bytes_read > 0 {
                    // Get the packet slice
                    let packet = &buffer[..bytes_read];
                    
                    // Process packet and route it
                    if let Some((dest_ip, processed_packet)) = packet_router.process_packet(packet) {
                        trace!("Routing packet to {}", dest_ip);
                        
                        // Record packet in metrics
                        network_monitor.record_received(bytes_read as u64).await;
                        
                        // Find client session by IP and send the packet
                        match session_manager.get_session_by_ip(&dest_ip).await {
                            Some(session) => {
                                let client_id = session.client_id.clone();
                                
                                // Get the session key
                                if let Some(session_key) = session_key_manager.get_key(&client_id).await {
                                    // Route the packet through the session
                                    if let Err(e) = packet_router.route_outbound_packet(
                                        &processed_packet,
                                        &session_key,
                                        session,
                                    ).await {
                                        trace!("Error routing packet to {}: {}", dest_ip, e);
                                    }
                                }
                            }
                            None => {
                                trace!("No session found for IP: {}", dest_ip);
                            }
                        }
                    }
                }
                
                // Check if we should still be running
                let current_state = *state.read().await;
                if current_state != ServerState::Running {
                    break;
                }
            }
        });
        
        Ok(handle)
    }
    
    /// Handle a client connection
    async fn handle_client(
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
                            data: challenge.data.clone(),
                            server_key: server_pubkey,
                            expires_at: current_timestamp_millis() + 30000, // 30 seconds
                            id: challenge.id.clone(),
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
        let shared_secret = match key_manager.get_shared_secret(&public_key_string).await {
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
        Self::process_client_session(
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
    
    /// Process a client session
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
        let address = session.address;
        
        // Setup heartbeat task
        let heartbeat_interval = Duration::from_secs(30);
        let session_clone = session.clone();
        let packet_router_clone = packet_router.clone();
        
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
                    warn!("Failed to send heartbeat to {}: {}", client_id, e);
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
        let client_id_clone = client_id.clone();
        
        // Start key rotation task
        let key_rotation_handle = tokio::spawn(async move {
            let mut interval = time::interval(rotation_interval);
            
            loop {
                interval.tick().await;
                
                // Skip if not needed
                if !session_key_manager_clone.needs_rotation(&client_id_clone).await {
                    continue;
                }
                
                debug!("Rotating session key for client {}", client_id_clone);
                
                // Generate new key
                let new_key = SessionKeyManager::generate_key();
                
                // Get current session key
                if let Some(current_key) = session_key_manager_clone.get_key(&client_id_clone).await {
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
                                warn!("Failed to send key rotation to {}: {}", client_id_clone, e);
                                break;
                            }
                            
                            // Update the key
                            session_key_manager_clone.store_key(&client_id_clone, new_key).await;
                            debug!("Session key rotated for client {}", client_id_clone);
                        }
                        Err(e) => {
                            warn!("Failed to encrypt new session key: {}", e);
                        }
                    }
                }
            }
        });
        
        // Process client messages
        let mut stream = session.take_stream()?;
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
                    session_manager.touch_session(&session_id).await;
                    
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
                                    warn!("Received unexpected packet type from {}: {:?}", client_id, packet);
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
    
    /// Get the server's current state
    pub async fn get_state(&self) -> ServerState {
        *self.state.read().await
    }
    
    /// Get the server metrics collector
    pub fn metrics(&self) -> Arc<ServerMetricsCollector> {
        self.metrics.clone()
    }
    
    /// Get the server network monitor
    pub fn network_monitor(&self) -> Arc<NetworkMonitor> {
        self.network_monitor.clone()
    }
    
    /// Get the session manager
    pub fn session_manager(&self) -> Arc<SessionManager> {
        self.session_manager.clone()
    }
    
    /// Get the IP pool manager
    pub fn ip_pool(&self) -> Arc<IpPoolManager> {
        self.ip_pool.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::config::settings::ServerArgs;
    
    #[tokio::test]
    async fn test_setup_tls() {
        // Create temporary directory
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("server.key");
        
        // Generate self-signed certificate for testing
        let status = std::process::Command::new("openssl")
            .args(&[
                "req", "-x509", 
                "-newkey", "rsa:2048", 
                "-keyout", &key_path.to_string_lossy(),
                "-out", &cert_path.to_string_lossy(),
                "-days", "1",
                "-nodes",
                "-subj", "/CN=localhost"
            ])
            .status()
            .unwrap();
            
        assert!(status.success());
        
        // Create test configuration
        let config = ServerConfig {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            tun_name: "tun0".to_string(),
            subnet: "10.7.0.0/24".to_string(),
            cert_file: cert_path,
            key_file: key_path,
            acl_file: PathBuf::from("acl.json"),
            enable_obfuscation: false,
            obfuscation_method: "xor".to_string(),
            enable_padding: false,
            key_rotation_interval: Duration::from_secs(3600),
            session_timeout: Duration::from_secs(3600),
            max_connections_per_ip: 5,
            data_dir: PathBuf::from("/tmp"),
            server_key_file: PathBuf::from("/tmp/server_key.json"),
            key_manager: None,
        };
        
        // Test TLS setup
        let result = VpnServer::setup_tls(&config);
        assert!(result.is_ok());
    }
}
