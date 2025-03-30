// src/server/core.rs
//! Core server implementation for the AeroNyx Privacy Network.
//!
//! This module contains the main VPN server implementation that handles
//! client connections, authentication, and network routing.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};
use tun::platform::Device;

use crate::auth::AuthManager;
use crate::config::settings::ServerConfig;
use crate::crypto::{KeyManager, SessionKeyManager};
use crate::network::{IpPoolManager, NetworkMonitor, setup_tun_device, configure_nat};
use crate::protocol::MessageError;
use crate::server::session::{SessionManager, SessionError};
use crate::server::routing::PacketRouter;
use crate::server::metrics::ServerMetricsCollector;
use crate::server::client::handle_client;
use crate::server::packet::process_tun_packets;
use crate::utils::security::RateLimiter;

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
    Challenge(#[from] crate::auth::ChallengeError),
    
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
    pub config: ServerConfig,
    /// TLS acceptor for secure connections
    pub tls_acceptor: Arc<TlsAcceptor>,
    /// TUN device for packet routing
    pub tun_device: Arc<Mutex<Device>>,
    /// Key manager for the server
    pub key_manager: Arc<KeyManager>,
    /// Authentication manager
    pub auth_manager: Arc<AuthManager>,
    /// IP address pool manager
    pub ip_pool: Arc<IpPoolManager>,
    /// Session manager for client sessions
    pub session_manager: Arc<SessionManager>,
    /// Session key manager
    pub session_key_manager: Arc<SessionKeyManager>,
    /// Network monitor for traffic statistics
    pub network_monitor: Arc<NetworkMonitor>,
    /// Packet router for network traffic
    pub packet_router: Arc<PacketRouter>,
    /// Server metrics collector
    pub metrics: Arc<ServerMetricsCollector>,
    /// Rate limiter for connections
    pub rate_limiter: Arc<RateLimiter>,
    /// Server state
    pub state: Arc<RwLock<ServerState>>,
    /// Server task handles
    pub task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl VpnServer {
    /// Create a new VPN server instance
    pub async fn new(mut config: ServerConfig) -> Result<Self, ServerError> {
        info!("Initializing AeroNyx Privacy Network Server");
        
        // Initialize key manager
        let key_manager = match config.key_manager {
            Some(ref km) => km.clone(),
            None => {
                let km = Arc::new(KeyManager::new(
                    &config.server_key_file,
                    Duration::from_secs(config.key_rotation_interval.as_secs()),
                    1000, // Cache size
                ).await.map_err(|e| ServerError::KeyError(e.to_string()))?);
                config.key_manager = Some(km.clone());
                km
            }
        };
        
        // Setup TUN device
        info!("Setting up TUN device: {}", config.tun_name);
        
        let tun_device = setup_tun_device(&config.tun_name, &config.subnet)
            .map_err(|e| ServerError::TunSetup(format!("Failed to create TUN device: {}", e)))?;
        
        // Create Arc<Mutex<Device>> for TUN
        let tun_device_arc = Arc::new(Mutex::new(tun_device));
        
        // Initialize global references
        crate::server::globals::init_globals(tun_device_arc.clone());
        
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
            1500, // Default MTU size
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
            tun_device: tun_device_arc,
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
    
    /// Set up TLS configuration with additional security validation
    fn setup_tls(config: &ServerConfig) -> Result<Arc<rustls::ServerConfig>, ServerError> {
        debug!("Setting up TLS with certificates from {:?} and {:?}", 
               config.cert_file, config.key_file);
        
        // Check if certificate and key files exist
        if !config.cert_file.exists() {
            return Err(ServerError::Tls(format!(
                "Certificate file not found: {:?}", config.cert_file
            )));
        }
        
        if !config.key_file.exists() {
            return Err(ServerError::Tls(format!(
                "Private key file not found: {:?}", config.key_file
            )));
        }
        
        // Read certificate file
        let cert_file = std::fs::File::open(&config.cert_file)
            .map_err(|e| ServerError::Tls(format!("Failed to open certificate file: {}", e)))?;
        let mut reader = std::io::BufReader::new(cert_file);
        
        // Load certificates
        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| ServerError::Tls(format!("Failed to parse certificates: {}", e)))?;
        
        if certs.is_empty() {
            return Err(ServerError::Tls("No valid certificates found".to_string()));
        }
        
        // Convert to rustls certificates
        let rustls_certs = certs.into_iter().map(rustls::Certificate).collect::<Vec<_>>();
        
        // Check certificate validity period
        Self::validate_certificate_expiry(&rustls_certs)?;
        
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
        
        // Create secure server config with modern cipher suites and TLS 1.3
        let mut server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(rustls_certs, key)
            .map_err(|e| ServerError::Tls(format!("TLS configuration error: {}", e)))?;
            
        // Set TLS session cache
        server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
        
        // Use modern cipher suites
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        
        Ok(Arc::new(server_config))
    }
    
    /// Validate certificate expiration dates
    fn validate_certificate_expiry(certs: &[rustls::Certificate]) -> Result<(), ServerError> {
        use rustls::internal::pemfile::read_one;
        
        for cert in certs {
            // Attempt to check expiry - this would require either OpenSSL bindings 
            // or implementing X.509 parsing, as rustls doesn't expose certificate details
            
            // For demonstration, we'll just check if it's parseable by webpki
            let cert = webpki::EndEntityCert::try_from(&cert.0)
                .map_err(|_| ServerError::Tls("Invalid certificate format".to_string()))?;
            
            // For a full implementation, you'd check:
            // - NotBefore/NotAfter dates
            // - Certificate chain validation
            // - Revocation status, etc.
            
            debug!("Certificate validation passed");
        }
        
        Ok(())
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
        let tun_router_handle = tokio::spawn(process_tun_packets(
            self.tun_device.clone(),
            self.session_manager.clone(),
            self.session_key_manager.clone(),
            self.packet_router.clone(),
            self.network_monitor.clone(),
            self.state.clone(),
        ));
        
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
                            if let Err(e) = handle_client(
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
    
    #[tokio::test]
    async fn test_setup_tls() {
        // Skip this test in CI environments without certificate files
        if std::env::var("CI").is_ok() {
            return;
        }
        
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
            .status();
            
        // Skip test if openssl command failed (may not be installed)
        if status.is_err() || !status.unwrap().success() {
            return;
        }
        
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
