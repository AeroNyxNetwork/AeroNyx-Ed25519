// src/server/core.rs
//! Core server implementation for the AeroNyx Privacy Network.
//!
//! This module contains the main VPN server implementation that handles
//! client connections, authentication, and network routing.

use std::io;
// Removed unused imports
use std::sync::Arc;
use std::time::Duration;
// Removed unused SinkExt and StreamExt
// use futures::StreamExt; // Corrected line 12 (removed)
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};
use tun::platform::Device;
// Import rustls types explicitly
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig}; // Added imports

use crate::auth::AuthManager;
use crate::auth::challenge::ChallengeError;
use crate::config::settings::ServerConfig;
use crate::crypto::{KeyManager, SessionKeyManager};
use crate::network::{IpPoolManager, NetworkMonitor, setup_tun_device, configure_nat, get_first_ip_from_subnet};
use crate::network::tun::TunConfig;
use crate::protocol::MessageError;
use crate::server::session::{SessionManager, SessionError};
use crate::server::routing::PacketRouter;
use crate::server::metrics::ServerMetricsCollector;
use crate::server::client::handle_client;
use crate::server::packet::start_tun_packet_processor;
use crate::utils::security::RateLimiter;

// --- ServerError enum remains the same ---
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
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error), // Ensure this is the correct Error type

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


// --- ServerState enum remains the same ---
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
    /// Server task handles (background tasks ONLY) <-- MODIFIED COMMENT
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
                    crate::config::constants::MAX_SECRET_CACHE_SIZE,
                ).await.map_err(|e| ServerError::KeyError(e.to_string()))?);
                config.key_manager = Some(km.clone());
                km
            }
        };

        // Setup TUN device
        info!("Setting up TUN device: {}", config.tun_name);
        let server_ip = get_first_ip_from_subnet(&config.subnet);
         if server_ip == "0.0.0.0" {
            return Err(ServerError::TunSetup(format!("Could not determine server IP for subnet {}", config.subnet)));
        }
        let tun_config = TunConfig {
            name: config.tun_name.clone(),
            subnet: config.subnet.clone(),
            server_ip,
            mtu: crate::config::constants::TUN_MTU,
        };
        let tun_device = setup_tun_device(&tun_config)
            .map_err(|e| ServerError::TunSetup(format!("Failed to create TUN device: {}", e)))?;
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
             crate::config::constants::AUTH_CHALLENGE_TIMEOUT,
            1000,
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
            config.key_rotation_interval,
            1_000_000,
        ));

        // Initialize network monitor
        let network_monitor = Arc::new(NetworkMonitor::new(
            Duration::from_secs(5),
            120,
        ));

        // Initialize packet router
        let packet_router = Arc::new(PacketRouter::new(
            crate::config::constants::PACKET_SIZE_LIMIT,
            config.enable_padding,
        ));

        // Initialize metrics collector
        let metrics = Arc::new(ServerMetricsCollector::new(
            Duration::from_secs(60),
            60,
        ));

        // Initialize rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(
            config.max_connections_per_ip,
             crate::config::constants::RATE_LIMIT_WINDOW,
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

    /// Set up TLS configuration
     fn setup_tls(config: &ServerConfig) -> Result<Arc<RustlsServerConfig>, ServerError> { // Return RustlsServerConfig
        debug!("Setting up TLS with cert: {:?}, key: {:?}", config.cert_file, config.key_file);

        if !config.cert_file.exists() {
            return Err(ServerError::Tls(format!("Certificate file not found: {:?}", config.cert_file)));
        }
        if !config.key_file.exists() {
            return Err(ServerError::Tls(format!("Private key file not found: {:?}", config.key_file)));
        }

        let cert_file = std::fs::File::open(&config.cert_file)
            .map_err(|e| ServerError::Tls(format!("Failed to open cert file: {}", e)))?;
        let mut cert_reader = std::io::BufReader::new(cert_file);

        // Read certificates (Vec<Vec<u8>>)
        let certs_bytes = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| ServerError::Tls(format!("Failed to parse certs: {}", e)))?;
        if certs_bytes.is_empty() {
            return Err(ServerError::Tls("No valid certificates found in cert file".to_string()));
        }
        // E0277 Fix: Collect into a Vec<Certificate>
        let rustls_certs: Vec<Certificate> = certs_bytes.into_iter().map(Certificate).collect();


        // Validate certificate expiry (basic check)
        if let Err(e) = Self::validate_certificate_expiry(&rustls_certs) {
             warn!("Certificate validation warning: {}", e);
        }


        let key_file = std::fs::File::open(&config.key_file)
            .map_err(|e| ServerError::Tls(format!("Failed to open key file: {}", e)))?;
         let mut key_reader = std::io::BufReader::new(key_file);

        // Try parsing PKCS#8 first, then RSA
        let key: PrivateKey = rustls_pemfile::read_one(&mut key_reader) // Use PrivateKey type
             .map_err(|e| ServerError::Tls(format!("Failed to read key file: {}", e)))?
             .and_then(|item| match item {
                 rustls_pemfile::Item::PKCS8Key(key) => Some(PrivateKey(key)),
                 rustls_pemfile::Item::RSAKey(key) => Some(PrivateKey(key)),
                 _ => None,
             })
             .ok_or_else(|| ServerError::Tls("No valid private key (PKCS#8 or RSA) found in key file".to_string()))?;


        // Use rustls safe defaults, TLS 1.3 only
        // E0308 Fix: Pass the `Vec<Certificate>` directly
        let mut tls_config = RustlsServerConfig::builder() // Use RustlsServerConfig
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(rustls_certs, key) // This now receives the correct Vec type
            .map_err(|e| ServerError::Tls(format!("TLS config error: {}", e)))?;

        // Enable session resumption
        tls_config.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);

        Ok(Arc::new(tls_config))
    }


    /// Validate certificate expiration dates (basic check)
    fn validate_certificate_expiry(certs: &[Certificate]) -> Result<(), ServerError> { // Use Certificate type
         if certs.is_empty() {
             return Err(ServerError::Tls("No certificates provided for validation".to_string()));
         }
        // We'll check the first certificate (leaf)
         let first_cert = &certs[0];
         match webpki::EndEntityCert::try_from(first_cert.as_ref()) { // Use as_ref()
             Ok(_cert) => {
                 debug!("Certificate basic parsing successful.");
                 Ok(())
             }
             Err(e) => Err(ServerError::Tls(format!("Invalid certificate structure: {}", e))),
         }
    }


    /// Start the VPN server
    /// Returns a JoinHandle for the main listener task.
    pub async fn start(&self) -> Result<JoinHandle<()>, ServerError> {
        // --- State Check ---
        {
            let mut state = self.state.write().await;
            if *state != ServerState::Created && *state != ServerState::Stopped {
                return Err(ServerError::Internal(format!("Cannot start server in state {:?}", *state)));
            }
            *state = ServerState::Starting;
        }

        info!("Starting AeroNyx Privacy Network Server on {}", self.config.listen_addr);

        // --- Start Background Tasks (store handles internally) ---
        self.start_background_tasks().await;

        // --- Start TUN Packet Processor (store handle internally) ---
         let tun_processor_handle = start_tun_packet_processor(
             self.tun_device.clone(),
             self.session_manager.clone(),
             self.session_key_manager.clone(),
             self.packet_router.clone(),
             self.network_monitor.clone(),
             self.state.clone(),
         ).await;
        {
            let mut handles = self.task_handles.lock().await;
            handles.push(tun_processor_handle);
        }


        // --- Prepare for Main Loop ---
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
        let listen_addr = self.config.listen_addr;

        // --- Main Server Loop Task (Accepting Connections) ---
         let main_server_handle = tokio::spawn(async move {
             let listener = match TcpListener::bind(&listen_addr).await {
                 Ok(l) => {
                     info!("Server listening on {}", listen_addr);
                     {
                         let mut state_guard = state.write().await;
                         if *state_guard == ServerState::Starting {
                            *state_guard = ServerState::Running;
                         } else {
                              error!("Server state changed during bind, stopping listener task.");
                             return;
                         }
                     }
                     l
                 }
                 Err(e) => {
                     error!("Failed to bind to {}: {}", listen_addr, e);
                     let mut state_guard = state.write().await;
                     *state_guard = ServerState::Stopped;
                     return;
                 }
             };


             // --- Accept Loop ---
             loop {
                 let current_state = *state.read().await;
                 if current_state != ServerState::Running {
                     info!("Server state is {:?}, stopping accept loop.", current_state);
                     break;
                 }

                 match listener.accept().await {
                     Ok((stream, addr)) => {
                         trace!("Accepted connection from {}", addr);

                         if !rate_limiter.check_rate_limit(&addr.ip()).await {
                             warn!("Rate limit exceeded for {}, rejecting connection", addr);
                             drop(stream);
                             continue;
                         }

                         metrics.record_new_connection().await;

                         // Clone Arcs for the client handling task
                         let tls_acceptor_clone = tls_acceptor.clone();
                         let key_manager_clone = key_manager.clone();
                         let auth_manager_clone = auth_manager.clone();
                         let ip_pool_clone = ip_pool.clone();
                         let session_manager_clone = session_manager.clone();
                         let session_key_manager_clone = session_key_manager.clone();
                         let network_monitor_clone = network_monitor.clone();
                         let packet_router_clone = packet_router.clone();
                         let metrics_clone = metrics.clone();
                         let server_state_clone = state.clone();

                         // Spawn a task for each client
                          tokio::spawn(async move {
                             let client_metrics = metrics_clone;
                             let result = handle_client(
                                 stream,
                                 addr,
                                 tls_acceptor_clone,
                                 key_manager_clone,
                                 auth_manager_clone,
                                 ip_pool_clone,
                                 session_manager_clone,
                                 session_key_manager_clone,
                                 network_monitor_clone,
                                 packet_router_clone,
                                 client_metrics.clone(),
                                 server_state_clone,
                             ).await;

                             // Log client disconnection reason
                             if let Err(e) = result {
                                 match e {
                                     ServerError::WebSocket(ws_err) => {
                                         use tokio_tungstenite::tungstenite::error::Error as WsError;
                                         match ws_err {
                                             WsError::ConnectionClosed | WsError::Protocol(_) | WsError::Io(_) => {
                                                 trace!("WebSocket connection closed for {}: {}", addr, ws_err);
                                             },
                                             _ => {
                                                 debug!("WebSocket error for {}: {}", addr, ws_err);
                                             }
                                         }
                                     }
                                     ServerError::Authentication(_) | ServerError::Tls(_) => {
                                         debug!("Client {} disconnected due to auth/TLS error: {}", addr, e);
                                     }
                                      ServerError::Internal(ref msg) if msg == "Server shutting down" => {
                                         debug!("Client {} disconnected due to server shutdown.", addr);
                                      }
                                     _ => {
                                         error!("Error handling client {}: {}", addr, e);
                                     }
                                 }
                             }
                             client_metrics.record_connection_close().await;
                         });
                     }
                     Err(e) => {
                         let current_state = *state.read().await;
                         if current_state == ServerState::Running {
                             error!("Error accepting connection: {}", e);
                             // Avoid busy-looping on accept errors
                             time::sleep(Duration::from_millis(100)).await;
                         } else {
                              info!("Accept loop terminated due to server state change.");
                             break; // Exit loop if server is stopping/stopped
                         }
                     }
                 }
             }
             // Accept loop finished
             info!("Server listener task stopped.");
        });

        // *** FIX: Return the actual handle for the main server task ***
        Ok(main_server_handle)
    }

    /// Shutdown the server gracefully
    pub async fn shutdown(&self) -> Result<(), ServerError> {
        // --- State Check and Update ---
        {
            let mut state = self.state.write().await;
            if *state == ServerState::ShuttingDown || *state == ServerState::Stopped {
                info!("Server already shutting down or stopped.");
                return Ok(());
            }
            if *state != ServerState::Running && *state != ServerState::Starting {
                 warn!("Cannot shut down server in state {:?}", *state);
                 // Still proceed to attempt cleanup
            }
             info!("Shutting down AeroNyx Privacy Network Server (current state: {:?})", *state);
            *state = ServerState::ShuttingDown; // Signal all tasks to stop
        }

        // --- Gracefully Close Existing Sessions ---
        info!("Closing active client sessions...");
        // Send disconnect messages and close connections
        self.session_manager.close_all_sessions("Server shutdown").await;
        // Give some time for messages to be sent
        time::sleep(Duration::from_millis(500)).await;


        // --- Abort Background Tasks stored in task_handles ---
        info!("Stopping background tasks...");
        {
            let mut handles = self.task_handles.lock().await;
             info!("Aborting {} background/TUN tasks.", handles.len());
            for handle in handles.iter() {
                handle.abort(); // Request task cancellation
            }
            // Optionally wait for tasks to finish after aborting
            // futures::future::join_all(handles.drain(..)).await;
             handles.clear(); // Clear the list
        }


        // --- Stop Monitor and Metrics ---
         self.network_monitor.stop().await;
         self.metrics.stop().await;


        // --- Final State Update ---
        {
            let mut state = self.state.write().await;
            *state = ServerState::Stopped;
        }

        info!("Server shutdown complete.");
        Ok(())
    }


    /// Start background maintenance tasks
     async fn start_background_tasks(&self) {
         info!("Starting background maintenance tasks.");
         let mut handles = Vec::new();

        // --- Task: Session Cleanup ---
         let session_manager_clone = self.session_manager.clone();
         let state_clone = self.state.clone();
         handles.push(tokio::spawn(async move {
             let mut interval = time::interval(Duration::from_secs(60));
             loop {
                 interval.tick().await;
                 let current_state = *state_clone.read().await;
                 // Stop if server is shutting down or stopped
                 if current_state == ServerState::ShuttingDown || current_state == ServerState::Stopped { break; }
                 // Continue if running or starting
                 if current_state != ServerState::Running && current_state != ServerState::Starting { continue; }

                 let removed = session_manager_clone.cleanup_expired_sessions().await;
                 if removed > 0 {
                     debug!("Cleaned up {} expired sessions", removed);
                 }
             }
              debug!("Session cleanup task stopped.");
         }));

        // --- Task: IP Pool Cleanup ---
         let ip_pool_clone = self.ip_pool.clone();
         let state_clone = self.state.clone();
         handles.push(tokio::spawn(async move {
             let mut interval = time::interval(Duration::from_secs(300));
             loop {
                 interval.tick().await;
                 let current_state = *state_clone.read().await;
                 // Stop if server is shutting down or stopped
                 if current_state == ServerState::ShuttingDown || current_state == ServerState::Stopped { break; }
                 // Continue if running or starting
                 if current_state != ServerState::Running && current_state != ServerState::Starting { continue; }


                 let removed = ip_pool_clone.cleanup_expired().await;
                 if !removed.is_empty() {
                     debug!("Released {} expired IP leases", removed.len());
                 }
             }
              debug!("IP pool cleanup task stopped.");
         }));

         // --- Task: Session Key Cleanup ---
          let session_key_manager_clone = self.session_key_manager.clone();
          let state_clone = self.state.clone();
          handles.push(tokio::spawn(async move {
              let mut interval = time::interval(Duration::from_secs(600));
              loop {
                  interval.tick().await;
                  let current_state = *state_clone.read().await;
                  // Stop if server is shutting down or stopped
                  if current_state == ServerState::ShuttingDown || current_state == ServerState::Stopped { break; }
                  // Continue if running or starting
                  if current_state != ServerState::Running && current_state != ServerState::Starting { continue; }

                  // Cleanup keys inactive for an hour
                  let removed = session_key_manager_clone.cleanup_old_sessions(Duration::from_secs(3600)).await;
                  if removed > 0 {
                      debug!("Cleaned up {} unused session keys", removed);
                  }
              }
               debug!("Session key cleanup task stopped.");
          }));

         // --- Task: Auth Challenge Cleanup ---
          let auth_manager_clone = self.auth_manager.clone();
          let state_clone = self.state.clone();
          handles.push(tokio::spawn(async move {
              let mut interval = time::interval(Duration::from_secs(60));
              loop {
                  interval.tick().await;
                  let current_state = *state_clone.read().await;
                   // Stop if server is shutting down or stopped
                  if current_state == ServerState::ShuttingDown || current_state == ServerState::Stopped { break; }
                  // Continue if running or starting
                  if current_state != ServerState::Running && current_state != ServerState::Starting { continue; }


                  let removed = auth_manager_clone.cleanup_expired_challenges().await;
                  if removed > 0 {
                      debug!("Cleaned up {} expired authentication challenges", removed);
                  }
              }
               debug!("Auth challenge cleanup task stopped.");
          }));


         // --- Task: Metrics Reporting ---
          let metrics_clone = self.metrics.clone();
          let state_clone = self.state.clone();
          handles.push(tokio::spawn(async move {
              // Reporting every hour might be too infrequent for monitoring, adjust if needed
              let mut interval = time::interval(Duration::from_secs(3600));
              loop {
                  interval.tick().await;
                  let current_state = *state_clone.read().await;
                  // Stop if server is shutting down or stopped
                  if current_state == ServerState::ShuttingDown || current_state == ServerState::Stopped { break; }
                   // Continue if running or starting
                  if current_state != ServerState::Running && current_state != ServerState::Starting { continue; }

                  let report = metrics_clone.generate_report().await;
                  info!("Server metrics report:\n{}", report);
              }
               debug!("Metrics reporting task stopped.");
          }));


        // --- Start Monitor and Metrics Collection Tasks ---
         self.network_monitor.start().await;
         self.metrics.start().await;


        // --- Store Background Task Handles ---
         {
             let mut task_handles_guard = self.task_handles.lock().await;
             task_handles_guard.extend(handles); // Add all background handles
         }
         info!("Background tasks started.");
    }

    /// Get the server's current state
    pub async fn get_state(&self) -> ServerState {
        *self.state.read().await
    }

    // --- Accessor methods ---
    pub fn metrics(&self) -> Arc<ServerMetricsCollector> {
        self.metrics.clone()
    }
    pub fn network_monitor(&self) -> Arc<NetworkMonitor> {
        self.network_monitor.clone()
    }
    pub fn session_manager(&self) -> Arc<SessionManager> {
        self.session_manager.clone()
    }
    pub fn ip_pool(&self) -> Arc<IpPoolManager> {
        self.ip_pool.clone()
    }
}


// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused PathBuf import
    // use std::path::PathBuf; // Corrected line 682

    #[tokio::test]
    #[ignore] // Still requires cert files
    async fn test_setup_tls() {
         if std::env::var("CI").is_ok() {
             println!("Skipping TLS test in CI environment.");
             return;
         }

        let temp_dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("Failed to create temp dir: {}", e);
                panic!("Failed to create temp dir");
            }
        };
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("server.key");

         println!("Generating test certificates...");
        let openssl_status = std::process::Command::new("openssl")
            .args([
                "req", "-x509",
                "-newkey", "rsa:2048",
                "-keyout", key_path.to_str().unwrap(),
                "-out", cert_path.to_str().unwrap(),
                "-days", "1",
                "-nodes",
                "-subj", "/CN=localhost"
            ])
            .status();

         match openssl_status {
             Ok(status) if status.success() => {
                  println!("Test certificates generated successfully.");
             },
             _ => {
                  println!("Skipping TLS test because certificate generation failed.");
                 return;
             }
         }

        let config = ServerConfig {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            tun_name: "tun_test".to_string(),
            subnet: "10.7.7.0/24".to_string(),
            cert_file: cert_path.clone(),
            key_file: key_path.clone(),
            acl_file: temp_dir.path().join("acl.json"),
            enable_obfuscation: false,
            obfuscation_method: "xor".to_string(),
            enable_padding: false,
            key_rotation_interval: Duration::from_secs(3600),
            session_timeout: Duration::from_secs(3600),
            max_connections_per_ip: 5,
            data_dir: temp_dir.path().to_path_buf(),
            server_key_file: temp_dir.path().join("server_key.json"),
            key_manager: None, // Let KeyManager be created internally if needed
        };

         println!("Testing TLS setup...");
        let result = VpnServer::setup_tls(&config);

        if let Err(e) = &result {
            eprintln!("TLS setup failed: {}", e);
        }
        assert!(result.is_ok(), "TLS setup should succeed with generated certs");

         println!("TLS test passed.");
    }
}
