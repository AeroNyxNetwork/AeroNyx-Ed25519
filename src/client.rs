use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{connect_async_tls_with_config, WebSocketStream};
use tokio_tungstenite::tungstenite::{Message, Result as WsResult};
use tun::{Device as TunDevice, Configuration as TunConfiguration};

use crate::config;
use crate::crypto::{self, SecretKeyCache, SessionKeyManager};
use crate::obfuscation::{ObfuscationMethod, TrafficShaper};
use crate::types::{PacketType, Result, VpnError};
use crate::utils;

/// VPN Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server hostname or IP
    pub server_host: String,
    /// Server port
    pub server_port: u16,
    /// Client's Solana keypair file path
    pub keypair_path: String,
    /// TUN device name
    pub tun_name: String,
    /// Enable obfuscation
    pub enable_obfuscation: bool,
    /// Obfuscation method
    pub obfuscation_method: String,
    /// Enable traffic padding
    pub enable_padding: bool,
    /// Log level
    pub log_level: String,
    /// Socket read timeout in seconds
    pub socket_timeout: u64,
    /// Reconnect attempts
    pub reconnect_attempts: u32,
    /// Reconnect delay in seconds
    pub reconnect_delay: u64,
    /// Auto-generate certificates if missing
    pub auto_generate_certs: bool,
    /// Custom TLS certificate path
    pub custom_cert_path: Option<String>,
    /// Trust custom certificates
    pub trust_custom_certs: bool,
    /// Auto-elevate privileges (requires password prompt)
    pub auto_elevate: bool,
    /// Connection auto-recovery
    pub auto_reconnect: bool,
    /// Certificate verification mode
    pub verify_certificates: bool,
    /// Data directory for storing configuration and keys
    pub data_dir: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        // Determine default data directory
        let data_dir = if cfg!(windows) {
            format!("{}\\AeroNyx", std::env::var("APPDATA").unwrap_or_else(|_| "C:\\Users\\Public\\Documents".to_string()))
        } else if cfg!(target_os = "macos") {
            format!("{}/Library/Application Support/AeroNyx", std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
        } else {
            format!("{}/.aeronyx", std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
        };

        Self {
            server_host: "localhost".to_string(),
            server_port: 8080,
            keypair_path: format!("{}/solana-keypair.json", data_dir),
            tun_name: if cfg!(windows) { "aeronyx0" } else { "tun0" }.to_string(),
            enable_obfuscation: false,
            obfuscation_method: "none".to_string(),
            enable_padding: false,
            log_level: "info".to_string(),
            socket_timeout: 60,
            reconnect_attempts: 5,
            reconnect_delay: 5,
            auto_generate_certs: true,
            custom_cert_path: None,
            trust_custom_certs: false,
            auto_elevate: true,
            auto_reconnect: true,
            verify_certificates: true,
            data_dir,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStats {
    /// Connection start time
    pub connected_since: Option<u64>,
    /// Assigned IP address
    pub assigned_ip: Option<String>,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Current session duration in seconds
    pub session_duration: u64,
    /// Connection latency in milliseconds
    pub latency_ms: u64,
    /// Connection status
    pub status: String,
    /// Server public key
    pub server_pubkey: Option<String>,
    /// Current session ID
    pub session_id: Option<String>,
}

impl Default for ClientStats {
    fn default() -> Self {
        Self {
            connected_since: None,
            assigned_ip: None,
            bytes_sent: 0,
            bytes_received: 0,
            session_duration: 0,
            latency_ms: 0,
            status: "Disconnected".to_string(),
            server_pubkey: None,
            session_id: None,
        }
    }
}

/// Connection state
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed(String),
}

/// VPN Client state
#[derive(Debug)]
pub struct VpnClient {
    /// Client configuration
    config: ClientConfig,
    /// Client's Solana keypair
    keypair: Keypair,
    /// WebSocket connection
    ws_stream: Option<Arc<Mutex<WebSocketStream<tokio_tungstenite::stream::Stream<TcpStream, tokio_rustls::client::TlsStream<TcpStream>>>>>>,
    /// TUN device
    tun_device: Option<Arc<Mutex<TunDevice>>>,
    /// Session key
    session_key: Arc<Mutex<Option<Vec<u8>>>>,
    /// Session ID
    session_id: Arc<Mutex<Option<String>>>,
    /// Assigned IP address
    assigned_ip: Arc<Mutex<Option<String>>>,
    /// Connection state
    connection_state: Arc<Mutex<ConnectionState>>,
    /// Session key manager
    session_manager: Arc<SessionKeyManager>,
    /// Traffic shaper for obfuscation
    traffic_shaper: Arc<TrafficShaper>,
    /// Secret key cache
    secret_cache: Arc<SecretKeyCache>,
    /// Packet counter for replay protection
    packet_counter: Arc<Mutex<u64>>,
    /// Server's public key
    server_pubkey: Arc<Mutex<Option<Pubkey>>>,
    /// Statistics
    stats: Arc<Mutex<ClientStats>>,
    /// Running tasks handles
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// Cancellation flag for all tasks
    cancel_flag: Arc<Mutex<bool>>,
}

impl VpnClient {
    /// Create a new VPN client
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Ensure data directory exists
        fs::create_dir_all(&config.data_dir)
            .map_err(|e| VpnError::Io(e))?;

        // Create or load client keypair
        let keypair = Self::ensure_keypair(&config.keypair_path).await?;
        
        // Initialize traffic shaper
        let obfuscation_method = ObfuscationMethod::from_str(&config.obfuscation_method);
        let traffic_shaper = TrafficShaper::new(obfuscation_method);
        
        let client = Self {
            config,
            keypair,
            ws_stream: None,
            tun_device: None,
            session_key: Arc::new(Mutex::new(None)),
            session_id: Arc::new(Mutex::new(None)),
            assigned_ip: Arc::new(Mutex::new(None)),
            connection_state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            session_manager: Arc::new(SessionKeyManager::new()),
            traffic_shaper: Arc::new(traffic_shaper),
            secret_cache: Arc::new(SecretKeyCache::new()),
            packet_counter: Arc::new(Mutex::new(0)),
            server_pubkey: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(ClientStats::default())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            cancel_flag: Arc::new(Mutex::new(false)),
        };
        
        Ok(client)
    }

    /// Ensure Solana keypair exists, create if it doesn't
    pub async fn ensure_keypair(path: &str) -> Result<Keypair> {
        // Check if keypair file exists
        if Path::new(path).exists() {
            // Load existing keypair
            return Self::load_keypair(path);
        }
        
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| VpnError::Io(e))?;
        }
        
        // Generate new keypair
        tracing::info!("Generating new Solana keypair at {}", path);
        let keypair = Keypair::new();
        
        // Save keypair to file
        let keypair_bytes = keypair.to_bytes();
        let json = serde_json::to_vec(&keypair_bytes.to_vec())
            .map_err(|e| VpnError::Json(e))?;
            
        fs::write(path, json)
            .map_err(|e| VpnError::Io(e))?;
            
        tracing::info!("New keypair generated with public key: {}", keypair.pubkey());
        
        Ok(keypair)
    }
    
    /// Load Solana keypair from file
    fn load_keypair(path: &str) -> Result<Keypair> {
        let keypair_bytes = std::fs::read_to_string(path)
            .map_err(|e| VpnError::Io(e))?;
            
        let keypair_json: Vec<u8> = serde_json::from_str(&keypair_bytes)
            .map_err(|e| VpnError::Json(e))?;
            
        let keypair = Keypair::from_bytes(&keypair_json)
            .map_err(|e| VpnError::Crypto(e.to_string()))?;
            
        tracing::info!("Loaded keypair with public key: {}", keypair.pubkey());
        
        Ok(keypair)
    }
    
    /// Generate a self-signed TLS certificate for development
    pub async fn generate_self_signed_cert(
        common_name: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<()> {
        // Ensure OpenSSL is available
        let openssl_check = TokioCommand::new("openssl")
            .arg("version")
            .output()
            .await;
            
        if openssl_check.is_err() {
            return Err(VpnError::Crypto("OpenSSL not found in PATH. Please install OpenSSL or manually generate certificates.".into()));
        }
        
        // Create directories if they don't exist
        if let Some(parent) = Path::new(cert_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| VpnError::Io(e))?;
        }
        
        if let Some(parent) = Path::new(key_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| VpnError::Io(e))?;
        }
        
        tracing::info!("Generating self-signed TLS certificate for {}", common_name);
        
        // Generate self-signed certificate using OpenSSL
        let output = TokioCommand::new("openssl")
            .arg("req")
            .arg("-x509")
            .arg("-newkey")
            .arg("rsa:4096")
            .arg("-keyout")
            .arg(key_path)
            .arg("-out")
            .arg(cert_path)
            .arg("-days")
            .arg("365")
            .arg("-nodes")
            .arg("-subj")
            .arg(format!("/CN={}", common_name))
            .output()
            .await
            .map_err(|e| VpnError::Crypto(format!("Failed to execute OpenSSL: {}", e)))?;
            
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(VpnError::Crypto(format!("Failed to generate certificate: {}", error)));
        }
        
        tracing::info!("Self-signed certificate generated successfully");
        
        Ok(())
    }
    
    /// Check if we have root/admin privileges
    pub fn has_elevated_privileges() -> bool {
        #[cfg(unix)]
        {
            nix::unistd::geteuid().is_root()
        }
        
        #[cfg(windows)]
        {
            // Check for admin privileges on Windows (simplified method)
            // In a real implementation, use IsUserAnAdmin from shell32.dll
            let output = Command::new("net")
                .args(&["session"])
                .output();
                
            match output {
                Ok(o) => o.status.success(),
                Err(_) => false,
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }
    
    /// Attempt to elevate privileges if needed
    pub async fn elevate_privileges() -> Result<bool> {
        if Self::has_elevated_privileges() {
            return Ok(true);
        }
        
        tracing::warn!("AeroNyx VPN requires elevated privileges to create TUN devices");
        tracing::info!("Attempting to restart with elevated privileges...");
        
        #[cfg(unix)]
        {
            // On Unix, use sudo
            let args: Vec<String> = std::env::args().collect();
            let current_exe = std::env::current_exe()
                .map_err(|e| VpnError::Io(e))?;
                
            let result = TokioCommand::new("sudo")
                .arg("-p")
                .arg("[sudo] Password required to create VPN tunnel: ")
                .arg(current_exe)
                .args(&args[1..])
                .spawn();
                
            match result {
                Ok(_) => {
                    tracing::info!("Launched with elevated privileges, exiting current process");
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::error!("Failed to elevate privileges: {}", e);
                    return Err(VpnError::Network(format!("Failed to elevate privileges: {}", e)));
                }
            }
        }
        
        #[cfg(windows)]
        {
            // On Windows, use ShellExecute with "runas"
            use std::os::windows::process::CommandExt;
            
            let args: Vec<String> = std::env::args().collect();
            let current_exe = std::env::current_exe()
                .map_err(|e| VpnError::Io(e))?;
                
            const RUNAS_FLAG: u32 = 0x00000002;
            
            let result = Command::new("cmd")
                .args(&["/C", "start", "AeroNyx VPN (Administrator)", "/wait"])
                .arg(current_exe)
                .args(&args[1..])
                .creation_flags(RUNAS_FLAG)
                .spawn();
                
            match result {
                Ok(_) => {
                    tracing::info!("Launched with elevated privileges, exiting current process");
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::error!("Failed to elevate privileges: {}", e);
                    return Err(VpnError::Network(format!("Failed to elevate privileges: {}", e)));
                }
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            return Err(VpnError::Network("Privilege elevation not supported on this platform".into()));
        }
        
        // Should never reach here because we exit the process above
        Ok(false)
    }
    
    /// Connect to the VPN server
    pub async fn connect(&mut self) -> Result<()> {
        // Check if already connected
        if self.is_connected().await {
            tracing::info!("Already connected to VPN server");
            return Ok(());
        }
        
        // Update connection state
        *self.connection_state.lock().await = ConnectionState::Connecting;
        *self.cancel_flag.lock().await = false;
        
        // Check if we need elevated privileges
        if !Self::has_elevated_privileges() {
            if self.config.auto_elevate {
                Self::elevate_privileges().await?;
                // If we get here, elevation failed but we want to continue anyway
                tracing::warn!("Continuing without elevated privileges, this may fail");
            } else {
                tracing::warn!("AeroNyx VPN requires elevated privileges to create TUN devices");
                tracing::warn!("Please run as root/administrator or enable auto_elevate in config");
            }
        }
        
        // Create TUN device
        match self.setup_tun_device().await {
            Ok(_) => tracing::info!("TUN device created successfully"),
            Err(e) => {
                *self.connection_state.lock().await = ConnectionState::Failed(format!("TUN setup failed: {}", e));
                return Err(e);
            }
        }
        
        // Connect to server
        match self.connect_to_server().await {
            Ok(_) => tracing::info!("Connected to VPN server"),
            Err(e) => {
                *self.connection_state.lock().await = ConnectionState::Failed(format!("Connection failed: {}", e));
                return Err(e);
            }
        }
        
        // Start the packet handler
        match self.start_packet_handler().await {
            Ok(_) => tracing::info!("Packet handler started"),
            Err(e) => {
                *self.connection_state.lock().await = ConnectionState::Failed(format!("Packet handler failed: {}", e));
                self.cleanup_connection().await;
                return Err(e);
            }
        }
        
        // Start stats collection task
        let stats = self.stats.clone();
        let session_id = self.session_id.clone();
        let assigned_ip = self.assigned_ip.clone();
        let server_pubkey = self.server_pubkey.clone();
        let cancel_flag = self.cancel_flag.clone();
        
        let stats_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let start_time = utils::current_timestamp_millis();
            
            while !*cancel_flag.lock().await {
                interval.tick().await;
                
                let mut stats_lock = stats.lock().await;
                stats_lock.connected_since = Some(start_time);
                stats_lock.session_duration = (utils::current_timestamp_millis() - start_time) / 1000;
                stats_lock.assigned_ip = assigned_ip.lock().await.clone();
                stats_lock.session_id = session_id.lock().await.clone();
                stats_lock.status = "Connected".to_string();
                
                if let Some(pubkey) = *server_pubkey.lock().await {
                    stats_lock.server_pubkey = Some(pubkey.to_string());
                }
            }
        });
        
        // Save task handle
        self.tasks.lock().await.push(stats_task);
        
        // Update connection state
        *self.connection_state.lock().await = ConnectionState::Connected;
        
        Ok(())
    }
    
    /// Set up the TUN device
    async fn setup_tun_device(&mut self) -> Result<()> {
        let mut config = TunConfiguration::default();
        
        config.name(&self.config.tun_name)
            .up()
            .mtu(1500);
            
        // Attempt to create TUN device
        let device = match tun::create(&config) {
            Ok(device) => device,
            Err(e) => {
                // Check if error is permissions-related
                let error_string = e.to_string();
                if error_string.contains("permission denied") {
                    tracing::error!("Permission denied when creating TUN device. Run as root/administrator.");
                    return Err(VpnError::Network("Permission denied when creating TUN device. Run as root/administrator.".into()));
                } else {
                    return Err(VpnError::Network(format!("Failed to create TUN device: {}", e)));
                }
            }
        };
            
        tracing::info!("TUN device {} created", self.config.tun_name);
        
        self.tun_device = Some(Arc::new(Mutex::new(device)));
        
        Ok(())
    }
    
    /// Connect to the VPN server
    async fn connect_to_server(&mut self) -> Result<()> {
        let server_url = format!(
            "wss://{}:{}",
            self.config.server_host,
            self.config.server_port
        );
        
        tracing::info!("Connecting to VPN server at {}", server_url);
        
        // Set up certificates
        let tls_config = self.setup_tls_config().await?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        
        // Connect to WebSocket server with TLS
        let (ws_stream, _) = connect_async_tls_with_config(
            &server_url,
            None,
            false,
            Some(connector),
        ).await.map_err(|e| VpnError::Network(format!("WebSocket connection failed: {}", e)))?;
        
        tracing::info!("Connected to server, performing authentication");
        
        let (mut write, mut read) = ws_stream.split();
        
        // Send authentication message
        let auth_message = PacketType::Auth {
            public_key: self.keypair.pubkey().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            features: vec![
                "chacha20poly1305".to_string(),
                "perfect_forward_secrecy".to_string(),
                if self.config.enable_obfuscation {
                    self.config.obfuscation_method.clone()
                } else {
                    "none".to_string()
                },
            ],
            nonce: utils::random_string(16),
        };
        
        let auth_json = serde_json::to_string(&auth_message)
            .map_err(|e| VpnError::Json(e))?;
            
        write.send(Message::Text(auth_json)).await
            .map_err(|e| VpnError::WebSocket(e))?;
            
        // Wait for challenge
        if let Some(Ok(msg)) = read.next().await {
            if let Ok(text) = msg.to_text() {
                let challenge: PacketType = serde_json::from_str(text)
                    .map_err(|e| VpnError::Json(e))?;
                    
                match challenge {
                    PacketType::Challenge { data, server_key, expires_at, id } => {
                        tracing::debug!("Received challenge: id={}, expires={}", id, expires_at);
                        
                        // Store server's public key
                        let server_pubkey = Pubkey::from_str(&server_key)
                            .map_err(|e| VpnError::Crypto(format!("Invalid server public key: {}", e)))?;
                            
                        *self.server_pubkey.lock().await = Some(server_pubkey);
                        
                        // Sign the challenge
                        let signature = self.keypair.sign_message(&data);
                        
                        // Send challenge response
                        let response = PacketType::ChallengeResponse {
                            signature: signature.to_string(),
                            public_key: self.keypair.pubkey().to_string(),
                            challenge_id: id,
                        };
                        
                        let response_json = serde_json::to_string(&response)
                            .map_err(|e| VpnError::Json(e))?;
                            
                        write.send(Message::Text(response_json)).await
                            .map_err(|e| VpnError::WebSocket(e))?;
                    }
                    _ => {
                        return Err(VpnError::AuthenticationFailed("Expected challenge".into()));
                    }
                }
            }
        } else {
            return Err(VpnError::AuthenticationFailed("No response from server".into()));
        }
        
        // Wait for IP assignment
        if let Some(Ok(msg)) = read.next().await {
            if let Ok(text) = msg.to_text() {
                let ip_assign: PacketType = serde_json::from_str(text)
                    .map_err(|e| VpnError::Json(e))?;
                    
                match ip_assign {
                    PacketType::IpAssign { ip_address, lease_duration, session_id, encrypted_session_key, key_nonce } => {
                        tracing::info!("Received IP assignment: {}, lease: {}s", ip_address, lease_duration);
                        
                        // Store assigned IP and session ID
                        *self.assigned_ip.lock().await = Some(ip_address.clone());
                        *self.session_id.lock().await = Some(session_id);
                        
                        // Update stats
                        let mut stats = self.stats.lock().await;
                        stats.assigned_ip = Some(ip_address.clone());
                        stats.status = "Connected".to_string();
                        
                        // Derive shared secret for key decryption
                        let server_pubkey = self.server_pubkey.lock().await.unwrap();
                        let shared_secret = self.secret_cache
                            .get_or_compute(&self.keypair, &server_pubkey)
                            .await?;
                            
                        // Decrypt the session key
                        let session_key = crypto::decrypt_session_key(
                            &encrypted_session_key,
                            &key_nonce,
                            &shared_secret,
                        )?;
                        
                        // Store the session key
                        *self.session_key.lock().await = Some(session_key);
                        
                        // Configure the TUN device with the assigned IP
                        self.configure_tun_ip(&ip_address).await?;
                    }
                    _ => {
                        return Err(VpnError::AuthenticationFailed("Expected IP assignment".into()));
                    }
                }
            }
        } else {
            return Err(VpnError::AuthenticationFailed("No IP assignment from server".into()));
        }
        
        // Store the WebSocket stream
        let ws_stream = write.reunite(read)
            .map_err(|_| VpnError::Network("Failed to reunite WebSocket stream".into()))?;
            
        self.ws_stream = Some(Arc::new(Mutex::new(ws_stream)));
        
        tracing::info!("Authentication successful, VPN connection established");
        
        Ok(())
    }
    
    /// Set up TLS configuration
    async fn setup_tls_config(&self) -> Result<ClientConfig> {
        // Determine certificate path
        let cert_path = match &self.config.custom_cert_path {
            Some(path) => path.clone(),
            None => {
                let default_path = format!("{}/server.crt", self.config.data_dir);
                
                // Auto-generate certificate if needed
                if self.config.auto_generate_certs && !Path::new(&default_path).exists() {
                    let key_path = format!("{}/server.key", self.config.data_dir);
                    Self::generate_self_signed_cert(&self.config.server_host, &default_path, &key_path).await?;
                }
                
                default_path
            }
        };
        
        // Load root certificates
        let mut root_store = RootCertStore::empty();
        
        // Load native certs if we're verifying certificates
        if self.config.verify_certificates {
            for cert in rustls_native_certs::load_native_certs()
                .map_err(|e| VpnError::Tls(format!("Failed to load native certs: {}", e)))? {
                root_store.add(&rustls::Certificate(cert.0))
                    .map_err(|e| VpnError::Tls(format!("Failed to add cert to store: {}", e)))?;
            }
        }
        
        // Add custom certificate if needed
        if self.config.trust_custom_certs && Path::new(&cert_path).exists() {
            let mut cert_file = File::open(&cert_path)
                .map_err(|e| VpnError::Tls(format!("Failed to open custom cert file: {}", e)))?;
                
            let mut cert_data = Vec::new();
            cert_file.read_to_end(&mut cert_data)
                .map_err(|e| VpnError::Tls(format!("Failed to read custom cert file: {}", e)))?;
                
            root_store.add(&rustls::Certificate(cert_data))
                .map_err(|e| VpnError::Tls(format!("Failed to add custom cert to store: {}", e)))?;
                
            tracing::info!("Added custom certificate from {}", cert_path);
        }
        
        // Create TLS configuration
        let mut tls_config = if self.config.verify_certificates {
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            // Skip certificate verification (not recommended for production)
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {}))
                .with_no_client_auth()
        };
        
        // Set session timeout
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        
        Ok(tls_config)
    }
    
    /// Configure TUN device with assigned IP
    async fn configure_tun_ip(&self, ip: &str) -> Result<()> {
        if let Some(tun_device) = &self.tun_device {
            tracing::info!("Configuring TUN device {} with IP {}", self.config.tun_name, ip);
            
            // Create a subnet string (assuming /24)
            let subnet = format!("{}/24", ip);
            
            // Platform-specific network configuration
            #[cfg(target_os = "linux")]
            {
                // For Linux, use ip command
                let status = TokioCommand::new("ip")
                    .args(&["addr", "add", &subnet, "dev", &self.config.tun_name])
                    .status()
                    .await
                    .map_err(|e| VpnError::Network(format!("Failed to configure TUN IP: {}", e)))?;
                
                if !status.success() {
                    tracing::warn!("Failed to configure TUN IP, exit code: {:?}", status.code());
                    return Err(VpnError::Network("Failed to configure TUN IP address".into()));
                }
                
                // Set the interface up
                let status = TokioCommand::new("ip")
                    .args(&["link", "set", "dev", &self.config.tun_name, "up"])
                    .status()
                    .await
                    .map_err(|e| VpnError::Network(format!("Failed to set TUN interface up: {}", e)))?;
                
                if !status.success() {
                    tracing::warn!("Failed to set TUN interface up, exit code: {:?}", status.code());
                    return Err(VpnError::Network("Failed to set TUN interface up".into()));
                }
            }
            
            #[cfg(target_os = "macos")]
            {
                // For macOS, use ifconfig
                let status = TokioCommand::new("ifconfig")
                    .args(&[&self.config.tun_name, "inet", ip, ip, "up"])
                    .status()
                    .await
                    .map_err(|e| VpnError::Network(format!("Failed to configure TUN IP: {}", e)))?;
                
                if !status.success() {
                    tracing::warn!("Failed to configure TUN IP, exit code: {:?}", status.code());
                    return Err(VpnError::Network("Failed to configure TUN IP address".into()));
                }
            }
            
            #[cfg(target_os = "windows")]
            {
                // For Windows, use netsh
                // First, get the interface index
                let output = TokioCommand::new("netsh")
                    .args(&["interface", "ipv4", "show", "interfaces"])
                    .output()
                    .await
                    .map_err(|e| VpnError::Network(format!("Failed to get network interfaces: {}", e)))?;
                
                let output_str = String::from_utf8_lossy(&output.stdout);
                let mut interface_index = None;
                
                for line in output_str.lines() {
                    if line.contains(&self.config.tun_name) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            interface_index = parts[0].parse::<u32>().ok();
                            break;
                        }
                    }
                }
                
                if let Some(idx) = interface_index {
                    // Set IP address
                    let status = TokioCommand::new("netsh")
                        .args(&[
                            "interface", "ipv4", "set", "address",
                            &format!("interface={}", idx),
                            "static", ip, "255.255.255.0"
                        ])
                        .status()
                        .await
                        .map_err(|e| VpnError::Network(format!("Failed to configure TUN IP: {}", e)))?;
                    
                    if !status.success() {
                        tracing::warn!("Failed to configure TUN IP, exit code: {:?}", status.code());
                        return Err(VpnError::Network("Failed to configure TUN IP address".into()));
                    }
                } else {
                    tracing::error!("Failed to find TUN interface index");
                    return Err(VpnError::Network("Failed to find TUN interface index".into()));
                }
            }
            
            tracing::info!("TUN device configured with IP {}", ip);
        } else {
            tracing::warn!("No TUN device available to configure");
        }
        
        Ok(())
    }
    
    /// Start the packet handler
    async fn start_packet_handler(&self) -> Result<()> {
        if self.ws_stream.is_none() || self.tun_device.is_none() {
            return Err(VpnError::Network("Not connected".into()));
        }
        
        let ws_stream = self.ws_stream.as_ref().unwrap().clone();
        let tun_device = self.tun_device.as_ref().unwrap().clone();
        let session_key = self.session_key.clone();
        let traffic_shaper = self.traffic_shaper.clone();
        let packet_counter = self.packet_counter.clone();
        let cancel_flag = self.cancel_flag.clone();
        let stats = self.stats.clone();
        
        // TUN to WebSocket task
        let ws_stream_clone = ws_stream.clone();
        let session_key_clone = session_key.clone();
        let packet_counter_clone = packet_counter.clone();
        let stats_clone = stats.clone();
        let cancel_flag_clone = cancel_flag.clone();
        
        let tun_to_ws_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            
            while !*cancel_flag_clone.lock().await {
                // Read packet from TUN device
                let n = {
                    let mut device = tun_device.lock().await;
                    match device.read(&mut buffer) {
                        Ok(n) => n,
                        Err(e) => {
                            if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
                                // Non-blocking operation would block, sleep a bit and retry
                                tokio::time::sleep(Duration::from_millis(1)).await;
                                continue;
                            }
                            
                            tracing::error!("Error reading from TUN: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                };
                
                if n > 0 {
                    // Update stats
                    {
                        let mut stats = stats_clone.lock().await;
                        stats.bytes_sent += n as u64;
                    }
                    
                    // Get session key
                    if let Some(key) = &*session_key_clone.lock().await {
                        // Apply traffic padding if enabled
                        let packet_data = traffic_shaper.add_padding(&buffer[..n]);
                        
                        // Encrypt the packet
                        match crypto::encrypt_packet(&packet_data, key) {
                            Ok((encrypted, nonce)) => {
                                // Increment packet counter
                                let counter = {
                                    let mut counter = packet_counter_clone.lock().await;
                                    let current = *counter;
                                    *counter += 1;
                                    current
                                };
                                
                                // Create data packet
                                let data_packet = PacketType::Data {
                                    encrypted,
                                    nonce,
                                    counter,
                                    padding: None,
                                };
                                
                                // Serialize and send
                                if let Ok(json) = serde_json::to_string(&data_packet) {
                                    let mut stream = ws_stream_clone.lock().await;
                                    if let Err(e) = stream.send(Message::Text(json)).await {
                                        tracing::error!("Error sending to server: {}", e);
                                        *cancel_flag_clone.lock().await = true;
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Encryption error: {}", e);
                            }
                        }
                    }
                }
            }
        });
        
        // WebSocket to TUN task
        let stats_clone = stats.clone();
        let cancel_flag_clone = cancel_flag.clone();
        
        let ws_to_tun_task = tokio::spawn(async move {
            let mut stream = ws_stream.lock().await;
            let mut last_counter: Option<u64> = None;
            
            while !*cancel_flag_clone.lock().await {
                match tokio::time::timeout(Duration::from_secs(1), stream.next()).await {
                    Ok(Some(Ok(msg))) => {
                        match msg {
                            Message::Text(text) => {
                                // Parse message
                                match serde_json::from_str::<PacketType>(&text) {
                                    Ok(PacketType::Data { encrypted, nonce, counter, padding: _ }) => {
                                        // Check for replay attacks
                                        if let Some(last) = last_counter {
                                            if counter <= last {
                                                tracing::warn!("Possible replay attack detected!");
                                                continue;
                                            }
                                        }
                                        last_counter = Some(counter);
                                        
                                        // Get session key
                                        if let Some(key) = &*session_key.lock().await {
                                            // Decrypt the packet
                                            match crypto::decrypt_packet(&encrypted, key, &nonce) {
                                                Ok(decrypted) => {
                                                    // Update stats
                                                    {
                                                        let mut stats = stats_clone.lock().await;
                                                        stats.bytes_received += decrypted.len() as u64;
                                                    }
                                                    
                                                    // Remove padding if present
                                                    let packet_data = traffic_shaper.remove_padding(&decrypted).unwrap_or(decrypted);
                                                    
                                                    // Write decrypted packet to TUN
                                                    let mut device = tun_device.lock().await;
                                                    if let Err(e) = device.write(&packet_data) {
                                                        tracing::error!("Error writing to TUN: {}", e);
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!("Decryption error: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    Ok(PacketType::Ping { timestamp, sequence }) => {
                                        // Respond with Pong
                                        let pong = PacketType::Pong {
                                            echo_timestamp: timestamp,
                                            server_timestamp: utils::current_timestamp_millis(),
                                            sequence,
                                        };
                                        
                                        // Calculate latency
                                        let now = utils::current_timestamp_millis();
                                        let latency = now - timestamp;
                                        
                                        // Update stats
                                        {
                                            let mut stats = stats_clone.lock().await;
                                            stats.latency_ms = latency;
                                        }
                                        
                                        if let Ok(json) = serde_json::to_string(&pong) {
                                            if let Err(e) = stream.send(Message::Text(json)).await {
                                                tracing::error!("Error sending pong: {}", e);
                                                *cancel_flag_clone.lock().await = true;
                                                break;
                                            }
                                        }
                                    }
                                    Ok(PacketType::KeyRotation { encrypted_new_key, nonce, key_id, signature }) => {
                                        // Handle key rotation
                                        if let Some(server_pubkey) = *self.server_pubkey.lock().await {
                                            // Verify signature
                                            let mut sign_data = key_id.clone().into_bytes();
                                            sign_data.extend_from_slice(&nonce);
                                            
                                            let sig = match Signature::from_str(&signature) {
                                                Ok(s) => s,
                                                Err(e) => {
                                                    tracing::error!("Invalid signature in key rotation: {}", e);
                                                    continue;
                                                }
                                            };
                                            
                                            if !crypto::verify_signature(&server_pubkey, &sign_data, &sig) {
                                                tracing::error!("Signature verification failed for key rotation");
                                                continue;
                                            }
                                            
                                            // Get current session key
                                            if let Some(current_key) = &*session_key.lock().await {
                                                // Decrypt the new key
                                                match crypto::decrypt_chacha20(&encrypted_new_key, current_key, &nonce) {
                                                    Ok(new_key) => {
                                                        // Update session key
                                                        *session_key.lock().await = Some(new_key);
                                                        tracing::info!("Session key rotated");
                                                    }
                                                    Err(e) => {
                                                        tracing::error!("Failed to decrypt new session key: {}", e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Ok(PacketType::Disconnect { reason, message }) => {
                                        tracing::info!("Server disconnecting: {} ({})", message, reason);
                                        *cancel_flag_clone.lock().await = true;
                                        break;
                                    }
                                    Ok(PacketType::Error { code, message }) => {
                                        tracing::error!("Server error: {} ({})", message, code);
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to parse message: {}", e);
                                    }
                                    _ => {}
                                }
                            }
                            Message::Binary(_) => {
                                // Handle binary messages if implemented
                            }
                            Message::Close(_) => {
                                tracing::info!("Server closed connection");
                                *cancel_flag_clone.lock().await = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    Ok(Some(Err(e))) => {
                        tracing::error!("WebSocket error: {}", e);
                        *cancel_flag_clone.lock().await = true;
                        break;
                    }
                    Ok(None) => {
                        tracing::info!("WebSocket stream ended");
                        *cancel_flag_clone.lock().await = true;
                        break;
                    }
                    Err(_) => {
                        // Timeout, just continue
                        continue;
                    }
                }
            }
        });
        
        // Store task handles
        let mut tasks = self.tasks.lock().await;
        tasks.push(tun_to_ws_task);
        tasks.push(ws_to_tun_task);
        
        Ok(())
    }
    
    /// Clean up connection resources
    async fn cleanup_connection(&mut self) {
        // Cancel all tasks
        *self.cancel_flag.lock().await = true;
        
        // Wait for tasks to complete
        let tasks = std::mem::take(&mut *self.tasks.lock().await);
        for task in tasks {
            let _ = task.abort();
        }
        
        // Close WebSocket connection
        if let Some(ws_stream) = &self.ws_stream {
            let mut stream = ws_stream.lock().await;
            let _ = stream.close(None).await;
        }
        
        // Clear session state
        *self.session_key.lock().await = None;
        *self.session_id.lock().await = None;
        
        // Release IP address on the server side
        if let Some(ip) = &*self.assigned_ip.lock().await {
            tracing::info!("Released IP address: {}", ip);
        }
        *self.assigned_ip.lock().await = None;
        
        // Update stats
        let mut stats = self.stats.lock().await;
        stats.status = "Disconnected".to_string();
        stats.connected_since = None;
        
        // Reset TUN device
        self.tun_device = None;
        
        // Reset WebSocket connection
        self.ws_stream = None;
        
        // Reset connection state
        *self.connection_state.lock().await = ConnectionState::Disconnected;
    }
    
    /// Disconnect from the VPN server
    pub async fn disconnect(&mut self) -> Result<()> {
        // Check if already disconnected
        if !self.is_connected().await {
            tracing::info!("Already disconnected from VPN server");
            return Ok(());
        }
        
        tracing::info!("Disconnecting from VPN server");
        
        if let Some(ws_stream) = &self.ws_stream {
            // Send disconnect message
            let disconnect = PacketType::Disconnect {
                reason: 0,
                message: "Client disconnecting".to_string(),
            };
            
            if let Ok(json) = serde_json::to_string(&disconnect) {
                let mut stream = ws_stream.lock().await;
                let _ = stream.send(Message::Text(json)).await;
                let _ = stream.close(None).await;
            }
        }
        
        // Clean up connection resources
        self.cleanup_connection().await;
        
        tracing::info!("Disconnected from VPN server");
        
        Ok(())
    }
    
    /// Check if the client is connected
    pub async fn is_connected(&self) -> bool {
        matches!(*self.connection_state.lock().await, ConnectionState::Connected)
    }
    
    /// Get the current connection state
    pub async fn get_connection_state(&self) -> String {
        match *self.connection_state.lock().await {
            ConnectionState::Disconnected => "Disconnected".to_string(),
            ConnectionState::Connecting => "Connecting".to_string(),
            ConnectionState::Connected => "Connected".to_string(),
            ConnectionState::Reconnecting => "Reconnecting".to_string(),
            ConnectionState::Failed(ref reason) => format!("Failed: {}", reason),
        }
    }
    
    /// Get the assigned IP address
    pub async fn get_assigned_ip(&self) -> Option<String> {
        self.assigned_ip.lock().await.clone()
    }
    
    /// Get current statistics
    pub async fn get_stats(&self) -> ClientStats {
        self.stats.lock().await.clone()
    }
    
    /// Check for root/admin privileges (static method)
    pub fn check_permissions() -> String {
        if Self::has_elevated_privileges() {
            "You have the necessary permissions to create VPN tunnels.".to_string()
        } else {
            "Warning: You do not have administrator/root privileges. \
             You may not be able to create VPN tunnels. \
             Please run this application with elevated privileges.".to_string()
        }
    }
    
    /// Get public key (useful for registration)
    pub fn get_public_key(&self) -> String {
        self.keypair.pubkey().to_string()
    }
    
    /// Save config to file
    pub fn save_config(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.config)
            .map_err(|e| VpnError::Json(e))?;
            
        fs::write(path, json)
            .map_err(|e| VpnError::Io(e))?;
            
        Ok(())
    }
    
    /// Load config from file
    pub fn load_config(path: &str) -> Result<ClientConfig> {
        let json = fs::read_to_string(path)
            .map_err(|e| VpnError::Io(e))?;
            
        let config = serde_json::from_str(&json)
            .map_err(|e| VpnError::Json(e))?;
            
        Ok(config)
    }
}

// This is only used when certificate verification is disabled (not recommended for production)
mod danger {
    use std::sync::Arc;
    use std::time::SystemTime;
    use rustls::{Certificate, ServerName, Error, ServerCertVerified, ServerCertVerifier};

    pub struct NoCertificateVerification {}

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, Error> {
            // This is unsafe and should only be used for development/testing
            Ok(ServerCertVerified::assertion())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    
    #[test]
    fn test_client_config() {
        let config = ClientConfig::default();
        assert_eq!(config.server_host, "localhost");
        assert_eq!(config.server_port, 8080);
    }
    
    #[test]
    fn test_permission_check() {
        let result = VpnClient::check_permissions();
        assert!(result.contains("privileges"));
    }
    
    #[test]
    fn test_config_save_load() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Create a temporary config file
            let temp_dir = tempfile::tempdir().unwrap();
            let config_path = temp_dir.path().join("test_config.json");
            
            // Create default config
            let config = ClientConfig::default();
            
            // Create client
            let client = VpnClient::new(config.clone()).await.unwrap();
            
            // Save config
            client.save_config(config_path.to_str().unwrap()).unwrap();
            
            // Load config
            let loaded_config = VpnClient::load_config(config_path.to_str().unwrap()).unwrap();
            
            // Compare
            assert_eq!(loaded_config.server_host, config.server_host);
            assert_eq!(loaded_config.server_port, config.server_port);
        });
    }
    
    // More comprehensive tests would require mocking the server
}
