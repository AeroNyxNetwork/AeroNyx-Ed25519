use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use rustls_pemfile::{certs, pkcs8_private_keys};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time;
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tun::platform::Device;

use crate::auth::AuthManager;
use crate::config;
use crate::crypto::{self, SecretKeyCache, SessionKeyManager};
use crate::network::{self, IpPoolManager, TrafficAnalyzer};
use crate::obfuscation::{ObfuscationMethod, TrafficShaper};
use crate::types::{Args, Client, PacketType, Result, ServerConfigVPN as ServerConfigType, Session, VpnError};
use crate::utils;

/// VPN Server main structure
pub struct VpnServer {
    /// Server keypair for authentication and encryption
    server_keypair: Keypair,
    /// Connected clients
    clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
    /// IP address pool manager
    ip_pool: Arc<Mutex<IpPoolManager>>,
    /// TUN device for packet routing
    tun_device: Arc<Mutex<Device>>,
    /// Secret key cache for performance
    secret_cache: Arc<SecretKeyCache>,
    /// Session key manager
    session_manager: Arc<SessionKeyManager>,
    /// Authentication manager
    auth_manager: Arc<AuthManager>,
    /// Traffic shaper for obfuscation
    traffic_shaper: Arc<TrafficShaper>,
    /// Traffic analyzer
    traffic_analyzer: Arc<Mutex<TrafficAnalyzer>>,
    /// Connection rate limiter (IP -> (count, first_seen))
    rate_limiter: Arc<Mutex<HashMap<String, (usize, Instant)>>>,
    /// Active sessions
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// Server configuration
    config: ServerConfigType,
}

impl VpnServer {
    /// Create a new VPN server instance with military-grade security
    pub async fn new(args: Args) -> Result<Self> {
        // Generate server keypair
        let server_keypair = Keypair::new();
        tracing::info!("Server public key: {}", server_keypair.pubkey());
        
        // Setup TUN device
        let tun_device = network::setup_tun_device(&args.tun_name, &args.subnet)?;
        
        // Create IP pool manager
        let ip_pool = IpPoolManager::new(&args.subnet)?;
        
        // Initialize authentication manager
        let auth_manager = AuthManager::new(Duration::from_secs(60));
        let acl_loaded = auth_manager.load_acl(&args.acl_file).await?;
        
        if acl_loaded {
            tracing::info!("Loaded access control list from {}", args.acl_file);
        } else {
            tracing::info!("Created new access control list at {}", args.acl_file);
        }
        
        // Setup TLS
        let tls_config = Self::setup_tls(&args)?;
        
        // Create traffic shaper
        let obfuscation_method = ObfuscationMethod::from_str(&args.obfuscation_method);
        let traffic_shaper = TrafficShaper::new(obfuscation_method);
        
        // Create server config with a copy of the keypair
        let keypair_for_config = Self::copy_keypair(&server_keypair);
        let config = ServerConfigType {
            tls_acceptor: Arc::new(TlsAcceptor::from(tls_config)),
            server_keypair: keypair_for_config,
            access_control: acl_loaded,
            args: args.clone(),
        };
        
        Ok(Self {
            server_keypair,
            clients: Arc::new(Mutex::new(HashMap::new())),
            ip_pool: Arc::new(Mutex::new(ip_pool)),
            tun_device: Arc::new(Mutex::new(tun_device)),
            secret_cache: Arc::new(SecretKeyCache::new()),
            session_manager: Arc::new(SessionKeyManager::new()),
            auth_manager: Arc::new(auth_manager),
            traffic_shaper: Arc::new(traffic_shaper),
            traffic_analyzer: Arc::new(Mutex::new(TrafficAnalyzer::new())),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config,
        })
    }
    
    /// Helper function to copy a keypair (since Keypair doesn't implement Clone)
    fn copy_keypair(keypair: &Keypair) -> Keypair {
        let keypair_bytes = keypair.to_bytes();
        Keypair::from_bytes(&keypair_bytes).expect("Failed to copy keypair")
    }
    
    /// Setup TLS configuration
    fn setup_tls(args: &Args) -> Result<Arc<tokio_rustls::rustls::ServerConfig>> {
        // Read certificate file
        let cert_file = File::open(&args.cert_file)
            .map_err(|e| VpnError::Tls(format!("Failed to open cert file: {}", e)))?;
        
        // Read key file
        let key_file = File::open(&args.key_file)
            .map_err(|e| VpnError::Tls(format!("Failed to open key file: {}", e)))?;
        
        // Parse certificate
        let cert_chain = certs(&mut std::io::BufReader::new(cert_file))
            .map_err(|e| VpnError::Tls(format!("Failed to parse cert: {}", e)))?
            .into_iter()
            .map(Certificate)
            .collect();
            
        // Parse private key
        let key = pkcs8_private_keys(&mut std::io::BufReader::new(key_file))
            .map_err(|e| VpnError::Tls(format!("Failed to parse key: {}", e)))?
            .into_iter()
            .map(PrivateKey)
            .next()
            .ok_or_else(|| VpnError::Tls("No private key found".into()))?;
            
        // Create server config
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| VpnError::Tls(format!("TLS error: {}", e)))?;
            
        Ok(Arc::new(server_config))
    }
    
    /// Start the VPN server with enhanced security
    pub async fn start(&self, listen_addr: &str) -> Result<()> {
        // Start the traffic shaper
        self.traffic_shaper.start().await;
        
        // Start periodic tasks
        self.start_periodic_tasks();
        
        // Create TLS acceptor
        let tls_acceptor = self.config.tls_acceptor.clone();
        
        // Bind to the listening address
        let listener = TcpListener::bind(listen_addr).await
            .map_err(|e| VpnError::Network(e.to_string()))?;
            
        tracing::info!("VPN Server listening securely on {}", listen_addr);
        
        // Spawn TUN reader task
        let tun_device = self.tun_device.clone();
        let clients = self.clients.clone();
        let session_manager = self.session_manager.clone();
        let traffic_shaper = self.traffic_shaper.clone();
        
        tokio::spawn(async move {
            Self::handle_tun_packets(tun_device, clients, session_manager, traffic_shaper).await;
        });
        
        // Accept incoming connections
        while let Ok((stream, addr)) = listener.accept().await {
            // Rate limit connections from this IP
            if !self.check_rate_limit(&addr).await {
                tracing::warn!("Connection from {} rejected due to rate limiting", addr);
                continue;
            }
            
            tracing::info!("New TCP connection from: {}", addr);
            
            // Clone required components for the connection handler
            let tls_acceptor = tls_acceptor.clone();
            let clients = self.clients.clone();
            let ip_pool = self.ip_pool.clone();
            let tun_device = self.tun_device.clone();
            let server_keypair = Self::copy_keypair(&self.server_keypair);
            let auth_manager = self.auth_manager.clone();
            let secret_cache = self.secret_cache.clone();
            let session_manager = self.session_manager.clone();
            let traffic_shaper = self.traffic_shaper.clone();
            let sessions = self.sessions.clone();
            
            // Handle connection in a separate task
            tokio::spawn(async move {
                // Perform TLS handshake
                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(e) => {
                        tracing::error!("TLS handshake failed with {}: {}", addr, e);
                        return;
                    }
                };
                
                tracing::debug!("TLS handshake successful with {}", addr);
                
                // Handle the WebSocket connection
                if let Err(e) = Self::handle_client(
                    tls_stream,
                    addr,
                    clients,
                    ip_pool,
                    tun_device,
                    server_keypair,
                    auth_manager,
                    secret_cache,
                    session_manager,
                    traffic_shaper,
                    sessions,
                ).await {
                    tracing::error!("Error handling client {}: {}", addr, e);
                }
            });
        }
        
        // Stop the traffic shaper
        self.traffic_shaper.stop().await;
        
        Ok(())
    }
    
    /// Start periodic maintenance tasks
    fn start_periodic_tasks(&self) {
        // Clone required components
        let ip_pool = self.ip_pool.clone();
        let clients = self.clients.clone();
        let sessions = self.sessions.clone();
        let traffic_analyzer = self.traffic_analyzer.clone();
        let rate_limiter = self.rate_limiter.clone();
        
        // IP pool cleanup task
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                match ip_pool.lock().await.cleanup_expired().await {
                    Ok(_) => tracing::debug!("IP pool cleanup successful"),
                    Err(e) => tracing::error!("IP pool cleanup failed: {}", e),
                }
            }
        });
        
        // Session cleanup task
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60)); // 1 minute
            loop {
                interval.tick().await;
                
                let now = utils::current_timestamp_millis();
                let mut to_remove = Vec::<String>::new();
                
                {
                    let mut sessions_lock = sessions.lock().await;
                    for (id, session) in sessions_lock.iter() {
                        if session.expires_at < now {
                            to_remove.push(id.clone());
                        }
                    }
                    
                    // Remove expired sessions
                    for id in &to_remove {
                        sessions_lock.remove(id);
                    }
                }
                
                // Remove disconnected clients - fixed by using async move closure
                let mut clients_lock = clients.lock().await;
                
                // Create a vector of addresses to remove
                let mut addrs_to_remove = Vec::new();
                
                for (addr, client) in clients_lock.iter() {
                    if let Ok(activity_lock) = client.last_activity.try_lock() {
                        if activity_lock.elapsed() > Duration::from_secs(300) { // 5 minutes
                            addrs_to_remove.push(*addr);
                }
                    }
                        }
                
                // Now remove the clients
                for addr in addrs_to_remove {
                    clients_lock.remove(&addr);
                }
                
                tracing::debug!("Cleaned up {} expired sessions", to_remove.len());
            }
        });
        
        // Security monitoring task
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60)); // 1 minute
            loop {
                interval.tick().await;
                
                // Check for suspicious activity
                let suspicious = {
                    let mut analyzer = traffic_analyzer.lock().await;
                    analyzer.get_suspicious_activity(Duration::from_secs(300))
                };
                
                if !suspicious.is_empty() {
                    for (ip, reason) in suspicious {
                        tracing::warn!("Suspicious activity detected from {}: {}", ip, reason);
                    }
                }
                
                // Clean up rate limiter
                let mut limiter = rate_limiter.lock().await;
                limiter.retain(|_, (_, first_seen)| {
                    (Instant::now() - *first_seen) < Duration::from_secs(3600) // 1 hour
                });
            }
        });
    }
    
    /// Check connection rate limits
    async fn check_rate_limit(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip().to_string();
        let mut limiter = self.rate_limiter.lock().await;
        
        let now = Instant::now();
        let max_connections = self.config.args.max_connections_per_ip;
        
        let entry = limiter.entry(ip).or_insert((0, now));
        
        // Reset counter if it's been more than the rate limit window
        if now.duration_since(entry.1) > config::RATE_LIMIT_WINDOW {
            *entry = (1, now);
            return true;
        }
        
        // Increment counter and check limit
        entry.0 += 1;
        entry.0 <= max_connections
    }
    
    /// Handle packets from TUN device and forward to clients
    async fn handle_tun_packets(
        tun_device: Arc<Mutex<Device>>,
        clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
        session_manager: Arc<SessionKeyManager>,
        traffic_shaper: Arc<TrafficShaper>,
    ) {
        let mut buffer = vec![0u8; 2048];
        
        loop {
            let n = {
                let mut device = tun_device.lock().await;
                match device.read(&mut buffer) {
                    Ok(n) => n,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
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
                // Process the packet and determine destination
                let packet = &buffer[..n];
                if let Some((dest_ip, processed_packet)) = network::process_packet(packet) {
                    tracing::debug!("Routing packet to destination IP: {}", dest_ip);
                    
                    // Find client with matching IP and forward the packet
                    let clients_lock = clients.lock().await;
                    for client in clients_lock.values() {
                        if client.assigned_ip == dest_ip {
                            // Update client's last activity timestamp
                            *client.last_activity.lock().await = Instant::now();
                            
                            // Get the client's session key
                            if let Some(session_key) = session_manager.get_key(&client.public_key.to_string()).await {
                                // Apply traffic padding if enabled
                                let padded_packet = if config::ENABLE_TRAFFIC_PADDING {
                                    traffic_shaper.add_padding(&processed_packet)
                                } else {
                                    processed_packet.clone()
                                };
                                
                                // Encrypt the packet with the session key
                                match crypto::encrypt_packet(&padded_packet, &session_key) {
                                    Ok((encrypted, nonce)) => {
                                        // Create data packet
                                        let data_packet = PacketType::Data {
                                            encrypted,
                                            nonce,
                                            counter: *client.packet_counter.lock().await,
                                            padding: None,
                                        };
                                        
                                        // Increment packet counter
                                        *client.packet_counter.lock().await += 1;
                                        
                                        // Serialize the packet
                                        if let Ok(json) = serde_json::to_string(&data_packet) {
                                            // Queue the packet through the traffic shaper for timing obfuscation
                                            let mut client_stream = client.stream.lock().await;
                                            if let Err(e) = client_stream.send(Message::Text(json)).await {
                                                tracing::error!("Error sending to client: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("Encryption error: {}", e);
                                    }
                                }
                            } else {
                                tracing::error!("No session key found for client: {}", client.public_key);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    /// Handle client WebSocket connection with enhanced security
    async fn handle_client(
        tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        addr: SocketAddr,
        clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
        ip_pool: Arc<Mutex<IpPoolManager>>,
        tun_device: Arc<Mutex<Device>>,
        server_keypair: Keypair,
        auth_manager: Arc<AuthManager>,
        secret_cache: Arc<SecretKeyCache>,
        session_manager: Arc<SessionKeyManager>,
        traffic_shaper: Arc<TrafficShaper>,
        sessions: Arc<Mutex<HashMap<String, Session>>>,
    ) -> Result<()> {
        // Upgrade connection to WebSocket
        let ws_stream = tokio_tungstenite::accept_async(tls_stream).await
            .map_err(|e| VpnError::WebSocket(e))?;
            
        tracing::info!("WebSocket connection established with {}", addr);
        
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        
        // Wait for client to send authentication message
        if let Some(Ok(msg)) = ws_receiver.next().await {
            if let Ok(text) = msg.to_text() {
                // Parse the authentication message
                let auth_message: PacketType = serde_json::from_str(text)
                    .map_err(|e| VpnError::AuthenticationFailed(format!("Invalid auth message: {}", e)))?;
                
                // Handle authentication
                if let PacketType::Auth { public_key, version, features, nonce } = auth_message {
                    // Parse the client's public key
                    let public_key = Pubkey::from_str(&public_key)
                        .map_err(|e| VpnError::AuthenticationFailed(format!("Invalid public key: {}", e)))?;
                    
                    tracing::info!("Client {} initiating authentication with key: {}", addr, public_key);
                    tracing::debug!("Client version: {}, features: {:?}", version, features);
                    
                    // Generate challenge
                    let (challenge_id, challenge_data) = auth_manager
                        .generate_challenge(&addr.to_string())
                        .await?;
                    
                    // Send challenge to client
                    let challenge = PacketType::Challenge {
                        data: challenge_data,
                        server_key: server_keypair.pubkey().to_string(),
                        expires_at: utils::current_timestamp_millis() + 60000, // 1 minute
                        id: challenge_id.clone(),
                    };
                    
                    let challenge_json = serde_json::to_string(&challenge)
                        .map_err(|e| VpnError::Json(e))?;
                    
                    ws_sender.send(Message::Text(challenge_json)).await
                        .map_err(|e| VpnError::WebSocket(e))?;
                    
                    // Wait for challenge response
                    if let Some(Ok(msg)) = ws_receiver.next().await {
                        if let Ok(text) = msg.to_text() {
                            let response: PacketType = serde_json::from_str(text)
                                .map_err(|e| VpnError::AuthenticationFailed(format!("Invalid challenge response: {}", e)))?;
                                
                            if let PacketType::ChallengeResponse { signature, public_key: pubkey_str, challenge_id: resp_challenge_id } = response {
                                // Verify challenge ID
                                if resp_challenge_id != challenge_id {
                                    return Err(VpnError::AuthenticationFailed("Challenge ID mismatch".into()));
                                }
                                
                                // Verify public key consistency
                                let response_pubkey = Pubkey::from_str(&pubkey_str)
                                    .map_err(|e| VpnError::AuthenticationFailed(format!("Invalid public key in response: {}", e)))?;
                                
                                if response_pubkey != public_key {
                                    return Err(VpnError::AuthenticationFailed("Public key mismatch".into()));
                                }
                                
                                // Parse signature
                                let signature = Signature::from_str(&signature)
                                    .map_err(|e| VpnError::AuthenticationFailed(format!("Invalid signature: {}", e)))?;
                                
                                // Verify signature
                                auth_manager.verify_challenge(
                                    &challenge_id,
                                    &signature,
                                    &public_key,
                                    &addr.to_string(),
                                ).await?;
                                
                                tracing::info!("Client {} successfully authenticated", addr);
                                
                                // Generate session key
                                let session_key = SessionKeyManager::generate_key();
                                
                                // Derive shared secret for key exchange
                                let shared_secret = secret_cache
                                    .get_or_compute(&server_keypair, &public_key)
                                    .await?;
                                
                                // Encrypt session key with shared secret
                                let (encrypted_key, key_nonce) = crypto::encrypt_session_key(
                                    &session_key,
                                    &shared_secret,
                                )?;
                                
                                // Store session key
                                session_manager.store_key(&public_key.to_string(), session_key).await;
                                
                                // Assign IP address
                                let ip_pool_manager = ip_pool.lock().await;
                                let assigned_ip = ip_pool_manager
                                    .allocate_ip(&public_key.to_string())
                                    .await?;
                                
                                // Generate session ID
                                let session_id = format!("session_{}", utils::random_string(16));
                                
                                // Send IP assignment
                                let ip_assign = PacketType::IpAssign {
                                    ip_address: assigned_ip.clone(),
                                    lease_duration: config::IP_LEASE_DURATION_SECS,
                                    session_id: session_id.clone(),
                                    encrypted_session_key: encrypted_key,
                                    key_nonce,
                                };
                                
                                let json = serde_json::to_string(&ip_assign)
                                    .map_err(|e| VpnError::Json(e))?;
                                
                                ws_sender.send(Message::Text(json)).await
                                    .map_err(|e| VpnError::WebSocket(e))?;
                                
                                // Recreate WebSocket stream
                                let ws_stream = ws_sender.reunite(ws_receiver)
                                    .map_err(|_| VpnError::Network("Failed to reunite WebSocket stream".into()))?;
                                
                                // Create client structure
                                let client = Client {
                                    stream: Arc::new(Mutex::new(ws_stream)),
                                    public_key,
                                    assigned_ip: assigned_ip.clone(),
                                    connected_at: Instant::now(),
                                    last_activity: Arc::new(Mutex::new(Instant::now())),
                                    session_key: Arc::new(Mutex::new([0u8; 32])), // Will be updated later
                                    key_created_at: Arc::new(Mutex::new(Instant::now())),
                                    packet_counter: Arc::new(Mutex::new(0)),
                                    rate_limit: Arc::new(Mutex::new(HashMap::new())),
                                };
                                
                                // Add client to active clients
                                {
                                    let mut clients_lock = clients.lock().await;
                                    clients_lock.insert(addr, client.clone());
                                }
                                
                                // Create session record
                                let now = utils::current_timestamp_millis();
                                let session = Session {
                                    id: session_id.clone(),
                                    client_key: public_key.to_string(),
                                    created_at: now,
                                    expires_at: now + config::IP_LEASE_DURATION_SECS * 1000,
                                    ip_address: assigned_ip.clone(),
                                };
                                
                                // Store session
                                {
                                    let mut sessions_lock = sessions.lock().await;
                                    sessions_lock.insert(session_id.clone(), session);
                                }
                                
                                tracing::info!("Client {} connected, assigned IP: {}", addr, assigned_ip);
                                
                                // Handle client in a separate function
                                Self::process_client_messages(
                                    addr,
                                    client,
                                    clients.clone(),
                                    ip_pool.clone(),
                                    tun_device.clone(),
                                    server_keypair,
                                    session_manager.clone(),
                                    traffic_shaper,
                                    sessions,
                                    session_id,
                                ).await?;
                            } else {
                                return Err(VpnError::AuthenticationFailed("Expected challenge response".into()));
                            }
                        }
                    } else {
                        return Err(VpnError::AuthenticationFailed("No challenge response received".into()));
                    }
                } else {
                    return Err(VpnError::AuthenticationFailed("Expected authentication message".into()));
                }
            }
        }
        
        Ok(())
    }
    
    /// Process messages from a connected client
    async fn process_client_messages(
        addr: SocketAddr,
        client: Client,
        clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
        ip_pool: Arc<Mutex<IpPoolManager>>,
        tun_device: Arc<Mutex<Device>>,
        server_keypair: Keypair,
        session_manager: Arc<SessionKeyManager>,
        traffic_shaper: Arc<TrafficShaper>,
        sessions: Arc<Mutex<HashMap<String, Session>>>,
        session_id: String,
    ) -> Result<()> {
        let client_public_key = client.public_key;
        let assigned_ip = client.assigned_ip.clone();
        
        // Create a heartbeat task
        let client_stream_clone = client.stream.clone();
        let packet_counter = client.packet_counter.clone();
        
        let heartbeat_task = tokio::spawn(async move {
            let mut interval = time::interval(config::HEARTBEAT_INTERVAL);
            loop {
                interval.tick().await;
                
                let counter = *packet_counter.lock().await;
                let ping = PacketType::Ping {
                    timestamp: utils::current_timestamp_millis(),
                    sequence: counter,
                };
                
                *packet_counter.lock().await += 1;
                
                let json = match serde_json::to_string(&ping) {
                    Ok(j) => j,
                    Err(_) => continue,
                };
                
                let mut stream = client_stream_clone.lock().await;
                if let Err(e) = stream.send(Message::Text(json)).await {
                    tracing::warn!("Heartbeat failed for {}: {}", addr, e);
                    break;
                }
            }
        });
        
        // Setup key rotation task
        let session_manager_clone = session_manager.clone();
        let client_public_key_str = client_public_key.to_string();
        let client_stream_clone = client.stream.clone();
        let server_keypair_clone = Self::copy_keypair(&server_keypair);
        
        let key_rotation_task = tokio::spawn(async move {
            let mut interval = time::interval(config::KEY_ROTATION_INTERVAL);
            loop {
                interval.tick().await;
                
                // Generate new session key
                let new_key = SessionKeyManager::generate_key();
                
                // Get current session key
                if let Some(current_key) = session_manager_clone.get_key(&client_public_key_str).await {
                    // Encrypt the new key with the current key
                    if let Ok((encrypted_new_key, nonce)) = crypto::encrypt_chacha20(&new_key, &current_key, None) {
                        // Create key ID for verification
                        let key_id = utils::random_string(16);
                        
                        // Sign key_id | nonce for authentication
                        let mut sign_data = key_id.clone().into_bytes();
                        sign_data.extend_from_slice(&nonce);
                        let signature = server_keypair_clone.sign_message(&sign_data);
                        
                        // Create key rotation message
                        let rotation = PacketType::KeyRotation {
                            encrypted_new_key,
                            nonce,
                            key_id,
                            signature: signature.to_string(),
                        };
                        
                        // Send key rotation message
                        let json = match serde_json::to_string(&rotation) {
                            Ok(j) => j,
                            Err(_) => continue,
                        };
                        
                        let mut stream = client_stream_clone.lock().await;
                        if let Err(e) = stream.send(Message::Text(json)).await {
                            tracing::warn!("Key rotation failed: {}", e);
                            break;
                        }
                        
                        // Update session key
                        session_manager_clone.store_key(&client_public_key_str, new_key).await;
                        tracing::debug!("Session key rotated for client {}", client_public_key_str);
                    }
                }
            }
        });
        
        // Process messages from the client
        let mut stream = client.stream.lock().await;
        let mut last_counter: Option<u64> = None;
        
        while let Some(result) = stream.next().await {
            match result {
                Ok(msg) => {
                    // Update last activity timestamp
                    *client.last_activity.lock().await = Instant::now();
                    
                    match msg {
                        Message::Text(text) => {
                            // Parse message
                            match serde_json::from_str::<PacketType>(&text) {
                                Ok(PacketType::Data { encrypted, nonce, counter, padding: _ }) => {
                                    // Check for replay attacks
                                    if let Some(last) = last_counter {
                                        if counter <= last {
                                            tracing::warn!("Possible replay attack detected: counter {} <= last {}", counter, last);
                                            continue;
                                        }
                                    }
                                    last_counter = Some(counter);
                                    
                                    // Get session key
                                    if let Some(session_key) = session_manager.get_key(&client_public_key.to_string()).await {
                                        // Decrypt the packet
                                        match crypto::decrypt_packet(&encrypted, &session_key, &nonce) {
                                            Ok(decrypted) => {
                                                // Remove padding if present
                                                let packet_data = traffic_shaper.remove_padding(&decrypted)?;
                                                
                                                // Write decrypted packet to TUN
                                                let mut tun = tun_device.lock().await;
                                                if let Err(e) = tun.write(&packet_data) {
                                                    tracing::error!("Error writing to TUN: {}", e);
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!("Decryption error: {}", e);
                                            }
                                        }
                                    } else {
                                        tracing::error!("No session key found for client {}", client_public_key);
                                    }
                                }
                                Ok(PacketType::Ping { timestamp, sequence }) => {
                                    // Respond with Pong
                                    let pong = PacketType::Pong {
                                        echo_timestamp: timestamp,
                                        server_timestamp: utils::current_timestamp_millis(),
                                        sequence,
                                    };
                                    
                                    let json = serde_json::to_string(&pong).unwrap_or_default();
                                    if let Err(e) = stream.send(Message::Text(json)).await {
                                        tracing::error!("Error sending pong: {}", e);
                                    }
                                }
                                Ok(PacketType::Pong { echo_timestamp, server_timestamp: _, sequence: _ }) => {
                                    // Calculate RTT
                                    let now = utils::current_timestamp_millis();
                                    let rtt = now - echo_timestamp;
                                    tracing::debug!("Ping RTT for client {}: {}ms", client_public_key, rtt);
                                }
                                Ok(PacketType::KeyRotation { .. }) => {
                                    // Client should not send key rotation messages
                                    tracing::warn!("Unexpected key rotation message from client");
                                }
                                Ok(PacketType::Disconnect { reason, message }) => {
                                    tracing::info!("Client {} disconnecting: {} ({})", client_public_key, message, reason);
                                    break;
                                }
                                Err(e) => {
                                    tracing::error!("Failed to parse message: {}", e);
                                }
                                _ => {
                                    tracing::warn!("Received unexpected message type from client");
                                }
                            }
                        }
                        Message::Binary(data) => {
                            // For binary messages, assume they are encrypted data
                            // This would require a custom binary protocol which we're not implementing here
                            tracing::warn!("Received binary message of {} bytes", data.len());
                        }
                        Message::Close(_) => {
                            tracing::info!("Client {} sent close frame", addr);
                            break;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    tracing::error!("WebSocket error for client {}: {}", addr, e);
                    break;
                }
            }
        }
        
        // Cancel background tasks
        heartbeat_task.abort();
        key_rotation_task.abort();
        
        // Clean up when client disconnects
        {
            // Remove from clients list
            let mut clients_lock = clients.lock().await;
            clients_lock.remove(&addr);
            
            // Return IP address to pool
            let ip_pool_lock = ip_pool.lock().await;
            if let Err(e) = ip_pool_lock.release_ip(&assigned_ip).await {
                tracing::error!("Error releasing IP {}: {}", assigned_ip, e);
            }
            
            // Remove session
            let mut sessions_lock = sessions.lock().await;
            sessions_lock.remove(&session_id);
            
            // Remove session key
            session_manager.remove_key(&client_public_key.to_string()).await;
        }
        
        tracing::info!("Client {} disconnected, IP {} returned to pool", addr, assigned_ip);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_copy_keypair() {
        let original = Keypair::new();
        let copy = VpnServer::copy_keypair(&original);
        
        // Both keypairs should have the same public key
        assert_eq!(original.pubkey(), copy.pubkey());
        
        // And they should produce the same signatures
        let message = b"test message";
        let sig1 = original.sign_message(message);
        let sig2 = copy.sign_message(message);
        
        assert_eq!(sig1, sig2);
    }
}
