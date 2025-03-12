use std::io::{Read, Write};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use futures::{SinkExt, StreamExt};
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::pubkey::Pubkey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{self, Duration};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use tun::platform::Device;

use crate::crypto::{decrypt_packet, encrypt_packet};
use crate::network::{process_packet, setup_tun_device, generate_ip_pool};
use crate::types::{Args, Client, PacketType, Result, VpnError};

// Helper function to clone a Keypair
fn clone_keypair(keypair: &Keypair) -> Keypair {
    let bytes = keypair.to_bytes();
    Keypair::from_bytes(&bytes).unwrap()
}

/// VPN Server main structure
pub struct VpnServer {
    /// Server keypair for encryption
    server_keypair: Keypair,
    /// Connected clients
    clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
    /// Available IP addresses pool
    ip_pool: Arc<Mutex<VecDeque<String>>>,
    /// TUN device for packet routing
    tun_device: Arc<Mutex<Device>>,
}

impl VpnServer {
    /// Create a new VPN server instance
    pub async fn new(args: Args) -> Result<Self> {
        // Generate server keypair
        let server_keypair = Keypair::new();
        
        // Setup TUN device
        let tun_device = setup_tun_device(&args.tun_name)?;
        
        // Initialize IP address pool from subnet
        let ip_pool = generate_ip_pool(&args.subnet)?;
        
        Ok(Self {
            server_keypair,
            clients: Arc::new(Mutex::new(HashMap::new())),
            ip_pool: Arc::new(Mutex::new(ip_pool)),
            tun_device: Arc::new(Mutex::new(tun_device)),
        })
    }
    
    /// Start the VPN server
    pub async fn start(&self, listen_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(listen_addr).await.map_err(|e| VpnError::Network(e.to_string()))?;
        tracing::info!("VPN Server listening on: {}", listen_addr);
        tracing::info!("Server public key: {}", self.server_keypair.pubkey());
        
        // Spawn TUN reader task
        let tun_device = self.tun_device.clone();
        let clients = self.clients.clone();
        let server_keypair_clone = clone_keypair(&self.server_keypair);
        
        tokio::spawn(async move {
            Self::handle_tun_packets(tun_device, clients, server_keypair_clone).await;
        });
        
        // Accept incoming WebSocket connections
        while let Ok((stream, addr)) = listener.accept().await {
            tracing::info!("New TCP connection from: {}", addr);
            
            let clients_clone = self.clients.clone();
            let ip_pool_clone = self.ip_pool.clone();
            let tun_device_clone = self.tun_device.clone();
            let server_keypair_clone = clone_keypair(&self.server_keypair);
            
            // Handle each client in a separate task
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(
                    stream, 
                    addr,
                    clients_clone,
                    ip_pool_clone,
                    tun_device_clone,
                    server_keypair_clone,
                ).await {
                    tracing::error!("Error handling client {}: {}", addr, e);
                }
            });
        }
        
        Ok(())
    }
    
    /// Handle packets from TUN device and forward to clients
    async fn handle_tun_packets(
        tun_device: Arc<Mutex<Device>>,
        clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
        server_keypair: Keypair,
    ) {
        let mut buffer = vec![0u8; 2048];
        
        loop {
            let n = {
                let mut device = tun_device.lock().await;
                match device.read(&mut buffer) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!("Error reading from TUN: {}", e);
                        drop(device); // Release the lock before sleep
                        time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            };
            
            if n > 0 {
                // Process the packet and determine destination
                let packet = &buffer[..n];
                if let Some((dest_ip, processed_packet)) = process_packet(packet) {
                    tracing::debug!("Routing packet to destination IP: {}", dest_ip);
                    
                    // Find client with matching IP and forward the packet
                    let clients_lock = clients.lock().await;
                    for client in clients_lock.values() {
                        if client.assigned_ip == dest_ip {
                            match encrypt_packet(
                                &processed_packet,
                                &server_keypair,
                                &client.public_key,
                            ) {
                                Ok(encrypted) => {
                                    let message = PacketType::Data { encrypted };
                                    let json = serde_json::to_string(&message)
                                        .unwrap_or_else(|_| "{}".to_string());
                                    
                                    let mut client_stream = client.stream.lock().await;
                                    if let Err(e) = client_stream.send(Message::Text(json)).await {
                                        tracing::error!("Error sending to client: {}", e);
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Encryption error: {}", e);
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    /// Handle client WebSocket connection
    async fn handle_client(
        stream: TcpStream,
        addr: SocketAddr,
        clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
        ip_pool: Arc<Mutex<VecDeque<String>>>,
        tun_device: Arc<Mutex<Device>>,
        server_keypair: Keypair,
    ) -> Result<()> {
        // Upgrade connection to WebSocket
        let ws_stream = accept_async(stream).await.map_err(|e| VpnError::Network(e.to_string()))?;
        tracing::info!("WebSocket connection established with {}", addr);
        
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        
        // Wait for client to send their public key
        if let Some(Ok(msg)) = ws_receiver.next().await {
            if let Ok(text) = msg.to_text() {
                // Parse the authentication message
                let auth_message: PacketType = serde_json::from_str(text)
                    .map_err(|_| VpnError::AuthenticationFailed)?;
                
                if let PacketType::Auth { public_key } = auth_message {
                    // Parse the client's public key
                    let public_key = Pubkey::from_str(&public_key)
                        .map_err(|_| VpnError::AuthenticationFailed)?;
                    
                    tracing::info!("Client {} authenticated with public key: {}", addr, public_key);
                    
                    // Assign IP address from pool
                    let assigned_ip = {
                        let mut ip_pool = ip_pool.lock().await;
                        ip_pool.pop_front().ok_or(VpnError::IpPoolExhausted)?
                    };
                    
                    // Send assigned IP to client
                    let ip_assign = PacketType::IpAssign {
                        ip_address: assigned_ip.clone(),
                    };
                    
                    let json = serde_json::to_string(&ip_assign)
                        .map_err(VpnError::Json)?;
                    
                    ws_sender.send(Message::Text(json)).await
                        .map_err(|e| VpnError::Network(e.to_string()))?;
                    
                    // Recreate WebSocket stream
                    let ws_stream = ws_sender.reunite(ws_receiver)
                        .map_err(|_| VpnError::Network("Failed to reunite WebSocket stream".into()))?;
                    
                    // Create client structure
                    let client = Client {
                        stream: Arc::new(Mutex::new(ws_stream)),
                        public_key,
                        assigned_ip: assigned_ip.clone(),
                    };
                    
                    // Add client to active clients
                    {
                        let mut clients_lock = clients.lock().await;
                        clients_lock.insert(addr, client.clone());
                    }
                    
                    tracing::info!("Client {} connected, assigned IP: {}", addr, assigned_ip);
                    
                    // Handle client in a separate function
                    Self::process_client_messages(
                        addr, 
                        client, 
                        clients.clone(), 
                        ip_pool.clone(),
                        server_keypair,
                        tun_device
                    ).await?;
                } else {
                    return Err(VpnError::AuthenticationFailed);
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
        ip_pool: Arc<Mutex<VecDeque<String>>>,
        server_keypair: Keypair,
        tun_device: Arc<Mutex<Device>>,
    ) -> Result<()> {
        let client_public_key = client.public_key;
        let assigned_ip = client.assigned_ip.clone();
        
        // Create a heartbeat task
        let client_stream_clone = client.stream.clone();
        let heartbeat_task = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let ping = PacketType::Ping;
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
        
        // Process messages from the client
        let mut stream = client.stream.lock().await;
        while let Some(result) = stream.next().await {
            match result {
                Ok(msg) => {
                    match msg {
                        Message::Text(text) => {
                            // Parse message
                            match serde_json::from_str::<PacketType>(&text) {
                                Ok(PacketType::Data { encrypted }) => {
                                    // Decrypt the packet using ECDH shared secret
                                    match decrypt_packet(
                                        &encrypted,
                                        &server_keypair,
                                        &client_public_key,
                                    ) {
                                        Ok(decrypted) => {
                                            // Write decrypted packet to TUN
                                            let mut tun = tun_device.lock().await;
                                            if let Err(e) = tun.write(&decrypted) {
                                                tracing::error!("Error writing to TUN: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!("Decryption error: {}", e);
                                        }
                                    }
                                }
                                Ok(PacketType::Ping) => {
                                    // Respond with Pong
                                    let pong = PacketType::Pong;
                                    let json = serde_json::to_string(&pong).unwrap_or_default();
                                    if let Err(e) = stream.send(Message::Text(json)).await {
                                        tracing::error!("Error sending pong: {}", e);
                                    }
                                }
                                Ok(PacketType::Pong) => {
                                    // Client responded to our ping, connection is alive
                                    tracing::debug!("Received pong from client {}", addr);
                                }
                                _ => {
                                    tracing::warn!("Received unexpected message type from client");
                                }
                            }
                        }
                        Message::Binary(data) => {
                            // Handle binary messages directly as encrypted data
                            match decrypt_packet(
                                &data,
                                &server_keypair,
                                &client_public_key,
                            ) {
                                Ok(decrypted) => {
                                    // Write decrypted packet to TUN
                                    let mut tun = tun_device.lock().await;
                                    if let Err(e) = tun.write(&decrypted) {
                                        tracing::error!("Error writing to TUN: {}", e);
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Decryption error for binary message: {}", e);
                                }
                            }
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
        
        // Cancel the heartbeat task
        heartbeat_task.abort();
        
        // Clean up when client disconnects
        {
            let mut clients_lock = clients.lock().await;
            clients_lock.remove(&addr);
            
            let mut ip_pool_lock = ip_pool.lock().await;
            ip_pool_lock.push_back(assigned_ip.clone());
        }
        
        tracing::info!("Client {} disconnected, IP {} returned to pool", addr, assigned_ip);
        
        Ok(())
    }
}
