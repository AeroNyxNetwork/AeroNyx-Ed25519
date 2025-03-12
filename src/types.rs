use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;

/// Represents client connection state
#[derive(Debug, Clone)]
pub struct Client {
    /// WebSocket connection with client
    pub stream: Arc<Mutex<WebSocketStream<TcpStream>>>,
    /// Client's Solana public key
    pub public_key: Pubkey,
    /// Assigned VPN IP address
    pub assigned_ip: String,
}

/// Information about available VPN nodes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node's public key (Base58 encoded)
    pub public_key: String,
    /// Node's IP address
    pub ip_address: String,
    /// Node's port
    pub port: u16,
}

/// Error types for VPN operations
#[derive(thiserror::Error, Debug)]
pub enum VpnError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("IP pool exhausted")]
    IpPoolExhausted,
    
    #[error("Invalid packet")]
    InvalidPacket,
    
    #[error("Authentication failed")]
    AuthenticationFailed,
}

/// Result type for VPN operations
pub type Result<T> = std::result::Result<T, VpnError>;

/// Command line arguments for VPN server
#[derive(clap::Parser, Debug, Clone)]
#[clap(author, version, about = "Solana-based VPN Server")]
pub struct Args {
    /// Server listen address
    #[clap(short, long, default_value = "0.0.0.0:8080")]
    pub listen: String,
    
    /// TUN interface name
    #[clap(short, long, default_value = "tun0")]
    pub tun_name: String,
    
    /// VPN subnet
    #[clap(short, long, default_value = "10.7.0.0/24")]
    pub subnet: String,
    
    /// Log level
    #[clap(short, long, default_value = "info")]
    pub log_level: String,
}

/// Packet types exchanged between server and clients
#[derive(Debug, Serialize, Deserialize)]
pub enum PacketType {
    /// Client authentication with public key
    Auth { public_key: String },
    
    /// Server assigns IP address to client
    IpAssign { ip_address: String },
    
    /// Encrypted data packet
    Data { encrypted: Vec<u8> },
    
    /// Ping to keep connection alive
    Ping,
    
    /// Pong response to ping
    Pong,
}
