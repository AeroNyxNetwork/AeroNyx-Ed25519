use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use serde::de::{self, Visitor};
use std::marker::PhantomData;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use tokio_rustls::TlsAcceptor;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;

// Custom type for results
pub type Result<T> = std::result::Result<T, VpnError>;

// Serialize/Deserialize wrapper for Instant
#[derive(Clone, Debug)]
pub struct SerializableInstant(pub Instant);

impl Serialize for SerializableInstant {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert to milliseconds since UNIX_EPOCH
        let now = SystemTime::now();
        let now_since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
        let self_since_epoch = now_since_epoch - self.0.elapsed();
        serializer.serialize_u64(self_since_epoch.as_millis() as u64)
    }
}

struct InstantVisitor {
    marker: PhantomData<fn() -> SerializableInstant>,
}

impl InstantVisitor {
    fn new() -> Self {
        InstantVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de> Visitor<'de> for InstantVisitor {
    type Value = SerializableInstant;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an integer representing milliseconds")
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Convert from milliseconds to an Instant
        let now = SystemTime::now();
        let now_since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
        let millis_duration = Duration::from_millis(value);
        
        if millis_duration > now_since_epoch {
            // Future time, not valid
            return Ok(SerializableInstant(Instant::now()));
        }
        
        let elapsed = now_since_epoch - millis_duration;
        let instant = Instant::now() - elapsed;
        
        Ok(SerializableInstant(instant))
    }
}

impl<'de> Deserialize<'de> for SerializableInstant {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(InstantVisitor::new())
    }
}

/// General error type for VPN operations
#[derive(Debug)]
pub enum VpnError {
    /// I/O error
    Io(std::io::Error),
    /// JSON serialization/deserialization error
    Json(serde_json::Error),
    /// Authentication failed
    AuthenticationFailed(String),
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Network error
    Network(String),
    /// Cryptographic error
    Crypto(String),
    /// TLS error
    Tls(String),
    /// Access denied
    AccessDenied(String),
    /// WebSocket error
    WebSocket(tokio_tungstenite::tungstenite::Error),
    /// IP pool exhausted
    IpPoolExhausted,
    /// Invalid configuration
    InvalidConfig(String),
    /// Blockchain error
    Blockchain(String),
}

impl fmt::Display for VpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VpnError::Io(e) => write!(f, "I/O error: {}", e),
            VpnError::Json(e) => write!(f, "JSON error: {}", e),
            VpnError::AuthenticationFailed(e) => write!(f, "Authentication failed: {}", e),
            VpnError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            VpnError::Network(e) => write!(f, "Network error: {}", e),
            VpnError::Crypto(e) => write!(f, "Cryptographic error: {}", e),
            VpnError::Tls(e) => write!(f, "TLS error: {}", e),
            VpnError::AccessDenied(e) => write!(f, "Access denied: {}", e),
            VpnError::WebSocket(e) => write!(f, "WebSocket error: {}", e),
            VpnError::IpPoolExhausted => write!(f, "IP pool exhausted"),
            VpnError::InvalidConfig(e) => write!(f, "Invalid configuration: {}", e),
            VpnError::Blockchain(e) => write!(f, "Blockchain error: {}", e),
        }
    }
}

impl std::error::Error for VpnError {}

impl From<std::io::Error> for VpnError {
    fn from(err: std::io::Error) -> Self {
        VpnError::Io(err)
    }
}

impl From<serde_json::Error> for VpnError {
    fn from(err: serde_json::Error) -> Self {
        VpnError::Json(err)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for VpnError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        VpnError::WebSocket(err)
    }
}

/// Command line arguments
#[derive(Parser, Debug, Clone)]
#[clap(name = "AeroNyx Privacy Network")]
#[clap(author = "AeroNyx Network <hi@aeronyx.network>")]
#[clap(version = "0.1.0")]
#[clap(about = "Military-grade privacy network with Solana keypair authentication")]
pub struct Args {
    /// Server address to listen on (IP:port)
    #[clap(long, default_value = "0.0.0.0:8080")]
    pub listen: String,

    /// TUN device name
    #[clap(long, default_value = "tun0")]
    pub tun_name: String,

    /// VPN subnet in CIDR notation
    #[clap(long, default_value = "10.7.0.0/24")]
    pub subnet: String,

    /// Log level
    #[clap(long, default_value = "info")]
    pub log_level: String,

    /// TLS certificate file
    #[clap(long, default_value = "server.crt")]
    pub cert_file: String,

    /// TLS key file
    #[clap(long, default_value = "server.key")]
    pub key_file: String,

    /// Access control list file
    #[clap(long, default_value = "access_control.json")]
    pub acl_file: String,

    /// Enable traffic obfuscation
    #[clap(long)]
    pub enable_obfuscation: bool,

    /// Traffic obfuscation method (xor, scramblesuit, obfs4)
    #[clap(long, default_value = "xor")]
    pub obfuscation_method: String,

    /// Enable traffic padding
    #[clap(long)]
    pub enable_padding: bool,

    /// Key rotation interval in seconds
    #[clap(long, default_value = "3600")]
    pub key_rotation_interval: u64,

    /// Session timeout in seconds
    #[clap(long, default_value = "86400")]
    pub session_timeout: u64,

    /// Maximum connections per IP
    #[clap(long, default_value = "5")]
    pub max_connections_per_ip: usize,
}

/// Server configuration - renamed to fix name conflict
pub struct ServerConfigVPN {
    /// TLS acceptor
    pub tls_acceptor: Arc<TlsAcceptor>,
    /// Server keypair
    pub server_keypair: Keypair,
    /// Access control settings
    pub access_control: bool,
    /// Command line arguments
    pub args: Args,
}

/// Access control list entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlEntry {
    /// Client public key
    pub public_key: String,
    /// Access level (0-100)
    pub access_level: u8,
    /// Whether the client is allowed
    pub is_allowed: bool,
    /// Bandwidth limit in bytes/sec (0 = unlimited)
    pub bandwidth_limit: u64,
    /// Maximum session duration in seconds
    pub max_session_duration: u64,
    /// Static IP assignment
    pub static_ip: Option<String>,
    /// Notes
    pub notes: Option<String>,
}

/// Access control list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlList {
    /// Default policy ("allow" or "deny")
    pub default_policy: String,
    /// List of access control entries
    pub entries: Vec<AccessControlEntry>,
    /// Last update timestamp
    pub updated_at: u64,
}

/// IP allocation
#[derive(Debug, Clone)]
pub struct IpAllocation {
    /// Allocated IP address
    pub ip_address: String,
    /// Client public key
    pub client_key: String,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Whether this is a static allocation
    pub is_static: bool,
}

/// Client connection
#[derive(Clone)]
pub struct Client {
    /// WebSocket stream
    pub stream: Arc<Mutex<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>,
    /// Client public key
    pub public_key: Pubkey,
    /// Assigned IP address
    pub assigned_ip: String,
    /// Connection time
    pub connected_at: Instant,
    /// Last activity time
    pub last_activity: Arc<Mutex<Instant>>,
    /// Session key
    pub session_key: Arc<Mutex<[u8; 32]>>,
    /// Key creation time
    pub key_created_at: Arc<Mutex<Instant>>,
    /// Packet counter for replay protection
    pub packet_counter: Arc<Mutex<u64>>,
    /// Rate limiting
    pub rate_limit: Arc<Mutex<std::collections::HashMap<String, (usize, Instant)>>>,
}

// Add Debug implementation manually since WebSocketStream doesn't implement Debug
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("public_key", &self.public_key)
            .field("assigned_ip", &self.assigned_ip)
            .field("connected_at", &self.connected_at)
            .finish()
    }
}

/// Client session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: String,
    /// Client public key
    pub client_key: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Assigned IP address
    pub ip_address: String,
}

/// Packet types for client-server communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PacketType {
    /// Authentication request
    Auth {
        /// Client public key
        public_key: String,
        /// Client version
        version: String,
        /// Supported features
        features: Vec<String>,
        /// Nonce for security
        nonce: String,
    },
    /// Challenge for authentication
    Challenge {
        /// Challenge data to sign
        data: Vec<u8>,
        /// Server public key
        server_key: String,
        /// Challenge expiration timestamp
        expires_at: u64,
        /// Challenge ID
        id: String,
    },
    /// Challenge response
    ChallengeResponse {
        /// Signature of the challenge
        signature: String,
        /// Client public key
        public_key: String,
        /// Challenge ID
        challenge_id: String,
    },
    /// IP assignment
    IpAssign {
        /// Assigned IP address
        ip_address: String,
        /// Lease duration in seconds
        lease_duration: u64,
        /// Session ID
        session_id: String,
        /// Encrypted session key
        encrypted_session_key: Vec<u8>,
        /// Nonce for key encryption
        key_nonce: Vec<u8>,
    },
    /// Encrypted data packet
    Data {
        /// Encrypted packet data
        encrypted: Vec<u8>,
        /// Encryption nonce
        nonce: Vec<u8>,
        /// Packet counter for replay protection
        counter: u64,
        /// Optional padding data
        padding: Option<Vec<u8>>,
    },
    /// Ping message
    Ping {
        /// Timestamp
        timestamp: u64,
        /// Sequence number
        sequence: u64,
    },
    /// Pong response
    Pong {
        /// Echo timestamp
        echo_timestamp: u64,
        /// Server timestamp
        server_timestamp: u64,
        /// Sequence number
        sequence: u64,
    },
    /// Session key rotation
    KeyRotation {
        /// Encrypted new key
        encrypted_new_key: Vec<u8>,
        /// Encryption nonce
        nonce: Vec<u8>,
        /// Key ID
        key_id: String,
        /// Signature for verification
        signature: String,
    },
    /// Disconnect notification
    Disconnect {
        /// Reason code
        reason: u16,
        /// Human-readable message
        message: String,
    },
    /// Error notification
    Error {
        /// Error code
        code: u16,
        /// Human-readable message
        message: String,
    },
}
