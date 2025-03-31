// src/server/session.rs

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use futures::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use tokio_tungstenite::tungstenite::Message;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::protocol::PacketType;
use crate::protocol::serialization::packet_to_ws_message;
use crate::server::core::ServerError;

/// Client session for connected users
#[derive(Clone)]
pub struct ClientSession {
    /// Unique session identifier
    pub id: String,
    /// Client's public key
    pub client_id: String,
    /// Assigned IP address
    pub ip_address: String,
    /// Client's address
    pub address: SocketAddr,
    /// WebSocket stream sender
    ws_sender: Arc<Mutex<SplitSink<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>, Message>>>,
    /// WebSocket stream receiver
    ws_receiver: Arc<Mutex<SplitStream<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>>,
    /// Last activity timestamp
    pub last_activity: Arc<Mutex<Instant>>,
    /// Stream already taken
    stream_taken: Arc<Mutex<bool>>,
}

impl ClientSession {
    /// Create a new client session with split WebSocket components
    pub fn new(
        id: String,
        client_id: String,
        ip_address: String,
        address: SocketAddr,
        ws_stream: WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    ) -> Result<Self, ServerError> {
        let (sender, receiver) = ws_stream.split();
        
        Ok(Self {
            id,
            client_id,
            ip_address,
            address,
            ws_sender: Arc::new(Mutex::new(sender)),
            ws_receiver: Arc::new(Mutex::new(receiver)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            stream_taken: Arc::new(Mutex::new(false)),
        })
    }
    
    /// Send a packet to the client
    pub async fn send_packet(&self, packet: &PacketType) -> Result<(), ServerError> {
        let message = packet_to_ws_message(packet)?;
        let mut sender = self.ws_sender.lock().await;
        sender.send(message).await.map_err(|e| ServerError::WebSocket(e))
    }
    
    /// Update last activity timestamp
    pub async fn update_activity(&self) {
        let mut last_activity = self.last_activity.lock().await;
        *last_activity = Instant::now();
    }
    
    /// Get time since last activity
    pub async fn idle_time(&self) -> Duration {
        let last_activity = self.last_activity.lock().await;
        last_activity.elapsed()
    }
    
    /// Receive the next message from the client
    pub async fn next_message(&self) -> Option<Result<Message, tokio_tungstenite::tungstenite::Error>> {
        let mut receiver = self.ws_receiver.lock().await;
        receiver.next().await
    }
    
    /// Take the stream for direct processing - can only be called once
    pub async fn take_stream(&self) -> Result<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>, SessionError> {
        let mut taken = self.stream_taken.lock().await;
        if *taken {
            return Err(SessionError::StreamConsumed);
        }
        
        // Get the sender and receiver
        let sender = self.ws_sender.lock().await;
        let receiver = self.ws_receiver.lock().await;
        
        // Attempt to reunite them
        let stream = sender.reunite(receiver)
            .map_err(|_| SessionError::StreamConsumed)?;
        
        // Mark as taken
        *taken = true;
        
        Ok(stream)
    }
}

/// Session manager for handling multiple client sessions
pub struct SessionManager {
    /// Active sessions (session_id -> session)
    sessions: Arc<Mutex<std::collections::HashMap<String, ClientSession>>>,
    /// IP to session mapping for quicker lookups
    ip_sessions: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// Maximum connections per IP
    max_connections_per_ip: usize,
    /// Session timeout
    session_timeout: Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(max_connections_per_ip: usize, session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            ip_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            max_connections_per_ip,
            session_timeout,
        }
    }
    
    /// Add a new session
    pub async fn add_session(&self, session: ClientSession) {
        let mut sessions = self.sessions.lock().await;
        let mut ip_sessions = self.ip_sessions.lock().await;
        
        // Store the session
        sessions.insert(session.id.clone(), session.clone());
        
        // Update IP to session mapping
        ip_sessions.insert(session.ip_address.clone(), session.id.clone());
    }
    
    /// Remove a session
    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().await;
        let mut ip_sessions = self.ip_sessions.lock().await;
        
        // Find the session
        if let Some(session) = sessions.remove(session_id) {
            // Remove from IP mapping
            ip_sessions.remove(&session.ip_address);
        }
    }
    
    /// Update session activity
    pub async fn touch_session(&self, session_id: &str) -> Result<(), ServerError> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.update_activity().await;
            Ok(())
        } else {
            Err(ServerError::Session(SessionError::NotFound(session_id.to_string())))
        }
    }
    
    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<ClientSession> {
        let sessions = self.sessions.lock().await;
        sessions.get(session_id).cloned()
    }
    
    /// Get a session by IP address
    pub async fn get_session_by_ip(&self, ip: &str) -> Option<ClientSession> {
        let ip_sessions = self.ip_sessions.lock().await;
        let session_id = ip_sessions.get(ip)?;
        
        let sessions = self.sessions.lock().await;
        sessions.get(session_id).cloned()
    }
    
    /// Check if a session exists
    pub async fn has_session(&self, session_id: &str) -> bool {
        let sessions = self.sessions.lock().await;
        sessions.contains_key(session_id)
    }
    
    /// Get all sessions
    pub async fn all_sessions(&self) -> Vec<ClientSession> {
        let sessions = self.sessions.lock().await;
        sessions.values().cloned().collect()
    }
    
    /// Count active sessions
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.lock().await;
        sessions.len()
    }
    
    /// Count sessions by client IP
    pub async fn count_sessions_by_ip(&self, ip: &std::net::IpAddr) -> usize {
        let sessions = self.sessions.lock().await;
        sessions.values()
            .filter(|s| s.address.ip() == *ip)
            .count()
    }
    
    /// Close all sessions
    pub async fn close_all_sessions(&self, reason: &str) {
        let mut sessions = self.sessions.lock().await;
        let mut ip_sessions = self.ip_sessions.lock().await;
        
        // Create disconnect packet
        let disconnect = crate::protocol::serialization::create_disconnect_packet(1, reason);
        
        // Send to all clients
        for session in sessions.values() {
            if let Err(e) = session.send_packet(&disconnect).await {
                warn!("Failed to send disconnect to {}: {}", session.client_id, e);
            }
        }
        
        // Clear all sessions
        sessions.clear();
        ip_sessions.clear();
    }
    
    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.lock().await;
        let mut ip_sessions = self.ip_sessions.lock().await;
        let before_count = sessions.len();
        
        // Find expired sessions
        let expired: Vec<(String, String)> = sessions.iter()
            .filter_map(|(id, session)| {
                // Check if session is expired
                let is_expired = session.idle_time().await > self.session_timeout;
                if is_expired {
                    Some((id.clone(), session.ip_address.clone()))
                } else {
                    None
                }
            })
            .collect();
        
        // Remove expired sessions
        for (id, ip) in &expired {
            sessions.remove(id);
            ip_sessions.remove(ip);
        }
        
        expired.len()
    }
}

/// Session error type
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    NotFound(String),
    
    #[error("Session limit reached for IP")]
    LimitReached,
    
    #[error("Session expired")]
    Expired,
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    
    #[error("Stream already consumed")]
    StreamConsumed,
}
