// src/server/session.rs
//! Client session management.
//!
//! This module handles client session tracking, management, and cleanup.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::{SinkExt, StreamExt};
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, trace, warn};

use crate::protocol::{PacketType, MessageError};
use crate::protocol::serialization::packet_to_ws_message;
use crate::utils::current_timestamp_millis;

/// Error type for session operations
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    NotFound(String),
    
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    
    #[error("Protocol error: {0}")]
    Protocol(#[from] MessageError),
    
    #[error("Session expired")]
    Expired,
    
    #[error("Invalid session state: {0}")]
    InvalidState(String),
    
    #[error("Session limit reached")]
    LimitReached,
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Client session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active
    Active,
    /// Session is inactive (no activity for a while)
    Inactive,
    /// Session is closing
    Closing,
    /// Session is closed
    Closed,
}

/// Client session information
pub struct ClientSession {
    /// Session ID
    pub id: String,
    /// Client public key
    pub client_id: String,
    /// Assigned IP address
    pub ip_address: String,
    /// Client socket address
    pub address: SocketAddr,
    /// Connection time
    pub connected_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Session state
    pub state: Arc<RwLock<SessionState>>,
    /// WebSocket stream for communication
    stream: Option<Arc<Mutex<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>>,
    /// Outgoing packet counter
    packet_counter: Arc<Mutex<u64>>,
}

impl ClientSession {
    /// Create a new client session
    pub fn new(
        id: String,
        client_id: String,
        ip_address: String,
        address: SocketAddr,
        stream: WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    ) -> Result<Self, SessionError> {
        let now = Instant::now();
        
        Ok(Self {
            id,
            client_id,
            ip_address,
            address,
            connected_at: now,
            last_activity: now,
            state: Arc::new(RwLock::new(SessionState::Active)),
            stream: Some(Arc::new(Mutex::new(stream))),
            packet_counter: Arc::new(Mutex::new(0)),
        })
    }
    
    /// Take ownership of the WebSocket stream
    pub fn take_stream(&self) -> Result<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>, SessionError> {
        if let Some(stream_arc) = self.stream.as_ref() {
            let mut stream_lock = stream_arc.try_lock()
                .map_err(|_| SessionError::Internal("Failed to lock WebSocket stream".to_string()))?;
                
            let stream_opt = std::mem::replace(&mut *stream_lock, WebSocketStream::from_raw_socket(
                tokio_tungstenite::tungstenite::protocol::WebSocket::from_partially_read(
                    tokio::io::duplex(Vec::new(), Vec::new()),
                    None,
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                ),
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            ));
            
            Ok(stream_opt)
        } else {
            Err(SessionError::InvalidState("Stream already taken".to_string()))
        }
    }
    
    /// Send a packet to the client
    pub async fn send_packet(&self, packet: &PacketType) -> Result<(), SessionError> {
        if let Some(stream_arc) = self.stream.as_ref() {
            let mut counter = self.packet_counter.lock().await;
            let ws_message = packet_to_ws_message(packet)?;
            
            let mut stream = stream_arc.lock().await;
            stream.send(ws_message).await?;
            
            *counter += 1;
            Ok(())
        } else {
            Err(SessionError::InvalidState("Stream not available".to_string()))
        }
    }
    
    /// Check if the session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
    
    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// Get the session duration
    pub fn duration(&self) -> Duration {
        self.connected_at.elapsed()
    }
    
    /// Get the current session state
    pub async fn get_state(&self) -> SessionState {
        *self.state.read().await
    }
    
    /// Set the session state
    pub async fn set_state(&self, state: SessionState) {
        let mut state_guard = self.state.write().await;
        *state_guard = state;
    }
}

impl Clone for ClientSession {
    fn clone(&self) -> Self {
        // Create a new instance with the same data but clone the stream reference
        Self {
            id: self.id.clone(),
            client_id: self.client_id.clone(),
            ip_address: self.ip_address.clone(),
            address: self.address,
            connected_at: self.connected_at,
            last_activity: self.last_activity,
            state: self.state.clone(),
            stream: self.stream.clone(),
            packet_counter: self.packet_counter.clone(),
        }
    }
}

/// Session manager for tracking client sessions
pub struct SessionManager {
    /// Active sessions by session ID
    sessions: Arc<RwLock<HashMap<String, ClientSession>>>,
    /// IP address to session ID mapping
    ip_mapping: Arc<RwLock<HashMap<String, String>>>,
    /// Client ID to session ID mapping
    client_mapping: Arc<RwLock<HashMap<String, String>>>,
    /// Maximum connections per IP
    max_connections_per_ip: usize,
    /// Session timeout
    session_timeout: Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(max_connections_per_ip: usize, session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ip_mapping: Arc::new(RwLock::new(HashMap::new())),
            client_mapping: Arc::new(RwLock::new(HashMap::new())),
            max_connections_per_ip,
            session_timeout,
        }
    }
    
    /// Add a new session
    pub async fn add_session(&self, session: ClientSession) {
        let session_id = session.id.clone();
        let ip_address = session.ip_address.clone();
        let client_id = session.client_id.clone();
        
        // Add to sessions map
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }
        
        // Update mappings
        {
            let mut ip_mapping = self.ip_mapping.write().await;
            ip_mapping.insert(ip_address, session_id.clone());
        }
        
        {
            let mut client_mapping = self.client_mapping.write().await;
            client_mapping.insert(client_id, session_id);
        }
    }
    
    /// Remove a session
    pub async fn remove_session(&self, session_id: &str) -> Option<ClientSession> {
        // Get session first
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };
        
        if let Some(ref session) = session {
            // Remove from mappings
            {
                let mut ip_mapping = self.ip_mapping.write().await;
                ip_mapping.remove(&session.ip_address);
            }
            
            {
                let mut client_mapping = self.client_mapping.write().await;
                client_mapping.remove(&session.client_id);
            }
        }
        
        session
    }
    
    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<ClientSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }
    
    /// Get a session by IP address
    pub async fn get_session_by_ip(&self, ip_address: &str) -> Option<ClientSession> {
        let ip_mapping = self.ip_mapping.read().await;
        
        if let Some(session_id) = ip_mapping.get(ip_address) {
            let sessions = self.sessions.read().await;
            return sessions.get(session_id).cloned();
        }
        
        None
    }
    
    /// Get a session by client ID
    pub async fn get_session_by_client_id(&self, client_id: &str) -> Option<ClientSession> {
        let client_mapping = self.client_mapping.read().await;
        
        if let Some(session_id) = client_mapping.get(client_id) {
            let sessions = self.sessions.read().await;
            return sessions.get(session_id).cloned();
        }
        
        None
    }
    
    /// Get all active sessions
    pub async fn get_all_sessions(&self) -> Vec<ClientSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }
    
    /// Get the number of active sessions
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }
    
    /// Update session activity timestamp
    pub async fn touch_session(&self, session_id: &str) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            session.touch();
            Ok(())
        } else {
            Err(SessionError::NotFound(session_id.to_string()))
        }
    }
    
    /// Check if a session exists
    pub async fn session_exists(&self, session_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(session_id)
    }
    
    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut to_remove = Vec::new();
        
        // First collect expired session IDs
        {
            let sessions = self.sessions.read().await;
            for (id, session) in sessions.iter() {
                if session.is_expired(self.session_timeout) {
                    to_remove.push(id.clone());
                }
            }
        }
        
        // Now remove them
        for session_id in &to_remove {
            self.remove_session(session_id).await;
        }
        
        let count = to_remove.len();
        if count > 0 {
            debug!("Cleaned up {} expired sessions", count);
        }
        
        count
    }
    
    /// Close a specific session
    pub async fn close_session(&self, session_id: &str, reason: &str) -> Result<(), SessionError> {
        let session = {
            let sessions = self.sessions.read().await;
            
            if let Some(session) = sessions.get(session_id) {
                session.clone()
            } else {
                return Err(SessionError::NotFound(session_id.to_string()));
            }
        };
        
        // Set session state to closing
        session.set_state(SessionState::Closing).await;
        
        // Send disconnect message
        let disconnect = PacketType::Disconnect {
            reason: 2, // Server initiated
            message: reason.to_string(),
        };
        
        if let Err(e) = session.send_packet(&disconnect).await {
            warn!("Failed to send disconnect message to session {}: {}", session_id, e);
        }
        
        // Remove the session
        self.remove_session(session_id).await;
        
        Ok(())
    }
    
    /// Close all active sessions
    pub async fn close_all_sessions(&self, reason: &str) {
        let session_ids = {
            let sessions = self.sessions.read().await;
            sessions.keys().cloned().collect::<Vec<_>>()
        };
        
        for session_id in session_ids {
            let _ = self.close_session(&session_id, reason).await;
        }
    }
    
    /// Check the number of connections from an IP address
    pub async fn count_connections_from_ip(&self, ip: &SocketAddr) -> usize {
        let sessions = self.sessions.read().await;
        sessions.values().filter(|s| s.address.ip() == ip.ip()).count()
    }
    
    /// Check if IP address has reached connection limit
    pub async fn has_reached_connection_limit(&self, ip: &SocketAddr) -> bool {
        self.count_connections_from_ip(ip).await >= self.max_connections_per_ip
    }
    
    /// Set a session state
    pub async fn set_session_state(&self, session_id: &str, state: SessionState) -> Result<(), SessionError> {
        let sessions = self.sessions.read().await;
        
        if let Some(session) = sessions.get(session_id) {
            session.set_state(state).await;
            Ok(())
        } else {
            Err(SessionError::NotFound(session_id.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::{Role, WebSocket};
    use tokio::io::duplex;
    
    // Helper to create a mock WebSocket stream for testing
    fn create_mock_stream() -> WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        // Create a mock TLS stream
        let (client, _server) = duplex(Vec::new(), Vec::new());
        let mock_tls_stream = tokio_rustls::server::TlsStream::new(client);
        
        // Wrap in a WebSocket stream
        WebSocketStream::from_raw_socket(
            WebSocket::from_partially_read(
                mock_tls_stream,
                None,
                Role::Server,
                None,
            ),
            Role::Server,
            None,
        )
    }
    
    #[tokio::test]
    async fn test_session_lifecycle() {
        // Create a session manager
        let manager = SessionManager::new(5, Duration::from_secs(60));
        
        // Create a mock session
        let mock_stream = create_mock_stream();
        let session = ClientSession::new(
            "test-session".to_string(),
            "client123".to_string(),
            "10.0.0.1".to_string(),
            "127.0.0.1:12345".parse().unwrap(),
            mock_stream,
        ).unwrap();
        
        // Add the session
        manager.add_session(session).await;
        
        // Verify it was added
        assert_eq!(manager.session_count().await, 1);
        assert!(manager.session_exists("test-session").await);
        
        // Get by different identifiers
        assert!(manager.get_session("test-session").await.is_some());
        assert!(manager.get_session_by_ip("10.0.0.1").await.is_some());
        assert!(manager.get_session_by_client_id("client123").await.is_some());
        
        // Remove the session
        let removed = manager.remove_session("test-session").await;
        assert!(removed.is_some());
        
        // Verify it was removed
        assert_eq!(manager.session_count().await, 0);
        assert!(!manager.session_exists("test-session").await);
    }
    
    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        // Create a session manager with very short timeout
        let manager = SessionManager::new(5, Duration::from_millis(10));
        
        // Add a mock session
        let mock_stream = create_mock_stream();
        let session = ClientSession::new(
            "test-session".to_string(),
            "client123".to_string(),
            "10.0.0.1".to_string(),
            "127.0.0.1:12345".parse().unwrap(),
            mock_stream,
        ).unwrap();
        
        manager.add_session(session).await;
        
        // Sleep longer than the timeout
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        // Cleanup expired sessions
        let removed = manager.cleanup_expired_sessions().await;
        
        // Verify the session was removed
        assert_eq!(removed, 1);
        assert_eq!(manager.session_count().await, 0);
    }
}
