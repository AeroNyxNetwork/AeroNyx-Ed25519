// src/server/session.rs

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;
use std::time::{Duration, Instant};
use tracing::{warn, info};
use std::sync::atomic::AtomicBool;

use crate::protocol::PacketType;
use crate::protocol::serialization::packet_to_ws_message;
use crate::server::core::ServerError;
use crate::crypto::flexible_encryption::EncryptionAlgorithm;
use crate::server::connection::WebSocketConnection;

/// Client session for connected users
#[derive(Clone)]
pub struct ClientSession {
    // Existing fields
    pub id: String,
    pub client_id: String,
    pub ip_address: String,
    pub address: SocketAddr,
    // Changed from concrete types to trait objects
    ws_sender: Arc<Mutex<Box<dyn WebSocketConnection>>>,
    ws_receiver: Arc<Mutex<Box<dyn WebSocketConnection>>>,
    pub last_activity: Arc<Mutex<Instant>>,
    stream_taken: Arc<AtomicBool>,
    
    // Existing encryption support fields
    pub encryption_algorithm: String,
    
    /// Current room ID
    current_room: Arc<RwLock<Option<String>>>,
    /// User display name
    display_name: Arc<RwLock<Option<String>>>,
    /// Fallback encryption enabled
    fallback_enabled: Arc<RwLock<bool>>,
}

impl ClientSession {
    /// Create a new client session with trait-based WebSocket connections
    pub fn new(
        id: String,
        client_id: String,
        ip_address: String,
        address: SocketAddr,
        ws_sender: Arc<Mutex<Box<dyn WebSocketConnection>>>,
        ws_receiver: Arc<Mutex<Box<dyn WebSocketConnection>>>,
        encryption_algorithm: Option<String>,
    ) -> Result<Self, ServerError> {
        // Default to ChaCha20Poly1305 if not specified
        let algorithm = encryption_algorithm.unwrap_or_else(|| "chacha20poly1305".to_string());
        
        // Log the encryption algorithm being used for this session
        info!("Creating client session with encryption algorithm: {}", algorithm);
        
        Ok(Self {
            id,
            client_id,
            ip_address,
            address,
            ws_sender,
            ws_receiver,
            last_activity: Arc::new(Mutex::new(Instant::now())),
            stream_taken: Arc::new(AtomicBool::new(false)),
            encryption_algorithm: algorithm,
            current_room: Arc::new(RwLock::new(None)),
            display_name: Arc::new(RwLock::new(None)),
            fallback_enabled: Arc::new(RwLock::new(true)), // Enable fallback by default
        })
    }
    
    /// Set whether fallback to alternative encryption algorithm is allowed
    pub async fn set_fallback_enabled(&self, enabled: bool) {
        let mut fallback = self.fallback_enabled.write().await;
        *fallback = enabled;
    }
    
    /// Get current fallback enabled status as boolean value
    pub async fn is_fallback_enabled(&self) -> bool {
        let fallback = self.fallback_enabled.read().await;
        *fallback
    }

    /// Get the EncryptionAlgorithm enum from the string representation
    pub fn get_encryption_algorithm(&self) -> Option<EncryptionAlgorithm> {
        EncryptionAlgorithm::from_str(&self.encryption_algorithm)
    }

    /// Send a packet to the client (acquires lock on sender)
    pub async fn send_packet(&self, packet: &PacketType) -> Result<(), ServerError> {
        let message = packet_to_ws_message(packet)?;
        let mut sender_guard = self.ws_sender.lock().await;
        sender_guard.send_message(message).await
    }

    /// Update last activity timestamp (acquires lock)
    pub async fn update_activity(&self) {
        let mut last_activity_guard = self.last_activity.lock().await;
        *last_activity_guard = Instant::now();
    }

    /// Get time since last activity (acquires lock)
    pub async fn idle_time(&self) -> Duration {
        let last_activity_guard = self.last_activity.lock().await;
        last_activity_guard.elapsed()
    }

    /// Receive the next message from the client (acquires lock on receiver)
    /// Returns Option<Result<Message, ServerError>> to handle stream end and errors.
    pub async fn next_message(&self) -> Option<Result<Message, ServerError>> {
        let mut receiver_guard = self.ws_receiver.lock().await;
        receiver_guard.next_message().await
    }

    /// Attempt to logically take the stream components.
    /// This marks the session as consumed but doesn't return the raw streams.
    /// Returns true if successfully marked as taken, false otherwise.
    pub async fn mark_stream_taken(&self) -> bool {
        use std::sync::atomic::Ordering;
        !self.stream_taken.swap(true, Ordering::SeqCst)
    }

    /// Check if the stream has been marked as taken.
    pub async fn is_stream_taken(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.stream_taken.load(Ordering::SeqCst)
    }

    // Close the underlying connection (best effort)
    pub async fn close(&self) {
        let mut sender_guard = self.ws_sender.lock().await;
        let _ = sender_guard.close().await; // Ignore errors on close
    }
    
    /// Get the current room ID
    pub async fn get_current_room(&self) -> Option<String> {
        let room = self.current_room.read().await;
        room.clone()
    }
    
    /// Set the current room ID
    pub async fn set_current_room(&self, room_id: Option<String>) {
        let mut room = self.current_room.write().await;
        *room = room_id;
    }
    
    /// Get display name
    pub fn get_display_name(&self) -> Option<String> {
        // This is a blocking operation, but it's quick and used rarely
        let display_name = futures::executor::block_on(self.display_name.read());
        display_name.clone()
    }
    
    /// Set display name
    pub async fn set_display_name(&self, name: Option<String>) {
        let mut display_name = self.display_name.write().await;
        *display_name = name;
    }
}

/// Session manager for handling multiple client sessions
pub struct SessionManager {
    /// Active sessions (session_id -> session)
    sessions: Arc<Mutex<std::collections::HashMap<String, ClientSession>>>,
    /// IP to session mapping for quicker lookups (IP String -> Session ID String)
    ip_sessions: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// Session timeout
    session_timeout: Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(
        _max_connections_per_ip: usize, // Parameter kept for signature compatibility but marked unused
        session_timeout: Duration
    ) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            ip_sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            session_timeout,
        }
    }

    /// Add a new session
    pub async fn add_session(&self, session: ClientSession) {
        let mut sessions_guard = self.sessions.lock().await;
        let mut ip_sessions_guard = self.ip_sessions.lock().await;

        // Store the session by ID
        let session_id = session.id.clone();
        let ip_addr_str = session.ip_address.clone();
        sessions_guard.insert(session_id.clone(), session);

        // Update IP to session ID mapping
        ip_sessions_guard.insert(ip_addr_str, session_id);
    }

    /// Remove a session by ID
    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions_guard = self.sessions.lock().await;
        // Remove from main session map
        if let Some(removed_session) = sessions_guard.remove(session_id) {
            // Remove from IP mapping as well
            let mut ip_sessions_guard = self.ip_sessions.lock().await;
            ip_sessions_guard.remove(&removed_session.ip_address);
            
            // Optionally close the session's connection
            tokio::spawn(async move { removed_session.close().await; });
        }
    }

    /// Update session activity timestamp
    pub async fn touch_session(&self, session_id: &str) -> Result<(), SessionError> {
        let sessions_guard = self.sessions.lock().await;
        if let Some(session) = sessions_guard.get(session_id) {
            session.update_activity().await;
            Ok(())
        } else {
            Err(SessionError::NotFound(session_id.to_string()))
        }
    }

    /// Get a clone of a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<ClientSession> {
        let sessions_guard = self.sessions.lock().await;
        sessions_guard.get(session_id).cloned()
    }

    /// Get a clone of a session by IP address
    pub async fn get_session_by_ip(&self, ip: &str) -> Option<ClientSession> {
        let ip_sessions_guard = self.ip_sessions.lock().await;
        // Find session ID associated with the IP
        if let Some(session_id) = ip_sessions_guard.get(ip) {
            // Now get the actual session using the ID
            let sessions_guard = self.sessions.lock().await;
            sessions_guard.get(session_id).cloned()
        } else {
            None
        }
    }

    /// Check if a session exists by ID
    pub async fn has_session(&self, session_id: &str) -> bool {
        let sessions_guard = self.sessions.lock().await;
        sessions_guard.contains_key(session_id)
    }

    /// Get clones of all active sessions
    pub async fn all_sessions(&self) -> Vec<ClientSession> {
        let sessions_guard = self.sessions.lock().await;
        sessions_guard.values().cloned().collect()
    }

    /// Count active sessions
    pub async fn session_count(&self) -> usize {
        let sessions_guard = self.sessions.lock().await;
        sessions_guard.len()
    }

    /// Count sessions by client IP address
    pub async fn count_sessions_by_ip(&self, ip: &std::net::IpAddr) -> usize {
        let sessions_guard = self.sessions.lock().await;
        sessions_guard.values()
            .filter(|s| s.address.ip() == *ip)
            .count()
    }

    /// Close all sessions gracefully (sends disconnect message)
    pub async fn close_all_sessions(&self, reason: &str) {
        let sessions_to_close = {
            let sessions_guard = self.sessions.lock().await;
            sessions_guard.values().cloned().collect::<Vec<_>>()
        };

        let disconnect_packet = crate::protocol::serialization::create_disconnect_packet(
            crate::protocol::types::disconnect_reason::SERVER_SHUTDOWN,
            reason
        );

        // Send disconnect notifications concurrently
        let close_futures = sessions_to_close.iter().map(|session| {
            let packet = disconnect_packet.clone();
            async move {
                if let Err(e) = session.send_packet(&packet).await {
                    warn!("Failed to send disconnect to {}: {}", session.client_id, e);
                }
                session.close().await;
            }
        });
        futures::future::join_all(close_futures).await;

        // Clear all session tracking data AFTER attempting notifications
        {
            let mut sessions_guard = self.sessions.lock().await;
            sessions_guard.clear();
        }
        {
            let mut ip_sessions_guard = self.ip_sessions.lock().await;
            ip_sessions_guard.clear();
        }
        info!("Cleared all active sessions.");
    }

    /// Clean up expired sessions based on idle time
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let timeout = self.session_timeout;
        let mut expired_ids = Vec::new();

        // Identify expired sessions
        {
            let sessions_guard = self.sessions.lock().await;
            for (id, session) in sessions_guard.iter() {
                if session.idle_time().await > timeout {
                    expired_ids.push(id.clone());
                }
            }
        }

        // Remove expired sessions
        if !expired_ids.is_empty() {
            let mut sessions_guard = self.sessions.lock().await;
            let mut ip_sessions_guard = self.ip_sessions.lock().await;

            for id in &expired_ids {
                if let Some(removed_session) = sessions_guard.remove(id) {
                    ip_sessions_guard.remove(&removed_session.ip_address);
                    // Optionally close the session's connection
                    tokio::spawn(async move { removed_session.close().await; });
                }
            }
        }

        expired_ids.len()
    }

    /// Get all sessions using a specific encryption algorithm
    pub async fn get_sessions_by_algorithm(&self, algorithm: &str) -> Vec<ClientSession> {
        let sessions_guard = self.sessions.lock().await;
        sessions_guard.values()
            .filter(|s| s.encryption_algorithm == algorithm)
            .cloned()
            .collect()
    }
    
    /// Get all sessions in a specific room
    pub async fn get_sessions_by_room(&self, room_id: &str) -> Vec<ClientSession> {
        let sessions = self.sessions.lock().await;
        sessions.values()
            .filter(|session| {
                let current_room = futures::executor::block_on(session.get_current_room());
                current_room.as_deref() == Some(room_id)
            })
            .cloned()
            .collect()
    }

    /// Get a session by client ID
    pub async fn get_session_by_client_id(&self, client_id: &str) -> Option<ClientSession> {
        let sessions = self.sessions.lock().await;
        for session in sessions.values() {
            if session.client_id == client_id {
                return Some(session.clone());
            }
        }
        None
    }
}

// Session error type
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

    #[error("Stream components have already been consumed or are unavailable")]
    StreamConsumed,
}
