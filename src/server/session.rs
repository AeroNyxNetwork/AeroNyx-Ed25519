// src/server/session.rs

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use futures::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use tokio_tungstenite::tungstenite::Message;
use std::time::{Duration, Instant};
// Remove unused imports: debug, info
use tracing::warn;
use tokio_rustls::server::TlsStream;
use tokio::net::TcpStream;


use crate::protocol::PacketType;
use crate::protocol::serialization::packet_to_ws_message;
use crate::server::core::ServerError;


/// Client session for connected users
#[derive(Clone)] // Keep Clone, but be mindful of Arc usage
pub struct ClientSession {
    /// Unique session identifier
    pub id: String,
    /// Client's public key
    pub client_id: String,
    /// Assigned IP address
    pub ip_address: String,
    /// Client's address
    pub address: SocketAddr,
    /// WebSocket stream sender (wrapped for thread safety)
    ws_sender: Arc<Mutex<SplitSink<WebSocketStream<TlsStream<TcpStream>>, Message>>>,
    /// WebSocket stream receiver (wrapped for thread safety)
    ws_receiver: Arc<Mutex<SplitStream<WebSocketStream<TlsStream<TcpStream>>>>>,
    /// Last activity timestamp (wrapped for thread safety)
    pub last_activity: Arc<Mutex<Instant>>,
     /// Indicates if the underlying stream components have been logically "taken"
     /// (prevents taking them multiple times). This doesn't actually take ownership.
    stream_taken: Arc<Mutex<bool>>,
}


impl ClientSession {
    /// Create a new client session with split WebSocket components wrapped in Arc<Mutex<>>
    pub fn new(
        id: String,
        client_id: String,
        ip_address: String,
        address: SocketAddr,
        ws_sender: Arc<Mutex<SplitSink<WebSocketStream<TlsStream<TcpStream>>, Message>>>,
        ws_receiver: Arc<Mutex<SplitStream<WebSocketStream<TlsStream<TcpStream>>>>>,
    ) -> Result<Self, ServerError> { // Return ServerError for consistency
        Ok(Self {
            id,
            client_id,
            ip_address,
            address,
            ws_sender, // Assign the provided Arc<Mutex<>> directly
            ws_receiver, // Assign the provided Arc<Mutex<>> directly
            last_activity: Arc::new(Mutex::new(Instant::now())),
            stream_taken: Arc::new(Mutex::new(false)),
        })
    }

    /// Send a packet to the client (acquires lock on sender)
    pub async fn send_packet(&self, packet: &PacketType) -> Result<(), ServerError> {
        let message = packet_to_ws_message(packet)?;
        let mut sender_guard = self.ws_sender.lock().await; // Lock the sender
        sender_guard.send(message).await
            .map_err(ServerError::WebSocket) // Map error type
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
         receiver_guard.next().await.map(|res| res.map_err(ServerError::WebSocket))
    }

    /// Attempt to logically take the stream components.
     /// This marks the session as consumed but doesn't return the raw streams.
     /// Returns true if successfully marked as taken, false otherwise.
     pub async fn mark_stream_taken(&self) -> bool {
         let mut taken_guard = self.stream_taken.lock().await;
         if *taken_guard {
             false // Already taken
         } else {
             *taken_guard = true;
             true // Successfully marked as taken
         }
     }

     /// Check if the stream has been marked as taken.
     pub async fn is_stream_taken(&self) -> bool {
         *self.stream_taken.lock().await
     }

     // Close the underlying connection (best effort)
      pub async fn close(&self) {
          let mut sender_guard = self.ws_sender.lock().await;
          let _ = sender_guard.close().await; // Ignore errors on close
      }
}


/// Session manager for handling multiple client sessions
pub struct SessionManager {
    /// Active sessions (session_id -> session)
    sessions: Arc<Mutex<std::collections::HashMap<String, ClientSession>>>,
    /// IP to session mapping for quicker lookups (IP String -> Session ID String)
    ip_sessions: Arc<Mutex<std::collections::HashMap<String, String>>>,
    // Remove unused max_connections_per_ip
    // max_connections_per_ip: usize,
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
            // self.max_connections_per_ip = max_connections_per_ip, // Removed assignment
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
             // tokio::spawn(async move { removed_session.close().await; });
        }
    }


    /// Update session activity timestamp
    pub async fn touch_session(&self, session_id: &str) -> Result<(), SessionError> { // Return SessionError
        let sessions_guard = self.sessions.lock().await; // Read lock is sufficient if update_activity takes &self
        if let Some(session) = sessions_guard.get(session_id) {
            session.update_activity().await; // Assuming update_activity is correctly implemented
            Ok(())
        } else {
            Err(SessionError::NotFound(session_id.to_string()))
        }
    }

    /// Get a clone of a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<ClientSession> {
        let sessions_guard = self.sessions.lock().await;
        sessions_guard.get(session_id).cloned() // Clone the session
    }

    /// Get a clone of a session by IP address
    pub async fn get_session_by_ip(&self, ip: &str) -> Option<ClientSession> {
        let ip_sessions_guard = self.ip_sessions.lock().await;
        // Find session ID associated with the IP
        if let Some(session_id) = ip_sessions_guard.get(ip) {
            // Now get the actual session using the ID
            let sessions_guard = self.sessions.lock().await;
            sessions_guard.get(session_id).cloned() // Clone the session
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
        let sessions_to_close = { // Scope to release lock quickly
             let sessions_guard = self.sessions.lock().await;
             sessions_guard.values().cloned().collect::<Vec<_>>()
        }; // sessions_guard lock released here

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
                 session.close().await; // Also explicitly close the connection
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
         tracing::info!("Cleared all active sessions.");
    }


    /// Clean up expired sessions based on idle time
    pub async fn cleanup_expired_sessions(&self) -> usize {
         let timeout = self.session_timeout;
         let mut expired_ids = Vec::new();

        // --- Identify expired sessions ---
         { // Scope for read lock
             let sessions_guard = self.sessions.lock().await;
             for (id, session) in sessions_guard.iter() {
                 if session.idle_time().await > timeout {
                     expired_ids.push(id.clone());
                 }
             }
         } // sessions_guard lock released

        // --- Remove expired sessions ---
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

         expired_ids.len() // Return the count of removed sessions
    }
}


// Session error type - Add StreamConsumed variant
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
