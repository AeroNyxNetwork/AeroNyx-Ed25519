// src/server/connection.rs
//! WebSocket connection abstraction layer.
//!
//! This module provides traits and implementations for abstracting
//! different types of WebSocket connections (TLS and non-TLS).

use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_rustls::server::TlsStream;
use tokio::net::TcpStream;
use futures::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};

use crate::server::core::ServerError;

/// Trait for WebSocket connections
#[async_trait]
pub trait WebSocketConnection: Send + Sync + 'static {
    /// Send a message through the connection
    async fn send_message(&mut self, msg: Message) -> Result<(), ServerError>;
    
    /// Receive the next message from the connection
    async fn next_message(&mut self) -> Option<Result<Message, ServerError>>;
    
    /// Close the connection
    async fn close(&mut self) -> Result<(), ServerError>;
}

/// Wrapper for WebSocket sender
pub struct WebSocketSender<S> {
    inner: SplitSink<WebSocketStream<S>, Message>,
}

/// Wrapper for WebSocket receiver
pub struct WebSocketReceiver<S> {
    inner: SplitStream<WebSocketStream<S>>,
}

// Implementation for TLS connections
#[async_trait]
impl WebSocketConnection for WebSocketSender<TlsStream<TcpStream>> {
    async fn send_message(&mut self, msg: Message) -> Result<(), ServerError> {
        self.inner.send(msg).await
            .map_err(ServerError::WebSocket)
    }
    
    async fn next_message(&mut self) -> Option<Result<Message, ServerError>> {
        // This is for sender only, should not be called
        None
    }
    
    async fn close(&mut self) -> Result<(), ServerError> {
        self.inner.close().await
            .map_err(ServerError::WebSocket)
    }
}

#[async_trait]
impl WebSocketConnection for WebSocketReceiver<TlsStream<TcpStream>> {
    async fn send_message(&mut self, _msg: Message) -> Result<(), ServerError> {
        // This is for receiver only, should not be called
        Err(ServerError::Internal("Cannot send on receiver".to_string()))
    }
    
    async fn next_message(&mut self) -> Option<Result<Message, ServerError>> {
        self.inner.next().await
            .map(|res| res.map_err(ServerError::WebSocket))
    }
    
    async fn close(&mut self) -> Result<(), ServerError> {
        // Receiver doesn't have close method
        Ok(())
    }
}

// Implementation for RAW (non-TLS) connections
#[async_trait]
impl WebSocketConnection for WebSocketSender<TcpStream> {
    async fn send_message(&mut self, msg: Message) -> Result<(), ServerError> {
        self.inner.send(msg).await
            .map_err(ServerError::WebSocket)
    }
    
    async fn next_message(&mut self) -> Option<Result<Message, ServerError>> {
        // This is for sender only, should not be called
        None
    }
    
    async fn close(&mut self) -> Result<(), ServerError> {
        self.inner.close().await
            .map_err(ServerError::WebSocket)
    }
}

#[async_trait]
impl WebSocketConnection for WebSocketReceiver<TcpStream> {
    async fn send_message(&mut self, _msg: Message) -> Result<(), ServerError> {
        // This is for receiver only, should not be called
        Err(ServerError::Internal("Cannot send on receiver".to_string()))
    }
    
    async fn next_message(&mut self) -> Option<Result<Message, ServerError>> {
        self.inner.next().await
            .map(|res| res.map_err(ServerError::WebSocket))
    }
    
    async fn close(&mut self) -> Result<(), ServerError> {
        // Receiver doesn't have close method
        Ok(())
    }
}

/// Combined connection wrapper that handles both send and receive
pub struct DuplexWebSocketConnection {
    sender: Arc<Mutex<Box<dyn WebSocketConnection>>>,
    receiver: Arc<Mutex<Box<dyn WebSocketConnection>>>,
}

impl DuplexWebSocketConnection {
    /// Create a new duplex connection from TLS stream
    pub fn new_tls(stream: WebSocketStream<TlsStream<TcpStream>>) -> Self {
        let (sender, receiver) = stream.split();
        
        Self {
            sender: Arc::new(Mutex::new(Box::new(WebSocketSender { inner: sender }))),
            receiver: Arc::new(Mutex::new(Box::new(WebSocketReceiver { inner: receiver }))),
        }
    }
    
    /// Create a new duplex connection from RAW stream
    pub fn new_raw(stream: WebSocketStream<TcpStream>) -> Self {
        let (sender, receiver) = stream.split();
        
        Self {
            sender: Arc::new(Mutex::new(Box::new(WebSocketSender { inner: sender }))),
            receiver: Arc::new(Mutex::new(Box::new(WebSocketReceiver { inner: receiver }))),
        }
    }
    
    /// Get the sender mutex
    pub fn sender(&self) -> Arc<Mutex<Box<dyn WebSocketConnection>>> {
        self.sender.clone()
    }
    
    /// Get the receiver mutex
    pub fn receiver(&self) -> Arc<Mutex<Box<dyn WebSocketConnection>>> {
        self.receiver.clone()
    }
    
    /// Send a message
    pub async fn send_message(&self, msg: Message) -> Result<(), ServerError> {
        let mut sender = self.sender.lock().await;
        sender.send_message(msg).await
    }
    
    /// Receive the next message
    pub async fn next_message(&self) -> Option<Result<Message, ServerError>> {
        let mut receiver = self.receiver.lock().await;
        receiver.next_message().await
    }
    
    /// Close the connection
    pub async fn close(&self) -> Result<(), ServerError> {
        let mut sender = self.sender.lock().await;
        sender.close().await
    }
}
