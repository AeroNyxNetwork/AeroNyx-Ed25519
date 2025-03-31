// src/server/packet.rs
//! TUN packet processing.
//!
//! This module handles reading packets from the TUN device
//! and routing them to the appropriate client.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tracing::{debug, error, trace, warn};
use tun::platform::Device;
use std::io::{Read, Write};
use crate::network::NetworkMonitor;
use crate::crypto::SessionKeyManager;
use crate::server::routing::PacketRouter;
use crate::server::session::SessionManager;
use crate::server::core::ServerState;

/// Error type for TUN packet processing
#[derive(Debug, thiserror::Error)]
pub enum TunPacketError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Packet processing error: {0}")]
    Processing(String),
    
    #[error("Session not found for IP {0}")]
    SessionNotFound(String),
    
    #[error("TUN device not initialized")]
    TunNotInitialized,
    
    #[error("Routing error: {0}")]
    Routing(String),
    
    #[error("Server shutdown")]
    Shutdown,
}

/// Process packets from the TUN device
pub async fn process_tun_packets(
    tun_device: Arc<Mutex<Device>>,
    session_manager: Arc<SessionManager>,
    session_key_manager: Arc<SessionKeyManager>,
    packet_router: Arc<PacketRouter>,
    network_monitor: Arc<NetworkMonitor>,
    server_state: Arc<RwLock<ServerState>>,
) -> Result<(), TunPacketError> {
    let mut buffer = vec![0u8; 2048];
    
    loop {
        // Check if we should still be running
        let current_state = *server_state.read().await;
        if current_state != ServerState::Running {
            return Err(TunPacketError::Shutdown);
        }
        
        // Read from TUN device
        let bytes_read = {
            let mut device = tun_device.lock().await;
            match device.read(&mut buffer) {
                Ok(n) => n,
                Err(e) => {
                    // Handle non-blocking errors
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        time::sleep(Duration::from_millis(1)).await;
                        continue;
                    }
                    
                    // Log other errors
                    error!("Error reading from TUN device: {}", e);
                    time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        };
        
        if bytes_read > 0 {
            // Get the packet slice
            let packet = &buffer[..bytes_read];
            
            // Process packet and route it
            if let Some((dest_ip, processed_packet)) = packet_router.process_packet(packet) {
                trace!("Routing packet to {}", dest_ip);
                
                // Record packet in metrics
                network_monitor.record_received(bytes_read as u64).await;
                
                // Find client session by IP and send the packet
                match session_manager.get_session_by_ip(&dest_ip).await {
                    Some(session) => {
                        let client_id = session.client_id.clone();
                        
                        // Get the session key
                        if let Some(session_key) = session_key_manager.get_key(&client_id).await {
                            // Route the packet through the session
                            if let Err(e) = packet_router.route_outbound_packet(
                                &processed_packet,
                                &session_key,
                                &session,
                            ).await {
                                trace!("Error routing packet to {}: {}", dest_ip, e);
                            }
                        } else {
                            warn!("No session key found for client {}", client_id);
                        }
                    }
                    None => {
                        trace!("No session found for IP: {}", dest_ip);
                    }
                }
            }
        }
    }
}

/// Write a packet to the TUN device
pub async fn write_to_tun(
    tun_device: Arc<Mutex<Device>>, 
    packet_data: &[u8]
) -> std::io::Result<usize> {
    let mut device = tun_device.lock().await;
    device.write(packet_data)
}

/// Start the TUN packet processing task
pub async fn start_tun_packet_processor(
    tun_device: Arc<Mutex<Device>>,
    session_manager: Arc<SessionManager>,
    session_key_manager: Arc<SessionKeyManager>,
    packet_router: Arc<PacketRouter>,
    network_monitor: Arc<NetworkMonitor>,
    server_state: Arc<RwLock<ServerState>>,
) -> tokio::task::JoinHandle<Result<(), TunPacketError>> {
    tokio::spawn(async move {
        let result = process_tun_packets(
            tun_device,
            session_manager,
            session_key_manager,
            packet_router,
            network_monitor,
            server_state,
        ).await;
        
        match &result {
            Ok(_) => debug!("TUN packet processor completed successfully"),
            Err(TunPacketError::Shutdown) => debug!("TUN packet processor shut down gracefully"),
            Err(e) => error!("TUN packet processor terminated with error: {}", e),
        }
        
        result
    })
}
