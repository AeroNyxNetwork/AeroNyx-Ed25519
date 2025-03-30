use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use solana_sdk::signer::Signer;  // Import the Signer trait here

use aeronyx_private_ed25519::client::{VpnClient, ClientConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_target(false)
        .init();

    // Create client configuration
    let mut config = ClientConfig::default();
    
    // Override default configuration with command line arguments
    // You could use clap or other arg parsing libraries here
    config.server_host = "localhost".to_string();
    config.server_port = 8080;
    
    // Create client
    let mut client = VpnClient::new(config).await?;
    
    // Log client's public key (useful for registration with server)
    let public_key = client.get_public_key();
    tracing::info!("Client public key: {}", public_key);
    
    // Permission check
    tracing::info!("{}", VpnClient::check_permissions());
    
    // Connect to VPN server
    tracing::info!("Connecting to VPN server...");
    if let Err(e) = client.connect().await {
        tracing::error!("Failed to connect: {}", e);
        return Err(anyhow::anyhow!("Connection failed: {}", e));
    }
    
    // Print connection stats
    let stats = client.get_stats().await;
    tracing::info!("Connected! Assigned IP: {}", stats.assigned_ip.unwrap_or_default());
    
    // Create a shared flag for graceful shutdown
    let shutdown = Arc::new(Mutex::new(false));
    let shutdown_clone = shutdown.clone();
    
    // Handle Ctrl+C
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
            return;
        }
        
        tracing::info!("Received Ctrl+C, shutting down gracefully...");
        let mut lock = shutdown_clone.lock().await;
        *lock = true;
    });
    
    // Main loop
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Check stats periodically
        let stats = client.get_stats().await;
        tracing::debug!(
            "Bytes sent: {}, Bytes received: {}, Session duration: {}s",
            stats.bytes_sent,
            stats.bytes_received,
            stats.session_duration
        );
        
        // Get network performance metrics
        if let Ok(performance) = client.get_network_performance().await {
            if let Some(latency) = performance.get("latency_ms") {
                tracing::debug!("Connection latency: {:.2} ms", latency);
            }
            
            if let Some(tx_throughput) = performance.get("tx_bytes_per_second") {
                tracing::debug!("Upload speed: {:.2} bytes/sec", tx_throughput);
            }
            
            if let Some(rx_throughput) = performance.get("rx_bytes_per_second") {
                tracing::debug!("Download speed: {:.2} bytes/sec", rx_throughput);
            }
        }
        
        // Check for connection issues and attempt auto-recovery if needed
        if !client.is_connected().await && client.config.auto_reconnect {
            tracing::warn!("Connection dropped, attempting to reconnect...");
            if let Err(e) = client.check_and_reconnect().await {
                tracing::error!("Auto-reconnect failed: {}", e);
            }
        }
        
        // Check if we need to exit
        if *shutdown.lock().await {
            break;
        }
    }
    
    // Disconnect
    tracing::info!("Disconnecting from VPN server...");
    if let Err(e) = client.disconnect().await {
        tracing::error!("Error during disconnect: {}", e);
    }
    
    tracing::info!("Disconnected. Goodbye!");
    Ok(())
}
