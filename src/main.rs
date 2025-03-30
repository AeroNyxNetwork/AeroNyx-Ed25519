// src/main.rs
//! AeroNyx Privacy Network Server
//! 
//! A privacy-focused VPN server using Solana keypairs for authentication
//! and end-to-end encryption.

use clap::Parser;
use std::path::Path;
use std::process;
use tokio::signal;
use tracing::{error, info};

mod auth;
mod config;
mod crypto;
mod network;
mod protocol;
mod server;
mod utils;

use config::settings::{ServerConfig, ServerArgs};
use server::VpnServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = ServerArgs::parse();
    
    // Initialize logging
    utils::logging::init_logging(&args.log_level)?;
    
    info!("Starting AeroNyx Privacy Network Server v{}", env!("CARGO_PKG_VERSION"));
    
    // Check if running as root (required for TUN device management)
    #[cfg(target_family = "unix")]
    if !utils::system::is_root() {
        error!("This application must be run as root to manage TUN devices");
        process::exit(1);
    }
    
    // Check if TLS certificate and key exist
    if !Path::new(&args.cert_file).exists() || !Path::new(&args.key_file).exists() {
        error!("TLS certificate or key file not found. Please ensure both files exist:");
        error!("  - Certificate: {}", args.cert_file);
        error!("  - Key file: {}", args.key_file);
        error!("You can generate self-signed certificates with OpenSSL:");
        error!("  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes");
        process::exit(1);
    }
    
    // Create server configuration
    let config = ServerConfig::from_args(args.clone())?;
    
    // Create and initialize VPN server
    let server = VpnServer::new(config).await?;
    info!("Server successfully initialized with military-grade security features");
    
    // Start server in the background
    let server_handle = server.start().await?;
    
    // Wait for shutdown signal
    let shutdown_future = wait_for_shutdown_signal();
    
    // Wait for either server to finish or shutdown signal
    tokio::select! {
        _ = server_handle => {
            info!("Server stopped");
        }
        _ = shutdown_future => {
            info!("Shutdown signal received, stopping server...");
            server.shutdown().await?;
        }
    }
    
    info!("Server shutdown complete");
    Ok(())
}

/// Wait for CTRL+C or termination signal
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
