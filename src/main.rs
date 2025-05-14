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
mod registration;

use config::settings::{ServerConfig, ServerArgs, Command};
use server::VpnServer;
use registration::RegistrationManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = ServerArgs::parse();
    
    // Initialize logging
    utils::logging::init_logging(&args.log_level)?;
    
    // Check if this is a registration command
    if let Some(Command::Setup { registration_code }) = &args.command {
        info!("Running registration setup with code: {}", registration_code);
        return handle_registration_setup(&registration_code, &args).await;
    }
    
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
        result = server_handle => {
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

/// Handle registration setup command
async fn handle_registration_setup(registration_code: &str, args: &ServerArgs) -> anyhow::Result<()> {
    info!("Setting up node registration");
    
    // Create temporary config
    let mut config = ServerConfig::from_args(args.clone())?;
    config.registration_code = Some(registration_code.to_string());
    
    // Create registration manager
    let reg_manager = RegistrationManager::new(&config.api_url);
    
    // Collect system information
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let os_type = std::env::consts::OS.to_string();
    let cpu_info = match sys_info::cpu_num() {
        Ok(count) => format!("{} cores", count),
        Err(_) => "Unknown".to_string(),
    };
    let memory_info = match sys_info::mem_info() {
        Ok(mem) => format!("{} MB total", mem.total / 1024),
        Err(_) => "Unknown".to_string(),
    };
    
    let node_info = serde_json::json!({
        "hostname": hostname,
        "os_type": os_type,
        "cpu_info": cpu_info,
        "memory_info": memory_info,
        "version": env!("CARGO_PKG_VERSION"),
    });
    
    // Confirm registration with the server
    match reg_manager.confirm_registration(registration_code, node_info).await {
        Ok(true) => {
            // Check status to get reference code
            match reg_manager.check_status(registration_code).await {
                Ok(status) => {
                    info!("Registration successful!");
                    info!("Node reference code: {}", status.reference_code);
                    info!("Node status: {}", status.status);
                    
                    // Save registration data
                    let wallet_address = args.wallet_address.clone().unwrap_or_else(|| "Unknown".to_string());
                    config.save_registration(&status.reference_code, &wallet_address)?;
                    
                    info!("Registration data saved. You can now start the node normally.");
                },
                Err(e) => {
                    error!("Failed to get node status: {}", e);
                    return Err(anyhow::anyhow!("Registration confirmation failed"));
                }
            }
        },
        Ok(false) => {
            error!("Registration was not confirmed by the server");
            return Err(anyhow::anyhow!("Registration not confirmed"));
        },
        Err(e) => {
            error!("Registration failed: {}", e);
            return Err(anyhow::anyhow!("Registration failed: {}", e));
        }
    }
    
    Ok(())
}
