// src/main.rs
//! AeroNyx Privacy Network Server
//! Decentralized Physical Infrastructure Network (DePIN) node
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
mod hardware;

pub mod hardware;

use config::settings::{ServerConfig, ServerArgs, Command};
use server::VpnServer;
use registration::RegistrationManager;
use hardware::HardwareInfo;

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

/// Handle registration setup command
async fn handle_registration_setup(registration_code: &str, args: &ServerArgs) -> anyhow::Result<()> {
    info!("Setting up AeroNyx node registration");
    
    // Create temporary config
    let mut config = ServerConfig::from_args(args.clone())?;
    config.registration_code = Some(registration_code.to_string());
    
    // Create registration manager
    let mut reg_manager = RegistrationManager::new(&config.api_url);
    reg_manager.set_data_dir(config.data_dir.clone());
    
    // Test API connection first
    info!("Testing connection to API server at {}", config.api_url);
    match reg_manager.test_api_connection().await {
        Ok(true) => info!("API connection test successful"),
        Ok(false) => {
            error!("API connection test failed");
            return Err(anyhow::anyhow!("Cannot connect to API server"));
        }
        Err(e) => {
            error!("Cannot connect to API server: {}", e);
            return Err(anyhow::anyhow!("Cannot connect to API server: {}", e));
        }
    }
    
    // Collect hardware information
    info!("Collecting hardware information...");
    let hardware_info = match HardwareInfo::collect().await {
        Ok(info) => {
            info!("Hardware information collected successfully");
            info!("  Hostname: {}", info.hostname);
            info!("  CPU: {} cores, {}", info.cpu.cores, info.cpu.model);
            info!("  Memory: {} GB", info.memory.total / (1024 * 1024 * 1024));
            info!("  OS: {} {}", info.os.distribution, info.os.version);
            info!("  Public IP: {}", info.public_ip);
            info
        }
        Err(e) => {
            error!("Failed to collect hardware information: {}", e);
            return Err(anyhow::anyhow!("Failed to collect hardware information: {}", e));
        }
    };
    
    // Generate hardware fingerprint
    let fingerprint = hardware_info.generate_fingerprint();
    info!("Hardware fingerprint generated: {}...", &fingerprint[..16]);
    
    // Confirm registration with hardware info
    info!("Confirming registration with server...");
    match reg_manager.confirm_registration_with_hardware(registration_code, &hardware_info).await {
        Ok(response) => {
            info!("Registration confirmed successfully!");
            info!("  Node ID: {}", response.node.id);
            info!("  Reference Code: {}", response.node.reference_code);
            info!("  Node Type: {}", response.node.node_type);
            info!("  Status: {}", response.node.status);
            info!("  Security Level: {}", response.security.security_level);
            
            if response.security.hardware_fingerprint_generated {
                info!("  Hardware fingerprint registered successfully");
            }
            
            // Save registration data to config file (for backward compatibility)
            let wallet_address = response.node.wallet_address.clone();
            config.save_registration(&response.node.reference_code, &wallet_address)?;
            
            info!("Registration data saved successfully");
            
            // Test WebSocket connection
            info!("Testing WebSocket connection...");
            match reg_manager.start_websocket_connection(
                response.node.reference_code.clone(),
                Some(registration_code.to_string())
            ).await {
                Ok(_) => info!("WebSocket connection test successful"),
                Err(e) => warn!("WebSocket connection test failed: {}", e),
            }
            
            info!("\nNext steps:");
            for (i, step) in response.next_steps.iter().enumerate() {
                info!("  {}. {}", i + 1, step);
            }
            
            info!("\nRegistration completed successfully! You can now start the node normally.");
        }
        Err(e) => {
            error!("Registration failed: {}", e);
            
            // Check for specific error types
            if e.contains("hardware_fingerprint_conflict") || e.contains("Hardware already registered") {
                error!("\nThis hardware has already been registered with another node.");
                error!("Each physical device can only be registered once to prevent abuse.");
                error!("If you believe this is an error, please contact support.");
            } else if e.contains("code_already_used") {
                error!("\nThis registration code has already been used.");
                error!("Please generate a new registration code from your dashboard.");
            } else if e.contains("code_expired") {
                error!("\nThis registration code has expired.");
                error!("Registration codes are valid for 24 hours. Please generate a new one.");
            }
            
            return Err(anyhow::anyhow!("Registration failed: {}", e));
        }
    }
    
    Ok(())
}
