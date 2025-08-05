// src/main.rs
//! AeroNyx Privacy Network Server
//! Decentralized Physical Infrastructure Network (DePIN) node
use clap::Parser;
use std::path::Path;
use std::process;
use tokio::signal;
use tracing::{error, info, warn};

mod auth;
mod config;
mod crypto;
mod network;
mod protocol;
mod server;
mod utils;
mod registration;
mod hardware;
mod remote_management;
mod zkp_halo2;
mod websocket_protocol;
mod remote_command_handler;
mod terminal;
mod terminal_manager;

use zkp_halo2::{initialize, SetupParams};
use config::settings::{ServerConfig, ServerArgs, Command, NodeMode, TransportSecurity};
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
    
    info!("Starting AeroNyx Node v{} in {:?} mode with {:?} transport", 
          env!("CARGO_PKG_VERSION"), 
          args.mode,
          args.transport_security);
    
    // Check root permission only for VPN mode
    #[cfg(target_family = "unix")]
    if matches!(args.mode, NodeMode::VPNEnabled | NodeMode::Hybrid) {
        if !utils::system::is_root() {
            error!("VPN mode requires root privileges to manage TUN devices");
            process::exit(1);
        }
    }
    
    // Check certificates only for VPN mode with TLS
    if matches!(args.mode, NodeMode::VPNEnabled | NodeMode::Hybrid) 
        && args.transport_security == TransportSecurity::Tls {
        if args.cert_file.is_none() || args.key_file.is_none() {
            error!("VPN mode with TLS requires TLS certificate and key files");
            error!("Use --cert-file and --key-file options, or run with --transport-security raw");
            process::exit(1);
        }
        
        let cert_file = args.cert_file.as_ref().unwrap();
        let key_file = args.key_file.as_ref().unwrap();
        
        if !Path::new(cert_file).exists() || !Path::new(key_file).exists() {
            error!("TLS certificate or key file not found:");
            error!("  - Certificate: {}", cert_file);
            error!("  - Key file: {}", key_file);
            error!("You can generate self-signed certificates with OpenSSL:");
            error!("  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes");
            error!("Or run with --transport-security raw to disable TLS");
            process::exit(1);
        }
    }
    
    // Create server configuration
    let config = ServerConfig::from_args(args.clone())?;
    
    // Warn about security implications of RAW mode
    if config.transport_security == TransportSecurity::Raw {
        warn!("⚠️  WARNING: Running in RAW mode without TLS encryption!");
        warn!("⚠️  Control channel will be unencrypted (authentication and key exchange)");
        warn!("⚠️  This mode is vulnerable to man-in-the-middle attacks");
        warn!("⚠️  Only use in trusted network environments or with additional encryption layers");
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
    
    // Run based on mode
    match config.mode {
        NodeMode::DePINOnly => {
            info!("Running in DePIN-only mode (no VPN server)");
            run_depin_only(config).await
        }
        NodeMode::VPNEnabled => {
            info!("Running in VPN-enabled mode");
            run_with_vpn(config).await
        }
        NodeMode::Hybrid => {
            info!("Running in hybrid mode (DePIN + VPN)");
            run_with_vpn(config).await
        }
    }
}

/// Run in DePIN-only mode (no VPN server)
async fn run_depin_only(config: ServerConfig) -> anyhow::Result<()> {
    // Create registration manager
    let mut reg_manager = RegistrationManager::new(&config.api_url);
    reg_manager.set_data_dir(config.data_dir.clone());
    
    // Initialize ZKP parameters
    let zkp_params = match reg_manager.initialize_zkp().await {
        Ok(params) => {
            info!("Zero-knowledge proof system initialized successfully");
            Some(params)
        }
        Err(e) => {
            warn!("Failed to initialize ZKP system: {}. Hardware attestation will be disabled.", e);
            None
        }
    };
    
    // Store ZKP params in registration manager if available
    if let Some(params) = zkp_params.clone() {
        reg_manager.set_zkp_params(params);
        info!("ZKP-enabled hardware attestation is available");
    }
    
    // Load registration data
    match reg_manager.load_from_config(&config) {
        Ok(true) => {
            info!("Registration data loaded successfully");
        }
        Ok(false) => {
            error!("No registration found. Please run setup command first.");
            return Err(anyhow::anyhow!("Not registered"));
        }
        Err(e) => {
            error!("Failed to load registration: {}", e);
            return Err(anyhow::anyhow!("Registration error: {}", e));
        }
    }
    
    // Verify hardware fingerprint
    if let Err(e) = reg_manager.verify_hardware_fingerprint().await {
        error!("Hardware verification failed: {}", e);
        return Err(anyhow::anyhow!("Hardware verification failed"));
    }
    
    info!("Starting DePIN node with reference code: {}", 
          reg_manager.reference_code.as_ref().unwrap());
    
    // Collect current hardware info for WebSocket connection
    let hardware_info = HardwareInfo::collect().await
        .map_err(|e| anyhow::anyhow!("Failed to collect hardware info: {}", e))?;
    
    // Get reference code and setup params
    let reference_code = reg_manager.reference_code.clone().unwrap();
    let setup_params = zkp_params.ok_or_else(|| anyhow::anyhow!("ZKP not initialized"))?;
    
    // Enable remote management if configured
    if config.enable_remote_management {
        info!("Remote management enabled");
        reg_manager.set_remote_management_enabled(true);
        
        // Set security mode based on configuration
        use crate::remote_command_handler::SecurityMode;
        let security_mode = match config.remote_security_mode.as_str() {
            "full-access" => {
                warn!("⚠️  WARNING: Remote management is in FULL ACCESS mode!");
                warn!("⚠️  This allows unrestricted command execution and file access.");
                warn!("⚠️  Use this mode only in trusted environments!");
                SecurityMode::FullAccess
            }
            _ => {
                info!("Remote management is in RESTRICTED mode (safer)");
                SecurityMode::Restricted
            }
        };
        
        reg_manager.set_remote_security_mode(security_mode);
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    // Run WebSocket connection with hardware info and setup params
    match reg_manager.start_websocket_connection(
        reference_code, 
        None
    ).await {
        Ok(_) => info!("WebSocket connection closed"),
        Err(e) => error!("WebSocket error: {}", e),
    }
    
    Ok(())
}

/// Run with VPN server (VPN-enabled or Hybrid mode)
async fn run_with_vpn(config: ServerConfig) -> anyhow::Result<()> {
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
    info!("Setting up AeroNyx node registration with ZKP support");
    
    let mut config = ServerConfig::from_args(args.clone())?;
    config.registration_code = Some(registration_code.to_string());
    
    let mut reg_manager = RegistrationManager::new(&config.api_url);
    reg_manager.set_data_dir(config.data_dir.clone());
    
    // Initialize ZKP system
    info!("Initializing zero-knowledge proof system...");
    let zkp_params = match reg_manager.initialize_zkp().await {
        Ok(params) => {
            reg_manager.set_zkp_params(params.clone());
            info!("✓ ZKP system initialized successfully");
            Some(params)
        }
        Err(e) => {
            warn!("Failed to initialize ZKP system: {}. Registration will proceed without ZKP.", e);
            None
        }
    };
    
    // Test API connection
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
            info!("  Public IP: {}", info.network.public_ip);
            info
        }
        Err(e) => {
            error!("Failed to collect hardware information: {}", e);
            return Err(anyhow::anyhow!("Failed to collect hardware information: {}", e));
        }
    };
    
    let fingerprint = hardware_info.generate_fingerprint();
    info!("Hardware fingerprint generated: {}...", &fingerprint[..16]);
    
    let commitment = hardware_info.generate_zkp_commitment();
    let commitment_hex = hex::encode(&commitment);
    info!("ZKP commitment generated: {}...", &commitment_hex[..16]);
    
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
            
            // Save registration data
            let wallet_address = response.node.wallet_address.clone();
            let hardware_fingerprint_str = hardware_info.generate_fingerprint();
            config.save_registration(&response.node.reference_code, &wallet_address, &hardware_fingerprint_str)?;
            
            info!("Registration data saved successfully");
            
            // Test WebSocket connection if ZKP is available
            if let Some(params) = zkp_params {
                info!("Testing WebSocket connection with ZKP support...");
                let test_duration = tokio::time::Duration::from_secs(10);
                let ws_test = tokio::time::timeout(
                    test_duration,
                    reg_manager.start_websocket_connection(
                        response.node.reference_code.clone(),
                        Some(registration_code.to_string())
                    )
                ).await;
                
                match ws_test {
                    Ok(Ok(_)) => info!("WebSocket connection test completed successfully"),
                    Ok(Err(e)) => warn!("WebSocket connection test failed: {}", e),
                    Err(_) => info!("WebSocket connection test completed (timeout)"),
                }
            }
            
            // Display success message
            info!("\n================================================================================");
            info!("Registration completed successfully! Your node is now registered.");
            info!("================================================================================");
            
            info!("\nNext steps:");
            for (i, step) in response.next_steps.iter().enumerate() {
                info!("  {}. {}", i + 1, step);
            }
            
            info!("\nTo start your node, use one of the following commands:");
            info!("");
            info!("  For DePIN-only mode (recommended for compute nodes):");
            info!("    {} --mode depin-only", env!("CARGO_PKG_NAME"));
            info!("");
            info!("  For DePIN-only mode with remote management (restricted mode):");
            info!("    {} --mode depin-only --enable-remote-management", env!("CARGO_PKG_NAME"));
            info!("");
            info!("  For DePIN-only mode with full remote access (use with caution!):");
            info!("    {} --mode depin-only --enable-remote-management --remote-security-mode full-access", env!("CARGO_PKG_NAME"));
            info!("");
            info!("  For VPN mode with TLS (secure):");
            info!("    {} --mode vpn-enabled --cert-file server.crt --key-file server.key", env!("CARGO_PKG_NAME"));
            info!("");
            info!("  For VPN mode without TLS (RAW mode - use with caution!):");
            info!("    {} --mode vpn-enabled --transport-security raw", env!("CARGO_PKG_NAME"));
            info!("");
            info!("Your reference code: {}", response.node.reference_code);
            if reg_manager.has_zkp_enabled() {
                info!("✓ Zero-knowledge proof hardware attestation is enabled");
            }
            info!("================================================================================");
        }
        Err(e) => {
            error!("Registration failed: {}", e);
            return Err(anyhow::anyhow!("Registration failed: {}", e));
        }
    }
    
    Ok(())
}
