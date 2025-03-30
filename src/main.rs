mod auth;
mod config;
mod crypto;
mod network;
mod obfuscation;
mod server;
mod types;
mod utils;

use clap::Parser;
use std::path::Path;
use tracing_subscriber::fmt;
use tracing_subscriber::EnvFilter;

use crate::server::VpnServer;
use crate::types::Args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Initialize logging
    let filter = EnvFilter::new(&args.log_level);
    
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    
    tracing::info!("Starting AeroNyx Privacy Network - Military-Grade Edition");
    tracing::info!("Server version: {}", env!("CARGO_PKG_VERSION"));
    
    // Check if TLS certificate and key exist
    if !Path::new(&args.cert_file).exists() || !Path::new(&args.key_file).exists() {
        tracing::error!("TLS certificate or key file not found. Please ensure both files exist:");
        tracing::error!("  - Certificate: {}", args.cert_file);
        tracing::error!("  - Key file: {}", args.key_file);
        tracing::info!("You can generate self-signed certificates with OpenSSL:");
        tracing::info!("  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes");
        return Err(anyhow::anyhow!("TLS certificate or key file not found"));
    }
    
    // Create and start VPN server
    let server = VpnServer::new(args.clone()).await?;
    tracing::info!("Server successfully initialized with military-grade security features");
    
    if args.enable_obfuscation {
        tracing::info!("Traffic obfuscation enabled: {}", args.obfuscation_method);
    }
    
    if args.enable_padding {
        tracing::info!("Traffic padding enabled");
    }
    
    server.start(&args.listen).await?;
    
    Ok(())
}
