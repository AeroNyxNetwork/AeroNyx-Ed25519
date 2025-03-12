mod crypto;
mod network;
mod server;
mod types;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use crate::server::VpnServer;
use crate::types::Args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(args.log_level.clone()));
    
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    
    tracing::info!("Starting Solana Private Server...");
    
    // Create and start VPN server
    let server = VpnServer::new(args.clone()).await?;
    server.start(&args.listen).await?;
    
    Ok(())
}
