mod crypto;
mod network;
mod server;
mod types;

use clap::Parser;
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
    
    tracing::info!("Starting Solana VPN Server...");
    
    // Create and start VPN server
    let server = VpnServer::new(args.clone()).await?;
    server.start(&args.listen).await?;
    
    Ok(())
}
