// Export all modules for public use
pub mod auth;
pub mod config;
pub mod crypto;
pub mod network;
pub mod network_monitor;
pub mod obfuscation;
pub mod server;
pub mod types;
pub mod utils;
pub mod client;

// Re-export the most commonly used items for convenience
pub use crate::client::{VpnClient, ClientConfig, ClientStats};
pub use crate::server::VpnServer;
pub use crate::types::{Result, VpnError, PacketType};
pub use crate::network_monitor::{NetworkMonitor, NetworkMetrics};

// Import the Signer trait to make pubkey() and sign_message() methods available
// This is re-exported to ensure it's available when using our crate
pub use solana_sdk::signer::Signer;
