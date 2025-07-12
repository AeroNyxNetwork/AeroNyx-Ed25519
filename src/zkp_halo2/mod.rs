// src/zkp_halo2/mod.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Module
// Version: 2.0.0

pub mod types;
pub mod circuit;
pub mod commitment;
pub mod prover;

pub use types::{SetupParams, Proof};
pub use prover::{generate_hardware_proof, verify_hardware_proof, generate_setup_params};
pub use commitment::PoseidonCommitment;

use tracing::info;

/// Initialize the ZKP system with specified security parameter
pub async fn initialize_with_k(k: u32) -> Result<SetupParams, String> {
    info!("Initializing Halo2 ZKP system with k={}", k);
    
    tokio::task::spawn_blocking(move || {
        generate_setup_params(k)
    })
    .await
    .map_err(|e| format!("Failed to spawn setup task: {}", e))?
}

/// Initialize with default parameters (k=10 for testing, k=14 for production)
pub async fn initialize() -> Result<SetupParams, String> {
    initialize_with_k(10).await
}
