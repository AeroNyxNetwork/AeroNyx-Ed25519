// src/zkp_halo2/mod.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Module
// Version: 5.0.0 - Production-ready

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
    info!("Initializing secure Halo2 ZKP system with k={}", k);
    generate_setup_params(k).await
}

/// Initialize with default parameters
pub async fn initialize() -> Result<SetupParams, String> {
    // k=10 for testing (2^10 rows)
    // k=14 for production (2^14 rows, higher security)
    #[cfg(test)]
    const DEFAULT_K: u32 = 10;
    
    #[cfg(not(test))]
    const DEFAULT_K: u32 = 14;
    
    initialize_with_k(DEFAULT_K).await
}
