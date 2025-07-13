// src/zkp_halo2/mod.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Module
// Version: 8.0.0 - Production-ready with optimized exports

pub mod types;
pub mod circuit;
pub mod commitment;
pub mod prover;

// Re-export key types and functions for convenience
pub use types::{SetupParams, Proof};
pub use circuit::{HardwareCircuit, compute_commitment};
pub use prover::{generate_hardware_proof, verify_hardware_proof};
pub use commitment::PoseidonCommitment;

use tracing::{info, warn};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Global setup parameters cache
static SETUP_CACHE: once_cell::sync::Lazy<Arc<RwLock<Option<SetupParams>>>> = 
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Initialize the ZKP system with specified security parameter
/// This function caches the setup parameters for reuse
pub async fn initialize_with_k(k: u32) -> Result<SetupParams, String> {
    info!("Initializing secure Halo2 ZKP system with k={}", k);
    
    // Check cache first
    {
        let cache = SETUP_CACHE.read().await;
        if let Some(params) = cache.as_ref() {
            info!("Using cached setup parameters");
            return Ok(params.clone());
        }
    }
    
    // Generate new parameters
    let params = circuit::generate_setup_params(k).await?;
    
    // Cache the parameters
    {
        let mut cache = SETUP_CACHE.write().await;
        *cache = Some(params.clone());
    }
    
    info!("Setup parameters generated and cached");
    Ok(params)
}

/// Initialize with default parameters
pub async fn initialize() -> Result<SetupParams, String> {
    // k=10 for testing (2^10 = 1024 rows)
    // k=14 for production (2^14 = 16384 rows, higher security)
    #[cfg(test)]
    const DEFAULT_K: u32 = 10;
    
    #[cfg(not(test))]
    const DEFAULT_K: u32 = 14;
    
    initialize_with_k(DEFAULT_K).await
}

/// Clear the setup parameters cache
pub async fn clear_cache() {
    let mut cache = SETUP_CACHE.write().await;
    *cache = None;
    info!("Setup parameters cache cleared");
}

/// Check if setup parameters are cached
pub async fn is_initialized() -> bool {
    let cache = SETUP_CACHE.read().await;
    cache.is_some()
}

/// Production-ready proof generation with automatic initialization
pub async fn generate_proof_auto(
    hardware_info: &crate::hardware::HardwareInfo,
) -> Result<(Proof, Vec<u8>), String> {
    // Ensure system is initialized
    let params = if is_initialized().await {
        SETUP_CACHE.read().await.as_ref().unwrap().clone()
    } else {
        info!("Auto-initializing ZKP system");
        initialize().await?
    };
    
    // Generate commitment
    let commitment = hardware_info.generate_zkp_commitment();
    
    // Generate proof
    let proof = generate_hardware_proof(hardware_info, &commitment, &params).await?;
    
    Ok((proof, commitment))
}

/// Production-ready proof verification with automatic initialization
pub async fn verify_proof_auto(
    proof: &Proof,
    commitment: &[u8],
) -> Result<bool, String> {
    // Ensure system is initialized
    let params = if is_initialized().await {
        SETUP_CACHE.read().await.as_ref().unwrap().clone()
    } else {
        warn!("ZKP system not initialized for verification, initializing now");
        initialize().await?
    };
    
    verify_hardware_proof(proof, commitment, &params)
}

/// Re-export the generate_setup_params function for backward compatibility
pub use circuit::generate_setup_params;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_auto_initialization() {
        // Clear any existing cache
        clear_cache().await;
        
        assert!(!is_initialized().await);
        
        // First call should initialize
        let params1 = initialize().await.unwrap();
        assert!(is_initialized().await);
        
        // Second call should use cache
        let params2 = initialize().await.unwrap();
        
        // Both should have the same SRS
        assert_eq!(params1.srs.len(), params2.srs.len());
    }
    
    #[tokio::test]
    async fn test_concurrent_initialization() {
        clear_cache().await;
        
        // Launch multiple concurrent initialization attempts
        let handles: Vec<_> = (0..5)
            .map(|_| tokio::spawn(async { initialize().await }))
            .collect();
        
        // All should succeed without race conditions
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
        
        assert!(is_initialized().await);
    }
}
