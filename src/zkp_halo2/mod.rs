// src/zkp_halo2/mod.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Module
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Main entry point for the zero-knowledge proof subsystem.
// See module documentation below for detailed information.

pub mod types;
pub mod poseidon_hasher;
pub mod hardware_circuit;
pub mod commitment;
pub mod prover;
pub mod verifier;

pub use types::{SetupParams, Proof};
pub use prover::{generate_hardware_proof, generate_setup_params};
pub use verifier::verify_hardware_proof;

use tracing::info;

/// Initialize the ZKP system with specified security parameter
pub async fn initialize_with_k(k: u32) -> Result<SetupParams, String> {
    info!("Initializing production Halo2 ZKP system with k={}", k);
    
    tokio::task::spawn_blocking(move || {
        generate_setup_params(k)
    })
    .await
    .map_err(|e| format!("Failed to spawn setup task: {}", e))?
}

/// Initialize with default parameters
pub async fn initialize() -> Result<SetupParams, String> {
    initialize_with_k(14).await // Added .await
}
