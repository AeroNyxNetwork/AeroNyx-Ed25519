//! Halo2 + Poseidon Zero-Knowledge Proof Module
//! 
//! This module implements zero-knowledge proofs for hardware attestation using:
//! - Halo2: A PLONK-based proof system with no trusted setup
//! - Poseidon: An algebraically efficient hash function
//! - Pasta curves: Pallas (base field) and Vesta (scalar field)
//!
//! The system proves knowledge of hardware information (CPU model, MAC address)
//! that hashes to a public commitment without revealing the actual hardware data.
//src/zkp_halo2/mod.rs
pub mod types;
pub mod circuit;
pub mod commitment;
pub mod prover;
pub mod verifier;

pub use types::{SetupParams, Proof, ProofType};
pub use commitment::PoseidonCommitment;
pub use prover::{generate_hardware_proof, HardwareProver};
pub use verifier::{verify_hardware_proof, HardwareVerifier};

use tracing::info;

/// Initialize the ZKP system and generate setup parameters
/// 
/// This creates the structured reference string (SRS) and verification keys
/// needed for proof generation and verification. The setup is deterministic
/// and doesn't require a trusted ceremony.
pub async fn initialize() -> Result<SetupParams, String> {
    info!("Initializing Halo2 ZKP system with Poseidon hash");
    
    // Generate setup parameters in a blocking task to avoid blocking the runtime
    tokio::task::spawn_blocking(|| {
        circuit::generate_setup_params()
    })
    .await
    .map_err(|e| format!("Failed to spawn setup task: {}", e))?
}
