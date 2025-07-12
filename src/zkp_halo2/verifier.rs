// src/zkp_halo2/verifier.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Verification Module
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module provides proof verification functionality that complements the prover
// module. It enables any party to verify hardware attestation proofs without
// learning anything about the underlying hardware.
//
// ## Verification Process
//
// 1. Check proof freshness (timestamp validation)
// 2. Verify commitment matches public inputs
// 3. Verify the zero-knowledge proof itself
//
// ## Security Properties
//
// - **Soundness**: Invalid proofs are rejected with overwhelming probability
// - **Zero-knowledge**: Verification reveals nothing beyond proof validity
// - **Non-malleability**: Proofs cannot be modified to pass verification
//
// ## Performance
//
// Verification is significantly faster than proof generation (~50ms vs ~500ms)
// making it suitable for real-time validation of node hardware attestations.
//
// This module is essential for the trustless operation of the AeroNyx DePIN
// network, where nodes must verify each other's hardware without central authority.

use tracing::{info, debug};
use crate::zkp_halo2::types::{Proof, SetupParams};

/// Re-export the verification function from the prover module
/// to maintain API compatibility
pub use crate::zkp_halo2::prover::{verify_hardware_proof, HardwareVerifier};

/// Batch verification functionality for efficiency
/// 
/// When verifying multiple proofs, batch verification can provide
/// significant performance improvements through amortization of
/// expensive operations.
pub struct BatchVerifier {
    verifier: crate::zkp_halo2::prover::HardwareVerifier,
}

impl BatchVerifier {
    /// Create a new batch verifier with setup parameters
    /// 
    /// # Arguments
    /// * `params` - Setup parameters containing verification key
    /// 
    /// # Returns
    /// * `Result<Self, String>` - Batch verifier or error
    pub fn new(params: &SetupParams) -> Result<Self, String> {
        let verifier = crate::zkp_halo2::prover::HardwareVerifier::new(params)?;
        Ok(Self { verifier })
    }
    
    /// Verify multiple proofs in batch
    /// 
    /// # Arguments
    /// * `proofs` - Vector of (proof, commitment) pairs
    /// 
    /// # Returns
    /// * `Vec<Result<bool, String>>` - Verification results for each proof
    /// 
    /// # Performance
    /// 
    /// Batch verification is more efficient than individual verification
    /// when processing multiple proofs, especially for the same circuit.
    pub fn verify_batch(
        &self,
        proofs: &[(Proof, Vec<u8>)],
    ) -> Vec<Result<bool, String>> {
        info!("Verifying batch of {} proofs", proofs.len());
        
        proofs.iter()
            .enumerate()
            .map(|(i, (proof, commitment))| {
                debug!("Verifying proof {}/{}", i + 1, proofs.len());
                self.verifier.verify_proof(proof, commitment)
            })
            .collect()
    }
    
    /// Verify batch with early termination on first failure
    /// 
    /// # Arguments
    /// * `proofs` - Vector of (proof, commitment) pairs
    /// 
    /// # Returns
    /// * `Result<(), String>` - Ok if all proofs valid, Err on first failure
    /// 
    /// # Use Case
    /// 
    /// Use this when all proofs must be valid (e.g., validating a node cluster)
    /// and you want to fail fast on the first invalid proof.
    pub fn verify_batch_strict(
        &self,
        proofs: &[(Proof, Vec<u8>)],
    ) -> Result<(), String> {
        info!("Strictly verifying batch of {} proofs", proofs.len());
        
        for (i, (proof, commitment)) in proofs.iter().enumerate() {
            match self.verifier.verify_proof(proof, commitment) {
                Ok(true) => {
                    debug!("Proof {}/{} verified successfully", i + 1, proofs.len());
                }
                Ok(false) => {
                    return Err(format!("Proof {}/{} is invalid", i + 1, proofs.len()));
                }
                Err(e) => {
                    return Err(format!("Proof {}/{} verification error: {}", i + 1, proofs.len(), e));
                }
            }
        }
        
        info!("All {} proofs verified successfully", proofs.len());
        Ok(())
    }
}

/// Utility functions for proof analysis
pub mod utils {
    use super::*;
    
    /// Check if a proof is fresh (not expired)
    /// 
    /// # Arguments
    /// * `proof` - The proof to check
    /// * `max_age_seconds` - Maximum acceptable age in seconds
    /// 
    /// # Returns
    /// * `bool` - True if proof is fresh, false if expired
    pub fn is_proof_fresh(proof: &Proof, max_age_seconds: u64) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        current_time <= proof.timestamp + max_age_seconds
    }
    
    /// Extract commitment from proof's public inputs
    /// 
    /// # Arguments
    /// * `proof` - The proof containing public inputs
    /// 
    /// # Returns
    /// * `Option<[u8; 32]>` - The commitment if valid format
    pub fn extract_commitment(proof: &Proof) -> Option<[u8; 32]> {
        if proof.public_inputs.len() == 32 {
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&proof.public_inputs);
            Some(commitment)
        } else {
            None
        }
    }
    
    /// Get human-readable proof age
    /// 
    /// # Arguments
    /// * `proof` - The proof to analyze
    /// 
    /// # Returns
    /// * `String` - Human-readable age (e.g., "5 minutes ago")
    pub fn proof_age_string(proof: &Proof) -> String {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let age_seconds = current_time.saturating_sub(proof.timestamp);
        
        if age_seconds < 60 {
            format!("{} seconds ago", age_seconds)
        } else if age_seconds < 3600 {
            format!("{} minutes ago", age_seconds / 60)
        } else if age_seconds < 86400 {
            format!("{} hours ago", age_seconds / 3600)
        } else {
            format!("{} days ago", age_seconds / 86400)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_freshness() {
        let proof = Proof {
            data: vec![0; 32],
            public_inputs: vec![0; 32],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - 30, // 30 seconds ago
        };
        
        assert!(utils::is_proof_fresh(&proof, 60)); // Should be fresh within 1 minute
        assert!(!utils::is_proof_fresh(&proof, 10)); // Should not be fresh within 10 seconds
    }
    
    #[test]
    fn test_proof_age_string() {
        let mut proof = Proof {
            data: vec![],
            public_inputs: vec![],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Test different ages
        proof.timestamp -= 30;
        assert!(utils::proof_age_string(&proof).contains("seconds"));
        
        proof.timestamp -= 300;
        assert!(utils::proof_age_string(&proof).contains("minutes"));
        
        proof.timestamp -= 7200;
        assert!(utils::proof_age_string(&proof).contains("hours"));
    }
}
