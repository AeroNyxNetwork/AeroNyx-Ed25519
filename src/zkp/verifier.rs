// src/zkp/verifier.rs
// Zero-knowledge proof verification for hardware attestation

use tracing::{info, debug, warn, error};
use ed25519_dalek::{PublicKey, Signature, Verifier as Ed25519Verifier};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::zkp::{Proof, SetupParams};

/// Error types for proof verification
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("Invalid proof format: {0}")]
    InvalidFormat(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    
    #[error("Proof expired (age: {age_seconds}s, max: {max_age}s)")]
    ProofExpired { age_seconds: u64, max_age: u64 },
    
    #[error("Invalid proof version: {0}")]
    InvalidVersion(u8),
    
    #[error("Cryptographic verification failed")]
    CryptoVerificationFailed,
}

/// Proof data structure (must match prover)
#[derive(Serialize, Deserialize)]
struct HardwareProofData {
    version: u8,
    commitment: [u8; 32],
    challenge: [u8; 32],
    #[serde(with = "serde_bytes")]
    response: Vec<u8>,
    aux_data: ProofAuxData,
}

/// Auxiliary data included with proof
#[derive(Serialize, Deserialize)]
struct ProofAuxData {
    nonce: [u8; 32],
    blinding_factor: [u8; 32],
    timestamp: u64,
    metadata_hash: [u8; 32],
}

/// Verification statistics
#[derive(Debug, Default)]
pub struct VerificationStats {
    /// Total verifications attempted
    pub total_verifications: u64,
    /// Successful verifications
    pub successful_verifications: u64,
    /// Failed verifications
    pub failed_verifications: u64,
    /// Average verification time in microseconds
    pub avg_verification_time_us: u64,
}

/// Hardware verifier for verifying zero-knowledge proofs
pub struct HardwareVerifier {
    /// Setup parameters (verifying key)
    params: SetupParams,
    /// Maximum proof age in seconds
    max_proof_age: u64,
    /// Verification statistics
    stats: VerificationStats,
}

impl HardwareVerifier {
    /// Create a new hardware verifier
    pub fn new(params: SetupParams, max_proof_age: u64) -> Self {
        Self {
            params,
            max_proof_age,
            stats: VerificationStats::default(),
        }
    }
    
    /// Get verification statistics
    pub fn stats(&self) -> &VerificationStats {
        &self.stats
    }
    
    /// Verify a hardware attestation proof
    pub fn verify_proof(
        &mut self,
        proof: &Proof,
        commitment: &[u8],
    ) -> Result<bool, VerifierError> {
        let start_time = std::time::Instant::now();
        info!("Verifying zero-knowledge proof");
        
        self.stats.total_verifications += 1;
        
        // Validate inputs
        self.validate_inputs(proof, commitment)?;
        
        // Check proof age
        self.check_proof_freshness(proof)?;
        
        // Deserialize and validate proof data
        let proof_data = self.deserialize_proof(&proof.data)?;
        
        // Verify proof version
        if proof_data.version != 1 {
            return Err(VerifierError::InvalidVersion(proof_data.version));
        }
        
        // Verify commitment matches
        if proof_data.commitment != commitment {
            return Err(VerifierError::InvalidParameters(
                "Proof commitment doesn't match expected commitment".to_string()
            ));
        }
        
        // Perform cryptographic verification
        let is_valid = self.verify_proof_internal(&proof_data, commitment)?;
        
        // Update statistics
        let verification_time = start_time.elapsed();
        self.update_stats(is_valid, verification_time.as_micros() as u64);
        
        if is_valid {
            info!("Proof verified successfully in {:?}", verification_time);
        } else {
            warn!("Proof verification failed");
        }
        
        Ok(is_valid)
    }
    
    /// Validate proof inputs
    fn validate_inputs(&self, proof: &Proof, commitment: &[u8]) -> Result<(), VerifierError> {
        // Check proof data not empty
        if proof.data.is_empty() {
            return Err(VerifierError::InvalidFormat("Empty proof data".to_string()));
        }
        
        // Check commitment length
        if commitment.len() != 32 {
            return Err(VerifierError::InvalidParameters(
                format!("Invalid commitment length: expected 32, got {}", commitment.len())
            ));
        }
        
        // Verify public inputs match
        if proof.public_inputs != commitment {
            return Err(VerifierError::InvalidParameters(
                "Public inputs don't match expected commitment".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Check if proof is fresh enough
    fn check_proof_freshness(&self, proof: &Proof) -> Result<(), VerifierError> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let proof_age = current_time.saturating_sub(proof.timestamp);
        
        if proof_age > self.max_proof_age {
            return Err(VerifierError::ProofExpired {
                age_seconds: proof_age,
                max_age: self.max_proof_age,
            });
        }
        
        // Also check proof isn't from the future (clock skew tolerance)
        if proof.timestamp > current_time + 300 { // 5 minute tolerance
            return Err(VerifierError::InvalidParameters(
                "Proof timestamp is in the future".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Deserialize proof data with validation
    fn deserialize_proof(&self, proof_data: &[u8]) -> Result<HardwareProofData, VerifierError> {
        // Check minimum size
        if proof_data.len() < 200 { // Approximate minimum valid proof size
            return Err(VerifierError::InvalidFormat(
                format!("Proof too small: {} bytes", proof_data.len())
            ));
        }
        
        bincode::deserialize(proof_data)
            .map_err(|e| VerifierError::InvalidFormat(
                format!("Failed to deserialize proof: {}", e)
            ))
    }
    
    /// Internal proof verification
    fn verify_proof_internal(
        &self,
        proof_data: &HardwareProofData,
        commitment: &[u8],
    ) -> Result<bool, VerifierError> {
        debug!("Performing cryptographic verification");
        
        // Extract public key from verifying key
        let public_key = PublicKey::from_bytes(&self.params.verifying_key)
            .map_err(|e| VerifierError::InvalidParameters(
                format!("Invalid public key: {}", e)
            ))?;
        
        // Recreate challenge using same process as prover
        let challenge = self.compute_challenge(
            commitment,
            &proof_data.aux_data.nonce,
            &proof_data.aux_data.blinding_factor,
            &proof_data.aux_data.metadata_hash,
            &public_key.to_bytes()
        );
        
        // Verify challenge matches
        if challenge != proof_data.challenge {
            debug!("Challenge mismatch");
            return Ok(false);
        }
        
        // Verify signature
        if proof_data.response.len() != 64 {
            return Err(VerifierError::InvalidFormat("Invalid signature length".to_string()));
        }
        
        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&proof_data.response);
        let signature = Signature::from_bytes(&signature_bytes)
            .map_err(|e| VerifierError::InvalidFormat(
                format!("Invalid signature format: {}", e)
            ))?;
        
        match public_key.verify(&challenge, &signature) {
            Ok(_) => {
                debug!("Signature verification successful");
                
                // Additional validation: check aux data consistency
                if !self.validate_aux_data(&proof_data.aux_data) {
                    debug!("Auxiliary data validation failed");
                    return Ok(false);
                }
                
                Ok(true)
            }
            Err(e) => {
                debug!("Signature verification failed: {:?}", e);
                Ok(false)
            }
        }
    }
    
    /// Compute challenge (must match prover exactly)
    fn compute_challenge(
        &self,
        commitment: &[u8],
        nonce: &[u8; 32],
        blinding_factor: &[u8; 32],
        metadata_hash: &[u8; 32],
        public_key: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Domain separator (must match prover)
        hasher.update(b"AERONYX_ZKP_CHALLENGE_V1");
        
        // Include all public values in same order as prover
        hasher.update(commitment);
        hasher.update(nonce);
        hasher.update(metadata_hash);
        hasher.update(public_key);
        
        // Include blinding factor
        hasher.update(blinding_factor);
        
        let result = hasher.finalize();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&result);
        challenge
    }
    
    /// Validate auxiliary data
    fn validate_aux_data(&self, aux_data: &ProofAuxData) -> bool {
        // Check timestamp is reasonable
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let time_diff = if aux_data.timestamp > current_time {
            aux_data.timestamp - current_time
        } else {
            current_time - aux_data.timestamp
        };
        
        if time_diff > 86400 { // More than 24 hours difference
            warn!("Auxiliary data timestamp too far from current time");
            return false;
        }
        
        // Verify nonce is not all zeros (indicates proper randomness)
        if aux_data.nonce.iter().all(|&b| b == 0) {
            warn!("Invalid nonce (all zeros)");
            return false;
        }
        
        // Verify blinding factor is not all zeros
        if aux_data.blinding_factor.iter().all(|&b| b == 0) {
            warn!("Invalid blinding factor (all zeros)");
            return false;
        }
        
        true
    }
    
    /// Update verification statistics
    fn update_stats(&mut self, success: bool, verification_time_us: u64) {
        if success {
            self.stats.successful_verifications += 1;
        } else {
            self.stats.failed_verifications += 1;
        }
        
        // Update average verification time
        let total = self.stats.total_verifications;
        let old_avg = self.stats.avg_verification_time_us;
        self.stats.avg_verification_time_us = 
            (old_avg * (total - 1) + verification_time_us) / total;
    }
}

/// High-level function to verify hardware proof
pub fn verify_hardware_proof(
    proof: &Proof,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<bool, VerifierError> {
    let mut verifier = HardwareVerifier::new(params.clone(), 3600); // 1 hour max age
    verifier.verify_proof(proof, commitment)
}

/// Batch verification of multiple proofs (more efficient)
pub fn verify_hardware_proofs_batch(
    proofs: &[(Proof, Vec<u8>)], // (proof, commitment) pairs
    params: &SetupParams,
    max_proof_age: u64,
) -> Vec<Result<bool, VerifierError>> {
    let mut verifier = HardwareVerifier::new(params.clone(), max_proof_age);
    
    proofs.iter()
        .map(|(proof, commitment)| verifier.verify_proof(proof, commitment))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::circuit::HardwareCommitment;

    #[tokio::test]
    async fn test_proof_verification() {
        let params = crate::zkp::circuit::generate_setup_params().await.unwrap();
        
        // Create mock hardware and generate valid proof
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        let commitment = HardwareCommitment::from_hardware_info(&hw_info);
        
        let proof = crate::zkp::prover::generate_hardware_proof(
            &hw_info,
            &commitment.to_bytes(),
            &params
        ).await.unwrap();
        
        let result = verify_hardware_proof(&proof, &commitment.to_bytes(), &params);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_expired_proof() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![0; 32], // Valid length
        };
        
        let commitment = [1u8; 32];
        let proof = Proof {
            data: vec![0; 200], // Minimum size
            public_inputs: commitment.to_vec(),
            timestamp: 0, // Very old timestamp
        };
        
        let result = verify_hardware_proof(&proof, &commitment, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifierError::ProofExpired { .. }));
    }
    
    #[test]
    fn test_commitment_mismatch() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![0; 32],
        };
        
        let commitment = [1u8; 32];
        let wrong_commitment = [2u8; 32];
        let proof = Proof {
            data: vec![0; 200],
            public_inputs: commitment.to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let result = verify_hardware_proof(&proof, &wrong_commitment, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifierError::InvalidParameters(_)));
    }
    
    #[test]
    fn test_invalid_proof_size() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![0; 32],
        };
        
        let commitment = [1u8; 32];
        let proof = Proof {
            data: vec![0; 10], // Too small
            public_inputs: commitment.to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let result = verify_hardware_proof(&proof, &commitment, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifierError::InvalidFormat(_)));
    }
    
    #[test]
    fn test_future_proof() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![0; 32],
        };
        
        let commitment = [1u8; 32];
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600; // 1 hour in future
        
        let proof = Proof {
            data: vec![0; 200],
            public_inputs: commitment.to_vec(),
            timestamp: future_time,
        };
        
        let result = verify_hardware_proof(&proof, &commitment, &params);
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_batch_verification() {
        let params = crate::zkp::circuit::generate_setup_params().await.unwrap();
        
        // Create multiple proofs
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        let commitment = HardwareCommitment::from_hardware_info(&hw_info);
        
        let mut proofs = Vec::new();
        for _ in 0..3 {
            let proof = crate::zkp::prover::generate_hardware_proof(
                &hw_info,
                &commitment.to_bytes(),
                &params
            ).await.unwrap();
            proofs.push((proof, commitment.to_bytes()));
        }
        
        let results = verify_hardware_proofs_batch(&proofs, &params, 3600);
        
        assert_eq!(results.len(), 3);
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap());
        }
    }
}
