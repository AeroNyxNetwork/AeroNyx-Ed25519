// src/zkp/verifier.rs
// Zero-knowledge proof verification for hardware attestation

use tracing::{info, debug};

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
    
    #[error("Proof expired")]
    ProofExpired,
}

/// Hardware verifier for verifying zero-knowledge proofs
pub struct HardwareVerifier {
    /// Setup parameters (verifying key)
    params: SetupParams,
    /// Maximum proof age in seconds
    max_proof_age: u64,
}

impl HardwareVerifier {
    /// Create a new hardware verifier
    pub fn new(params: SetupParams, max_proof_age: u64) -> Self {
        Self {
            params,
            max_proof_age,
        }
    }
    
    /// Verify a hardware attestation proof
    pub fn verify_proof(
        &self,
        proof: &Proof,
        commitment: &[u8],
    ) -> Result<bool, VerifierError> {
        info!("Verifying zero-knowledge proof");
        
        // Check proof age
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if current_time > proof.timestamp + self.max_proof_age {
            return Err(VerifierError::ProofExpired);
        }
        
        // Verify public inputs match
        if proof.public_inputs != commitment {
            return Err(VerifierError::InvalidParameters(
                "Public inputs don't match expected commitment".to_string()
            ));
        }
        
        // Verify proof format
        if proof.data.is_empty() {
            return Err(VerifierError::InvalidFormat("Empty proof data".to_string()));
        }
        
        // Perform verification
        let is_valid = self.verify_proof_internal(&proof.data, commitment)?;
        
        if is_valid {
            info!("Proof verified successfully");
        } else {
            info!("Proof verification failed");
        }
        
        Ok(is_valid)
    }
    
    /// Internal proof verification
    fn verify_proof_internal(
        &self,
        proof_data: &[u8],
        commitment: &[u8],
    ) -> Result<bool, VerifierError> {
        // In a real implementation, this would:
        // 1. Deserialize the verifying key from params.verifying_key
        // 2. Deserialize the proof from proof_data
        // 3. Verify the proof using Halo2's verification system
        
        // Placeholder implementation
        debug!("Verifying proof of {} bytes", proof_data.len());
        
        // Simulate verification (always returns true for valid format)
        if proof_data.len() >= 8 && commitment.len() == 32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// High-level function to verify hardware proof
pub fn verify_hardware_proof(
    proof: &Proof,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<bool, VerifierError> {
    let verifier = HardwareVerifier::new(params.clone(), 3600); // 1 hour max age
    verifier.verify_proof(proof, commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::circuit::HardwareCommitment;

    #[test]
    fn test_proof_verification() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![4, 5, 6],
        };
        
        let commitment = [1u8; 32];
        let proof = Proof {
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            public_inputs: commitment.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let result = verify_hardware_proof(&proof, &commitment, &params);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_expired_proof() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![4, 5, 6],
        };
        
        let commitment = [1u8; 32];
        let proof = Proof {
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            public_inputs: commitment.to_vec(),
            timestamp: 0, // Very old timestamp
        };
        
        let result = verify_hardware_proof(&proof, &commitment, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifierError::ProofExpired));
    }
    
    #[test]
    fn test_commitment_mismatch() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![4, 5, 6],
        };
        
        let commitment = [1u8; 32];
        let wrong_commitment = [2u8; 32];
        let proof = Proof {
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            public_inputs: commitment.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let result = verify_hardware_proof(&proof, &wrong_commitment, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VerifierError::InvalidParameters(_)));
    }
}
