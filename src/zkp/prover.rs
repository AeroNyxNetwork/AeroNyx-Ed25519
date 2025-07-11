// src/zkp/prover.rs
// Zero-knowledge proof generation for hardware attestation

use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task;
use tracing::{info, debug, error};

use crate::hardware::HardwareInfo;
use crate::zkp::{circuit::{HardwareCircuit, HardwareCommitment}, Proof, SetupParams};

/// Error types for proof generation
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Circuit synthesis error: {0}")]
    CircuitSynthesis(String),
    
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),
    
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}

/// Hardware prover for generating zero-knowledge proofs
pub struct HardwareProver {
    /// Setup parameters (proving key)
    params: SetupParams,
}

impl HardwareProver {
    /// Create a new hardware prover
    pub fn new(params: SetupParams) -> Self {
        Self { params }
    }
    
    /// Generate a proof for hardware attestation
    pub async fn generate_proof(
        &self,
        hardware_info: &HardwareInfo,
        commitment: &[u8],
    ) -> Result<Proof, ProverError> {
        info!("Generating zero-knowledge proof for hardware attestation");
        
        // Serialize hardware info
        let hardware_data = self.serialize_hardware_info(hardware_info)?;
        debug!("Hardware data serialized: {} bytes", hardware_data.len());
        
        // Verify commitment matches
        let computed_commitment = HardwareCommitment::from_hardware_info(hardware_info);
        if computed_commitment.to_bytes() != commitment {
            return Err(ProverError::InvalidParameters(
                "Commitment mismatch - hardware info doesn't match provided commitment".to_string()
            ));
        }
        
        // Convert commitment to correct format
        let mut commitment_array = [0u8; 32];
        commitment_array.copy_from_slice(&commitment[..32]);
        
        // Create circuit
        let circuit = HardwareCircuit::new(hardware_data, commitment_array);
        
        // Generate proof in blocking task (CPU intensive)
        let params_clone = self.params.clone();
        let proof_data = task::spawn_blocking(move || {
            Self::generate_proof_blocking(circuit, params_clone)
        })
        .await
        .map_err(|e| ProverError::ProofGeneration(format!("Task join error: {}", e)))?
        .map_err(|e| ProverError::ProofGeneration(e))?;
        
        // Create proof structure
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let proof = Proof {
            data: proof_data,
            public_inputs: commitment.to_vec(),
            timestamp,
        };
        
        info!("Zero-knowledge proof generated successfully");
        Ok(proof)
    }
    
    /// Serialize hardware info for circuit input
    fn serialize_hardware_info(&self, hw_info: &HardwareInfo) -> Result<Vec<u8>, ProverError> {
        bincode::serialize(hw_info)
            .map_err(|e| ProverError::Serialization(format!("Failed to serialize hardware info: {}", e)))
    }
    
    /// Generate proof (blocking implementation)
    fn generate_proof_blocking(
        circuit: HardwareCircuit,
        params: SetupParams,
    ) -> Result<Vec<u8>, String> {
        // In a real implementation, this would:
        // 1. Deserialize the proving key from params.proving_key
        // 2. Create a proof using Halo2's proving system
        // 3. Serialize the proof to bytes
        
        // Placeholder implementation
        info!("Generating proof (this is CPU intensive)...");
        
        // Simulate CPU-intensive work
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        // Return dummy proof data
        Ok(vec![1, 2, 3, 4, 5, 6, 7, 8])
    }
}

/// High-level function to generate hardware proof
pub async fn generate_hardware_proof(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, ProverError> {
    let prover = HardwareProver::new(params.clone());
    prover.generate_proof(hardware_info, commitment).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proof_generation() {
        // Initialize with mock parameters
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![4, 5, 6],
        };
        
        // Create mock hardware info
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        
        // Generate commitment
        let commitment = HardwareCommitment::from_hardware_info(&hw_info);
        
        // Generate proof
        let result = generate_hardware_proof(
            &hw_info,
            &commitment.to_bytes(),
            &params
        ).await;
        
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert!(!proof.data.is_empty());
        assert_eq!(proof.public_inputs, commitment.to_bytes());
    }
    
    #[tokio::test]
    async fn test_commitment_mismatch() {
        let params = SetupParams {
            proving_key: vec![1, 2, 3],
            verifying_key: vec![4, 5, 6],
        };
        
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        
        // Use wrong commitment
        let wrong_commitment = vec![0u8; 32];
        
        let result = generate_hardware_proof(
            &hw_info,
            &wrong_commitment,
            &params
        ).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ProverError::InvalidParameters(_)));
    }
}
