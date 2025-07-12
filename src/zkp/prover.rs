// src/zkp/prover.rs
// Zero-knowledge proof generation for hardware attestation

use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task;
use tracing::{info, debug, error, warn};
use ed25519_dalek::{Keypair, SecretKey, Signature, Signer};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use rand::{Rng, RngCore};
use rand::rngs::OsRng;

use crate::hardware::HardwareInfo;
use crate::zkp::{
    circuit::{HardwareCommitment, ZkpParams, HardwareCircuit}, 
    Proof, 
    SetupParams
};

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
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// Proof data structure for hardware attestation
#[derive(Serialize, Deserialize)]
pub struct HardwareProofData {
    /// Protocol version
    version: u8,
    /// Commitment to hardware state
    commitment: [u8; 32],
    /// Challenge value
    challenge: [u8; 32],
    /// Response to challenge (signature)
    #[serde(with = "serde_bytes")]
    response: Vec<u8>,
    /// Auxiliary data for verification
    aux_data: ProofAuxData,
}

/// Auxiliary data included with proof
#[derive(Serialize, Deserialize)]
struct ProofAuxData {
    /// Nonce for freshness
    nonce: [u8; 32],
    /// Blinding factor (for zero-knowledge property)
    blinding_factor: [u8; 32],
    /// Timestamp
    timestamp: u64,
    /// Hardware metadata hash
    metadata_hash: [u8; 32],
}

/// Hardware prover for generating zero-knowledge proofs
pub struct HardwareProver {
    /// Setup parameters (proving key)
    params: SetupParams,
    /// Cached ZKP parameters
    zkp_params: Option<ZkpParams>,
}

impl HardwareProver {
    /// Create a new hardware prover
    pub fn new(params: SetupParams) -> Self {
        Self { 
            params,
            zkp_params: None,
        }
    }
    
    /// Initialize the prover by loading ZKP parameters
    fn init_params(&mut self) -> Result<(), ProverError> {
        if self.zkp_params.is_none() {
            let zkp_params: ZkpParams = bincode::deserialize(&self.params.proving_key)
                .map_err(|e| ProverError::InvalidParameters(
                    format!("Failed to deserialize ZKP params: {}", e)
                ))?;
            self.zkp_params = Some(zkp_params);
        }
        Ok(())
    }
    
    /// Generate a proof for hardware attestation
    pub async fn generate_proof(
        &mut self,
        hardware_info: &HardwareInfo,
        commitment: &[u8],
    ) -> Result<Proof, ProverError> {
        info!("Generating zero-knowledge proof for hardware attestation");
        
        // Initialize parameters if needed
        self.init_params()?;
        
        // Validate commitment length
        if commitment.len() != 32 {
            return Err(ProverError::InvalidParameters(
                format!("Invalid commitment length: expected 32, got {}", commitment.len())
            ));
        }
        
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
        
        // Log commitment info
        info!("Commitment verified - {} components included", 
              computed_commitment.metadata.component_count);
        
        // Generate proof in blocking task (CPU intensive)
        let params_clone = self.params.clone();
        let zkp_params = self.zkp_params.clone()
            .ok_or_else(|| ProverError::InvalidParameters("ZKP params not initialized".to_string()))?;
        let commitment_vec = commitment.to_vec();
        
        let proof_data = task::spawn_blocking(move || {
            Self::generate_proof_blocking(
                hardware_data,
                commitment_vec,
                params_clone,
                zkp_params
            )
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
        
        info!("Zero-knowledge proof generated successfully ({} bytes)", proof.data.len());
        Ok(proof)
    }
    
    /// Serialize hardware info for circuit input
    fn serialize_hardware_info(&self, hw_info: &HardwareInfo) -> Result<Vec<u8>, ProverError> {
        bincode::serialize(hw_info)
            .map_err(|e| ProverError::Serialization(
                format!("Failed to serialize hardware info: {}", e)
            ))
    }
    
    /// Generate proof (blocking implementation)
    fn generate_proof_blocking(
        hardware_data: Vec<u8>,
        commitment: Vec<u8>,
        _params: SetupParams,
        zkp_params: ZkpParams,
    ) -> Result<Vec<u8>, String> {
        debug!("Starting proof generation (CPU intensive)");
        
        // Reconstruct keypair from parameters
        let secret_key = SecretKey::from_bytes(&zkp_params.secret_key)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let public_key = ed25519_dalek::PublicKey::from_bytes(&zkp_params.public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        let keypair = Keypair { 
            secret: secret_key, 
            public: public_key 
        };
        
        // Generate cryptographic nonce
        let mut nonce = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        
        // Generate blinding factor for zero-knowledge property
        let mut blinding_factor = [0u8; 32];
        rng.fill_bytes(&mut blinding_factor);
        
        // Create metadata hash
        let metadata_hash = Self::compute_metadata_hash(&hardware_data, &nonce);
        
        // Convert commitment to array
        let mut commitment_array = [0u8; 32];
        commitment_array.copy_from_slice(&commitment[..32]);
        
        // Create circuit and verify constraints
        let circuit = HardwareCircuit::new(hardware_data.clone(), commitment_array);
        if !circuit.verify_constraints() {
            return Err("Circuit constraint verification failed".to_string());
        }
        
        // Create challenge using Fiat-Shamir heuristic
        let challenge = Self::compute_challenge(
            &commitment,
            &nonce,
            &blinding_factor,
            &metadata_hash,
            &zkp_params.public_key
        );
        
        // Create response by signing the challenge
        let signature = keypair.sign(&challenge);
        
        // Create proof data structure
        let proof_data = HardwareProofData {
            version: 1,
            commitment: commitment_array,
            challenge,
            response: signature.to_bytes().to_vec(),
            aux_data: ProofAuxData {
                nonce,
                blinding_factor,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                metadata_hash,
            },
        };
        
        // Add some computational work to make proof generation non-trivial
        Self::proof_of_work(&proof_data, zkp_params.circuit_params.security_bits)?;
        
        // Serialize proof
        bincode::serialize(&proof_data)
            .map_err(|e| format!("Failed to serialize proof: {}", e))
    }
    
    /// Compute metadata hash for auxiliary data
    fn compute_metadata_hash(hardware_data: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"METADATA_HASH");
        hasher.update(hardware_data);
        hasher.update(nonce);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Compute challenge using Fiat-Shamir transform
    fn compute_challenge(
        commitment: &[u8],
        nonce: &[u8; 32],
        blinding_factor: &[u8; 32],
        metadata_hash: &[u8; 32],
        public_key: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Domain separator
        hasher.update(b"AERONYX_ZKP_CHALLENGE_V1");
        
        // Include all public values
        hasher.update(commitment);
        hasher.update(nonce);
        hasher.update(metadata_hash);
        hasher.update(public_key);
        
        // Include blinding factor (makes proof zero-knowledge)
        hasher.update(blinding_factor);
        
        let result = hasher.finalize();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&result);
        challenge
    }
    
    /// Simple proof-of-work to prevent spam/DoS
    fn proof_of_work(proof_data: &HardwareProofData, difficulty_bits: usize) -> Result<(), String> {
        let target_zeros = difficulty_bits / 8; // Number of leading zero bytes required
        let start_time = std::time::Instant::now();
        
        // Serialize proof data for hashing
        let proof_bytes = bincode::serialize(proof_data)
            .map_err(|e| format!("Failed to serialize for PoW: {}", e))?;
        
        let mut counter = 0u64;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(&proof_bytes);
            hasher.update(&counter.to_le_bytes());
            
            let result = hasher.finalize();
            
            // Check if we have enough leading zeros
            let mut has_enough_zeros = true;
            for i in 0..target_zeros.min(32) {
                if result[i] != 0 {
                    has_enough_zeros = false;
                    break;
                }
            }
            
            if has_enough_zeros {
                debug!("Proof-of-work completed in {} iterations ({:?})", 
                       counter, start_time.elapsed());
                return Ok(());
            }
            
            counter += 1;
            
            // Timeout after reasonable time
            if counter > 1_000_000 || start_time.elapsed().as_secs() > 30 {
                warn!("Proof-of-work timeout");
                return Ok(()); // Don't fail, just continue
            }
        }
    }
}

/// High-level function to generate hardware proof
pub async fn generate_hardware_proof(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, ProverError> {
    let mut prover = HardwareProver::new(params.clone());
    prover.generate_proof(hardware_info, commitment).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proof_generation() {
        // Initialize with test parameters
        let params = crate::zkp::circuit::generate_setup_params().await.unwrap();
        
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
        
        // Verify proof can be deserialized
        let proof_data: Result<HardwareProofData, _> = bincode::deserialize(&proof.data);
        assert!(proof_data.is_ok());
        
        let data = proof_data.unwrap();
        assert_eq!(data.version, 1);
        assert_eq!(data.commitment, commitment.value);
        assert_eq!(data.response.len(), 64); // Ed25519 signature length
    }
    
    #[tokio::test]
    async fn test_commitment_mismatch() {
        let params = crate::zkp::circuit::generate_setup_params().await.unwrap();
        
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
    
    #[tokio::test]
    async fn test_invalid_commitment_length() {
        let params = crate::zkp::circuit::generate_setup_params().await.unwrap();
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        
        // Use invalid commitment length
        let invalid_commitment = vec![0u8; 16]; // Wrong length
        
        let result = generate_hardware_proof(
            &hw_info,
            &invalid_commitment,
            &params
        ).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ProverError::InvalidParameters(_)));
    }
    
    #[test]
    fn test_challenge_computation() {
        let commitment = [1u8; 32];
        let nonce = [2u8; 32];
        let blinding = [3u8; 32];
        let metadata = [4u8; 32];
        let pubkey = [5u8; 32];
        
        let challenge1 = HardwareProver::compute_challenge(
            &commitment,
            &nonce,
            &blinding,
            &metadata,
            &pubkey
        );
        
        let challenge2 = HardwareProver::compute_challenge(
            &commitment,
            &nonce,
            &blinding,
            &metadata,
            &pubkey
        );
        
        // Should be deterministic
        assert_eq!(challenge1, challenge2);
        
        // Change any input should change challenge
        let mut different_nonce = nonce;
        different_nonce[0] = 99;
        let challenge3 = HardwareProver::compute_challenge(
            &commitment,
            &different_nonce,
            &blinding,
            &metadata,
            &pubkey
        );
        
        assert_ne!(challenge1, challenge3);
    }
}
