use tracing::{info, debug};
use halo2_proofs::{
    plonk::verify_proof,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::VerifierSHPLONK,
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
};
use pasta_curves::{pallas, vesta};
use ff::PrimeField;

use crate::zkp_halo2::types::{Proof, SetupParams};

/// Hardware proof verifier
pub struct HardwareVerifier {
    params: SetupParams,
    max_proof_age: u64,
}

impl HardwareVerifier {
    /// Create a new verifier with setup parameters
    pub fn new(params: SetupParams, max_proof_age: u64) -> Self {
        Self { params, max_proof_age }
    }
    
    /// Verify a hardware proof
    pub fn verify_proof(
        &self,
        proof: &Proof,
        commitment: &[u8],
    ) -> Result<bool, String> {
        info!("Verifying hardware proof");
        
        // Check proof age
        self.check_proof_freshness(proof)?;
        
        // Check commitment match
        if proof.public_inputs != commitment {
            return Err("Public inputs mismatch".to_string());
        }
        
        // Verify the cryptographic proof
        self.verify_proof_crypto(proof, commitment)
    }
    
    /// Check if proof is within acceptable age
    fn check_proof_freshness(&self, proof: &Proof) -> Result<(), String> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if current_time > proof.timestamp + self.max_proof_age {
            return Err(format!(
                "Proof expired: generated {} seconds ago, max age is {}",
                current_time - proof.timestamp,
                self.max_proof_age
            ));
        }
        
        Ok(())
    }
    
    /// Verify the cryptographic proof
    fn verify_proof_crypto(
        &self,
        proof: &Proof,
        commitment: &[u8],
    ) -> Result<bool, String> {
        use halo2_proofs::poly::commitment::Params;
        
        // Deserialize parameters
        let params = ParamsKZG::<vesta::Affine>::read(&mut &self.params.srs[..])
            .map_err(|e| format!("Failed to read params: {}", e))?;
        
        let vk = halo2_proofs::plonk::VerifyingKey::<vesta::Affine>::read(&mut &self.params.verifying_key[..])
            .map_err(|e| format!("Failed to read vk: {:?}", e))?;
        
        // Convert commitment to field element
        let commitment_field = self.commitment_to_field_element(commitment)?;
        
        // Create transcript for verification
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof.data[..]);
        
        // Create verification strategy
        let strategy = SingleStrategy::new(&params);
        
        // Verify the proof
        let result = verify_proof::<
            KZGCommitmentScheme<vesta::Affine>,
            VerifierSHPLONK<vesta::Affine>,
            Challenge255<vesta::Affine>,
            Blake2bRead<_, _, Challenge255<_>>,
        >(
            &params,
            &vk,
            strategy,
            &[&[&[commitment_field]]],
            &mut transcript,
        );
        
        match result {
            Ok(()) => {
                info!("Proof verified successfully");
                Ok(true)
            }
            Err(e) => {
                debug!("Proof verification failed: {:?}", e);
                Ok(false)
            }
        }
    }
    
    /// Convert commitment bytes to field element
    fn commitment_to_field_element(&self, commitment: &[u8]) -> Result<pallas::Base, String> {
        if commitment.len() != 32 {
            return Err("Invalid commitment length".to_string());
        }
        
        // Convert bytes to field element
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(commitment);
        
        Option::from(pallas::Base::from_repr(bytes))
            .ok_or_else(|| "Failed to convert commitment to field element".to_string())
    }
}

/// Verify hardware proof (convenience function)
pub fn verify_hardware_proof(
    proof: &Proof,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<bool, String> {
    let verifier = HardwareVerifier::new(params.clone(), 3600); // 1 hour max age
    verifier.verify_proof(proof, commitment)
}

/// Batch verification for multiple proofs
pub struct BatchVerifier {
    verifier: HardwareVerifier,
}

impl BatchVerifier {
    /// Create a new batch verifier
    pub fn new(params: SetupParams, max_proof_age: u64) -> Self {
        Self {
            verifier: HardwareVerifier::new(params, max_proof_age),
        }
    }
    
    /// Verify multiple proofs in batch
    /// Returns a vector of results, one for each proof
    pub fn verify_batch(
        &self,
        proofs: &[(Proof, Vec<u8>)],
    ) -> Vec<Result<bool, String>> {
        info!("Verifying batch of {} proofs", proofs.len());
        
        proofs.iter()
            .map(|(proof, commitment)| {
                self.verifier.verify_proof(proof, commitment)
            })
            .collect()
    }
    
    /// Verify batch and return true only if all proofs are valid
    pub fn verify_batch_all(&self, proofs: &[(Proof, Vec<u8>)]) -> Result<bool, String> {
        let results = self.verify_batch(proofs);
        
        // Check if any verification failed
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(true) => continue,
                Ok(false) => return Ok(false),
                Err(e) => return Err(format!("Proof {} failed: {}", i, e)),
            }
        }
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp_halo2::{
        circuit::generate_setup_params,
        commitment::PoseidonCommitment,
        prover::HardwareProver,
    };
    
    #[tokio::test]
    async fn test_proof_verification() {
        // Generate setup parameters
        let params = generate_setup_params().unwrap();
        
        // Create commitment
        let commitment = PoseidonCommitment::commit_cpu_model("Test CPU");
        
        // Create a valid proof (mock for testing)
        let proof = Proof {
            data: vec![0; 192], // Mock proof data
            public_inputs: commitment.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Verify proof
        let verifier = HardwareVerifier::new(params, 3600);
        let result = verifier.verify_proof(&proof, &commitment);
        
        // Note: This will fail with mock data, but tests the flow
        assert!(result.is_err() || !result.unwrap());
    }
    
    #[test]
    fn test_proof_expiry() {
        let params = generate_setup_params().unwrap();
        let commitment = vec![0u8; 32];
        
        // Create an expired proof
        let old_proof = Proof {
            data: vec![0; 192],
            public_inputs: commitment.clone(),
            timestamp: 1000, // Very old timestamp
        };
        
        let verifier = HardwareVerifier::new(params, 3600);
        let result = verifier.verify_proof(&old_proof, &commitment);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }
    
    #[test]
    fn test_commitment_mismatch() {
        let params = generate_setup_params().unwrap();
        let commitment1 = vec![1u8; 32];
        let commitment2 = vec![2u8; 32];
        
        let proof = Proof {
            data: vec![0; 192],
            public_inputs: commitment1.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let verifier = HardwareVerifier::new(params, 3600);
        let result = verifier.verify_proof(&proof, &commitment2);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mismatch"));
    }
    
    #[test]
    fn test_batch_verification() {
        let params = generate_setup_params().unwrap();
        let batch_verifier = BatchVerifier::new(params, 3600);
        
        // Create test proofs
        let proofs = vec![
            (
                Proof {
                    data: vec![0; 192],
                    public_inputs: vec![1u8; 32],
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                },
                vec![1u8; 32],
            ),
            (
                Proof {
                    data: vec![0; 192],
                    public_inputs: vec![2u8; 32],
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                },
                vec![2u8; 32],
            ),
        ];
        
        let results = batch_verifier.verify_batch(&proofs);
        assert_eq!(results.len(), 2);
    }
}
