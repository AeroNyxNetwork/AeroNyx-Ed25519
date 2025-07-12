// src/zkp_halo2/prover.rs
// Fixed version for halo2_proofs 0.3.0

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use ff::PrimeField;
use pasta_curves::{pallas, vesta};
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof,
        ProvingKey, VerifyingKey, SingleVerifier,
    },
    poly::{
        commitment::{Params, ParamsProver, Prover, Verifier},
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptRead, TranscriptWrite,
    },
};
use rand::rngs::OsRng;

use crate::zkp_halo2::{
    hardware_circuit::{HardwareAttestationCircuit, compute_expected_commitment},
    types::{Proof, SetupParams},
};

/// Generate setup parameters for the ZKP system
pub fn generate_setup_params(k: u32) -> Result<SetupParams, String> {
    info!("Generating Halo2 setup parameters with k={}", k);
    
    // Generate IPA parameters (no trusted setup needed)
    let params = ParamsIPA::<vesta::Affine>::new(k);
    
    // Create a dummy circuit for key generation
    let empty_circuit = HardwareAttestationCircuit::new("dummy", "00:00:00:00:00:00");
    
    // Generate verification key
    let vk = keygen_vk(&params, &empty_circuit)
        .map_err(|e| format!("Failed to generate verification key: {:?}", e))?;
    
    // Generate proving key
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit)
        .map_err(|e| format!("Failed to generate proving key: {:?}", e))?;
    
    // Serialize parameters
    let srs_bytes = bincode::serialize(&params)
        .map_err(|e| format!("Failed to serialize params: {:?}", e))?;
    
    let vk_bytes = bincode::serialize(&vk)
        .map_err(|e| format!("Failed to serialize VK: {:?}", e))?;
    
    let pk_bytes = bincode::serialize(&pk)
        .map_err(|e| format!("Failed to serialize PK: {:?}", e))?;
    
    Ok(SetupParams {
        srs: srs_bytes,
        verifying_key: vk_bytes,
        proving_key: Some(pk_bytes),
    })
}

/// Hardware proof generator
pub struct HardwareProver {
    params: ParamsIPA<vesta::Affine>,
    pk: ProvingKey<vesta::Affine>,
}

impl HardwareProver {
    /// Create a new prover from setup parameters
    pub fn new(setup: &SetupParams) -> Result<Self, String> {
        // Deserialize parameters
        let params: ParamsIPA<vesta::Affine> = bincode::deserialize(&setup.srs)
            .map_err(|e| format!("Failed to deserialize params: {:?}", e))?;
        
        // Deserialize proving key
        let pk_bytes = setup.proving_key.as_ref()
            .ok_or("Proving key not found in setup parameters")?;
        
        let pk: ProvingKey<vesta::Affine> = bincode::deserialize(pk_bytes)
            .map_err(|e| format!("Failed to deserialize proving key: {:?}", e))?;
        
        Ok(Self { params, pk })
    }
    
    /// Generate a proof for hardware information
    pub fn generate_proof(
        &self,
        hardware_info: &HardwareInfo,
        commitment: &[u8],
    ) -> Result<Proof, String> {
        info!("Generating zero-knowledge proof for hardware attestation");
        
        // Extract hardware data
        let cpu_model = &hardware_info.cpu.model;
        let mac_address = hardware_info.network.interfaces
            .iter()
            .find(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
            .map(|iface| &iface.mac_address)
            .ok_or("No physical network interface found")?;
        
        // Verify commitment matches
        let expected_commitment = compute_expected_commitment(cpu_model, mac_address);
        let expected_bytes = expected_commitment.to_bytes();
        
        if commitment.len() != 32 || &expected_bytes[..] != commitment {
            return Err("Commitment mismatch - hardware may have changed".to_string());
        }
        
        // Create circuit
        let circuit = HardwareAttestationCircuit::new(cpu_model, mac_address);
        
        // Create proof
        let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
        
        create_proof::<
            IPACommitmentScheme<vesta::Affine>,
            ProverIPA<'_, vesta::Affine>,
            Challenge255<vesta::Affine>,
            _,
            Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>,
        >(
            &self.params,
            &self.pk,
            &[circuit],
            &[&[&[expected_commitment]]],
            OsRng,
            &mut transcript,
        )
        .map_err(|e| format!("Failed to create proof: {:?}", e))?;
        
        let proof_bytes = transcript.finalize();
        
        Ok(Proof {
            data: proof_bytes,
            public_inputs: commitment.to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

/// Hardware proof verifier
pub struct HardwareVerifier {
    params: ParamsIPA<vesta::Affine>,
    vk: VerifyingKey<vesta::Affine>,
}

impl HardwareVerifier {
    /// Create a new verifier from setup parameters
    pub fn new(setup: &SetupParams) -> Result<Self, String> {
        // Deserialize parameters
        let params: ParamsIPA<vesta::Affine> = bincode::deserialize(&setup.srs)
            .map_err(|e| format!("Failed to deserialize params: {:?}", e))?;
        
        // Deserialize verification key
        let vk: VerifyingKey<vesta::Affine> = bincode::deserialize(&setup.verifying_key)
            .map_err(|e| format!("Failed to deserialize verification key: {:?}", e))?;
        
        Ok(Self { params, vk })
    }
    
    /// Verify a hardware proof
    pub fn verify_proof(
        &self,
        proof: &Proof,
        commitment: &[u8],
    ) -> Result<bool, String> {
        info!("Verifying zero-knowledge proof");
        
        // Check proof age
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        const MAX_PROOF_AGE: u64 = 3600; // 1 hour
        if current_time > proof.timestamp + MAX_PROOF_AGE {
            return Err(format!(
                "Proof expired: generated {} seconds ago, max age is {}",
                current_time - proof.timestamp,
                MAX_PROOF_AGE
            ));
        }
        
        // Check commitment match
        if proof.public_inputs != commitment {
            return Err("Public inputs mismatch".to_string());
        }
        
        // Parse commitment as field element
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(commitment);
        let commitment_fe = pallas::Base::from_bytes(&commitment_bytes)
            .ok_or("Invalid commitment format")?;
        
        // Create transcript for verification
        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof.data[..]);
        
        // Verify proof
        let strategy = SingleStrategy::new(&self.params);
        let result = verify_proof::<
            IPACommitmentScheme<vesta::Affine>,
            VerifierIPA<'_, vesta::Affine>,
            Challenge255<vesta::Affine>,
            Blake2bRead<&[u8], vesta::Affine, Challenge255<vesta::Affine>>,
        >(
            &self.params,
            &self.vk,
            strategy,
            &[&[&[commitment_fe]]],
            &mut transcript,
        );
        
        match result {
            Ok(()) => {
                info!("Proof verified successfully");
                Ok(true)
            }
            Err(e) => {
                info!("Proof verification failed: {:?}", e);
                Ok(false)
            }
        }
    }
}

/// Generate hardware proof (convenience function)
pub async fn generate_hardware_proof(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, String> {
    let hw_clone = hardware_info.clone();
    let commitment_vec = commitment.to_vec();
    let params_clone = params.clone();
    
    tokio::task::spawn_blocking(move || {
        let prover = HardwareProver::new(&params_clone)?;
        prover.generate_proof(&hw_clone, &commitment_vec)
    })
    .await
    .map_err(|e| format!("Failed to spawn proof generation task: {}", e))?
}

/// Verify hardware proof (convenience function)
pub fn verify_hardware_proof(
    proof: &Proof,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<bool, String> {
    let verifier = HardwareVerifier::new(params)?;
    verifier.verify_proof(proof, commitment)
}
