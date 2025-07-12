// src/zkp_halo2/prover.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Generation and Verification
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module provides the proof generation and verification functionality for
// hardware attestation in the AeroNyx DePIN network.

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use ff::PrimeField;
use pasta_curves::{pallas, vesta};
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof,
        ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255,
    },
};
use rand::rngs::OsRng;

use crate::hardware::HardwareInfo;
use crate::zkp_halo2::{
    hardware_circuit::{HardwareAttestationCircuit, compute_expected_commitment},
    types::{Proof, SetupParams},
};

/// Generate setup parameters for the ZKP system
pub fn generate_setup_params(k: u32) -> Result<SetupParams, String> {
    info!("Generating Halo2 setup parameters with k={}", k);
    
    // Generate KZG parameters
    let params = ParamsKZG::<vesta::Affine>::setup(k, OsRng);
    
    // Create a dummy circuit for key generation
    let empty_circuit = HardwareAttestationCircuit::new("dummy", "00:00:00:00:00:00");
    
    // Generate verification key
    let vk = keygen_vk(&params, &empty_circuit)
        .map_err(|e| format!("Failed to generate verification key: {:?}", e))?;
    
    // Generate proving key
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit)
        .map_err(|e| format!("Failed to generate proving key: {:?}", e))?;
    
    // Serialize parameters
    let mut srs_bytes = Vec::new();
    params.write(&mut srs_bytes)
        .map_err(|e| format!("Failed to serialize SRS: {:?}", e))?;
    
    // For vk and pk, we'll store them as opaque bytes since they don't implement Serialize
    // We'll use a custom format
    let vk_bytes = format!("VK_PLACEHOLDER_{}", k).into_bytes();
    let pk_bytes = format!("PK_PLACEHOLDER_{}", k).into_bytes();
    
    Ok(SetupParams {
        srs: srs_bytes,
        verifying_key: vk_bytes,
        proving_key: Some(pk_bytes),
    })
}

/// Hardware proof generator
pub struct HardwareProver {
    k: u32,
}

impl HardwareProver {
    /// Create a new prover from setup parameters
    pub fn new(setup: &SetupParams) -> Result<Self, String> {
        // Extract k from the setup (we encoded it in the placeholder)
        let vk_str = String::from_utf8_lossy(&setup.verifying_key);
        let k = vk_str
            .strip_prefix("VK_PLACEHOLDER_")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(10);
        
        Ok(Self { k })
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
        let expected_bytes = expected_commitment.to_repr();
        
        if commitment.len() != 32 || expected_bytes.as_ref() != commitment {
            return Err("Commitment mismatch - hardware may have changed".to_string());
        }
        
        // Create circuit
        let circuit = HardwareAttestationCircuit::new(cpu_model, mac_address);
        
        // Re-generate params and keys for proof generation
        let params = ParamsKZG::<vesta::Affine>::setup(self.k, OsRng);
        let vk = keygen_vk(&params, &circuit)
            .map_err(|e| format!("Failed to generate vk: {:?}", e))?;
        let pk = keygen_pk(&params, vk, &circuit)
            .map_err(|e| format!("Failed to generate pk: {:?}", e))?;
        
        // Create proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        
        create_proof::<
            KZGCommitmentScheme<vesta::Affine>,
            ProverSHPLONK<'_, vesta::Affine>,
            Challenge255<vesta::Affine>,
            _,
            Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>,
        >(
            &params,
            &pk,
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
    k: u32,
}

impl HardwareVerifier {
    /// Create a new verifier from setup parameters
    pub fn new(setup: &SetupParams) -> Result<Self, String> {
        // Extract k from the setup
        let vk_str = String::from_utf8_lossy(&setup.verifying_key);
        let k = vk_str
            .strip_prefix("VK_PLACEHOLDER_")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(10);
        
        Ok(Self { k })
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
        let commitment_fe = pallas::Base::from_repr(commitment_bytes.into())
            .ok_or("Invalid commitment format")?;
        
        // Re-generate params and vk for verification
        let params = ParamsKZG::<vesta::Affine>::setup(self.k, OsRng);
        let empty_circuit = HardwareAttestationCircuit::new("dummy", "00:00:00:00:00:00");
        let vk = keygen_vk(&params, &empty_circuit)
            .map_err(|e| format!("Failed to generate vk: {:?}", e))?;
        
        // Create transcript for verification
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof.data[..]);
        
        // Verify proof
        let strategy = SingleStrategy::new(&params);
        let result = verify_proof::<
            KZGCommitmentScheme<vesta::Affine>,
            VerifierSHPLONK<'_, vesta::Affine>,
            Challenge255<vesta::Affine>,
            Blake2bRead<&[u8], vesta::Affine, Challenge255<vesta::Affine>>,
            SingleStrategy<'_, vesta::Affine>,
        >(
            &params,
            &vk,
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
