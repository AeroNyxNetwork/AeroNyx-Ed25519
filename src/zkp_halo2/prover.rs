// src/zkp_halo2/prover.rs
// Production-grade zero-knowledge proof generation

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use pasta_curves::{pallas, vesta};
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier,
        ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriteBuffer,
    },
};
use rand::rngs::OsRng;

use crate::hardware::HardwareInfo;
use crate::zkp_halo2::{
    circuit::hardware_circuit::{HardwareAttestationCircuit, compute_expected_commitment},
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
    
    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, halo2_proofs::SerdeFormat::RawBytes)
        .map_err(|e| format!("Failed to serialize VK: {:?}", e))?;
    
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, halo2_proofs::SerdeFormat::RawBytes)
        .map_err(|e| format!("Failed to serialize PK: {:?}", e))?;
    
    Ok(SetupParams {
        srs: srs_bytes,
        verifying_key: vk_bytes,
        proving_key: Some(pk_bytes),
    })
}

/// Hardware proof generator
pub struct HardwareProver {
    params: ParamsKZG<vesta::Affine>,
    pk: ProvingKey<vesta::Affine>,
}

impl HardwareProver {
    /// Create a new prover from setup parameters
    pub fn new(setup: &SetupParams) -> Result<Self, String> {
        // Deserialize parameters
        let params = ParamsKZG::<vesta::Affine>::read(&mut &setup.srs[..])
            .map_err(|e| format!("Failed to read SRS: {:?}", e))?;
        
        // Deserialize proving key
        let pk_bytes = setup.proving_key.as_ref()
            .ok_or("Proving key not found in setup parameters")?;
        
        let pk = ProvingKey::<vesta::Affine>::read(
            &mut &pk_bytes[..],
            halo2_proofs::SerdeFormat::RawBytes,
        )
        .map_err(|e| format!("Failed to read proving key: {:?}", e))?;
        
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
        let expected_bytes = expected_commitment.to_repr();
        
        if commitment.len() != 32 || &expected_bytes.as_ref()[..] != commitment {
            return Err("Commitment mismatch - hardware may have changed".to_string());
        }
        
        // Create circuit
        let circuit = HardwareAttestationCircuit::new(cpu_model, mac_address);
        
        // Create proof
        let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
        
        create_proof::<
            KZGCommitmentScheme<vesta::Affine>,
            ProverGWC<'_, vesta::Affine>,
            Challenge255<vesta::Affine>,
            _,
            Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>,
            _,
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
    params: ParamsKZG<vesta::Affine>,
    vk: VerifyingKey<vesta::Affine>,
}

impl HardwareVerifier {
    /// Create a new verifier from setup parameters
    pub fn new(setup: &SetupParams) -> Result<Self, String> {
        // Deserialize parameters
        let params = ParamsKZG::<vesta::Affine>::read(&mut &setup.srs[..])
            .map_err(|e| format!("Failed to read SRS: {:?}", e))?;
        
        // Deserialize verification key
        let vk = VerifyingKey::<vesta::Affine>::read(
            &mut &setup.verifying_key[..],
            halo2_proofs::SerdeFormat::RawBytes,
        )
        .map_err(|e| format!("Failed to read verification key: {:?}", e))?;
        
        Ok(Self { params, vk })
    }
    
    /// Verify a hardware proof
    pub fn verify_proof(
        &self,
        proof: &Proof,
        commitment: &[u8],
    ) -> Result<bool, String> {
        info!("Verifying zero-knowledge proof");
        
        // Check proof age (optional - can be configurable)
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
        let commitment_fe = pallas::Base::from_repr(commitment_bytes)
            .ok_or("Invalid commitment format")?;
        
        // Create transcript for verification
        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof.data[..]);
        
        // Verify proof
        let strategy = SingleStrategy::new(&self.params);
        let result = verify_proof::<
            KZGCommitmentScheme<vesta::Affine>,
            VerifierGWC<'_, vesta::Affine>,
            Challenge255<vesta::Affine>,
            Blake2bRead<&[u8], vesta::Affine, Challenge255<vesta::Affine>>,
            SingleStrategy<'_, vesta::Affine>,
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
    // Run in blocking task since proof generation is CPU-intensive
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_setup_generation() {
        let k = 10;
        let setup = generate_setup_params(k).unwrap();
        
        assert!(!setup.srs.is_empty());
        assert!(!setup.verifying_key.is_empty());
        assert!(setup.proving_key.is_some());
    }
    
    #[tokio::test]
    async fn test_proof_generation_and_verification() {
        // Generate setup
        let k = 10;
        let setup = generate_setup_params(k).unwrap();
        
        // Create mock hardware info
        let hw_info = HardwareInfo {
            hostname: "test-node".to_string(),
            cpu: crate::hardware::CpuInfo {
                cores: 8,
                model: "Intel Core i7-9700K".to_string(),
                frequency: 3600000000,
                architecture: "x86_64".to_string(),
                vendor_id: Some("GenuineIntel".to_string()),
            },
            memory: crate::hardware::MemoryInfo {
                total: 16000000000,
                available: 8000000000,
            },
            disk: crate::hardware::DiskInfo {
                total: 1000000000000,
                available: 500000000000,
                filesystem: "ext4".to_string(),
            },
            network: crate::hardware::NetworkInfo {
                interfaces: vec![
                    crate::hardware::NetworkInterface {
                        name: "eth0".to_string(),
                        ip_address: "192.168.1.100".to_string(),
                        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                        interface_type: "ethernet".to_string(),
                        is_physical: true,
                    }
                ],
                public_ip: "1.2.3.4".to_string(),
            },
            os: crate::hardware::OsInfo {
                os_type: "linux".to_string(),
                version: "22.04".to_string(),
                distribution: "Ubuntu".to_string(),
                kernel: "5.15.0".to_string(),
            },
            system_uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            machine_id: Some("abcdef1234567890".to_string()),
            bios_info: None,
        };
        
        // Generate commitment
        let commitment = compute_expected_commitment(
            &hw_info.cpu.model,
            &hw_info.network.interfaces[0].mac_address
        );
        let commitment_bytes = commitment.to_repr();
        
        // Generate proof
        let proof = generate_hardware_proof(&hw_info, &commitment_bytes, &setup).await.unwrap();
        
        // Verify proof
        let valid = verify_hardware_proof(&proof, &commitment_bytes, &setup).unwrap();
        assert!(valid);
        
        // Test with wrong commitment
        let wrong_commitment = [0u8; 32];
        let invalid = verify_hardware_proof(&proof, &wrong_commitment, &setup).unwrap();
        assert!(!invalid);
    }
}
