// src/zkp_halo2/prover.rs
// AeroNyx Privacy Network - Secure Zero-Knowledge Proof Generation
// Version: 5.0.0 - Production-ready implementation

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, debug};
use ff::PrimeField;
use pasta_curves::{pallas, vesta};
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof,
        ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255,
        TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
};

use crate::hardware::HardwareInfo;
use crate::zkp_halo2::{
    circuit::{HardwareCircuit, compute_commitment},
    types::{Proof, SetupParams},
};

// Create a deterministic RNG for testing (DO NOT use in production without proper randomness)
#[cfg(test)]
fn test_rng() -> impl rand_core::RngCore {
    use rand::SeedableRng;
    rand::rngs::StdRng::seed_from_u64(0x1234_5678_9ABC_DEF0)
}

#[cfg(not(test))]
fn test_rng() -> impl rand_core::RngCore {
    rand::rngs::OsRng
}

/// Generate setup parameters for the proof system
pub async fn generate_setup_params(k: u32) -> Result<SetupParams, String> {
    use tokio::task;
    
    info!("Generating Halo2 setup parameters with k={}", k);
    
    task::spawn_blocking(move || {
        // Generate KZG parameters
        // Note: In production, use a ceremony-generated SRS
        let params = ParamsKZG::<vesta::Affine>::setup(k, test_rng());
        
        // Create empty circuit for key generation
        let empty_circuit = HardwareCircuit::without_witnesses();
        
        // Generate verifying key
        let vk = keygen_vk(&params, &empty_circuit)
            .map_err(|e| format!("Failed to generate vk: {:?}", e))?;
        
        // Generate proving key
        let pk = keygen_pk(&params, vk.clone(), &empty_circuit)
            .map_err(|e| format!("Failed to generate pk: {:?}", e))?;
        
        // Serialize parameters
        let mut srs_bytes = Vec::new();
        params.write(&mut srs_bytes)
            .map_err(|e| format!("Failed to serialize SRS: {:?}", e))?;
        
        let mut vk_bytes = Vec::new();
        vk.write(&mut vk_bytes, SerdeFormat::RawBytes)
            .map_err(|e| format!("Failed to serialize vk: {:?}", e))?;
        
        let mut pk_bytes = Vec::new();
        pk.write(&mut pk_bytes, SerdeFormat::RawBytes)
            .map_err(|e| format!("Failed to serialize pk: {:?}", e))?;
        
        info!("Setup complete - SRS: {} bytes, VK: {} bytes, PK: {} bytes",
              srs_bytes.len(), vk_bytes.len(), pk_bytes.len());
        
        Ok(SetupParams {
            srs: srs_bytes,
            verifying_key: vk_bytes,
            proving_key: Some(pk_bytes),
        })
    })
    .await
    .map_err(|e| format!("Task error: {}", e))?
}

/// Generate a hardware attestation proof
pub async fn generate_hardware_proof(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, String> {
    info!("Starting ZKP proof generation...");
    
    // Extract hardware data
    let cpu_model = &hardware_info.cpu.model;
    let mac_address = hardware_info.network.interfaces
        .iter()
        .find(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
        .map(|iface| &iface.mac_address[..])
        .unwrap_or("00:00:00:00:00:00");
    
    debug!("CPU: {}, MAC: {}", cpu_model, mac_address);
    
    // Verify commitment matches
    let expected = compute_commitment(cpu_model, mac_address);
    let expected_bytes = expected.to_repr();
    
    if commitment.len() != 32 || expected_bytes.as_ref() != commitment {
        return Err("Commitment mismatch - hardware changed".to_string());
    }
    
    // Clone for async task
    let circuit = HardwareCircuit::new(cpu_model, mac_address);
    let params_clone = params.clone();
    let public_inputs = vec![expected];
    
    // Generate proof in blocking task
    let proof_bytes = tokio::task::spawn_blocking(move || {
        // Deserialize parameters
        let srs = ParamsKZG::<vesta::Affine>::read(&mut &params_clone.srs[..])
            .map_err(|e| format!("Failed to read SRS: {}", e))?;
        
        let pk_bytes = params_clone.proving_key.as_ref()
            .ok_or("Proving key not found")?;
        
        let pk = ProvingKey::<vesta::Affine>::read::<_, HardwareCircuit>(
            &mut &pk_bytes[..],
            SerdeFormat::RawBytes,
        )
        .map_err(|e| format!("Failed to read pk: {}", e))?;
        
        // Create proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        
        create_proof::<
            KZGCommitmentScheme<vesta::Affine>,
            ProverGWC<'_, vesta::Affine>,
            Challenge255<vesta::Affine>,
            _,
            Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>,
            _,
        >(
            &srs,
            &pk,
            &[circuit],
            &[&[&public_inputs[..]]],
            test_rng(),
            &mut transcript,
        )
        .map_err(|e| format!("Proof creation failed: {:?}", e))?;
        
        Ok(transcript.finalize())
    })
    .await
    .map_err(|e| format!("Proof generation task failed: {}", e))??;
    
    info!("Proof generated successfully ({} bytes)", proof_bytes.len());
    
    Ok(Proof {
        data: proof_bytes,
        public_inputs: commitment.to_vec(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}

/// Verify a hardware attestation proof
pub fn verify_hardware_proof(
    proof: &Proof,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<bool, String> {
    info!("Verifying hardware attestation proof...");
    
    // Check proof freshness (1 hour max)
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    const MAX_AGE: u64 = 3600;
    if current_time > proof.timestamp + MAX_AGE {
        return Err(format!("Proof expired: {} seconds old", 
                         current_time - proof.timestamp));
    }
    
    // Check commitment match
    if proof.public_inputs != commitment {
        return Ok(false);
    }
    
    // Parse commitment
    let mut comm_bytes = [0u8; 32];
    comm_bytes.copy_from_slice(commitment);
    let commitment_point = pallas::Base::from_repr(comm_bytes).unwrap();
    
    // Deserialize parameters
    let srs = ParamsKZG::<vesta::Affine>::read(&mut &params.srs[..])
        .map_err(|e| format!("Failed to read SRS: {}", e))?;
    
    let vk = VerifyingKey::<vesta::Affine>::read::<_, HardwareCircuit>(
        &mut &params.verifying_key[..],
        SerdeFormat::RawBytes,
    )
    .map_err(|e| format!("Failed to read vk: {}", e))?;
    
    // Verify proof
    let strategy = SingleStrategy::new(&srs);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof.data[..]);
    
    let result = verify_proof::<
        KZGCommitmentScheme<vesta::Affine>,
        VerifierGWC<'_, vesta::Affine>,
        Challenge255<vesta::Affine>,
        Blake2bRead<&[u8], vesta::Affine, Challenge255<vesta::Affine>>,
        SingleStrategy<'_, vesta::Affine>,
    >(
        &srs,
        &vk,
        strategy,
        &[&[&[commitment_point]]],
        &mut transcript,
    );
    
    match result {
        Ok(()) => {
            info!("Proof verified successfully!");
            Ok(true)
        }
        Err(e) => {
            debug!("Proof verification failed: {:?}", e);
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::*;
    
    fn create_test_hardware() -> HardwareInfo {
        HardwareInfo {
            hostname: "test-node".to_string(),
            cpu: CpuInfo {
                cores: 8,
                model: "Intel Core i7-9700K".to_string(),
                frequency: 3600000000,
                architecture: "x86_64".to_string(),
                vendor_id: Some("GenuineIntel".to_string()),
            },
            memory: MemoryInfo {
                total: 16000000000,
                available: 8000000000,
            },
            disk: DiskInfo {
                total: 1000000000000,
                available: 500000000000,
                filesystem: "ext4".to_string(),
            },
            network: NetworkInfo {
                interfaces: vec![
                    NetworkInterface {
                        name: "eth0".to_string(),
                        ip_address: "192.168.1.100".to_string(),
                        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                        interface_type: "ethernet".to_string(),
                        is_physical: true,
                    }
                ],
                public_ip: "1.2.3.4".to_string(),
            },
            os: OsInfo {
                os_type: "linux".to_string(),
                version: "22.04".to_string(),
                distribution: "Ubuntu".to_string(),
                kernel: "5.15.0".to_string(),
            },
            system_uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            machine_id: Some("abcdef1234567890".to_string()),
            bios_info: None,
        }
    }
    
    #[tokio::test]
    async fn test_full_zkp_flow() {
        // Generate setup
        let params = generate_setup_params(10).await.unwrap();
        
        // Create hardware
        let hw = create_test_hardware();
        
        // Generate commitment
        let commitment = compute_commitment(
            &hw.cpu.model,
            &hw.network.interfaces[0].mac_address
        );
        let comm_bytes = commitment.to_repr();
        
        // Generate proof
        let proof = generate_hardware_proof(&hw, comm_bytes.as_ref(), &params)
            .await
            .unwrap();
        
        // Verify proof
        let valid = verify_hardware_proof(&proof, comm_bytes.as_ref(), &params)
            .unwrap();
        
        assert!(valid, "Proof should be valid");
        
        // Test with wrong commitment
        let wrong_comm = [0u8; 32];
        let invalid = verify_hardware_proof(&proof, &wrong_comm, &params)
            .unwrap();
        
        assert!(!invalid, "Proof should be invalid with wrong commitment");
    }
}
