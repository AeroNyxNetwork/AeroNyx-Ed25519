// src/zkp_halo2/prover.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Generation
// Version: 2.0.0

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, debug};
use ff::PrimeField;
use pasta_curves::pallas;
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof,
        ProvingKey, VerifyingKey,
    },
    poly::{
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255,
        TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;

use crate::hardware::HardwareInfo;
use crate::zkp_halo2::{
    circuit::{HardwareCircuit, compute_commitment},
    types::{Proof, SetupParams},
};

/// Generate setup parameters for the proof system
pub fn generate_setup_params(k: u32) -> Result<SetupParams, String> {
    info!("Generating Halo2 IPA parameters with k={}", k);
    
    // Generate IPA parameters (no trusted setup needed)
    let params = ParamsIPA::<pallas::Affine>::new(k);
    
    // Create empty circuit for key generation
    let empty_circuit = HardwareCircuit::without_witnesses();
    
    // Generate verification key
    let vk = keygen_vk(&params, &empty_circuit)
        .map_err(|e| format!("Failed to generate verification key: {:?}", e))?;
    
    // Generate proving key
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit)
        .map_err(|e| format!("Failed to generate proving key: {:?}", e))?;
    
    // Serialize parameters
    let mut srs_bytes = Vec::new();
    params.write(&mut srs_bytes)
        .map_err(|e| format!("Failed to serialize params: {:?}", e))?;
    
    // Serialize keys using bincode
    let vk_bytes = bincode::serialize(&vk)
        .map_err(|e| format!("Failed to serialize vk: {:?}", e))?;
    
    let pk_bytes = bincode::serialize(&pk)
        .map_err(|e| format!("Failed to serialize pk: {:?}", e))?;
    
    info!("Setup complete - SRS: {} bytes, VK: {} bytes, PK: {} bytes", 
          srs_bytes.len(), vk_bytes.len(), pk_bytes.len());
    
    Ok(SetupParams {
        srs: srs_bytes,
        verifying_key: vk_bytes,
        proving_key: Some(pk_bytes),
    })
}

/// Generate a hardware attestation proof
pub async fn generate_hardware_proof(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, String> {
    let hw = hardware_info.clone();
    let comm = commitment.to_vec();
    let setup = params.clone();
    
    // Run proof generation in blocking thread
    tokio::task::spawn_blocking(move || {
        generate_proof_sync(&hw, &comm, &setup)
    })
    .await
    .map_err(|e| format!("Failed to spawn proof task: {}", e))?
}

/// Synchronous proof generation
fn generate_proof_sync(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, String> {
    info!("Generating hardware attestation proof");
    
    // Extract hardware data
    let cpu_model = &hardware_info.cpu.model;
    let mac_address = hardware_info.network.interfaces
        .iter()
        .find(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
        .map(|iface| &iface.mac_address[..])
        .unwrap_or("00:00:00:00:00:00");
    
    debug!("CPU: {}, MAC: {}", cpu_model, mac_address);
    
    // Verify commitment matches hardware
    let expected = compute_commitment(cpu_model, mac_address);
    let expected_bytes = expected.to_repr();
    
    if commitment.len() != 32 || expected_bytes.as_ref() != commitment {
        return Err("Commitment mismatch - hardware changed".to_string());
    }
    
    // Deserialize parameters
    let ipa_params = ParamsIPA::<pallas::Affine>::read(&mut &params.srs[..])
        .map_err(|e| format!("Failed to deserialize params: {:?}", e))?;
    
    let pk: ProvingKey<pallas::Affine> = bincode::deserialize(&params.proving_key.as_ref().unwrap())
        .map_err(|e| format!("Failed to deserialize pk: {:?}", e))?;
    
    // Create circuit with witnesses
    let circuit = HardwareCircuit::new(cpu_model, mac_address);
    
    // Create proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    
    create_proof::<
        IPACommitmentScheme<pallas::Affine>,
        ProverIPA<'_, pallas::Affine>,
        Challenge255<pallas::Affine>,
        _,
        Blake2bWrite<Vec<u8>, pallas::Affine, Challenge255<pallas::Affine>>,
        _,
    >(
        &ipa_params,
        &pk,
        &[circuit],
        &[&[&[expected]]],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| format!("Proof generation failed: {:?}", e))?;
    
    let proof_data = transcript.finalize();
    
    info!("Proof generated successfully ({} bytes)", proof_data.len());
    
    Ok(Proof {
        data: proof_data,
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
    info!("Verifying hardware attestation proof");
    
    // Check proof freshness (1 hour max)
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    const MAX_AGE: u64 = 3600;
    if current_time > proof.timestamp + MAX_AGE {
        return Err(format!("Proof too old: {} seconds", current_time - proof.timestamp));
    }
    
    // Check commitment match
    if proof.public_inputs != commitment {
        return Err("Public input mismatch".to_string());
    }
    
    // Parse commitment
    let mut comm_bytes = [0u8; 32];
    comm_bytes.copy_from_slice(commitment);
    let commitment_point = pallas::Base::from_repr(comm_bytes).unwrap();
    
    // Deserialize parameters
    let ipa_params = ParamsIPA::<pallas::Affine>::read(&mut &params.srs[..])
        .map_err(|e| format!("Failed to deserialize params: {:?}", e))?;
    
    let vk: VerifyingKey<pallas::Affine> = bincode::deserialize(&params.verifying_key)
        .map_err(|e| format!("Failed to deserialize vk: {:?}", e))?;
    
    // Create verifier
    let strategy = AccumulatorStrategy::new(&ipa_params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof.data[..]);
    
    // Verify proof
    let result = verify_proof::<
        IPACommitmentScheme<pallas::Affine>,
        VerifierIPA<'_, pallas::Affine>,
        Challenge255<pallas::Affine>,
        Blake2bRead<&[u8], pallas::Affine, Challenge255<pallas::Affine>>,
        AccumulatorStrategy<'_, pallas::Affine>,
    >(
        &ipa_params,
        &vk,
        strategy,
        &[&[&[commitment_point]]],
        &mut transcript,
    );
    
    match result {
        Ok(strategy) => {
            // Finalize verification
            match strategy.finalize() {
                Ok(()) => {
                    info!("Proof verified successfully");
                    Ok(true)
                }
                Err(e) => {
                    debug!("Verification failed: {:?}", e);
                    Ok(false)
                }
            }
        }
        Err(e) => {
            debug!("Proof verification error: {:?}", e);
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
    async fn test_proof_generation_and_verification() {
        // Setup
        let params = generate_setup_params(10).unwrap();
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
        
        assert!(valid);
    }
}
