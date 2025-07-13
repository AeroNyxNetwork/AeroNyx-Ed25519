// src/zkp_halo2/prover.rs
// AeroNyx Privacy Network - Production-Ready Zero-Knowledge Proof Generation
// Version: 8.0.0 - Optimized for production with key caching

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, debug, instrument};
use ff::PrimeField;
use pasta_curves::{pallas, vesta};
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey,
    },
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    poly::commitment::Params,
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255,
        TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
};
use rand::rngs::OsRng;

use crate::hardware::HardwareInfo;
use crate::zkp_halo2::{
    circuit::{HardwareCircuit, compute_commitment},
    types::{Proof, SetupParams},
};

/// Generate a hardware attestation proof with optimized key handling
#[instrument(skip_all, fields(hw_cpu = %hardware_info.cpu.model))]
pub async fn generate_hardware_proof(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, String> {
    info!("Starting optimized ZKP proof generation...");
    
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
        generate_proof_internal(circuit, public_inputs, params_clone)
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

/// Internal proof generation with optimized key handling
fn generate_proof_internal(
    circuit: HardwareCircuit,
    public_inputs: Vec<pallas::Base>,
    params: SetupParams,
) -> Result<Vec<u8>, String> {
    // Deserialize parameters
    let srs = ParamsKZG::<vesta::Affine>::read(&mut &params.srs[..])
        .map_err(|e| format!("Failed to read SRS: {}", e))?;
    
    // Try to use cached proving key if available
    let pk = if let Some(pk_bytes) = params.proving_key.as_ref() {
        debug!("Using cached proving key");
        bincode::deserialize::<ProvingKey<vesta::Affine>>(pk_bytes)
            .map_err(|e| format!("Failed to deserialize cached pk: {}", e))?
    } else {
        debug!("Generating proving key (no cache available)");
        // Need to generate vk first
        let empty_circuit = HardwareCircuit::without_witnesses();
        let vk = if params.verifying_key.is_empty() {
            keygen_vk(&srs, &empty_circuit)
                .map_err(|e| format!("Failed to generate vk: {}", e))?
        } else {
            bincode::deserialize::<VerifyingKey<vesta::Affine>>(&params.verifying_key)
                .map_err(|e| format!("Failed to deserialize vk: {}", e))?
        };
        
        keygen_pk(&srs, vk, &circuit)
            .map_err(|e| format!("Failed to generate pk: {}", e))?
    };
    
    // Create proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    
    create_proof::<
        KZGCommitmentScheme<vesta::Affine>,
        ProverGWC<'_, vesta::Affine>,
        Challenge255<vesta::Affine>,
        OsRng,
        Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>,
        HardwareCircuit,
    >(
        &srs,
        &pk,
        &[circuit],
        &[&[&public_inputs[..]]],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| format!("Proof creation failed: {:?}", e))?;
    
    Ok(transcript.finalize())
}

/// Verify a hardware attestation proof with optimized key handling
#[instrument(skip_all, fields(proof_size = proof.data.len()))]
pub fn verify_hardware_proof(
    proof: &Proof,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<bool, String> {
    info!("Verifying hardware attestation proof...");
    
    // Check proof freshness (5 minutes max for stricter security)
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    const MAX_AGE: u64 = 300; // 5 minutes
    if current_time > proof.timestamp + MAX_AGE {
        return Err(format!("Proof expired: {} seconds old", 
                         current_time - proof.timestamp));
    }
    
    // Check commitment match
    if proof.public_inputs != commitment {
        debug!("Commitment mismatch in public inputs");
        return Ok(false);
    }
    
    // Parse commitment
    let mut comm_bytes = [0u8; 32];
    comm_bytes.copy_from_slice(commitment);
    let commitment_point = pallas::Base::from_repr(comm_bytes)
        .ok_or("Invalid commitment format")?;
    
    // Deserialize parameters
    let srs = ParamsKZG::<vesta::Affine>::read(&mut &params.srs[..])
        .map_err(|e| format!("Failed to read SRS: {}", e))?;
    
    // Use cached verifying key if available
    let vk = if !params.verifying_key.is_empty() {
        debug!("Using cached verifying key");
        bincode::deserialize::<VerifyingKey<vesta::Affine>>(&params.verifying_key)
            .map_err(|e| format!("Failed to deserialize cached vk: {}", e))?
    } else {
        debug!("Generating verifying key (no cache)");
        let empty_circuit = HardwareCircuit::without_witnesses();
        keygen_vk(&srs, &empty_circuit)
            .map_err(|e| format!("Failed to generate vk: {}", e))?
    };
    
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

/// Generate setup parameters for the proof system with full key generation
pub async fn generate_setup_params(k: u32) -> Result<SetupParams, String> {
    use crate::zkp_halo2::circuit::HardwareCircuit;
    
    info!("Generating Halo2 setup parameters with k={}", k);
    
    tokio::task::spawn_blocking(move || {
        let start = std::time::Instant::now();
        
        // Generate KZG parameters
        let params = ParamsKZG::<vesta::Affine>::setup(k, OsRng);
        debug!("SRS generation took {:?}", start.elapsed());
        
        // Create empty circuit for key generation
        let empty_circuit = HardwareCircuit::without_witnesses();
        
        // Generate verifying key
        let vk_start = std::time::Instant::now();
        let vk = keygen_vk(&params, &empty_circuit)
            .map_err(|e| format!("Failed to generate vk: {:?}", e))?;
        debug!("VK generation took {:?}", vk_start.elapsed());
        
        // Generate proving key
        let pk_start = std::time::Instant::now();
        let pk = keygen_pk(&params, vk.clone(), &empty_circuit)
            .map_err(|e| format!("Failed to generate pk: {:?}", e))?;
        debug!("PK generation took {:?}", pk_start.elapsed());
        
        // Serialize all parameters
        let mut srs_bytes = Vec::new();
        params.write(&mut srs_bytes)
            .map_err(|e| format!("Failed to serialize SRS: {:?}", e))?;
        
        let vk_bytes = bincode::serialize(&vk)
            .map_err(|e| format!("Failed to serialize vk: {:?}", e))?;
        
        let pk_bytes = bincode::serialize(&pk)
            .map_err(|e| format!("Failed to serialize pk: {:?}", e))?;
        
        info!("Setup complete - SRS: {} KB, VK: {} KB, PK: {} KB", 
              srs_bytes.len() / 1024,
              vk_bytes.len() / 1024, 
              pk_bytes.len() / 1024);
        
        info!("Total setup time: {:?}", start.elapsed());
        
        Ok(SetupParams {
            srs: srs_bytes,
            verifying_key: vk_bytes,
            proving_key: Some(pk_bytes),
        })
    })
    .await
    .map_err(|e| format!("Task error: {}", e))?
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
    }
    
    #[tokio::test]
    async fn test_proof_with_wrong_commitment() {
        let params = generate_setup_params(10).await.unwrap();
        let hw = create_test_hardware();
        
        let commitment = compute_commitment(&hw.cpu.model, &hw.network.interfaces[0].mac_address);
        let comm_bytes = commitment.to_repr();
        
        let proof = generate_hardware_proof(&hw, comm_bytes.as_ref(), &params)
            .await
            .unwrap();
        
        // Verify with wrong commitment
        let wrong_commitment = [0u8; 32];
        let valid = verify_hardware_proof(&proof, &wrong_commitment, &params)
            .unwrap();
        
        assert!(!valid, "Proof should be invalid with wrong commitment");
    }
}
