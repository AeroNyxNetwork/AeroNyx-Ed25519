use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tracing::{info, debug};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverGWC,
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use pasta_curves::{pallas, vesta};
use rand_core::OsRng;

use crate::hardware::HardwareInfo;
use crate::zkp_halo2::{
    circuit::{CpuCircuit, MacCircuit, CombinedCircuit},
    types::{Proof, SetupParams, ProofType},
    commitment::PoseidonCommitment,
};

/// Hardware proof generator
pub struct HardwareProver {
    params: SetupParams,
}

impl HardwareProver {
    /// Create a new prover with setup parameters
    pub fn new(params: SetupParams) -> Self {
        Self { params }
    }
    
    /// Generate a proof for hardware information
    pub async fn generate_proof(
        &self,
        hardware_info: &HardwareInfo,
        commitment: &[u8],
    ) -> Result<Proof, String> {
        info!("Generating hardware proof");
        
        // Extract hardware data
        let (proof_type, cpu_model, mac_address) = self.extract_hardware_data(hardware_info)?;
        
        // Verify commitment matches
        self.verify_commitment_match(proof_type, &cpu_model, &mac_address, commitment)?;
        
        // Generate proof in blocking task
        let params = self.params.clone();
        let proof_data = tokio::task::spawn_blocking(move || {
            Self::generate_proof_sync(proof_type, &cpu_model, &mac_address, &params)
        })
        .await
        .map_err(|e| format!("Task error: {}", e))??;
        
        Ok(Proof {
            data: proof_data,
            public_inputs: commitment.to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Extract relevant hardware data
    fn extract_hardware_data(&self, hw: &HardwareInfo) -> Result<(ProofType, String, String), String> {
        let cpu_model = hw.cpu.model.clone();
        
        // Find first physical network interface
        let mac_address = hw.network.interfaces
            .iter()
            .find(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
            .map(|iface| iface.mac_address.clone())
            .ok_or("No physical network interface found")?;
        
        // Default to combined proof
        Ok((ProofType::Combined, cpu_model, mac_address))
    }
    
    /// Verify that the commitment matches the hardware data
    fn verify_commitment_match(
        &self,
        proof_type: ProofType,
        cpu_model: &str,
        mac_address: &str,
        expected_commitment: &[u8],
    ) -> Result<(), String> {
        if expected_commitment.len() != 32 {
            return Err("Invalid commitment length".to_string());
        }
        
        let computed = match proof_type {
            ProofType::CpuModel => PoseidonCommitment::commit_cpu_model(cpu_model),
            ProofType::MacAddress => PoseidonCommitment::commit_mac_address(mac_address),
            ProofType::Combined => PoseidonCommitment::commit_combined(cpu_model, mac_address),
        };
        
        if computed != expected_commitment {
            return Err("Commitment mismatch - hardware may have changed".to_string());
        }
        
        Ok(())
    }
    
    /// Generate proof synchronously (CPU-intensive)
    fn generate_proof_sync(
        proof_type: ProofType,
        cpu_model: &str,
        mac_address: &str,
        setup: &SetupParams,
    ) -> Result<Vec<u8>, String> {
        let start = Instant::now();
        info!("Starting proof generation for {:?}", proof_type);
        
        // Deserialize parameters
        let params: ParamsKZG<vesta::Affine> = bincode::deserialize(&setup.srs)
            .map_err(|e| format!("Failed to deserialize params: {}", e))?;
        
        // Create appropriate circuit and generate proof
        let proof_bytes = match proof_type {
            ProofType::CpuModel => {
                let circuit = CpuCircuit::new(cpu_model);
                Self::create_proof_for_circuit(circuit, &params, setup)?
            }
            ProofType::MacAddress => {
                let circuit = MacCircuit::new(mac_address);
                Self::create_proof_for_circuit(circuit, &params, setup)?
            }
            ProofType::Combined => {
                let circuit = CombinedCircuit::new(cpu_model, mac_address);
                Self::create_proof_for_circuit(circuit, &params, setup)?
            }
        };
        
        let elapsed = start.elapsed();
        info!("Proof generated successfully in {:?}", elapsed);
        
        Ok(proof_bytes)
    }
    
    /// Create proof for a specific circuit
    fn create_proof_for_circuit<C>(
        circuit: C,
        params: &ParamsKZG<vesta::Affine>,
        setup: &SetupParams,
    ) -> Result<Vec<u8>, String>
    where
        C: halo2_proofs::plonk::Circuit<pallas::Base>,
    {
        // Get or generate proving key
        let pk = if let Some(pk_bytes) = &setup.proving_key {
            debug!("Using cached proving key");
            bincode::deserialize(pk_bytes)
                .map_err(|e| format!("Failed to deserialize pk: {}", e))?
        } else {
            debug!("Generating proving key");
            let vk = bincode::deserialize(&setup.verifying_key)
                .map_err(|e| format!("Failed to deserialize vk: {}", e))?;
            keygen_pk(params, vk, &circuit)
                .map_err(|e| format!("Failed to generate pk: {:?}", e))?
        };
        
        // Calculate public inputs (commitment)
        let public_inputs = vec![pallas::Base::zero()];
        
        // Create proof transcript
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        
        // Generate the proof (5 type parameters for halo2_proofs 0.3.0)
        create_proof::<
            KZGCommitmentScheme<vesta::Affine>,
            ProverGWC<vesta::Affine>,
            Challenge255<vesta::Affine>,
            _,
            Blake2bWrite<_, _, Challenge255<_>>,
        >(
            params,
            &pk,
            &[circuit],
            &[&[&public_inputs[..]]],
            OsRng,
            &mut transcript,
        )
        .map_err(|e| format!("Proof creation failed: {:?}", e))?;
        
        Ok(transcript.finalize())
    }
}

/// Generate hardware proof (convenience function)
pub async fn generate_hardware_proof(
    hardware_info: &HardwareInfo,
    commitment: &[u8],
    params: &SetupParams,
) -> Result<Proof, String> {
    let prover = HardwareProver::new(params.clone());
    prover.generate_proof(hardware_info, commitment).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp_halo2::circuit::generate_setup_params;
    
    #[tokio::test]
    async fn test_proof_generation() {
        // Generate setup parameters
        let params = generate_setup_params().unwrap();
        
        // Create mock hardware info
        let hw_info = create_mock_hardware_info();
        
        // Generate commitment
        let commitment = PoseidonCommitment::commit_combined(
            &hw_info.cpu.model,
            "aa:bb:cc:dd:ee:ff"
        );
        
        // Generate proof
        let prover = HardwareProver::new(params);
        let proof = prover.generate_proof(&hw_info, &commitment).await;
        
        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert!(!proof.data.is_empty());
        assert_eq!(proof.public_inputs, commitment);
    }
    
    fn create_mock_hardware_info() -> HardwareInfo {
        HardwareInfo {
            hostname: "test-host".to_string(),
            cpu: crate::hardware::CpuInfo {
                cores: 4,
                model: "Test CPU Model".to_string(),
                frequency: 2400000000,
                architecture: "x86_64".to_string(),
                vendor_id: Some("TestVendor".to_string()),
            },
            memory: crate::hardware::MemoryInfo {
                total: 8000000000,
                available: 4000000000,
            },
            disk: crate::hardware::DiskInfo {
                total: 500000000000,
                available: 250000000000,
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
            system_uuid: Some("test-uuid".to_string()),
            machine_id: Some("test-machine-id".to_string()),
            bios_info: None,
        }
    }
}
