use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tracing::{info, debug};
use pasta_curves::pallas;

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
        
        // For now, generate a dummy proof
        // In production, you'd use the actual halo2 proof generation
        let proof_data = self.generate_dummy_proof(&cpu_model, &mac_address);
        
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
        
        let mac_address = hw.network.interfaces
            .iter()
            .find(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
            .map(|iface| iface.mac_address.clone())
            .ok_or("No physical network interface found")?;
        
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
    
    /// Generate a dummy proof for testing
    fn generate_dummy_proof(&self, cpu_model: &str, mac_address: &str) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(b"PROOF:");
        hasher.update(cpu_model.as_bytes());
        hasher.update(b"|");
        hasher.update(mac_address.as_bytes());
        hasher.update(b"|");
        hasher.update(&self.params.srs);
        
        hasher.finalize().to_vec()
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
