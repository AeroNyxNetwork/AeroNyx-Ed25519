// src/zkp/mod.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Module
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module implements zero-knowledge proofs for hardware attestation
// using Halo2, enabling nodes to prove hardware ownership without
// revealing sensitive hardware details.

pub mod circuit;
pub mod prover;
pub mod verifier;

pub use circuit::{HardwareCircuit, HardwareCommitment};
pub use prover::{HardwareProver, ProverError, generate_hardware_proof};
pub use verifier::{HardwareVerifier, VerifierError, verify_hardware_proof};

use serde::{Serialize, Deserialize};

/// ZKP proof structure containing the serialized proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Serialized proof data
    pub data: Vec<u8>,
    /// Public inputs (commitment)
    pub public_inputs: Vec<u8>,
    /// Proof generation timestamp
    pub timestamp: u64,
}

/// ZKP setup parameters (proving and verifying keys)
#[derive(Clone, Serialize, Deserialize)]
pub struct SetupParams {
    /// Proving key bytes
    pub proving_key: Vec<u8>,
    /// Verifying key bytes
    pub verifying_key: Vec<u8>,
}

/// Initialize the ZKP module with setup parameters
pub async fn initialize() -> Result<SetupParams, String> {
    circuit::generate_setup_params().await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::hardware::HardwareInfo;

    pub fn create_mock_hardware_info() -> HardwareInfo {
        HardwareInfo {
            hostname: "test-node".to_string(),
            cpu: crate::hardware::CpuInfo {
                cores: 4,
                model: "Test CPU".to_string(),
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

    #[tokio::test]
    async fn test_zkp_flow() {
        // Initialize ZKP module
        let params = initialize().await.unwrap();
        
        // Create mock hardware info
        let hw_info = create_mock_hardware_info();
        
        // Generate commitment
        let commitment = HardwareCommitment::from_hardware_info(&hw_info);
        
        // Generate proof
        let proof = generate_hardware_proof(&hw_info, &commitment.to_bytes(), &params)
            .await
            .unwrap();
        
        // Verify proof
        let is_valid = verify_hardware_proof(&proof, &commitment.to_bytes(), &params)
            .unwrap();
        
        assert!(is_valid);
    }
}
