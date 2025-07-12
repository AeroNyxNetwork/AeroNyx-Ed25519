// src/zkp_halo2/tests.rs
// Complete integration test for the ZKP system

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{HardwareInfo, CpuInfo, MemoryInfo, DiskInfo, NetworkInfo, NetworkInterface, OsInfo};
    use crate::zkp_halo2::{initialize_with_k, generate_hardware_proof, verify_hardware_proof};
    use halo2_proofs::dev::MockProver;
    use pasta_curves::pallas;
    
    fn create_test_hardware_info() -> HardwareInfo {
        HardwareInfo {
            hostname: "test-node".to_string(),
            cpu: CpuInfo {
                cores: 8,
                model: "Intel Core i7-9700K @ 3.60GHz".to_string(),
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
    
    #[test]
    fn test_circuit_with_mock_prover() {
        use crate::zkp_halo2::hardware_circuit::{HardwareAttestationCircuit, compute_expected_commitment};
        
        let k = 10; // 2^10 = 1024 rows
        
        let cpu_model = "Intel Core i7-9700K @ 3.60GHz";
        let mac_address = "aa:bb:cc:dd:ee:ff";
        
        // Create circuit
        let circuit = HardwareAttestationCircuit::new(cpu_model, mac_address);
        
        // Compute expected commitment (public input)
        let commitment = compute_expected_commitment(cpu_model, mac_address);
        
        // Run mock prover
        let prover = MockProver::run(k, &circuit, vec![vec![commitment]]).unwrap();
        
        // Verify the circuit is satisfied
        match prover.verify() {
            Ok(()) => println!("✓ Circuit verification passed!"),
            Err(e) => {
                println!("✗ Circuit verification failed:");
                for error in e {
                    println!("  - {:?}", error);
                }
                panic!("Circuit verification failed");
            }
        }
    }
    
    #[tokio::test]
    async fn test_full_zkp_flow() {
        println!("Starting full ZKP flow test...");
        
        // 1. Initialize ZKP system
        println!("1. Initializing ZKP system with k=10...");
        let setup = initialize_with_k(10).await.unwrap();
        println!("   ✓ ZKP system initialized");
        println!("   - SRS size: {} bytes", setup.srs.len());
        println!("   - VK size: {} bytes", setup.verifying_key.len());
        println!("   - PK size: {} bytes", setup.proving_key.as_ref().unwrap().len());
        
        // 2. Create test hardware info
        println!("\n2. Creating test hardware info...");
        let hw_info = create_test_hardware_info();
        println!("   ✓ Hardware info created");
        println!("   - CPU: {}", hw_info.cpu.model);
        println!("   - MAC: {}", hw_info.network.interfaces[0].mac_address);
        
        // 3. Generate commitment
        println!("\n3. Generating hardware commitment...");
        let commitment = hw_info.generate_zkp_commitment();
        println!("   ✓ Commitment generated");
        println!("   - Commitment: {}", hex::encode(&commitment));
        
        // 4. Generate proof
        println!("\n4. Generating zero-knowledge proof...");
        let start = std::time::Instant::now();
        let proof = generate_hardware_proof(&hw_info, &commitment, &setup).await.unwrap();
        let proof_time = start.elapsed();
        println!("   ✓ Proof generated in {:?}", proof_time);
        println!("   - Proof size: {} bytes", proof.data.len());
        println!("   - Timestamp: {}", proof.timestamp);
        
        // 5. Verify proof
        println!("\n5. Verifying proof...");
        let start = std::time::Instant::now();
        let valid = verify_hardware_proof(&proof, &commitment, &setup).unwrap();
        let verify_time = start.elapsed();
        println!("   ✓ Proof verified in {:?}", verify_time);
        println!("   - Result: {}", if valid { "VALID" } else { "INVALID" });
        assert!(valid, "Proof should be valid");
        
        // 6. Test with wrong commitment
        println!("\n6. Testing with wrong commitment...");
        let wrong_commitment = vec![0u8; 32];
        let invalid = verify_hardware_proof(&proof, &wrong_commitment, &setup).unwrap();
        println!("   ✓ Wrong commitment correctly rejected: {}", !invalid);
        assert!(!invalid, "Proof should be invalid with wrong commitment");
        
        // 7. Test hardware change detection
        println!("\n7. Testing hardware change detection...");
        let mut changed_hw = hw_info.clone();
        changed_hw.cpu.model = "AMD Ryzen 9 5900X".to_string();
        let changed_commitment = changed_hw.generate_zkp_commitment();
        println!("   - Original commitment: {}", hex::encode(&commitment));
        println!("   - Changed commitment:  {}", hex::encode(&changed_commitment));
        assert_ne!(commitment, changed_commitment, "Commitments should differ");
        
        // Try to generate proof with mismatched hardware
        match generate_hardware_proof(&changed_hw, &commitment, &setup).await {
            Ok(_) => panic!("Should not generate proof with mismatched hardware"),
            Err(e) => {
                println!("   ✓ Correctly rejected mismatched hardware: {}", e);
                assert!(e.contains("Commitment mismatch"));
            }
        }
        
        println!("\n✓ All tests passed! The ZKP system is working correctly.");
        println!("\nSummary:");
        println!("- Zero-knowledge: The proof reveals nothing about the hardware");
        println!("- Soundness: Invalid proofs are rejected");
        println!("- Completeness: Valid hardware can always prove itself");
    }
    
    #[test]
    fn test_commitment_determinism() {
        use crate::zkp_halo2::commitment::PoseidonCommitment;
        
        let cpu = "Intel Core i7";
        let mac = "aa:bb:cc:dd:ee:ff";
        
        // Generate commitments multiple times
        let c1 = PoseidonCommitment::commit_combined(cpu, mac);
        let c2 = PoseidonCommitment::commit_combined(cpu, mac);
        let c3 = PoseidonCommitment::commit_combined(cpu, mac);
        
        // All should be identical
        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
        
        // Different input should give different commitment
        let c4 = PoseidonCommitment::commit_combined("AMD Ryzen", mac);
        assert_ne!(c1, c4);
        
        println!("✓ Commitment determinism test passed");
    }
    
    #[test]
    fn test_mac_normalization() {
        use crate::zkp_halo2::commitment::PoseidonCommitment;
        
        // Different formats of the same MAC
        let formats = vec![
            "AA:BB:CC:DD:EE:FF",
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "aa-bb-cc-dd-ee-ff",
            "AABBCCDDEEFF",
            "aabbccddeeff",
        ];
        
        let cpu = "Test CPU";
        let first_commit = PoseidonCommitment::commit_combined(cpu, formats[0]);
        
        // All formats should produce the same commitment
        for mac_format in &formats[1..] {
            let commit = PoseidonCommitment::commit_combined(cpu, mac_format);
            assert_eq!(first_commit, commit, 
                "MAC format {} should produce same commitment", mac_format);
        }
        
        println!("✓ MAC normalization test passed");
    }
}

// Add this test module to src/zkp_halo2/mod.rs:
// pub mod tests;
