// src/zkp_halo2/commitment.rs
// AeroNyx Privacy Network - Commitment Generation Module
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module provides commitment generation functionality for hardware attestation.
// Commitments are cryptographic hashes that bind to specific hardware configurations
// without revealing the actual hardware details.
//
// ## Features
//
// - **Deterministic**: Same hardware always produces the same commitment
// - **One-way**: Cannot recover hardware details from commitment
// - **Collision-resistant**: Different hardware produces different commitments
//
// ## Commitment Types
//
// 1. **CPU-only**: Commitment to CPU model
// 2. **MAC-only**: Commitment to MAC address
// 3. **Combined**: Commitment to both CPU and MAC (recommended)
//
// ## Implementation
//
// Uses Poseidon hash function via the hardware circuit's implementation
// to ensure consistency between commitment generation and proof verification.
// This module serves as a high-level interface for the lower-level circuit
// implementation.

use ff::PrimeField;
use crate::zkp_halo2::{
    types::{HardwareCommitment, CommitmentMetadata, ProofType},
    hardware_circuit::compute_expected_commitment,
};

/// Production Poseidon commitment generator
pub struct PoseidonCommitment;

impl PoseidonCommitment {
    /// Generate a commitment for CPU and MAC using production Poseidon
    pub fn commit_combined(cpu_model: &str, mac: &str) -> [u8; 32] {
        // Use the circuit's commitment function for consistency
        let commitment = compute_expected_commitment(cpu_model, mac);
        let repr = commitment.to_repr();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        bytes
    }
    
    pub fn commit_cpu_model(cpu_model: &str) -> [u8; 32] {
        // For CPU-only, use empty MAC
        Self::commit_combined(cpu_model, "00:00:00:00:00:00")
    }
    
    pub fn commit_mac_address(mac: &str) -> [u8; 32] {
        // For MAC-only, use empty CPU model
        Self::commit_combined("", mac)
    }
    
    /// Create a complete hardware commitment with metadata
    pub fn create_commitment(
        proof_type: ProofType,
        cpu_model: &str,
        mac: &str,
    ) -> HardwareCommitment {
        let value = match proof_type {
            ProofType::CpuModel => Self::commit_cpu_model(cpu_model),
            ProofType::MacAddress => Self::commit_mac_address(mac),
            ProofType::Combined => Self::commit_combined(cpu_model, mac),
        };
        
        HardwareCommitment {
            value,
            proof_type,
            metadata: CommitmentMetadata {
                version: 1,
                algorithm: "Poseidon-128".to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        }
    }
    
    /// Encode a string to field elements
    pub fn encode_string_to_field_elements<F: PrimeField>(s: &str) -> Vec<F> {
        Self::encode_bytes_to_field_elements(s.as_bytes())
    }
    
    /// Encode bytes to field elements with proper type constraint
    pub fn encode_bytes_to_field_elements<F>(bytes: &[u8]) -> Vec<F> 
    where
        F: PrimeField,
        F::Repr: From<[u8; 32]>,
    {
        const BYTES_PER_ELEMENT: usize = 31;
        
        bytes.chunks(BYTES_PER_ELEMENT)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[1..chunk.len() + 1].copy_from_slice(chunk);
                
                // Convert bytes to field element
                F::from_repr(padded.into()).unwrap()
            })
            .collect()
    }
}
