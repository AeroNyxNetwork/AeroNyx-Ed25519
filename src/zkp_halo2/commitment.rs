// src/zkp_halo2/commitment.rs
// AeroNyx Privacy Network - Commitment Generation Module
// Version: 2.0.0

use crate::zkp_halo2::circuit::compute_commitment;
use pasta_curves::pallas;

/// Production commitment generator using circuit's hash function
pub struct PoseidonCommitment;

impl PoseidonCommitment {
    /// Generate a commitment for CPU and MAC
    pub fn commit_combined(cpu_model: &str, mac: &str) -> [u8; 32] {
        let commitment = compute_commitment(cpu_model, mac);
        let repr = commitment.to_repr();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        bytes
    }
    
    /// Commit to CPU model only
    pub fn commit_cpu_model(cpu_model: &str) -> [u8; 32] {
        Self::commit_combined(cpu_model, "00:00:00:00:00:00")
    }
    
    /// Commit to MAC address only
    pub fn commit_mac_address(mac: &str) -> [u8; 32] {
        Self::commit_combined("", mac)
    }
    
    /// Encode string to field elements (for compatibility)
    pub fn encode_string_to_field_elements<F: ff::PrimeField>(s: &str) -> Vec<F> {
        Self::encode_bytes_to_field_elements(s.as_bytes())
    }
    
    /// Encode bytes to field elements
    pub fn encode_bytes_to_field_elements<F: ff::PrimeField>(bytes: &[u8]) -> Vec<F> {
        use sha2::{Sha256, Digest};
        
        const BYTES_PER_ELEMENT: usize = 31;
        
        bytes.chunks(BYTES_PER_ELEMENT)
            .enumerate()
            .map(|(i, chunk)| {
                let mut hasher = Sha256::new();
                hasher.update(b"ENCODE_");
                hasher.update(&i.to_le_bytes());
                hasher.update(chunk);
                let hash = hasher.finalize();
                
                let mut padded = [0u8; 32];
                padded[1..32].copy_from_slice(&hash[..31]);
                
                F::from_repr(padded).unwrap()
            })
            .collect()
    }
}
