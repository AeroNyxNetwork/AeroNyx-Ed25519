// src/zkp_halo2/commitment.rs
// AeroNyx Privacy Network - Production-Ready Commitment Functions
// Version: 8.0.1 - Fixed CtOption conversions

use ff::PrimeField;
use pasta_curves::pallas;
use sha2::{Digest, Sha256};
use blake2b_simd::Params as Blake2bParams;

/// Domain separation tags for different input types
const DOMAIN_CPU: &[u8] = b"AERONYX_CPU_V1";
const DOMAIN_MAC: &[u8] = b"AERONYX_MAC_V1";
const DOMAIN_STRING: &[u8] = b"AERONYX_STRING_V1";

/// Converts a string into a field element deterministically
/// Uses SHA256 with domain separation for security
pub fn string_to_field(s: &str) -> pallas::Base {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_CPU);
    hasher.update(s.as_bytes());
    let hash = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    
    // Fixed: Convert CtOption to Option
    Option::from(pallas::Base::from_repr(bytes)).unwrap_or_else(|| {
        // Fallback: interpret as big integer and reduce
        let mut acc = pallas::Base::zero();
        let mut base = pallas::Base::one();
        
        for &byte in hash.iter().rev() {
            for i in 0..8 {
                if byte & (1 << i) != 0 {
                    acc = acc + base;
                }
                base = base.double();
            }
        }
        
        acc
    })
}

/// Converts MAC address to field element
pub fn mac_to_field(mac: &str) -> pallas::Base {
    // Normalize MAC address format
    let normalized = mac
        .to_lowercase()
        .replace([':', '-'], "");
    
    let bytes = hex::decode(&normalized)
        .expect("Invalid MAC address format");
    
    if bytes.len() != 6 {
        panic!("MAC address must be 6 bytes");
    }
    
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MAC);
    hasher.update(&bytes);
    let hash = hasher.finalize();
    
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    
    // Fixed: Convert CtOption to Option
    Option::from(pallas::Base::from_repr(hash_bytes)).unwrap_or_else(|| {
        // Fallback: manual reduction
        let mut acc = pallas::Base::zero();
        let mut base = pallas::Base::one();
        
        for &byte in hash.iter().rev() {
            for i in 0..8 {
                if byte & (1 << i) != 0 {
                    acc = acc + base;
                }
                base = base.double();
            }
        }
        
        acc
    })
}

/// Generic hash-to-field function with domain separation
fn hash_to_field(data: &[u8], domain: &[u8]) -> pallas::Base {
    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(domain)
        .to_state()
        .update(data)
        .finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_bytes());
    
    // Try direct conversion first
    Option::from(pallas::Base::from_repr(bytes)).unwrap_or_else(|| {
        // If it fails (very unlikely), use modular reduction
        reduce_bytes_to_field(&bytes)
    })
}

/// Reduce arbitrary bytes to field element via modular reduction
fn reduce_bytes_to_field(bytes: &[u8]) -> pallas::Base {
    let mut acc = pallas::Base::zero();
    let mut base = pallas::Base::one();
    
    // Process bytes in little-endian order
    for &byte in bytes.iter() {
        for i in 0..8 {
            if byte & (1 << i) != 0 {
                acc += base;
            }
            base = base.double();
        }
    }
    
    acc
}

/// Main commitment interface for compatibility
pub struct PoseidonCommitment;

impl PoseidonCommitment {
    /// Generate commitment for CPU and MAC using circuit's compute_commitment
    pub fn commit_combined(cpu_model: &str, mac: &str) -> [u8; 32] {
        let commitment = crate::zkp_halo2::circuit::compute_commitment(cpu_model, mac);
        let repr = commitment.to_repr();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        bytes
    }
    
    /// CPU-only commitment (with default MAC)
    pub fn commit_cpu_model(cpu_model: &str) -> [u8; 32] {
        Self::commit_combined(cpu_model, "00:00:00:00:00:00")
    }
    
    /// MAC-only commitment (with empty CPU)
    pub fn commit_mac_address(mac: &str) -> [u8; 32] {
        Self::commit_combined("", mac)
    }
    
    /// Extended commitment for multiple components
    pub fn commit_multiple(components: &[&str]) -> [u8; 32] {
        if components.len() == 2 {
            // Optimize for the common case
            return Self::commit_combined(components[0], components[1]);
        }
        
        // For other cases, use SHA256 to combine all components
        let mut hasher = Sha256::new();
        hasher.update(b"AERONYX_MULTI_V1");
        hasher.update(&(components.len() as u64).to_le_bytes());
        
        for component in components {
            hasher.update(&(component.len() as u64).to_le_bytes());
            hasher.update(component.as_bytes());
        }
        
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        bytes
    }
}

/// Batch commitment generation for efficiency
pub struct BatchCommitment {
    commitments: Vec<[u8; 32]>,
}

impl BatchCommitment {
    pub fn new() -> Self {
        Self {
            commitments: Vec::new(),
        }
    }
    
    /// Add a hardware commitment to the batch
    pub fn add_hardware(&mut self, cpu_model: &str, mac: &str) {
        let commitment = PoseidonCommitment::commit_combined(cpu_model, mac);
        self.commitments.push(commitment);
    }
    
    /// Get all commitments
    pub fn commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }
    
    /// Generate a merkle root of all commitments (simplified)
    pub fn aggregate_commitment(&self) -> [u8; 32] {
        if self.commitments.is_empty() {
            return [0u8; 32];
        }
        
        if self.commitments.len() == 1 {
            return self.commitments[0];
        }
        
        // Simple aggregation using Blake2b
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(b"AERONYX_AGGREGATE")
            .to_state()
            .update(&(self.commitments.len() as u64).to_le_bytes())
            .update(self.commitments.iter().flatten().cloned().collect::<Vec<u8>>().as_slice())
            .finalize();
        
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_string_to_field_determinism() {
        let s1 = "Intel Core i9-13900K";
        let s2 = "Intel Core i9-13900K";
        let s3 = "AMD Ryzen 9 7950X";
        
        let f1 = string_to_field(s1);
        let f2 = string_to_field(s2);
        let f3 = string_to_field(s3);
        
        assert_eq!(f1, f2, "Same string should produce same field element");
        assert_ne!(f1, f3, "Different strings should produce different field elements");
    }
    
    #[test]
    fn test_mac_normalization() {
        let mac_formats = vec![
            "AA:BB:CC:DD:EE:FF",
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "aa-bb-cc-dd-ee-ff",
            "AABBCCDDEEFF",
            "aabbccddeeff",
        ];
        
        let first = mac_to_field(mac_formats[0]);
        
        for mac in &mac_formats[1..] {
            let field = mac_to_field(mac);
            assert_eq!(first, field, "All MAC formats should normalize to same value");
        }
    }
    
    #[test]
    fn test_short_string_optimization() {
        // Test that short strings are handled efficiently
        let short = "CPU123";
        let field = string_to_field(short);
        
        // Should produce a valid field element
        let _ = field.to_repr();
    }
    
    #[test]
    fn test_batch_commitment() {
        let mut batch = BatchCommitment::new();
        
        batch.add_hardware("CPU1", "aa:bb:cc:dd:ee:ff");
        batch.add_hardware("CPU2", "11:22:33:44:55:66");
        
        assert_eq!(batch.commitments().len(), 2);
        
        let agg = batch.aggregate_commitment();
        assert_ne!(agg, [0u8; 32]);
    }
}
