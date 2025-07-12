// src/zkp_halo2/commitment.rs
// AeroNyx Privacy Network - Commitment Helper Functions
// Version: 6.0.0 - 修复字段元素转换 API

use ff::PrimeField;
use pasta_curves::pallas;
use sha2::{Digest, Sha256};

/// Converts a string into a field element deterministically
/// Uses SHA256 with domain separation for security
pub fn string_to_field(s: &str) -> pallas::Base {
    // Domain separator prevents collisions between different data types
    let mut hasher = Sha256::new();
    hasher.update(b"AERONYX_V1_CPU_STRING:");
    hasher.update(s.as_bytes());
    let hash_result = hasher.finalize();
    
    // Convert 32-byte hash to field element
    // Since we can't use from_bytes_wide in v0.3, we need to reduce manually
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash_result);
    
    // Use from_repr which expects the bytes in little-endian
    // If this fails, we'll use a modular reduction approach
    pallas::Base::from_repr(bytes).unwrap_or_else(|| {
        // Fallback: interpret as big integer and reduce
        let mut acc = pallas::Base::zero();
        let mut base = pallas::Base::one();
        
        for &byte in hash_result.iter().rev() {
            for _ in 0..8 {
                if byte & (1 << 7) != 0 {
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
    
    // Hash with domain separator
    let mut hasher = Sha256::new();
    hasher.update(b"AERONYX_V1_MAC_ADDR:");
    hasher.update(&bytes);
    let hash_result = hasher.finalize();
    
    // Convert to field element (same approach as string_to_field)
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash_result);
    
    pallas::Base::from_repr(bytes).unwrap_or_else(|| {
        // Fallback: manual reduction
        let mut acc = pallas::Base::zero();
        let mut base = pallas::Base::one();
        
        for &byte in hash_result.iter().rev() {
            for _ in 0..8 {
                if byte & (1 << 7) != 0 {
                    acc = acc + base;
                }
                base = base.double();
            }
        }
        
        acc
    })
}

/// Main commitment interface for compatibility
pub struct PoseidonCommitment;

impl PoseidonCommitment {
    /// Generate commitment for CPU and MAC
    pub fn commit_combined(cpu_model: &str, mac: &str) -> [u8; 32] {
        let commitment = crate::zkp_halo2::circuit::compute_commitment(cpu_model, mac);
        let repr = commitment.to_repr();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        bytes
    }
    
    /// CPU-only commitment
    pub fn commit_cpu_model(cpu_model: &str) -> [u8; 32] {
        Self::commit_combined(cpu_model, "00:00:00:00:00:00")
    }
    
    /// MAC-only commitment
    pub fn commit_mac_address(mac: &str) -> [u8; 32] {
        Self::commit_combined("", mac)
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
        let mac1 = "AA:BB:CC:DD:EE:FF";
        let mac2 = "aa-bb-cc-dd-ee-ff";
        let mac3 = "11:22:33:44:55:66";
        
        let f1 = mac_to_field(mac1);
        let f2 = mac_to_field(mac2);
        let f3 = mac_to_field(mac3);
        
        assert_eq!(f1, f2, "Different MAC formats should normalize to same value");
        assert_ne!(f1, f3, "Different MACs should produce different values");
    }
}
