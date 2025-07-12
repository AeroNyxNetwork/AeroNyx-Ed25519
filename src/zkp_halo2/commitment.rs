// src/zkp_halo2/commitment.rs
// AeroNyx Privacy Network - Commitment Helper Functions
// Version: 5.0.0 - Secure field element encoding

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
    
    // from_bytes_wide reduces modulo field order safely
    pallas::Base::from_bytes_wide(&hash_result.into())
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
    
    pallas::Base::from_bytes_wide(&hash_result.into())
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
    
    #[test]
    fn test_commitment_interface() {
        let cpu = "Intel Xeon Gold 6258R";
        let mac = "de:ad:be:ef:ca:fe";
        
        let c1 = PoseidonCommitment::commit_combined(cpu, mac);
        let c2 = PoseidonCommitment::commit_combined(cpu, mac);
        
        assert_eq!(c1, c2, "Commitment should be deterministic");
        assert_eq!(c1.len(), 32, "Commitment should be 32 bytes");
    }
}
