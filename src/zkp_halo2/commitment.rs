use ff::PrimeField;
use pasta_curves::pallas;
use crate::zkp_halo2::types::{HardwareCommitment, CommitmentMetadata, ProofType};

/// Poseidon hash parameters for 128-bit security
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_CAPACITY: usize = 1;
const POSEIDON_FULL_ROUNDS: usize = 8;
const POSEIDON_PARTIAL_ROUNDS: usize = 56;

/// Poseidon commitment generator for hardware attestation
pub struct PoseidonCommitment;

impl PoseidonCommitment {
    /// Generate a commitment for a CPU model string
    pub fn commit_cpu_model(cpu_model: &str) -> [u8; 32] {
        let encoded = Self::encode_string_to_field_elements::<pallas::Base>(cpu_model);
        Self::poseidon_hash(&encoded)
    }
    
    /// Generate a commitment for a MAC address
    pub fn commit_mac_address(mac: &str) -> [u8; 32] {
        // Normalize MAC address format
        let normalized = mac.to_lowercase()
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "");
        
        if normalized.len() != 12 {
            panic!("Invalid MAC address format: expected 12 hex characters");
        }
        
        let bytes = hex::decode(&normalized)
            .expect("Invalid MAC address: not valid hexadecimal");
        
        if bytes.len() != 6 {
            panic!("Invalid MAC address: expected 6 bytes");
        }
        
        let encoded = Self::encode_bytes_to_field_elements::<pallas::Base>(&bytes);
        Self::poseidon_hash(&encoded)
    }
    
    /// Generate a combined commitment for CPU model and MAC address
    pub fn commit_combined(cpu_model: &str, mac: &str) -> [u8; 32] {
        // Encode CPU model
        let cpu_encoded = Self::encode_string_to_field_elements::<pallas::Base>(cpu_model);
        
        // Normalize and encode MAC address
        let mac_normalized = mac.to_lowercase()
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "");
        let mac_bytes = hex::decode(&mac_normalized)
            .expect("Invalid MAC address");
        let mac_encoded = Self::encode_bytes_to_field_elements::<pallas::Base>(&mac_bytes);
        
        // Combine with domain separation
        let mut combined = Vec::new();
        
        // Add domain tag for combined commitment
        let domain_tag = Self::encode_string_to_field_elements::<pallas::Base>("COMBINED_HARDWARE_V1");
        combined.extend_from_slice(&domain_tag);
        
        // Add CPU data with length prefix
        combined.push(pallas::Base::from(cpu_encoded.len() as u64));
        combined.extend_from_slice(&cpu_encoded);
        
        // Add MAC data with length prefix
        combined.push(pallas::Base::from(mac_encoded.len() as u64));
        combined.extend_from_slice(&mac_encoded);
        
        Self::poseidon_hash(&combined)
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
    /// 
    /// Strings are encoded as UTF-8 bytes, then packed into field elements.
    /// Each field element can hold up to 31 bytes to ensure it fits in the field.
    pub fn encode_string_to_field_elements<F: PrimeField>(s: &str) -> Vec<F> 
    where
        F::Repr: From<[u8; 32]>,
    {
        Self::encode_bytes_to_field_elements(s.as_bytes())
    }
    
    /// Encode bytes to field elements
    /// 
    /// Packs bytes into field elements, using 31 bytes per element to ensure
    /// the value is less than the field modulus.
    pub fn encode_bytes_to_field_elements<F: PrimeField>(bytes: &[u8]) -> Vec<F> 
    where
        <F as PrimeField>::Repr: From<[u8; 32]>,
    {
        const BYTES_PER_ELEMENT: usize = 31;
        
        bytes.chunks(BYTES_PER_ELEMENT)
            .map(|chunk| {
                // Pad chunk to 32 bytes (with leading zero)
                let mut padded = [0u8; 32];
                padded[1..chunk.len() + 1].copy_from_slice(chunk);
                
                // Convert to field element
                F::from_repr(padded.into()).unwrap()
            })
            .collect()
    }
    
    /// Compute Poseidon hash of field elements
    /// 
    /// Uses the Poseidon sponge construction with:
    /// - Width 3 (rate 2 + capacity 1)
    /// - 8 full rounds + 56 partial rounds
    /// - Optimized round constants and MDS matrix
    fn poseidon_hash<F: PrimeField>(inputs: &[F]) -> [u8; 32] {
        use crate::zkp_halo2::circuit::poseidon::{PoseidonSponge, PoseidonConfig};
        
        // Initialize Poseidon with standard parameters
        let config = PoseidonConfig::<F, POSEIDON_WIDTH, POSEIDON_RATE>::new(
            POSEIDON_FULL_ROUNDS,
            POSEIDON_PARTIAL_ROUNDS,
        );
        
        let mut sponge = PoseidonSponge::new(config);
        
        // Absorb all inputs
        sponge.absorb(inputs);
        
        // Squeeze one output element
        let output = sponge.squeeze();
        
        // Convert field element to bytes
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&output.to_repr().as_ref()[..32]);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cpu_commitment_deterministic() {
        let cpu1 = "Intel Core i7-9700K";
        let cpu2 = "Intel Core i7-9700K";
        let cpu3 = "AMD Ryzen 9 5900X";
        
        let commit1 = PoseidonCommitment::commit_cpu_model(cpu1);
        let commit2 = PoseidonCommitment::commit_cpu_model(cpu2);
        let commit3 = PoseidonCommitment::commit_cpu_model(cpu3);
        
        // Same input produces same output
        assert_eq!(commit1, commit2);
        // Different input produces different output
        assert_ne!(commit1, commit3);
    }
    
    #[test]
    fn test_mac_commitment_normalization() {
        // Different formats of the same MAC address
        let mac1 = "aa:bb:cc:dd:ee:ff";
        let mac2 = "AA:BB:CC:DD:EE:FF";
        let mac3 = "aa-bb-cc-dd-ee-ff";
        let mac4 = "aabbccddeeff";
        
        let commit1 = PoseidonCommitment::commit_mac_address(mac1);
        let commit2 = PoseidonCommitment::commit_mac_address(mac2);
        let commit3 = PoseidonCommitment::commit_mac_address(mac3);
        let commit4 = PoseidonCommitment::commit_mac_address(mac4);
        
        // All formats should produce the same commitment
        assert_eq!(commit1, commit2);
        assert_eq!(commit1, commit3);
        assert_eq!(commit1, commit4);
    }
    
    #[test]
    fn test_combined_commitment() {
        let cpu = "Intel Core i7";
        let mac = "11:22:33:44:55:66";
        
        let combined1 = PoseidonCommitment::commit_combined(cpu, mac);
        let combined2 = PoseidonCommitment::commit_combined(cpu, mac);
        
        // Should be deterministic
        assert_eq!(combined1, combined2);
        
        // Should be different from individual commitments
        let cpu_only = PoseidonCommitment::commit_cpu_model(cpu);
        let mac_only = PoseidonCommitment::commit_mac_address(mac);
        
        assert_ne!(combined1, cpu_only);
        assert_ne!(combined1, mac_only);
    }
    
    #[test]
    #[should_panic(expected = "Invalid MAC address format")]
    fn test_invalid_mac_format() {
        PoseidonCommitment::commit_mac_address("invalid:mac");
    }
    
    #[test]
    fn test_commitment_metadata() {
        let commitment = PoseidonCommitment::create_commitment(
            ProofType::CpuModel,
            "Test CPU",
            "00:00:00:00:00:00",
        );
        
        assert_eq!(commitment.proof_type, ProofType::CpuModel);
        assert_eq!(commitment.metadata.version, 1);
        assert_eq!(commitment.metadata.algorithm, "Poseidon-128");
        assert!(commitment.metadata.created_at > 0);
    }
}
