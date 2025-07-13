// src/zkp_halo2/types.rs
// AeroNyx Privacy Network - Production-Ready Type Definitions
// Version: 8.0.0 - Optimized for efficient parameter management

use serde::{Serialize, Deserialize};
use std::fmt;

/// Zero-knowledge proof data structure
/// 
/// Contains the proof itself along with metadata needed for verification.
/// The proof demonstrates knowledge of hardware details without revealing them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// The actual proof bytes (serialized Halo2 proof)
    /// Size: ~2-4KB for typical hardware attestation proofs
    pub data: Vec<u8>,
    
    /// Public inputs to the circuit (the commitment)
    /// This is what the verifier checks against
    pub public_inputs: Vec<u8>,
    
    /// Unix timestamp when the proof was generated
    /// Used for freshness checks and audit trails
    pub timestamp: u64,
    
    /// Optional proof metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProofMetadata>,
}

/// Metadata associated with a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Circuit version used to generate the proof
    pub circuit_version: String,
    
    /// Prover version
    pub prover_version: String,
    
    /// Optional proof generation duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_time_ms: Option<u64>,
    
    /// Optional hardware identifier (non-sensitive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

/// Setup parameters for the proof system (OPTIMIZED)
/// 
/// Generated once during initialization and reused for all proofs.
/// This version includes pre-generated keys for optimal performance.
#[derive(Clone, Serialize, Deserialize)]
pub struct SetupParams {
    /// Structured Reference String (KZG parameters)
    /// This is public and can be shared freely
    pub srs: Vec<u8>,
    
    /// Verification key for proof verification (CACHED)
    /// Pre-serialized for fast loading
    pub verifying_key: Vec<u8>,
    
    /// Proving key (CACHED for optimal performance)
    /// Pre-serialized to avoid regeneration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proving_key: Option<Vec<u8>>,
    
    /// Metadata about the setup parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SetupMetadata>,
}

/// Metadata for setup parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupMetadata {
    /// Circuit degree (k parameter)
    pub k: u32,
    
    /// Generation timestamp
    pub generated_at: u64,
    
    /// Circuit version these parameters are for
    pub circuit_version: String,
    
    /// Size information
    pub size_info: SizeInfo,
}

/// Size information for setup parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeInfo {
    /// SRS size in bytes
    pub srs_size: usize,
    
    /// Verifying key size in bytes
    pub vk_size: usize,
    
    /// Proving key size in bytes
    pub pk_size: usize,
}

impl SetupParams {
    /// Create new setup parameters with metadata
    pub fn new(srs: Vec<u8>, verifying_key: Vec<u8>, proving_key: Option<Vec<u8>>, k: u32) -> Self {
        let size_info = SizeInfo {
            srs_size: srs.len(),
            vk_size: verifying_key.len(),
            pk_size: proving_key.as_ref().map(|pk| pk.len()).unwrap_or(0),
        };
        
        let metadata = SetupMetadata {
            k,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            circuit_version: env!("CARGO_PKG_VERSION").to_string(),
            size_info,
        };
        
        Self {
            srs,
            verifying_key,
            proving_key,
            metadata: Some(metadata),
        }
    }
    
    /// Get the circuit degree
    pub fn k(&self) -> u32 {
        self.metadata.as_ref().map(|m| m.k).unwrap_or(14)
    }
    
    /// Check if proving key is available
    pub fn has_proving_key(&self) -> bool {
        self.proving_key.is_some()
    }
    
    /// Get total size of all parameters
    pub fn total_size(&self) -> usize {
        self.srs.len() + 
        self.verifying_key.len() + 
        self.proving_key.as_ref().map(|pk| pk.len()).unwrap_or(0)
    }
}

impl fmt::Debug for SetupParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupParams")
            .field("srs_size", &self.srs.len())
            .field("vk_size", &self.verifying_key.len())
            .field("pk_size", &self.proving_key.as_ref().map(|pk| pk.len()))
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Type of hardware proof being generated
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofType {
    /// Proves knowledge of CPU model only
    CpuModel,
    
    /// Proves knowledge of MAC address only
    MacAddress,
    
    /// Proves knowledge of both CPU model and MAC address
    Combined,
    
    /// Proves knowledge of extended hardware components
    Extended { component_count: usize },
}

/// Hardware commitment with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCommitment {
    /// The Poseidon hash value (32 bytes)
    pub value: [u8; 32],
    
    /// Type of proof this commitment is for
    pub proof_type: ProofType,
    
    /// Additional metadata about the commitment
    pub metadata: CommitmentMetadata,
}

/// Metadata for hardware commitments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentMetadata {
    /// Version of the commitment scheme
    pub version: u8,
    
    /// Hash algorithm used
    pub algorithm: String,
    
    /// Unix timestamp when created
    pub created_at: u64,
    
    /// Optional hardware fingerprint (non-sensitive hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl HardwareCommitment {
    /// Create a new hardware commitment
    pub fn new(value: [u8; 32], proof_type: ProofType) -> Self {
        Self {
            value,
            proof_type,
            metadata: CommitmentMetadata {
                version: 1,
                algorithm: "Poseidon-128".to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                fingerprint: None,
            },
        }
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.value)
    }
    
    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Invalid hex: {}", e))?;
        
        if bytes.len() != 32 {
            return Err(format!("Invalid commitment length: {} (expected 32)", bytes.len()));
        }
        
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes);
        Ok(commitment)
    }
}

/// Circuit-specific constants
pub mod constants {
    /// Maximum length of CPU model string in bytes
    pub const MAX_CPU_MODEL_LEN: usize = 64;
    
    /// MAC address length in bytes (always 6 for Ethernet)
    pub const MAC_ADDRESS_LEN: usize = 6;
    
    /// Number of advice columns in the circuit
    pub const NUM_ADVICE_COLUMNS: usize = 3;
    
    /// Circuit degree for testing
    pub const CIRCUIT_DEGREE_TEST: u32 = 10;
    
    /// Circuit degree for production
    pub const CIRCUIT_DEGREE_PROD: u32 = 14;
    
    /// Maximum proof age in seconds (5 minutes)
    pub const MAX_PROOF_AGE_SECS: u64 = 300;
    
    /// Commitment size in bytes
    pub const COMMITMENT_SIZE: usize = 32;
}

/// Errors that can occur in the ZKP system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZkpError {
    /// Setup parameters not initialized
    NotInitialized,
    
    /// Proof generation failed
    ProofGenerationFailed(String),
    
    /// Proof verification failed
    VerificationFailed(String),
    
    /// Invalid commitment format
    InvalidCommitment(String),
    
    /// Proof expired
    ProofExpired { age_secs: u64 },
    
    /// Hardware mismatch
    HardwareMismatch,
    
    /// Serialization error
    SerializationError(String),
}

impl fmt::Display for ZkpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "ZKP system not initialized"),
            Self::ProofGenerationFailed(e) => write!(f, "Proof generation failed: {}", e),
            Self::VerificationFailed(e) => write!(f, "Proof verification failed: {}", e),
            Self::InvalidCommitment(e) => write!(f, "Invalid commitment: {}", e),
            Self::ProofExpired { age_secs } => write!(f, "Proof expired ({} seconds old)", age_secs),
            Self::HardwareMismatch => write!(f, "Hardware commitment mismatch"),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for ZkpError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_setup_params_size() {
        let params = SetupParams::new(
            vec![0; 1024 * 100], // 100KB SRS
            vec![0; 1024 * 10],  // 10KB VK
            Some(vec![0; 1024 * 50]), // 50KB PK
            14,
        );
        
        assert_eq!(params.total_size(), 1024 * 160);
        assert_eq!(params.k(), 14);
        assert!(params.has_proving_key());
    }
    
    #[test]
    fn test_commitment_hex_conversion() {
        let mut value = [0u8; 32];
        value[0] = 0xAB;
        value[31] = 0xCD;
        
        let commitment = HardwareCommitment::new(value, ProofType::Combined);
        let hex = commitment.to_hex();
        
        assert!(hex.starts_with("ab"));
        assert!(hex.ends_with("cd"));
        
        let parsed = HardwareCommitment::from_hex(&hex).unwrap();
        assert_eq!(parsed, value);
    }
    
    #[test]
    fn test_error_display() {
        let err = ZkpError::ProofExpired { age_secs: 600 };
        assert_eq!(err.to_string(), "Proof expired (600 seconds old)");
    }
}
