//src/zkp_halo2/types.rs
use serde::{Serialize, Deserialize};

/// Zero-knowledge proof data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// The actual proof bytes (serialized Halo2 proof)
    pub data: Vec<u8>,
    /// Public inputs to the circuit (the commitment)
    pub public_inputs: Vec<u8>,
    /// Unix timestamp when the proof was generated
    pub timestamp: u64,
}

/// Setup parameters for the proof system
/// 
/// Contains the structured reference string (SRS) and verification keys.
/// These parameters are generated once and can be reused for all proofs.
#[derive(Clone, Serialize, Deserialize)]
pub struct SetupParams {
    /// Structured Reference String (KZG parameters)
    pub srs: Vec<u8>,
    /// Verification key for proof verification
    pub verifying_key: Vec<u8>,
    /// Proving key (optional, for caching)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proving_key: Option<Vec<u8>>,
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
    /// Hash algorithm used (always "Poseidon-128")
    pub algorithm: String,
    /// Unix timestamp when created
    pub created_at: u64,
}

/// Circuit-specific constants
pub mod constants {
    /// Maximum length of CPU model string in bytes
    pub const MAX_CPU_MODEL_LEN: usize = 64;
    /// MAC address length in bytes
    pub const MAC_ADDRESS_LEN: usize = 6;
    /// Number of advice columns in the circuit
    pub const NUM_ADVICE_COLUMNS: usize = 3;
    /// Circuit degree (2^K rows)
    pub const CIRCUIT_DEGREE: u32 = 10;
}
