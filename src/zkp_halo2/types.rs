// src/zkp_halo2/types.rs
// AeroNyx Privacy Network - Zero-Knowledge Proof Type Definitions
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module defines the core data structures used throughout the ZKP system.
// These types provide a stable interface between the various components of the
// zero-knowledge proof implementation.
//
// ## Key Types
//
// - `Proof`: Contains the zero-knowledge proof data and metadata
// - `SetupParams`: One-time generated parameters for the proof system
// - `ProofType`: Enumeration of supported proof types
// - `HardwareCommitment`: Commitment with metadata for hardware attestation
//
// ## Design Principles
//
// 1. **Serialization-friendly**: All types implement Serialize/Deserialize
// 2. **Forward-compatible**: Versioned structures for future upgrades
// 3. **Self-contained**: Proofs include all necessary verification data
// 4. **Timestamped**: Proofs include generation time for freshness checks
//
// These types form the foundation of the AeroNyx hardware attestation protocol,
// enabling privacy-preserving verification of node hardware in the DePIN network.

use serde::{Serialize, Deserialize};

/// Zero-knowledge proof data structure
/// 
/// Contains the proof itself along with metadata needed for verification.
/// The proof demonstrates knowledge of hardware details without revealing them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// The actual proof bytes (serialized Halo2 proof)
    /// Size: ~1.5KB for typical hardware attestation proofs
    pub data: Vec<u8>,
    
    /// Public inputs to the circuit (the commitment)
    /// This is what the verifier checks against
    pub public_inputs: Vec<u8>,
    
    /// Unix timestamp when the proof was generated
    /// Used for freshness checks and audit trails
    pub timestamp: u64,
}

/// Setup parameters for the proof system
/// 
/// Generated once during initialization and reused for all proofs.
/// Contains the structured reference string (SRS) and verification keys.
/// These parameters are deterministic and don't require a trusted setup.
#[derive(Clone, Serialize, Deserialize)]
pub struct SetupParams {
    /// Structured Reference String (IPA parameters)
    /// This is public and can be shared freely
    pub srs: Vec<u8>,
    
    /// Verification key for proof verification
    /// Derived from the circuit structure
    pub verifying_key: Vec<u8>,
    
    /// Proving key (optional, for caching)
    /// Can be regenerated from SRS if needed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proving_key: Option<Vec<u8>>,
}

/// Type of hardware proof being generated
/// 
/// Allows for different proof strategies depending on requirements.
/// Currently, Combined is recommended for maximum security.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofType {
    /// Proves knowledge of CPU model only
    /// Use when MAC address is not available or not required
    CpuModel,
    
    /// Proves knowledge of MAC address only
    /// Use for network-focused attestation
    MacAddress,
    
    /// Proves knowledge of both CPU model and MAC address
    /// Recommended for full hardware attestation
    Combined,
}

/// Hardware commitment with metadata
/// 
/// Wraps the raw commitment value with additional information
/// for versioning and algorithm identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCommitment {
    /// The Poseidon hash value (32 bytes)
    /// This is the binding commitment to the hardware
    pub value: [u8; 32],
    
    /// Type of proof this commitment is for
    pub proof_type: ProofType,
    
    /// Additional metadata about the commitment
    pub metadata: CommitmentMetadata,
}

/// Metadata for hardware commitments
/// 
/// Provides context about how the commitment was generated,
/// enabling future compatibility and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentMetadata {
    /// Version of the commitment scheme
    /// Allows for protocol upgrades while maintaining compatibility
    pub version: u8,
    
    /// Hash algorithm used (always "Poseidon-128" currently)
    pub algorithm: String,
    
    /// Unix timestamp when created
    pub created_at: u64,
}

/// Circuit-specific constants
/// 
/// These parameters define the constraints and limits of the ZKP circuits.
/// They must be consistent across proof generation and verification.
pub mod constants {
    /// Maximum length of CPU model string in bytes
    /// Longer strings will be truncated
    pub const MAX_CPU_MODEL_LEN: usize = 64;
    
    /// MAC address length in bytes (always 6 for Ethernet)
    pub const MAC_ADDRESS_LEN: usize = 6;
    
    /// Number of advice columns in the circuit
    /// Determines parallelism in constraint evaluation
    pub const NUM_ADVICE_COLUMNS: usize = 3;
    
    /// Circuit degree (2^K rows)
    /// K=10 for testing, K=14 for production
    pub const CIRCUIT_DEGREE: u32 = 10;
}
