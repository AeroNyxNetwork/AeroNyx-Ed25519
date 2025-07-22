// src/websocket_protocol.rs
// AeroNyx Privacy Network - WebSocket Protocol Implementation


use serde::{Deserialize, Serialize};
use crate::zkp_halo2::types::Proof;

/// Server messages received via WebSocket
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Initial connection message
    #[serde(rename = "connected")]
    Connected {
        #[serde(default)]
        message: Option<String>,
    },
    
    /// Authentication success/failure
    #[serde(rename = "auth_response")]
    AuthResponse {
        success: bool,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        node_info: Option<serde_json::Value>,
    },
    
    /// ZKP challenge request from server
    #[serde(rename = "challenge_request")]
    ChallengeRequest {
        challenge_id: String,
        #[serde(default)]
        nonce: Option<String>,
    },
    
    /// Acknowledgment of challenge response
    #[serde(rename = "challenge_response_ack")]
    ChallengeResponseAck {
        challenge_id: String,
        status: String,
        #[serde(default)]
        message: Option<String>,
    },
    
    /// Heartbeat acknowledgment
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck {
        #[serde(default)]
        received_at: Option<u64>,
        #[serde(default)]
        next_interval: Option<u64>,
    },
    
    /// Error message
    #[serde(rename = "error")]
    Error {
        error_code: String,
        message: String,
    },
    
    /// Generic message for any unhandled types
    #[serde(other)]
    Unknown,
}

/// Client messages sent via WebSocket
#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Authentication message (using 'code' field like in test script)
    #[serde(rename = "auth")]
    Auth {
        code: String,  // This is the reference_code or registration_code
    },
    
    /// Challenge response with ZKP proof
    #[serde(rename = "challenge_response")]
    ChallengeResponse {
        challenge_id: String,
        proof: ProofData,
    },
    
    /// Heartbeat message
    #[serde(rename = "heartbeat")]
    Heartbeat {
        metrics: HeartbeatMetrics,
        #[serde(skip_serializing_if = "Option::is_none")]
        timestamp: Option<u64>,
    },
}

/// Proof data structure for challenge responses
#[derive(Serialize, Debug, Clone)]
pub struct ProofData {
    /// The actual proof bytes (hex encoded)
    pub data: String,
    /// Public inputs (commitment) in hex
    pub public_inputs: String,
    /// Timestamp of proof generation
    pub timestamp: u64,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// System metrics for heartbeat (matching test script format)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatMetrics {
    pub cpu: f64,
    pub memory: f64,
    pub disk: f64,
    pub network: f64,
}

impl From<&Proof> for ProofData {
    fn from(proof: &Proof) -> Self {
        Self {
            data: hex::encode(&proof.data),
            public_inputs: hex::encode(&proof.public_inputs),
            timestamp: proof.timestamp,
            metadata: proof.metadata.as_ref().map(|m| {
                serde_json::json!({
                    "circuit_version": m.circuit_version,
                    "prover_version": m.prover_version,
                    "generation_time_ms": m.generation_time_ms,
                    "node_id": m.node_id,
                })
            }),
        }
    }
}

/// API request for attestation verification (if needed)
#[derive(Serialize, Debug)]
pub struct AttestationVerifyRequest {
    pub proof: ProofData,
}
