// src/websocket_protocol.rs
// AeroNyx Privacy Network - WebSocket Protocol Implementation


use serde::{Deserialize, Serialize};
use crate::zkp_halo2::types::Proof;

/// Server messages received via WebSocket
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// ZKP challenge request from server
    #[serde(rename = "CHALLENGE_REQUEST")]
    ChallengeRequest {
        payload: ChallengeRequestPayload,
    },
    
    /// Acknowledgment of challenge response
    #[serde(rename = "CHALLENGE_RESPONSE_ACK")]
    ChallengeResponseAck {
        payload: ChallengeResponseAckPayload,
    },
    
    /// Authentication success
    #[serde(rename = "auth_success")]
    AuthSuccess {
        #[serde(default)]
        heartbeat_interval: Option<u64>,
        #[serde(default)]
        node_info: Option<serde_json::Value>,
    },
    
    /// Heartbeat acknowledgment
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck {
        #[serde(default)]
        next_interval: Option<u64>,
    },
    
    /// Error message
    #[serde(rename = "error")]
    Error {
        error_code: String,
        message: String,
    },
    
    /// Connection established
    #[serde(rename = "connection_established")]
    ConnectionEstablished,
    
    /// Generic message for backward compatibility
    #[serde(other)]
    Unknown,
}

/// Challenge request payload
#[derive(Deserialize, Debug, Clone)]
pub struct ChallengeRequestPayload {
    pub challenge_id: String,
}

/// Challenge response acknowledgment payload
#[derive(Deserialize, Debug, Clone)]
pub struct ChallengeResponseAckPayload {
    pub challenge_id: String,
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
}

/// Client messages sent via WebSocket
#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Authentication message
    #[serde(rename = "auth")]
    Auth {
        reference_code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        registration_code: Option<String>,
    },
    
    /// Challenge response with ZKP proof
    #[serde(rename = "CHALLENGE_RESPONSE")]
    ChallengeResponse {
        payload: ChallengeResponsePayload,
    },
    
    /// Heartbeat message
    #[serde(rename = "heartbeat")]
    Heartbeat {
        status: String,
        uptime_seconds: u64,
        metrics: HeartbeatMetrics,
    },
    
    /// Status update
    #[serde(rename = "status_update")]
    StatusUpdate {
        status: String,
    },
}

/// Challenge response payload containing the ZKP proof
#[derive(Serialize, Debug, Clone)]
pub struct ChallengeResponsePayload {
    pub challenge_id: String,
    pub proof: ProofData,
}

/// Proof data structure matching the Python backend expectations
#[derive(Serialize, Debug, Clone)]
pub struct ProofData {
    /// The actual proof bytes
    pub data: Vec<u8>,
    /// Public inputs (commitment)
    pub public_inputs: Vec<u8>,
    /// Timestamp of proof generation
    pub timestamp: u64,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// System metrics for heartbeat
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatMetrics {
    pub cpu: f64,
    pub mem: f64,
    pub disk: f64,
    pub net: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<u32>,
}

impl From<&Proof> for ProofData {
    fn from(proof: &Proof) -> Self {
        Self {
            data: proof.data.clone(),
            public_inputs: proof.public_inputs.clone(),
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

/// API request for attestation verification
#[derive(Serialize, Debug)]
pub struct AttestationVerifyRequest {
    pub proof: ProofData,
}

/// API response for attestation verification
#[derive(Deserialize, Debug)]
pub struct AttestationVerifyResponse {
    pub valid: bool,
    pub challenge_id: Option<String>,
    pub message: String,
}
