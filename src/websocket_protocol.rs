// src/websocket_protocol.rs
// Fixed version with correct message structures

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
    
    /// Connection established (alternative name)
    #[serde(rename = "connection_established")]
    ConnectionEstablished,
    
    /// Authentication success
    #[serde(rename = "auth_success")]
    AuthSuccess {
        #[serde(default)]
        heartbeat_interval: Option<u64>,
        #[serde(default)]
        node_info: Option<serde_json::Value>,
    },
    
    /// Authentication response (alternative)
    #[serde(rename = "auth_response")]
    AuthResponse {
        success: bool,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        node_info: Option<serde_json::Value>,
    },
    
    /// Remote command from server
    #[serde(rename = "remote_command")]
    RemoteCommand {
        request_id: String,
        command: serde_json::Value,
        from_session: String,
    },
    
    /// Remote auth message
    #[serde(rename = "remote_auth")]
    RemoteAuth {
        jwt_token: String,
    },
    
    /// ZKP challenge request
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
    /// Authentication message - simplified format
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

/// Challenge request payload
#[derive(Deserialize, Debug, Clone)]
pub struct ChallengeRequestPayload {
    pub challenge_id: String,
}

/// Challenge response payload
#[derive(Serialize, Debug, Clone)]
pub struct ChallengeResponsePayload {
    pub challenge_id: String,
    pub proof: ProofData,
}

/// Proof data structure
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

/// System metrics for heartbeat
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

/// API request for attestation verification
#[derive(Serialize, Debug)]
pub struct AttestationVerifyRequest {
    pub proof: ProofData,
}
