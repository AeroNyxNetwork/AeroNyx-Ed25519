// src/remote_command_handler/models.rs
// ============================================
// Data structures for remote command handling
// ============================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Remote command received from server
#[derive(Debug, Deserialize, Serialize)]
pub struct RemoteCommandData {
    #[serde(rename = "type")]
    pub command_type: String,
    
    // Common fields
    pub path: Option<String>,
    pub paths: Option<Vec<String>>,
    pub content: Option<String>,
    pub timeout: Option<u64>,
    
    // Execute command fields
    pub cmd: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Option<HashMap<String, String>>,
    
    // File operation fields
    pub destination: Option<String>,
    pub overwrite: Option<bool>,
    pub recursive: Option<bool>,
    pub preserve_attributes: Option<bool>,
    
    // Search fields
    pub query: Option<String>,
    pub use_regex: Option<bool>,
    pub case_sensitive: Option<bool>,
    pub max_depth: Option<u32>,
    pub include_hidden: Option<bool>,
    pub file_type: Option<String>,
    
    // Permission fields
    pub mode: Option<String>,
    pub owner: Option<u32>,
    pub group: Option<u32>,
    
    // Archive fields
    pub format: Option<String>,
    pub compression_level: Option<u32>,
    
    // List/info fields
    pub categories: Option<Vec<String>>,
    pub sort_by: Option<String>,
    pub sort_reverse: Option<bool>,
    pub max_size: Option<u64>,
}

/// Remote command response
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteCommandResponse {
    pub request_id: String,
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<RemoteCommandError>,
    pub executed_at: String,
    pub execution_time_ms: Option<u64>,
}

/// Error structure for remote commands
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteCommandError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Batch operation result
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchResult {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub results: Vec<SingleOperationResult>,
}

/// Single operation result in batch
#[derive(Debug, Serialize, Deserialize)]
pub struct SingleOperationResult {
    pub path: String,
    pub success: bool,
    pub error: Option<String>,
}

/// File search result
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub path: String,
    pub name: String,
    pub file_type: String,
    pub size: u64,
    pub modified: String,
    pub match_context: Option<String>,
}
