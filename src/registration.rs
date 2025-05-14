// src/registration.rs
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info};

// API Response structure
#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
    pub errors: Option<serde_json::Value>,
}

// Registration code response
#[derive(Debug, Deserialize)]
pub struct RegistrationCodeResponse {
    pub node_id: u64,
    pub reference_code: String,
    pub registration_code: String,
    pub setup_command: String,
}

// Node status response
#[derive(Debug, Deserialize)]
pub struct NodeStatusResponse {
    pub id: u64,
    pub reference_code: String,
    pub name: String,
    pub status: String,
    pub node_type: String,
    pub created_at: String,
    pub activated_at: Option<String>,
    pub last_seen: Option<String>,
    pub uptime: String,
    pub resources: NodeResources,
}

#[derive(Debug, Deserialize)]
pub struct NodeResources {
    pub cpu_usage: i32,
    pub memory_usage: i32,
    pub storage_usage: i32,
    pub bandwidth_usage: i32,
}

// Heartbeat response
#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub id: u64,
    pub status: String,
    pub last_seen: String,
    pub next_heartbeat: String,
}

// Node registration handler
pub struct RegistrationManager {
    client: Client,
    api_url: String,
    reference_code: Option<String>,
    registration_code: Option<String>,
    wallet_address: Option<String>,
    node_signature: Option<String>,
}

impl RegistrationManager {
    pub fn new(api_url: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            api_url: api_url.to_string(),
            reference_code: None,
            registration_code: None,
            wallet_address: None,
            node_signature: None,
        }
    }

    // Load existing registration
    pub fn load_from_config(&mut self, config: &crate::config::settings::ServerConfig) -> Result<bool, String> {
        // Load registration data from config
        if let Some(reference_code) = &config.registration_reference_code {
            self.reference_code = Some(reference_code.clone());
        }
        
        if let Some(registration_code) = &config.registration_code {
            self.registration_code = Some(registration_code.clone());
        }
        
        if let Some(wallet_address) = &config.wallet_address {
            self.wallet_address = Some(wallet_address.clone());
        }
        
        // Check if we have the minimum required data
        Ok(self.reference_code.is_some() && self.wallet_address.is_some())
    }

    // Check registration status
    pub async fn check_status(&self) -> Result<NodeStatusResponse, String> {
        if self.reference_code.is_none() || self.wallet_address.is_none() {
            return Err("Missing reference code or wallet address".to_string());
        }

        let response = self.client
            .post(&format!("{}/api/aeronyx/node/check-status", self.api_url))
            .json(&serde_json::json!({
                "reference_code": self.reference_code,
                "wallet_address": self.wallet_address,
            }))
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                let api_response: ApiResponse<NodeStatusResponse> = response.json().await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;
                
                if api_response.success {
                    api_response.data.ok_or_else(|| "No data in response".to_string())
                } else {
                    Err(api_response.message)
                }
            },
            status => {
                Err(format!("API returned error status: {}", status))
            }
        }
    }

    // Confirm registration with the server
    pub async fn confirm_registration(&self, node_info: serde_json::Value) -> Result<bool, String> {
        if self.registration_code.is_none() {
            return Err("Missing registration code".to_string());
        }

        // Create a system signature (in production would be cryptographically secure)
        let node_signature = format!("node-sig-{}", utils::random_string(16));

        let response = self.client
            .post(&format!("{}/api/aeronyx/node/confirm-registration", self.api_url))
            .json(&serde_json::json!({
                "registration_code": self.registration_code,
                "node_signature": node_signature,
                "node_info": node_info,
            }))
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                let api_response: ApiResponse<serde_json::Value> = response.json().await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;
                
                Ok(api_response.success)
            },
            status => {
                Err(format!("API returned error status: {}", status))
            }
        }
    }

    // Send heartbeat to server
    pub async fn send_heartbeat(&self, status_info: serde_json::Value) -> Result<HeartbeatResponse, String> {
        if self.reference_code.is_none() {
            return Err("Missing reference code".to_string());
        }

        // Create a system signature (in production would be cryptographically secure)
        let node_signature = format!("node-sig-{}", utils::random_string(16));

        let response = self.client
            .post(&format!("{}/api/aeronyx/node/heartbeat", self.api_url))
            .json(&serde_json::json!({
                "reference_code": self.reference_code,
                "node_signature": node_signature,
                "status_info": status_info,
            }))
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                let api_response: ApiResponse<HeartbeatResponse> = response.json().await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;
                
                if api_response.success {
                    api_response.data.ok_or_else(|| "No data in response".to_string())
                } else {
                    Err(api_response.message)
                }
            },
            status => {
                Err(format!("API returned error status: {}", status))
            }
        }
    }

    // Start heartbeat loop
    pub async fn start_heartbeat_loop(&self, server_state: Arc<RwLock<crate::server::core::ServerState>>) {
        info!("Starting heartbeat loop");
        let mut interval = time::interval(Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // Check if server is still running
            let state = *server_state.read().await;
            if state != crate::server::core::ServerState::Running {
                info!("Server not running, stopping heartbeat loop");
                break;
            }
            
            // Collect system metrics
            let status_info = self.collect_system_metrics().await;
            
            // Send heartbeat
            match self.send_heartbeat(status_info).await {
                Ok(response) => {
                    debug!("Heartbeat successful. Next heartbeat in {}", response.next_heartbeat);
                    
                    // Adjust heartbeat interval if needed
                    if response.next_heartbeat.contains("30 seconds") {
                        interval = time::interval(Duration::from_secs(30));
                    } else if response.next_heartbeat.contains("120 seconds") {
                        interval = time::interval(Duration::from_secs(120));
                    }
                },
                Err(e) => {
                    error!("Heartbeat failed: {}", e);
                }
            }
        }
    }

    // Collect system metrics for heartbeat
    async fn collect_system_metrics(&self) -> serde_json::Value {
        // Get memory usage
        let memory = match crate::utils::system::get_system_memory() {
            Ok((total, available)) => {
                let used_percentage = ((total - available) as f64 / total as f64) * 100.0;
                used_percentage as i32
            },
            Err(_) => 0,
        };
        
        // Get CPU load
        let cpu = match crate::utils::system::get_load_average() {
            Ok((one_min, _, _)) => (one_min * 10.0) as i32,
            Err(_) => 0,
        };
        
        // Get uptime (simplified)
        let uptime = "0 days, 1 hour"; // Would use actual system uptime
        
        serde_json::json!({
            "status": "active",
            "uptime": uptime,
            "cpu_usage": cpu,
            "memory_usage": memory,
            "storage_usage": 30, // Placeholder
            "bandwidth_usage": 20, // Placeholder
        })
    }
}
