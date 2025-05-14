// Modified src/registration.rs
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::config::settings::ServerConfig;
use crate::server::core::ServerState;
use crate::server::metrics::ServerMetricsCollector;
use crate::utils;

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
#[derive(Clone)]
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
        // Build a robust client with retry capability
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .user_agent("AeroNyx-Node/1.0")
            .build()
            .unwrap_or_else(|_| {
                warn!("Failed to build custom HTTP client, using default");
                Client::new()
            });

        Self {
            client,
            api_url: api_url.to_string(),
            reference_code: None,
            registration_code: None,
            wallet_address: None,
            node_signature: None,
        }
    }

    // Load existing registration from config
    pub fn load_from_config(&mut self, config: &ServerConfig) -> Result<bool, String> {
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
        
        // Check if we have the minimum required data for operation
        Ok(self.reference_code.is_some() && self.wallet_address.is_some())
    }

    // Check registration status
    pub async fn check_status(&self, registration_code: &str) -> Result<NodeStatusResponse, String> {
        debug!("Checking node status with API");
        
        let response = self.client
            .post(&format!("{}/api/aeronyx/node/check-status", self.api_url))
            .json(&serde_json::json!({
                "registration_code": registration_code,
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
                    Err(format!("API error: {}", api_response.message))
                }
            },
            status => {
                Err(format!("API returned error status: {}", status))
            }
        }
    }

    // Confirm registration with the server
    pub async fn confirm_registration(&self, registration_code: &str, node_info: serde_json::Value) -> Result<bool, String> {
        info!("Confirming node registration with API");

        // Generate a node signature (in production this would be cryptographically secure)
        let node_signature = format!("node-sig-{}", utils::random_string(16));

        let response = self.client
            .post(&format!("{}/api/aeronyx/node/confirm-registration", self.api_url))
            .json(&serde_json::json!({
                "registration_code": registration_code,
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
                
                if !api_response.success {
                    warn!("Registration confirmation rejected: {}", api_response.message);
                }
                
                Ok(api_response.success)
            },
            StatusCode::TOO_MANY_REQUESTS => {
                Err("Rate limit exceeded. Please try again later.".to_string())
            },
            status => {
                Err(format!("API returned error status: {}", status))
            }
        }
    }

    // Send heartbeat to server
    pub async fn send_heartbeat(&self, status_info: serde_json::Value) -> Result<HeartbeatResponse, String> {
        if self.reference_code.is_none() {
            return Err("Missing reference code for heartbeat".to_string());
        }

        // Generate a new node signature for each heartbeat
        let node_signature = format!("node-sig-{}", utils::random_string(16));

        let reference_code = self.reference_code.as_ref().unwrap();
        debug!("Sending heartbeat for node {}", reference_code);

        let response = self.client
            .post(&format!("{}/api/aeronyx/node/heartbeat", self.api_url))
            .json(&serde_json::json!({
                "reference_code": reference_code,
                "node_signature": node_signature,
                "status_info": status_info,
            }))
            .send()
            .await
            .map_err(|e| format!("Heartbeat API request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                let api_response: ApiResponse<HeartbeatResponse> = response.json().await
                    .map_err(|e| format!("Failed to parse heartbeat response: {}", e))?;
                
                if api_response.success {
                    api_response.data.ok_or_else(|| "No data in heartbeat response".to_string())
                } else {
                    Err(format!("Heartbeat API error: {}", api_response.message))
                }
            },
            StatusCode::TOO_MANY_REQUESTS => {
                warn!("Heartbeat rate limit exceeded");
                Err("Rate limit exceeded for heartbeat".to_string())
            },
            status => {
                Err(format!("Heartbeat API returned error status: {}", status))
            }
        }
    }

    // Start heartbeat loop
    pub async fn start_heartbeat_loop(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        metrics: Arc<ServerMetricsCollector>,
    ) {
        info!("Starting node heartbeat loop");
        
        // Start with a default 60 second interval
        let mut interval = time::interval(Duration::from_secs(60));
        let mut consecutive_failures = 0;
        
        loop {
            interval.tick().await;
            
            // Check if server is still running
            let state = *server_state.read().await;
            if state != ServerState::Running {
                info!("Server not running (state: {:?}), stopping heartbeat loop", state);
                break;
            }
            
            // Collect system metrics and server data
            let status_info = self.collect_system_metrics(&metrics).await;
            
            // Send heartbeat
            match self.send_heartbeat(status_info).await {
                Ok(response) => {
                    consecutive_failures = 0;
                    debug!("Heartbeat successful. Node status: {}. Next heartbeat in {}", 
                           response.status, response.next_heartbeat);
                    
                    // Adjust heartbeat interval based on server response
                    if let Some(seconds) = self.parse_next_heartbeat(&response.next_heartbeat) {
                        if seconds != interval.period().as_secs() {
                            info!("Adjusting heartbeat interval to {} seconds", seconds);
                            interval = time::interval(Duration::from_secs(seconds));
                        }
                    }
                },
                Err(e) => {
                    consecutive_failures += 1;
                    error!("Heartbeat failed: {} (consecutive failures: {})", e, consecutive_failures);
                    
                    // Exponential backoff for failures, but not more than 5 minutes
                    if consecutive_failures > 1 {
                        let backoff_secs = (60 * consecutive_failures).min(300);
                        warn!("Increasing heartbeat interval to {} seconds due to failures", backoff_secs);
                        interval = time::interval(Duration::from_secs(backoff_secs));
                    }
                }
            }
        }
        
        info!("Heartbeat loop terminated");
    }

    // Helper to parse next heartbeat interval from API response
    fn parse_next_heartbeat(&self, next_heartbeat: &str) -> Option<u64> {
        // Handle different formats returned by API
        if next_heartbeat.contains("30 seconds") {
            Some(30)
        } else if next_heartbeat.contains("60 seconds") || next_heartbeat.contains("1 minute") {
            Some(60)
        } else if next_heartbeat.contains("120 seconds") || next_heartbeat.contains("2 minutes") {
            Some(120)
        } else if next_heartbeat.contains("300 seconds") || next_heartbeat.contains("5 minutes") {
            Some(300)
        } else {
            // Default to 60 seconds if we can't parse
            debug!("Could not parse next heartbeat time '{}', using default 60 seconds", next_heartbeat);
            Some(60)
        }
    }

    // Collect system metrics for heartbeat
    async fn collect_system_metrics(&self, metrics_collector: &ServerMetricsCollector) -> serde_json::Value {
        // Get memory usage
        let memory = match utils::system::get_system_memory() {
            Ok((total, available)) => {
                let used_percentage = ((total - available) as f64 / total as f64) * 100.0;
                used_percentage as i32
            },
            Err(_) => 0,
        };
        
        // Get CPU load
        let cpu = match utils::system::get_load_average() {
            Ok((one_min, _, _)) => (one_min * 10.0) as i32,
            Err(_) => 0,
        };
        
        // Get disk usage
        let storage = match utils::system::get_disk_usage() {
            Ok(percentage) => percentage as i32,
            Err(_) => 0,
        };
        
        // Get server metrics
        let active_connections = metrics_collector.get_active_connections().await;
        let bytes_sent = metrics_collector.get_total_bytes_sent().await;
        let bytes_received = metrics_collector.get_total_bytes_received().await;
        
        // Get uptime
        let uptime = match utils::system::get_system_uptime() {
            Ok(uptime_secs) => {
                let days = uptime_secs / 86400;
                let hours = (uptime_secs % 86400) / 3600;
                format!("{} days, {} hours", days, hours)
            },
            Err(_) => "Unknown".to_string(),
        };
        
        serde_json::json!({
            "status": "active",
            "uptime": uptime,
            "cpu_usage": cpu,
            "memory_usage": memory,
            "storage_usage": storage,
            "bandwidth_usage": {
                "sent_bytes": bytes_sent,
                "received_bytes": bytes_received,
                "active_connections": active_connections
            },
            "node_version": env!("CARGO_PKG_VERSION"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use tokio;

    #[tokio::test]
    async fn test_confirm_registration() {
        let mut server = Server::new();
        
        // Setup mock server
        let mock = server.mock("POST", "/api/aeronyx/node/confirm-registration")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"message":"Registration confirmed","data":{},"errors":null}"#)
            .create();
        
        let manager = RegistrationManager::new(&server.url());
        let result = manager.confirm_registration(
            "test-code", 
            serde_json::json!({"hostname": "test", "os_type": "linux"})
        ).await;
        
        mock.assert();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_check_status() {
        let mut server = Server::new();
        
        // Setup mock server
        let mock = server.mock("POST", "/api/aeronyx/node/check-status")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"message":"Status retrieved","data":{"id":1,"reference_code":"test-ref","name":"test-node","status":"active","node_type":"basic","created_at":"2023-01-01","activated_at":"2023-01-01","last_seen":"2023-01-01","uptime":"1 day","resources":{"cpu_usage":10,"memory_usage":20,"storage_usage":30,"bandwidth_usage":40}},"errors":null}"#)
            .create();
        
        let manager = RegistrationManager::new(&server.url());
        let result = manager.check_status("test-code").await;
        
        mock.assert();
        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.reference_code, "test-ref");
        assert_eq!(status.status, "active");
    }
}
