// src/registration.rs
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, info, warn};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use std::path::PathBuf;
use std::fs;

use crate::config::settings::ServerConfig;
use crate::server::core::ServerState;
use crate::server::metrics::ServerMetricsCollector;
use crate::utils;
use crate::hardware::HardwareInfo;

// API Response structures
#[derive(Debug, Deserialize, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
    pub errors: Option<serde_json::Value>,
}

// Registration confirmation response
#[derive(Debug, Deserialize)]
pub struct RegistrationConfirmResponse {
    pub success: bool,
    pub result_code: String,
    pub node: NodeInfo,
    pub security: SecurityInfo,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct NodeInfo {
    pub id: u64,
    pub reference_code: String,
    pub name: String,
    pub status: String,
    pub node_type: String,
    pub registration_confirmed_at: String,
    pub wallet_address: String,
}

#[derive(Debug, Deserialize)]
pub struct SecurityInfo {
    pub hardware_fingerprint_generated: bool,
    pub fingerprint_preview: String,
    pub security_level: String,
    pub registration_ip: String,
}

// WebSocket message types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    #[serde(rename = "auth")]
    Auth {
        reference_code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        registration_code: Option<String>,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat {
        status: String,
        uptime_seconds: u64,
        metrics: HeartbeatMetrics,
    },
    #[serde(rename = "status_update")]
    StatusUpdate {
        status: String,
    },
    #[serde(rename = "ping")]
    Ping {
        timestamp: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatMetrics {
    pub cpu: f64,
    pub mem: f64,
    pub disk: f64,
    pub net: f64,
}

// Stored registration data
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredRegistration {
    pub reference_code: String,
    pub wallet_address: String,
    pub hardware_fingerprint: String,
    pub registered_at: String,
    pub node_type: String,
}

// Node registration and WebSocket handler
#[derive(Clone)]
pub struct RegistrationManager {
    client: Client,
    api_url: String,
    pub reference_code: Option<String>,
    pub registration_code: Option<String>,
    pub wallet_address: Option<String>,
    hardware_fingerprint: Option<String>,
    websocket_connected: Arc<RwLock<bool>>,
    start_time: std::time::Instant,
    data_dir: PathBuf,
}

impl RegistrationManager {
    pub fn new(api_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .user_agent("AeroNyx-Node/1.0")
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(Some(Duration::from_secs(90)))
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
            hardware_fingerprint: None,
            websocket_connected: Arc::new(RwLock::new(false)),
            start_time: std::time::Instant::now(),
            data_dir: PathBuf::from("data"),
        }
    }

    // Set data directory for storing registration info
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir;
    }

    // Load existing registration from local storage
    pub fn load_from_config(&mut self, config: &ServerConfig) -> Result<bool, String> {
        debug!("Loading registration configuration");
        
        self.data_dir = config.data_dir.clone();
        
        // Try to load stored registration data
        let reg_file = self.data_dir.join("registration.json");
        if reg_file.exists() {
            match fs::read_to_string(&reg_file) {
                Ok(content) => {
                    match serde_json::from_str::<StoredRegistration>(&content) {
                        Ok(stored_reg) => {
                            info!("Loaded stored registration data");
                            self.reference_code = Some(stored_reg.reference_code.clone());
                            self.wallet_address = Some(stored_reg.wallet_address.clone());
                            self.hardware_fingerprint = Some(stored_reg.hardware_fingerprint.clone());
                            
                            // Verify hardware fingerprint hasn't changed
                            if let Err(e) = self.verify_hardware_fingerprint().await {
                                error!("Hardware fingerprint verification failed: {}", e);
                                return Err("Hardware has changed since registration".to_string());
                            }
                            
                            return Ok(true);
                        }
                        Err(e) => {
                            error!("Failed to parse registration data: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read registration file: {}", e);
                }
            }
        }
        
        // Fall back to config file data if available
        if let Some(reference_code) = &config.registration_reference_code {
            self.reference_code = Some(reference_code.clone());
            debug!("Loaded reference code from config: {}", reference_code);
        }
        
        if let Some(wallet_address) = &config.wallet_address {
            self.wallet_address = Some(wallet_address.clone());
            debug!("Loaded wallet address from config: {}", wallet_address);
        }
        
        let has_minimum = self.reference_code.is_some();
        info!("Registration configuration loaded, has minimum required data: {}", has_minimum);
        
        Ok(has_minimum)
    }

    // Verify hardware fingerprint hasn't changed
    async fn verify_hardware_fingerprint(&self) -> Result<(), String> {
        if let Some(stored_fingerprint) = &self.hardware_fingerprint {
            let current_hardware = HardwareInfo::collect().await
                .map_err(|e| format!("Failed to collect hardware info: {}", e))?;
            let current_fingerprint = current_hardware.generate_fingerprint();
            
            if &current_fingerprint != stored_fingerprint {
                error!("Hardware fingerprint mismatch!");
                error!("Stored: {}", stored_fingerprint);
                error!("Current: {}", current_fingerprint);
                return Err("Hardware has changed since registration".to_string());
            }
            
            debug!("Hardware fingerprint verified successfully");
        }
        
        Ok(())
    }

    // Save registration data locally
    fn save_registration_data(&self, node_info: &NodeInfo, hardware_fingerprint: String) -> Result<(), String> {
        let stored_reg = StoredRegistration {
            reference_code: node_info.reference_code.clone(),
            wallet_address: node_info.wallet_address.clone(),
            hardware_fingerprint,
            registered_at: node_info.registration_confirmed_at.clone(),
            node_type: node_info.node_type.clone(),
        };
        
        // Ensure data directory exists
        fs::create_dir_all(&self.data_dir)
            .map_err(|e| format!("Failed to create data directory: {}", e))?;
        
        let reg_file = self.data_dir.join("registration.json");
        let json = serde_json::to_string_pretty(&stored_reg)
            .map_err(|e| format!("Failed to serialize registration data: {}", e))?;
        
        fs::write(&reg_file, json)
            .map_err(|e| format!("Failed to save registration data: {}", e))?;
        
        info!("Registration data saved to {:?}", reg_file);
        Ok(())
    }

    // Confirm registration with hardware fingerprint
    pub async fn confirm_registration_with_hardware(
        &mut self,
        registration_code: &str,
        hardware_info: &HardwareInfo,
    ) -> Result<RegistrationConfirmResponse, String> {
        info!("Confirming node registration with hardware fingerprint");

        let hardware_fingerprint = hardware_info.generate_fingerprint();
        info!("Generated hardware fingerprint: {}...", &hardware_fingerprint[..16]);

        let node_info = serde_json::to_value(hardware_info)
            .map_err(|e| format!("Failed to serialize hardware info: {}", e))?;
        
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/json"));
        
        let payload = serde_json::json!({
            "registration_code": registration_code,
            "node_info": node_info,
            "node_signature": format!("node-sig-{}", utils::random_string(32)),
        });
        
        let url = format!("{}/api/aeronyx/confirm-registration/", self.api_url);
        debug!("Sending registration confirmation to: {}", url);

        let response = self.client
            .post(&url)
            .headers(headers)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to send registration request: {}", e))?;

        let status = response.status();
        let text = response.text().await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        debug!("Registration response: {} - {}", status, text);

        if status.is_success() {
            let api_response: ApiResponse<RegistrationConfirmResponse> = serde_json::from_str(&text)
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if api_response.success {
                if let Some(ref data) = api_response.data {
                    // Save registration data locally
                    self.save_registration_data(&data.node, hardware_fingerprint.clone())?;
                    
                    // Update internal state
                    self.reference_code = Some(data.node.reference_code.clone());
                    self.wallet_address = Some(data.node.wallet_address.clone());
                    self.hardware_fingerprint = Some(hardware_fingerprint);
                }
                
                api_response.data.ok_or_else(|| "No data in response".to_string())
            } else {
                Err(format!("Registration failed: {}", api_response.message))
            }
        } else {
            Err(format!("Registration failed with status {}: {}", status, text))
        }
    }

    // Start WebSocket connection for all node communication
    pub async fn start_websocket_connection(
        &mut self,
        reference_code: String,
        registration_code: Option<String>,
    ) -> Result<(), String> {
        self.reference_code = Some(reference_code.clone());
        if let Some(code) = registration_code {
            self.registration_code = Some(code);
        }

        // Build WebSocket URL
        let ws_url = self.api_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let ws_url = format!("{}/ws/aeronyx/node/", ws_url.trim_end_matches('/'));
        
        info!("Connecting to WebSocket: {}", ws_url);

        // Connect with retry logic
        let mut retry_count = 0;
        let max_retries = 5;
        
        loop {
            match self.connect_and_run_websocket(&ws_url).await {
                Ok(_) => {
                    info!("WebSocket connection closed normally");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    retry_count += 1;
                    
                    if retry_count >= max_retries {
                        return Err(format!("Failed to establish WebSocket connection after {} attempts", max_retries));
                    }
                    
                    let backoff = Duration::from_secs(2u64.pow(retry_count));
                    warn!("Retrying WebSocket connection in {:?} (attempt {}/{})", backoff, retry_count, max_retries);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        
        Ok(())
    }

    async fn connect_and_run_websocket(&self, ws_url: &str) -> Result<(), String> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| format!("WebSocket connection failed: {}", e))?;
        
        info!("WebSocket connected successfully");
        *self.websocket_connected.write().await = true;
        
        let (mut write, mut read) = ws_stream.split();
        
        // Set up heartbeat interval
        let mut heartbeat_interval = time::interval(Duration::from_secs(60));
        let mut authenticated = false;
        let metrics_collector = Arc::new(ServerMetricsCollector::new(
            Duration::from_secs(60),
            60,
        ));
        
        loop {
            tokio::select! {
                Some(message) = read.next() => {
                    match message {
                        Ok(Message::Text(text)) => {
                            debug!("Received WebSocket message: {}", text);
                            
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                match json.get("type").and_then(|t| t.as_str()) {
                                    Some("connection_established") => {
                                        info!("WebSocket connection established, sending auth");
                                        
                                        // Send authentication
                                        let auth_msg = if self.registration_code.is_some() {
                                            WebSocketMessage::Auth {
                                                reference_code: self.reference_code.clone().unwrap(),
                                                registration_code: self.registration_code.clone(),
                                            }
                                        } else {
                                            WebSocketMessage::Auth {
                                                reference_code: self.reference_code.clone().unwrap(),
                                                registration_code: None,
                                            }
                                        };
                                        
                                        let auth_json = serde_json::to_string(&auth_msg)
                                            .map_err(|e| format!("Failed to serialize auth: {}", e))?;
                                        
                                        write.send(Message::Text(auth_json)).await
                                            .map_err(|e| format!("Failed to send auth: {}", e))?;
                                    }
                                    
                                    Some("auth_success") => {
                                        info!("WebSocket authentication successful");
                                        authenticated = true;
                                        
                                        // Get heartbeat interval from server
                                        if let Some(interval_secs) = json.get("heartbeat_interval").and_then(|v| v.as_u64()) {
                                            heartbeat_interval = time::interval(Duration::from_secs(interval_secs));
                                        }
                                    }
                                    
                                    Some("heartbeat_ack") => {
                                        debug!("Heartbeat acknowledged");
                                        
                                        // Update next heartbeat interval if provided
                                        if let Some(next_interval) = json.get("next_interval").and_then(|v| v.as_u64()) {
                                            heartbeat_interval = time::interval(Duration::from_secs(next_interval));
                                        }
                                    }
                                    
                                    Some("error") => {
                                        let error_code = json.get("error_code").and_then(|c| c.as_str()).unwrap_or("unknown");
                                        let message = json.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                                        error!("WebSocket error [{}]: {}", error_code, message);
                                        
                                        // Handle specific errors
                                        match error_code {
                                            "hardware_fingerprint_conflict" => {
                                                return Err("Hardware already registered with another node".to_string());
                                            }
                                            "auth_failed" => {
                                                return Err("Authentication failed - invalid reference code".to_string());
                                            }
                                            "node_suspended" => {
                                                return Err("Node has been suspended".to_string());
                                            }
                                            _ => {}
                                        }
                                    }
                                    
                                    Some("command") => {
                                        // Handle server commands
                                        if let Some(command) = json.get("command").and_then(|c| c.as_str()) {
                                            info!("Received server command: {}", command);
                                            // TODO: Implement command handling
                                        }
                                    }
                                    
                                    Some("pong") => {
                                        debug!("Pong received");
                                    }
                                    
                                    _ => {
                                        debug!("Unknown message type: {:?}", json);
                                    }
                                }
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("WebSocket closed by server");
                            break;
                        }
                        Ok(Message::Ping(data)) => {
                            debug!("Received ping, sending pong");
                            write.send(Message::Pong(data)).await
                                .map_err(|e| format!("Failed to send pong: {}", e))?;
                        }
                        Err(e) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
                
                _ = heartbeat_interval.tick() => {
                    if authenticated {
                        let heartbeat = self.create_heartbeat_message(&metrics_collector).await;
                        let heartbeat_json = serde_json::to_string(&heartbeat)
                            .map_err(|e| format!("Failed to serialize heartbeat: {}", e))?;
                        
                        if let Err(e) = write.send(Message::Text(heartbeat_json)).await {
                            error!("Failed to send heartbeat: {}", e);
                            break;
                        }
                        debug!("Heartbeat sent via WebSocket");
                    }
                }
            }
        }
        
        *self.websocket_connected.write().await = false;
        
        if !authenticated {
            Err("Failed to authenticate with WebSocket server".to_string())
        } else {
            Ok(())
        }
    }

    async fn create_heartbeat_message(&self, metrics_collector: &ServerMetricsCollector) -> WebSocketMessage {
        let uptime_seconds = self.start_time.elapsed().as_secs();
        
        // Collect system metrics
        let cpu_usage = self.get_cpu_usage().await;
        let mem_usage = self.get_memory_usage().await;
        let disk_usage = self.get_disk_usage().await;
        let net_usage = self.get_network_usage().await;
        
        WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds,
            metrics: HeartbeatMetrics {
                cpu: cpu_usage,
                mem: mem_usage,
                disk: disk_usage,
                net: net_usage,
            },
        }
    }

    async fn get_cpu_usage(&self) -> f64 {
        if let Ok((one_min, _, _)) = tokio::task::spawn_blocking(|| utils::system::get_load_average()).await.unwrap_or(Err("Failed".to_string())) {
            let cpu_count = sys_info::cpu_num().unwrap_or(1) as f64;
            (one_min / cpu_count * 100.0).min(100.0)
        } else {
            0.0
        }
    }

    async fn get_memory_usage(&self) -> f64 {
        if let Ok(Ok((total, available))) = tokio::task::spawn_blocking(|| utils::system::get_system_memory()).await {
            ((total - available) as f64 / total as f64 * 100.0)
        } else {
            0.0
        }
    }

    async fn get_disk_usage(&self) -> f64 {
        if let Ok(Ok(usage)) = tokio::task::spawn_blocking(|| utils::system::get_disk_usage()).await {
            usage
        } else {
            0.0
        }
    }

    async fn get_network_usage(&self) -> f64 {
        // TODO: Implement actual network usage calculation
        10.0
    }

    // Test API connection
    pub async fn test_api_connection(&self) -> Result<bool, String> {
        info!("Testing API connection to {}", self.api_url);
        
        let url = format!("{}/api/aeronyx/node-types/", self.api_url);
        
        let response = self.client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("Connection test failed: {}", e))?;
        
        let status = response.status();
        info!("Connection test response: {}", status);
        
        Ok(status.is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_websocket_message_serialization() {
        let auth = WebSocketMessage::Auth {
            reference_code: "AERO-12345".to_string(),
            registration_code: Some("AERO-REG123".to_string()),
        };
        
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"auth\""));
        assert!(json.contains("AERO-12345"));
        
        let heartbeat = WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds: 3600,
            metrics: HeartbeatMetrics {
                cpu: 25.5,
                mem: 45.2,
                disk: 60.1,
                net: 10.3,
            },
        };
        
        let json = serde_json::to_string(&heartbeat).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
        assert!(json.contains("\"cpu\":25.5"));
    }
}
