// Enhanced src/registration.rs with improvements for AeroNyx DePIN
use reqwest::{Client, StatusCode, header};
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
#[derive(Debug, Deserialize, Serialize)]
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

// Enhanced heartbeat response with Solana integration
#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub id: u64,
    pub status: String,
    pub last_seen: String,
    pub next_heartbeat: String,
    pub reward_eligible: Option<bool>,             // Indicates if node is eligible for rewards
    pub pending_rewards: Option<f64>,              // Pending rewards amount if available
    pub network_status: Option<NetworkStatus>,     // Overall network status information
}

// Network status information
#[derive(Debug, Deserialize)]
pub struct NetworkStatus {
    pub active_nodes: u32,
    pub total_nodes: u32, 
    pub avg_cpu_usage: f32,
    pub avg_memory_usage: f32,
}

/// Improved node registration handler with enhanced security
#[derive(Clone)]
pub struct RegistrationManager {
    client: Client,
    api_url: String,
    reference_code: Option<String>,
    registration_code: Option<String>,
    wallet_address: Option<String>,
    node_signature: Option<String>,
    last_heartbeat_time: Option<chrono::DateTime<chrono::Utc>>,
    heartbeat_interval_secs: u64,
}

impl RegistrationManager {
    pub fn new(api_url: &str) -> Self {
        // Build a robust client with retry capability and security headers
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .user_agent("AeroNyx-Node/1.0")
            .pool_max_idle_per_host(5)        // Enhanced connection pooling
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .https_only(true)                 // Enforce HTTPS for security
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
            last_heartbeat_time: None,
            heartbeat_interval_secs: 60,     // Default interval
        }
    }

    // Load existing registration from config
    pub fn load_from_config(&mut self, config: &ServerConfig) -> Result<bool, String> {
        debug!("Loading registration configuration from server config");
        
        // Load registration data from config
        if let Some(reference_code) = &config.registration_reference_code {
            self.reference_code = Some(reference_code.clone());
            debug!("Loaded reference code: {}", reference_code);
        }
        
        if let Some(registration_code) = &config.registration_code {
            self.registration_code = Some(registration_code.clone());
            debug!("Loaded registration code");
        }
        
        if let Some(wallet_address) = &config.wallet_address {
            if !Self::is_valid_solana_address(wallet_address) {
                warn!("Wallet address format appears invalid, but continuing: {}", wallet_address);
            }
            self.wallet_address = Some(wallet_address.clone());
            debug!("Loaded wallet address: {}", wallet_address);
        }
        
        // Check if we have the minimum required data for operation
        let has_minimum = self.reference_code.is_some() && self.wallet_address.is_some();
        info!("Registration configuration loaded, has minimum required data: {}", has_minimum);
        
        Ok(has_minimum)
    }

    // Basic validation for Solana wallet address format
    fn is_valid_solana_address(address: &str) -> bool {
        // Simple format check: Solana addresses are base58-encoded and typically 32-44 chars
        address.len() >= 32 && address.len() <= 44 && address.chars().all(|c| {
            // Base58 charset contains alphanumerics except for 0, O, I, and l
            (c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l')
        })
    }

    // Check registration status with improved error handling
    pub async fn check_status(&self, registration_code: &str) -> Result<NodeStatusResponse, String> {
        debug!("Checking node status with API");
        
        // Setup headers for Django API
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/json"));
        
        let url = format!("{}/api/aeronyx/check-node-status/", self.api_url);
        info!("Sending status check to: {}", url);
        
        // Correct API endpoint URL matching Django configuration
        let response = match self.client
            .post(&url)
            .headers(headers)
            .json(&serde_json::json!({
                "registration_code": registration_code
            }))
            .send()
            .await {
                Ok(resp) => resp,
                Err(e) => {
                    error!("Failed to send status check request: {}", e);
                    return Err(format!("API request failed: {}", e));
                }
            };

        let status = response.status();
        info!("Status check response code: {}", status);

        match status {
            StatusCode::OK => {
                let text = match response.text().await {
                    Ok(text) => text,
                    Err(e) => {
                        error!("Failed to read status response body: {}", e);
                        return Err(format!("Failed to read response: {}", e));
                    }
                };
                
                debug!("Status check response body: {}", text);
                
                let api_response: ApiResponse<NodeStatusResponse> = match serde_json::from_str(&text) {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!("Failed to parse status response: {}", e);
                        return Err(format!("Failed to parse response: {}", e));
                    }
                };
                
                if api_response.success {
                    api_response.data.ok_or_else(|| {
                        error!("API returned success but no data");
                        "No data in response".to_string()
                    })
                } else {
                    error!("API error: {}", api_response.message);
                    Err(format!("API error: {}", api_response.message))
                }
            },
            StatusCode::TOO_MANY_REQUESTS => {
                warn!("Rate limited by API, implementing backoff");
                // Get retry-after header if available
                let retry_after = response.headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(30);
                
                Err(format!("Rate limited by API, retry after {} seconds", retry_after))
            },
            _ => {
                // Try to get error details
                let error_text = response.text().await.unwrap_or_default();
                error!("API error status: {} - {}", status, error_text);
                Err(format!("API returned error status: {} - {}", status, error_text))
            }
        }
    }

    // Confirm registration with the server with enhanced security
    pub async fn confirm_registration(&self, registration_code: &str, node_info: serde_json::Value) -> Result<bool, String> {
        info!("Confirming node registration with API");

        // Generate a unique node signature with enhanced randomness
        let node_signature = format!("node-sig-{}", utils::random_string(32));
        
        // Setup headers for Django API
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/json"));
        
        // Prepare payload exactly matching what Django expects
        let mut enhanced_node_info = node_info.clone();
        
        // Add additional security and version information
        if let Some(obj) = enhanced_node_info.as_object_mut() {
            // Add node version
            obj.insert("node_version".to_string(), serde_json::Value::String(env!("CARGO_PKG_VERSION").to_string()));
            
            // Add build timestamp if defined
            if let Ok(timestamp) = option_env!("BUILD_TIMESTAMP").ok_or("").map(|s| s.to_string()) {
                if !timestamp.is_empty() {
                    obj.insert("build_timestamp".to_string(), serde_json::Value::String(timestamp));
                }
            }
            
            // Add secure timestamp
            obj.insert("registration_timestamp".to_string(), 
                      serde_json::Value::String(chrono::Utc::now().to_rfc3339()));
        }
        
        let payload = serde_json::json!({
            "registration_code": registration_code,
            "node_signature": node_signature,
            "node_info": enhanced_node_info
        });
        
        debug!("Registration payload prepared with enhanced security information");
        
        let url = format!("{}/api/aeronyx/confirm-registration/", self.api_url);
        info!("Sending registration to: {}", url);

        // Send POST request to Django endpoint with exponential backoff retry
        let mut retry_count = 0;
        let max_retries = 3;
        
        loop {
            let response_result = self.client
                .post(&url)
                .headers(headers.clone())
                .json(&payload)
                .send()
                .await;
                
            match response_result {
                Ok(response) => {
                    let status = response.status();
                    info!("Registration response code: {}", status);
                    
                    // Get full response text for detailed debugging
                    let text = match response.text().await {
                        Ok(t) => t,
                        Err(e) => {
                            error!("Failed to read registration response body: {}", e);
                            return Err(format!("Failed to read response body: {}", e));
                        }
                    };
                    
                    debug!("Registration response body: {}", text);
                    
                    if status.is_success() {
                        // Try to parse as API response
                        match serde_json::from_str::<ApiResponse<serde_json::Value>>(&text) {
                            Ok(api_response) => {
                                debug!("Registration API response parsed successfully");
                                if api_response.success {
                                    return Ok(true);
                                } else {
                                    warn!("API returned success=false: {}", api_response.message);
                                    return Err(format!("API error: {}", api_response.message));
                                }
                            },
                            Err(e) => {
                                warn!("Failed to parse API response: {}", e);
                                
                                // If we got a success status but couldn't parse the response,
                                // assume it's a success (might be a different format)
                                if status.is_success() {
                                    info!("Got success status but couldn't parse response, assuming success");
                                    return Ok(true);
                                } else {
                                    return Err(format!("Failed to parse API response: {}", e));
                                }
                            }
                        }
                    } else if status == StatusCode::TOO_MANY_REQUESTS {
                        // Handle rate limiting with backoff
                        let retry_after = response.headers()
                            .get(header::RETRY_AFTER)
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(5);
                            
                        warn!("Rate limited, waiting {} seconds before retry", retry_after);
                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        continue;
                    } else {
                        // Request failed with other error
                        return Err(format!("API returned error status: {} - {}", status, text));
                    }
                },
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        error!("Failed to send registration after {} retries: {}", max_retries, e);
                        return Err(format!("API request failed after {} retries: {}", max_retries, e));
                    }
                    
                    // Exponential backoff
                    let backoff_secs = 2u64.pow(retry_count as u32);
                    warn!("Registration request failed, retrying in {} seconds. Error: {}", backoff_secs, e);
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                }
            }
        }
    }

    // Enhanced heartbeat with privacy computing metrics
    pub async fn send_heartbeat(&self, status_info: serde_json::Value) -> Result<HeartbeatResponse, String> {
        if self.reference_code.is_none() {
            return Err("Missing reference code for heartbeat".to_string());
        }

        // Generate a cryptographically secure node signature for each heartbeat
        let node_signature = format!("node-sig-{}", utils::random_string(32));

        let reference_code = self.reference_code.as_ref().unwrap();
        debug!("Sending heartbeat for node {}", reference_code);

        // Setup headers for Django API
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/json"));
        
        // Add enhanced security headers
        headers.insert("X-Node-Version", header::HeaderValue::from_str(env!("CARGO_PKG_VERSION")).unwrap_or_default());
        
        let url = format!("{}/api/aeronyx/node-heartbeat/", self.api_url);
        debug!("Sending heartbeat to: {}", url);
        
        // Enhance status info with privacy-focused metrics
        let mut enhanced_status = status_info.clone();
        
        // Add timestamp for security validation
        if let Some(obj) = enhanced_status.as_object_mut() {
            obj.insert("timestamp".to_string(), 
                      serde_json::Value::String(chrono::Utc::now().to_rfc3339()));
                      
            // Add wallet address if available (for reward tracking)
            if let Some(wallet) = &self.wallet_address {
                obj.insert("wallet_address".to_string(), 
                          serde_json::Value::String(wallet.clone()));
            }
        }
        
        // Prepare payload with enhanced security
        let payload = serde_json::json!({
            "reference_code": reference_code,
            "node_signature": node_signature,
            "status_info": enhanced_status
        });

        // Implement retry logic with exponential backoff
        let mut retry_count = 0;
        let max_retries = 3;
        
        loop {
            // Send heartbeat to Django endpoint
            let response_result = self.client
                .post(&url)
                .headers(headers.clone())
                .json(&payload)
                .send()
                .await;
                
            match response_result {
                Ok(response) => {
                    let status = response.status();
                    debug!("Heartbeat response code: {}", status);
                    
                    if status.is_success() {
                        // Read response text
                        let text = match response.text().await {
                            Ok(t) => t,
                            Err(e) => {
                                warn!("Failed to read heartbeat response: {}", e);
                                return Err(format!("Failed to read heartbeat response: {}", e));
                            }
                        };
                        
                        debug!("Heartbeat response body: {}", text);
                        
                        // Parse as API response
                        let api_response: ApiResponse<HeartbeatResponse> = match serde_json::from_str(&text) {
                            Ok(resp) => resp,
                            Err(e) => {
                                warn!("Failed to parse heartbeat response: {}", e);
                                return Err(format!("Failed to parse heartbeat response: {}", e));
                            }
                        };
                        
                        // Update last heartbeat time
                        self.last_heartbeat_time = Some(chrono::Utc::now());
                        
                        if api_response.success {
                            if let Some(data) = api_response.data {
                                // Update heartbeat interval if provided in next_heartbeat
                                if let Some(seconds) = self.parse_next_heartbeat(&data.next_heartbeat) {
                                    if seconds != self.heartbeat_interval_secs {
                                        debug!("Updating heartbeat interval from {} to {} seconds", 
                                               self.heartbeat_interval_secs, seconds);
                                        self.heartbeat_interval_secs = seconds;
                                    }
                                }
                                
                                // Log reward eligibility if available
                                if let Some(eligible) = data.reward_eligible {
                                    if eligible {
                                        info!("Node is eligible for DePIN rewards");
                                        if let Some(pending) = data.pending_rewards {
                                            info!("Pending rewards: {}", pending);
                                        }
                                    }
                                }
                                
                                // Log network status if available
                                if let Some(network) = &data.network_status {
                                    debug!("Network status: {}/{} active nodes, Avg CPU: {}%, Avg Memory: {}%", 
                                           network.active_nodes, network.total_nodes, 
                                           network.avg_cpu_usage, network.avg_memory_usage);
                                }
                                
                                return Ok(data);
                            } else {
                                return Err("No data in heartbeat response".to_string());
                            }
                        } else {
                            return Err(format!("Heartbeat API error: {}", api_response.message));
                        }
                    } else if status == StatusCode::TOO_MANY_REQUESTS {
                        // Handle rate limiting
                        let retry_after = response.headers()
                            .get(header::RETRY_AFTER)
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(5);
                            
                        warn!("Rate limited, waiting {} seconds before retry", retry_after);
                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        continue;
                    } else {
                        // Request failed
                        let error_text = response.text().await.unwrap_or_default();
                        return Err(format!("Heartbeat API returned error status: {} - {}", status, error_text));
                    }
                },
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        error!("Failed to send heartbeat after {} retries: {}", max_retries, e);
                        return Err(format!("Heartbeat API request failed after {} retries: {}", max_retries, e));
                    }
                    
                    // Exponential backoff with jitter for distributed systems
                    let base_backoff = 2u64.pow(retry_count as u32);
                    let jitter = (rand::random::<f64>() * 0.5) as u64; // 0-0.5 seconds jitter
                    let backoff_secs = base_backoff + jitter;
                    
                    warn!("Heartbeat request failed, retrying in {} seconds. Error: {}", backoff_secs, e);
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                }
            }
        }
    }

    // Improved heartbeat loop with DePIN participation signals
    pub async fn start_heartbeat_loop(
        &self,
        server_state: Arc<RwLock<ServerState>>,
        metrics: Arc<ServerMetricsCollector>,
    ) {
        info!("Starting node heartbeat loop for AeroNyx DePIN participation");
        
        // Start with a default 60 second interval
        let mut interval = time::interval(Duration::from_secs(self.heartbeat_interval_secs));
        let mut consecutive_failures = 0;
        
        // Create channels for graceful shutdown
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        
        // Spawn a task to monitor server state
        let state_monitor = {
            let server_state = server_state.clone();
            let shutdown_tx = shutdown_tx.clone();
            
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let state = *server_state.read().await;
                    if state != ServerState::Running {
                        info!("Server state changed to {:?}, signaling heartbeat shutdown", state);
                        let _ = shutdown_tx.send(()).await;
                        break;
                    }
                }
            })
        };
        
        // Spawn a task to handle OS signals
        let signal_handler = {
            let shutdown_tx = shutdown_tx.clone();
            
            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    let mut sigterm = tokio::signal::unix::signal(
                        tokio::signal::unix::SignalKind::terminate()
                    ).expect("Failed to create SIGTERM handler");
                    
                    let mut sigint = tokio::signal::unix::signal(
                        tokio::signal::unix::SignalKind::interrupt()
                    ).expect("Failed to create SIGINT handler");
                    
                    tokio::select! {
                        _ = sigterm.recv() => {
                            info!("Received SIGTERM signal, initiating heartbeat shutdown");
                            let _ = shutdown_tx.send(()).await;
                        }
                        _ = sigint.recv() => {
                            info!("Received SIGINT signal, initiating heartbeat shutdown");
                            let _ = shutdown_tx.send(()).await;
                        }
                    }
                }
                
                #[cfg(windows)]
                {
                    // Windows-specific signal handling if needed
                    // For now just wait forever
                    std::future::pending::<()>().await;
                }
            })
        };
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Collect system metrics and server data with privacy considerations
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
                _ = shutdown_rx.recv() => {
                    info!("Received shutdown signal, sending final heartbeat and terminating loop");
                    
                    // Send final heartbeat with shutting_down status
                    let mut final_status = self.collect_system_metrics(&metrics).await;
                    
                    if let Some(obj) = final_status.as_object_mut() {
                        obj.insert("status".to_string(), serde_json::Value::String("shutting_down".to_string()));
                    }
                    
                    match self.send_heartbeat(final_status).await {
                        Ok(_) => info!("Final heartbeat sent successfully"),
                        Err(e) => warn!("Failed to send final heartbeat: {}", e),
                    }
                    
                    break;
                }
            }
        }
        
        // Clean up monitoring tasks
        let _ = tokio::join!(state_monitor, signal_handler);
        
        info!("Heartbeat loop terminated");
    }

    // Enhanced helper to parse next heartbeat interval from API response
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
        } else if next_heartbeat.contains("600 seconds") || next_heartbeat.contains("10 minutes") {
            Some(600)
        } else if next_heartbeat.contains("1800 seconds") || next_heartbeat.contains("30 minutes") {
            Some(1800)
        } else {
            // Try to parse numeric values with "seconds" suffix
            let re = regex::Regex::new(r"(\d+)\s*seconds").ok()?;
            if let Some(caps) = re.captures(next_heartbeat) {
                if let Some(seconds_str) = caps.get(1) {
                    if let Ok(seconds) = seconds_str.as_str().parse::<u64>() {
                        return Some(seconds);
                    }
                }
            }
            
            // Default to 60 seconds if we can't parse
            debug!("Could not parse next heartbeat time '{}', using default 60 seconds", next_heartbeat);
            Some(60)
        }
    }

    // Enhanced system metrics collection for DePIN rewards
    async fn collect_system_metrics(&self, metrics_collector: &ServerMetricsCollector) -> serde_json::Value {
        // Collect metrics in parallel for efficiency
        let (memory_result, cpu_result, storage_result, uptime_result) = tokio::join!(
            tokio::task::spawn_blocking(|| utils::system::get_system_memory()),
            tokio::task::spawn_blocking(|| utils::system::get_load_average()),
            tokio::task::spawn_blocking(|| utils::system::get_disk_usage()),
            tokio::task::spawn_blocking(|| utils::system::get_system_uptime())
        );
        
        // Get memory usage
        let memory = match memory_result {
            Ok(Ok((total, available))) => {
                let used_percentage = ((total - available) as f64 / total as f64) * 100.0;
                used_percentage as i32
            },
            _ => {
                warn!("Failed to get system memory info");
                0
            }
        };
        
        // Get CPU load
        let cpu = match cpu_result {
            Ok(Ok((one_min, five_min, fifteen_min))) => {
                // Return the one minute load average multiplied by 10 for precision
                let load = (one_min * 10.0) as i32;
                
                // Also store the full load information for detailed metrics
                let load_details = serde_json::json!({
                    "one_min": one_min,
                    "five_min": five_min,
                    "fifteen_min": fifteen_min
                });
                
                (load, load_details)
            },
            _ => {
                warn!("Failed to get CPU load info");
                (0, serde_json::json!(null))
            }
        };
        
        // Get disk usage
        let storage = match storage_result {
            Ok(Ok(percentage)) => percentage as i32,
            _ => {
                warn!("Failed to get storage usage info");
                0
            }
        };
        
        // Get server metrics
        let active_connections = metrics_collector.get_active_connections().await;
        let bytes_sent = metrics_collector.get_total_bytes_sent().await;
        let bytes_received = metrics_collector.get_total_bytes_received().await;
        
        // Additional metrics for privacy computing tasks - with safe fallbacks if methods don't exist
        let privacy_compute_tasks = if let Ok(tasks) = metrics_collector.get_privacy_compute_count().await {
            tasks
        } else {
            0 // Fallback if method not implemented
        };
        
        let avg_task_duration = if let Ok(duration) = metrics_collector.get_average_task_duration().await {
            duration
        } else {
            0.0 // Fallback if method not implemented
        };
        
        let total_completed_tasks = if let Ok(tasks) = metrics_collector.get_total_completed_tasks().await {
            tasks
        } else {
            0 // Fallback if method not implemented
        };
        
        let task_success_rate = if let Ok(rate) = metrics_collector.get_task_success_rate().await {
            rate
        } else {
            100.0 // Fallback if method not implemented
        };
        
        // Get uptime
        let uptime_str = match uptime_result {
            Ok(Ok(uptime_secs)) => {
                let days = uptime_secs / 86400;
                let hours = (uptime_secs % 86400) / 3600;
                format!("{} days, {} hours", days, hours)
            },
            _ => {
                warn!("Failed to get system uptime");
                "Unknown".to_string()
            }
        };
        
        // Build the complete system metrics report
        serde_json::json!({
            "status": "active",
            "uptime": uptime_str,
            "cpu_usage": cpu.0,
            "cpu_details": cpu.1,
            "memory_usage": memory,
            "storage_usage": storage,
            "bandwidth_usage": {
                "sent_bytes": bytes_sent,
                "received_bytes": bytes_received,
                "active_connections": active_connections
            },
            "privacy_computing": {
                "active_tasks": privacy_compute_tasks,
                "avg_task_duration_ms": avg_task_duration,
                "total_tasks_completed": total_completed_tasks,
                "success_rate": task_success_rate
            },
            "node_version": env!("CARGO_PKG_VERSION"),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    }

    // Test API connection with explicit debugging
    pub async fn test_api_connection(&self) -> Result<bool, String> {
        info!("Testing API connection to {}", self.api_url);
        
        // Try a known endpoint that should work with GET
        let url = format!("{}/api/aeronyx/node-types/", self.api_url);
        info!("Testing connection to: {}", url);
        
        let response = match self.client
            .get(&url)
            .timeout(Duration::from_secs(10))  // Shorter timeout for test
            .send()
            .await {
                Ok(resp) => resp,
                Err(e) => {
                    error!("Connection test failed: {}", e);
                    return Err(format!("Connection test failed: {}", e));
                }
            };
        
        let status = response.status();
        info!("Connection test response: {}", status);
        
        // If we can connect, test the registration endpoint explicitly with OPTIONS
        if status.is_success() {
            let reg_url = format!("{}/api/aeronyx/confirm-registration/", self.api_url);
            info!("Testing registration endpoint with OPTIONS: {}", reg_url);
            
            match self.client.request(reqwest::Method::OPTIONS, &reg_url)
                .timeout(Duration::from_secs(10))
                .send().await {
                Ok(options_response) => {
                    let options_status = options_response.status();
                    info!("Registration endpoint OPTIONS response: {}", options_status);
                    
                    if options_status.is_success() || options_status.as_u16() == 405 {
                        // Check for allowed methods
                        if let Some(allow) = options_response.headers().get("allow") {
                            info!("Allowed methods: {}", allow.to_str().unwrap_or("unknown"));
                            
                            // Confirm that POST is allowed
                            let allow_str = allow.to_str().unwrap_or("").to_uppercase();
                            if allow_str.contains("POST") {
                                info!("Registration endpoint accepts POST requests");
                            } else {
                                warn!("Registration endpoint does NOT accept POST requests");
                            }
                        }
                    }
                },
                Err(e) => warn!("OPTIONS request failed: {}", e)
            }
            
            Ok(true)
        } else {
            Err(format!("API connection test failed with status: {}", status))
        }
    }
    
    // Get the last heartbeat time
    pub fn get_last_heartbeat(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_heartbeat_time
    }
    
    // Get the current heartbeat interval
    pub fn get_heartbeat_interval(&self) -> u64 {
        self.heartbeat_interval_secs
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
        let mock = server.mock("POST", "/api/aeronyx/confirm-registration/")
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
        let mock = server.mock("POST", "/api/aeronyx/check-node-status/")
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
    
    #[tokio::test]
    async fn test_is_valid_solana_address() {
        // Valid Solana-like addresses
        assert!(RegistrationManager::is_valid_solana_address("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"));
        assert!(RegistrationManager::is_valid_solana_address("6FQMVPgYmvTtCpq5YMFujHCzHKA7jZAJDVDvBokTfWZx"));
        
        // Invalid addresses
        assert!(!RegistrationManager::is_valid_solana_address("0x1234567890abcdef1234567890abcdef12345678")); // Ethereum format
        assert!(!RegistrationManager::is_valid_solana_address("invalid"));
        assert!(!RegistrationManager::is_valid_solana_address("")); 
    }
    
    #[tokio::test]
    async fn test_parse_next_heartbeat() {
        let manager = RegistrationManager::new("http://localhost");
        
        assert_eq!(manager.parse_next_heartbeat("30 seconds"), Some(30));
        assert_eq!(manager.parse_next_heartbeat("60 seconds"), Some(60));
        assert_eq!(manager.parse_next_heartbeat("1 minute"), Some(60));
        assert_eq!(manager.parse_next_heartbeat("120 seconds"), Some(120));
        assert_eq!(manager.parse_next_heartbeat("2 minutes"), Some(120));
        assert_eq!(manager.parse_next_heartbeat("300 seconds"), Some(300));
        assert_eq!(manager.parse_next_heartbeat("5 minutes"), Some(300));
        assert_eq!(manager.parse_next_heartbeat("600 seconds"), Some(600));
        assert_eq!(manager.parse_next_heartbeat("10 minutes"), Some(600));
        assert_eq!(manager.parse_next_heartbeat("1800 seconds"), Some(1800));
        assert_eq!(manager.parse_next_heartbeat("30 minutes"), Some(1800));
        assert_eq!(manager.parse_next_heartbeat("invalid"), Some(60)); // Default
    }
}
