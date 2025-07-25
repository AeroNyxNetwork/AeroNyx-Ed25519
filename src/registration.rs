// src/registration.rs
// AeroNyx Privacy Network - Node Registration Module Entry Point
// Version: 1.0.1
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This is the main entry point for the registration module.
// It re-exports all public types and functionality from the submodules.

mod types;
mod websocket;
mod hardware_verification;
mod metrics;

pub use types::*;
pub use websocket::*;
pub use hardware_verification::*;
pub use metrics::*;

use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, info, warn};
use std::path::PathBuf;
use std::fs;
use std::collections::HashSet;
use crate::zkp_halo2::{generate_hardware_proof, verify_hardware_proof, SetupParams, Proof};
use crate::websocket_protocol::{
    ServerMessage, ProofData,
    AttestationVerifyRequest,
};

use crate::config::settings::ServerConfig;
use crate::server::metrics::ServerMetricsCollector;
use crate::utils;
use crate::hardware::HardwareInfo;
use crate::remote_management::{RemoteManagementHandler, CommandResponse};
use crate::remote_command_handler::{
    RemoteCommandData, 
    RemoteCommandHandler, 
    RemoteCommandConfig, 
    RemoteCommandResponse,
    SecurityMode,
    log_remote_command
};
use crate::terminal::TerminalSessionManager;

/// Main registration manager handling node lifecycle
#[derive(Clone)]
pub struct RegistrationManager {
    /// HTTP client for API communication
    client: Client,
    /// Base API URL
    api_url: String,
    /// Node reference code
    pub reference_code: Option<String>,
    /// Registration code (used during initial setup)
    pub registration_code: Option<String>,
    /// Wallet address for rewards
    pub wallet_address: Option<String>,
    /// Hardware fingerprint
    hardware_fingerprint: Option<String>,
    /// Stored hardware components
    hardware_components: Option<HardwareComponents>,
    /// WebSocket connection status
    websocket_connected: Arc<RwLock<bool>>,
    /// Node start time
    start_time: std::time::Instant,
    /// Data directory for persistence
    data_dir: PathBuf,
    /// Remote command handler
    remote_handler: Arc<RemoteManagementHandler>,
    /// Hardware tolerance configuration
    tolerance_config: HardwareToleranceConfig,
    /// ZKP setup parameters
    zkp_params: Option<Arc<SetupParams>>,
    /// Cached hardware info for ZKP operations
    hardware_info: Option<HardwareInfo>,
    /// Remote command handler
    remote_command_handler: Arc<RemoteCommandHandler>,
    /// Remote management enabled flag
    remote_management_enabled: Arc<RwLock<bool>>,
    /// Terminal session manager
    terminal_manager: Arc<TerminalSessionManager>,
}

impl RegistrationManager {
    /// Create a new registration manager instance
    pub fn new(api_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .user_agent("AeroNyx-Node/1.0.0")
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build()
            .unwrap_or_else(|e| {
                warn!("Failed to build custom HTTP client: {}, using default", e);
                Client::new()
            });
        
        // Use restricted mode by default for security
        let remote_config = RemoteCommandConfig::default();
        let remote_command_handler = Arc::new(RemoteCommandHandler::new(remote_config));

        Self {
            client,
            api_url: api_url.to_string(),
            reference_code: None,
            registration_code: None,
            wallet_address: None,
            hardware_fingerprint: None,
            hardware_components: None,
            websocket_connected: Arc::new(RwLock::new(false)),
            start_time: std::time::Instant::now(),
            data_dir: PathBuf::from("data"),
            remote_handler: Arc::new(RemoteManagementHandler::new()),
            tolerance_config: HardwareToleranceConfig::default(),
            zkp_params: None,
            hardware_info: None,
            remote_command_handler,
            remote_management_enabled: Arc::new(RwLock::new(false)),
            terminal_manager: Arc::new(TerminalSessionManager::new()),
        }
    }
    
    /// Set security mode for remote commands
    pub fn set_remote_security_mode(&mut self, mode: SecurityMode) {
        let config = match mode {
            SecurityMode::FullAccess => {
                warn!("Setting remote command handler to FULL ACCESS mode - use with caution!");
                RemoteCommandConfig::full_access()
            }
            SecurityMode::Restricted => {
                info!("Setting remote command handler to RESTRICTED mode");
                // Create restricted config with common paths
                RemoteCommandConfig::restricted_with_paths(vec![
                    PathBuf::from("/"),
                    PathBuf::from("/home"),
                    PathBuf::from("/var"),
                    PathBuf::from("/var/log"),
                    PathBuf::from("/tmp"),
                    PathBuf::from("/etc"),
                    PathBuf::from("/usr"),
                    PathBuf::from("/opt"),
                    self.data_dir.clone(),
                ])
            }
        };
        
        self.remote_command_handler = Arc::new(RemoteCommandHandler::new(config));
    }

    /// Initialize ZKP parameters (call this during startup)
    pub async fn initialize_zkp(&self) -> Result<SetupParams, String> {
        info!("Initializing Halo2 zero-knowledge proof parameters");
        crate::zkp_halo2::initialize().await
    }

    /// Set ZKP parameters
    pub fn set_zkp_params(&mut self, params: SetupParams) {
        self.zkp_params = Some(Arc::new(params));
    }

    /// Check if ZKP is enabled
    pub fn has_zkp_enabled(&self) -> bool {
        self.zkp_params.is_some()
    }

    /// Set hardware tolerance configuration
    pub fn set_tolerance_config(&mut self, config: HardwareToleranceConfig) {
        self.tolerance_config = config;
    }

    /// Enable or disable remote management capabilities
    pub fn set_remote_management_enabled(&self, enabled: bool) {
        tokio::spawn({
            let remote_management_enabled = self.remote_management_enabled.clone();
            async move {
                *remote_management_enabled.write().await = enabled;
                if enabled {
                    info!("Remote management capabilities enabled");
                } else {
                    info!("Remote management capabilities disabled");
                }
            }
        });
    }

    /// Set data directory for storing registration information
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir;
        debug!("Data directory set to: {:?}", self.data_dir);
    }

    /// Load existing registration from local storage
    pub fn load_from_config(&mut self, config: &ServerConfig) -> Result<bool, String> {
        info!("Loading registration configuration from disk");
        
        self.data_dir = config.data_dir.clone();
        
        // Try to load stored registration data
        let reg_file = self.data_dir.join("registration.json");
        if reg_file.exists() {
            match fs::read_to_string(&reg_file) {
                Ok(content) => {
                    match serde_json::from_str::<StoredRegistration>(&content) {
                        Ok(stored_reg) => {
                            info!("Successfully loaded stored registration data");
                            info!("Node type: {}, Registered: {}", 
                                  stored_reg.node_type, stored_reg.registered_at);
                            
                            self.reference_code = Some(stored_reg.reference_code.clone());
                            self.wallet_address = Some(stored_reg.wallet_address.clone());
                            self.hardware_fingerprint = Some(stored_reg.hardware_fingerprint.clone());
                            self.hardware_components = stored_reg.hardware_components.clone();
                            
                            if let Some(commitment) = stored_reg.hardware_commitment {
                                info!("ZKP commitment found: {}...", &commitment[..16.min(commitment.len())]);
                            }
    
                            // Configure remote command handler with appropriate paths
                            let mut remote_config = RemoteCommandConfig::default();
                            remote_config.working_dir = config.data_dir.clone();
                            remote_config.allowed_paths = vec![
                                PathBuf::from("/"),              // Allow root for listing
                                PathBuf::from("/home"),
                                PathBuf::from("/var"),
                                PathBuf::from("/var/log"),
                                PathBuf::from("/var/log/aeronyx"),
                                PathBuf::from("/tmp"),
                                PathBuf::from("/etc"),           // For reading config files
                                PathBuf::from("/usr"),           // For system commands
                                PathBuf::from("/opt"),           // For optional software
                                config.data_dir.clone(),         // The node's data directory
                            ];
                            
                            // Add more permissive command whitelist for remote management
                            remote_config.command_whitelist = vec![
                                "ls".to_string(),
                                "cat".to_string(),
                                "grep".to_string(),
                                "tail".to_string(),
                                "head".to_string(),
                                "ps".to_string(),
                                "df".to_string(),
                                "du".to_string(),
                                "free".to_string(),
                                "uptime".to_string(),
                                "whoami".to_string(),
                                "pwd".to_string(),
                                "echo".to_string(),
                                "date".to_string(),
                                "hostname".to_string(),
                                "uname".to_string(),
                                "which".to_string(),
                                "wc".to_string(),
                                "sort".to_string(),
                                "uniq".to_string(),
                                "find".to_string(),
                                "stat".to_string(),
                                "file".to_string(),
                                "id".to_string(),
                                "env".to_string(),
                                "top".to_string(),
                                "htop".to_string(),
                                "iotop".to_string(),
                                "netstat".to_string(),
                                "ss".to_string(),
                                "lsof".to_string(),
                                "kill".to_string(),
                                "killall".to_string(),
                                "pkill".to_string(),
                                "sh".to_string(),
                                "bash".to_string(),
                            ];
                            
                            // Don't enable whitelist by default (allow all safe commands)
                            remote_config.enable_command_whitelist = false;
                            
                            self.remote_command_handler = Arc::new(RemoteCommandHandler::new(remote_config));
                            
                            return Ok(true);
                        }
                        Err(e) => {
                            error!("Failed to parse registration data: {}", e);
                            error!("Registration file may be corrupted or from an incompatible version");
                            return Err("Invalid registration file format".to_string());
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read registration file: {}", e);
                    return Err(format!("Cannot read registration file: {}", e));
                }
            }
        }
        
        // Fall back to config file data if available (legacy support)
        let mut loaded_from_config = false;
        
        if let Some(reference_code) = &config.registration_reference_code {
            self.reference_code = Some(reference_code.clone());
            debug!("Loaded reference code from config: {}", reference_code);
            loaded_from_config = true;
        }
        
        if let Some(wallet_address) = &config.wallet_address {
            self.wallet_address = Some(wallet_address.clone());
            debug!("Loaded wallet address from config");
            loaded_from_config = true;
        }
        
        if loaded_from_config {
            warn!("Using legacy configuration format. Please re-register for full functionality.");
            
            // Still need to configure remote command handler for legacy configs
            let mut remote_config = RemoteCommandConfig::default();
            remote_config.working_dir = config.data_dir.clone();
            remote_config.allowed_paths = vec![
                PathBuf::from("/"),
                PathBuf::from("/home"),
                PathBuf::from("/var"),
                PathBuf::from("/tmp"),
                PathBuf::from("/etc"),
                PathBuf::from("/usr"),
                PathBuf::from("/opt"),
                config.data_dir.clone(),
            ];
            remote_config.enable_command_whitelist = false;
            
            self.remote_command_handler = Arc::new(RemoteCommandHandler::new(remote_config));
        }
        
        let has_minimum = self.reference_code.is_some();
        info!("Registration data loaded, has minimum requirements: {}", has_minimum);
        
        Ok(has_minimum)
    }

    /// Extract hardware components from HardwareInfo
    pub(crate) fn extract_hardware_components(hw: &HardwareInfo) -> HardwareComponents {
        let mac_addresses = hw.network.interfaces
            .iter()
            .filter(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
            .map(|iface| iface.mac_address.to_lowercase())
            .collect();
        
        let bios_info = hw.bios_info.as_ref().map(|bios| {
            format!("{} {}", bios.system_manufacturer, bios.system_product)
        });
        
        HardwareComponents {
            mac_addresses,
            system_uuid: hw.system_uuid.clone(),
            machine_id: hw.machine_id.clone(),
            cpu_model: hw.cpu.model.clone(),
            bios_info,
        }
    }

    /// Create a deterministic serialization for ZKP circuit input
    pub fn to_zkp_bytes(&self) -> Result<Vec<u8>, String> {
        // Load the stored registration data to get the commitment
        let reg_data = self.load_registration_file()
            .map_err(|e| format!("Failed to load registration data: {}", e))?;
        
        // Get the stored commitment
        let commitment_hex = reg_data.hardware_commitment
            .ok_or("No hardware commitment found in registration")?;
        
        // Decode the hex commitment
        let commitment = hex::decode(&commitment_hex)
            .map_err(|e| format!("Invalid commitment format: {}", e))?;
        
        Ok(commitment)
    }

    /// Generate and store hardware commitment during registration
    pub async fn generate_hardware_commitment(
        &mut self,
        hardware_info: &HardwareInfo,
    ) -> Result<Vec<u8>, String> {
        info!("Generating hardware commitment for ZKP");
        
        // Use the hardware info parameter to generate commitment
        let commitment = hardware_info.generate_zkp_commitment();
        let commitment_hex = hex::encode(&commitment);
        
        info!("Hardware commitment generated: {}...", &commitment_hex[..16.min(commitment_hex.len())]);
        Ok(commitment)
    }

    /// Save registration data locally with enhanced hardware tracking
    pub(crate) fn save_registration_data(&self, node_info: &NodeInfo, hw_info: &HardwareInfo) -> Result<(), String> {
        let hardware_components = Self::extract_hardware_components(hw_info);
        let hardware_fingerprint = hw_info.generate_fingerprint();
        
        // Generate ZKP commitment
        let commitment = hw_info.generate_zkp_commitment();
        let commitment_hex = hex::encode(&commitment);
        
        let stored_reg = StoredRegistration {
            reference_code: node_info.reference_code.clone(),
            wallet_address: node_info.wallet_address.clone(),
            hardware_fingerprint,
            registered_at: node_info.registration_confirmed_at.clone(),
            node_type: node_info.node_type.clone(),
            version: 2, // Registration format version
            hardware_components: Some(hardware_components),
            hardware_commitment: Some(commitment_hex),
        };
        
        // Ensure data directory exists
        fs::create_dir_all(&self.data_dir)
            .map_err(|e| format!("Failed to create data directory: {}", e))?;
        
        let reg_file = self.data_dir.join("registration.json");
        let json = serde_json::to_string_pretty(&stored_reg)
            .map_err(|e| format!("Failed to serialize registration data: {}", e))?;
        
        // Write atomically to prevent corruption
        let temp_file = reg_file.with_extension("tmp");
        fs::write(&temp_file, json)
            .map_err(|e| format!("Failed to write registration data: {}", e))?;
        
        fs::rename(&temp_file, &reg_file)
            .map_err(|e| format!("Failed to finalize registration file: {}", e))?;
        
        info!("Registration data saved successfully to {:?}", reg_file);
        Ok(())
    }

    /// Confirm registration with hardware fingerprint
    pub async fn confirm_registration_with_hardware(
        &mut self,
        registration_code: &str,
        hardware_info: &HardwareInfo,
    ) -> Result<RegistrationConfirmResponse, String> {
        info!("Confirming node registration with hardware fingerprint and ZKP commitment");

        let hardware_fingerprint = hardware_info.generate_fingerprint();
        info!("Generated hardware fingerprint: {}...", &hardware_fingerprint[..16]);
        
        // Generate ZKP commitment
        let commitment = hardware_info.generate_zkp_commitment();
        let commitment_hex = hex::encode(&commitment);
        
        info!("Generated ZKP commitment: {}...", &commitment_hex[..16]);
        info!("Hardware details: {}", hardware_info.generate_fingerprint_summary());

        // Detect cloud provider if possible
        if let Some(provider) = hardware_info.detect_cloud_provider() {
            info!("Detected cloud provider: {}", provider);
        }

        let node_info = serde_json::to_value(hardware_info)
            .map_err(|e| format!("Failed to serialize hardware info: {}", e))?;
        
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/json"));
        
        let payload = serde_json::json!({
            "registration_code": registration_code,
            "node_info": node_info,
            "zkp_commitment": commitment_hex,
            "hardware_fingerprint": hardware_fingerprint,
            "node_signature": format!("node-sig-{}", utils::random_string(32)),
            "client_version": env!("CARGO_PKG_VERSION"),
            "tolerance_config": {
                "allow_minor_changes": self.tolerance_config.allow_minor_changes,
                "max_change_percentage": self.tolerance_config.max_change_percentage,
            }
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

        debug!("Registration response status: {}", status);

        if status.is_success() {
            let api_response: ApiResponse<RegistrationConfirmResponse> = serde_json::from_str(&text)
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if api_response.success {
                if let Some(ref data) = api_response.data {
                    // Save registration data locally with hardware components
                    self.save_registration_data(&data.node, hardware_info)?;
                    
                    // Update internal state
                    self.reference_code = Some(data.node.reference_code.clone());
                    self.wallet_address = Some(data.node.wallet_address.clone());
                    self.hardware_fingerprint = Some(hardware_fingerprint);
                    self.hardware_components = Some(Self::extract_hardware_components(hardware_info));
                    self.hardware_info = Some(hardware_info.clone());
                    
                    info!("Registration confirmed successfully!");
                    info!("Node ID: {}, Type: {}", data.node.id, data.node.node_type);
                }
                
                api_response.data.ok_or_else(|| "No data in response".to_string())
            } else {
                Err(format!("Registration failed: {}", api_response.message))
            }
        } else {
            // Parse error response for better error messages
            if let Ok(error_response) = serde_json::from_str::<ApiResponse<()>>(&text) {
                Err(format!("Registration failed: {}", error_response.message))
            } else {
                Err(format!("Registration failed with status {}: {}", status, text))
            }
        }
    }

    /// Verify hardware attestation proof (for server-side verification)
    pub fn verify_attestation_proof(
        &self,
        proof_data: Vec<u8>,
        commitment_hex: &str,
    ) -> Result<bool, String> {
        info!("Verifying hardware attestation proof");
        
        let zkp_params = self.zkp_params.as_ref()
            .ok_or("ZKP not initialized")?;
        
        let commitment = hex::decode(commitment_hex)
            .map_err(|e| format!("Invalid commitment format: {}", e))?;
        
        // Fixed: Add metadata field when creating Proof
        let proof = Proof {
            data: proof_data,
            public_inputs: commitment.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metadata: None,  // Add this missing field
        };
        
        verify_hardware_proof(&proof, &commitment, zkp_params)
            .map_err(|e| format!("Proof verification failed: {}", e))
    }

    // Helper methods for file operations
    pub(crate) fn load_registration_file(&self) -> Result<StoredRegistration, String> {
        let reg_file = self.data_dir.join("registration.json");
        let content = fs::read_to_string(&reg_file)
            .map_err(|e| format!("Failed to read registration file: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse registration data: {}", e))
    }

    pub(crate) fn save_registration_file(&self, data: &StoredRegistration) -> Result<(), String> {
        let reg_file = self.data_dir.join("registration.json");
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Failed to serialize registration data: {}", e))?;
        fs::write(&reg_file, json)
            .map_err(|e| format!("Failed to write registration file: {}", e))
    }

    /// Submit attestation proof proactively
    pub async fn submit_attestation_proof(
        &self,
        session_token: &str,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        info!("Proactively submitting hardware attestation proof");
        
        // Generate commitment and proof
        let commitment = hardware_info.generate_zkp_commitment();
        let proof = crate::zkp_halo2::generate_hardware_proof(hardware_info, &commitment, setup_params)
            .await
            .map_err(|e| format!("Failed to generate proof: {}", e))?;
        
        // Prepare request
        let request = AttestationVerifyRequest {
            proof: ProofData::from(&proof),
        };
        
        let url = format!("{}/api/aeronyx/attestation/verify/", self.api_url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", session_token))
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        
        if response.status().is_success() {
            info!("✅ Server successfully verified the submitted proof");
            Ok(())
        } else {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            Err(format!("Verification failed with status {}: {}", status, error_body))
        }
    }

    /// Test API connection health
    pub async fn test_api_connection(&self) -> Result<bool, String> {
        info!("Testing API connection to {}", self.api_url);
        
        let url = format!("{}/api/aeronyx/health/", self.api_url);
        
        let response = self.client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("Connection test failed: {}", e))?;
        
        let status = response.status();
        
        if status.is_success() {
            info!("API connection test successful");
            Ok(true)
        } else if status.as_u16() == 404 {
            // Fallback to node-types endpoint for older API versions
            let fallback_url = format!("{}/api/aeronyx/node-types/", self.api_url);
            
            let fallback_response = self.client
                .get(&fallback_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| format!("Fallback connection test failed: {}", e))?;
            
            Ok(fallback_response.status().is_success())
        } else {
            warn!("API connection test failed with status: {}", status);
            Ok(false)
        }
    }

    /// Check if node is currently connected to WebSocket
    pub async fn is_connected(&self) -> bool {
        *self.websocket_connected.read().await
    }

    /// Get node uptime in seconds
    pub fn get_uptime(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get terminal manager
    pub fn get_terminal_manager(&self) -> Arc<TerminalSessionManager> {
        self.terminal_manager.clone()
    }
    
    /// Request hardware change approval (for future implementation)
    pub async fn request_hardware_change_approval(&self, reason: &str) -> Result<(), String> {
        info!("Requesting hardware change approval: {}", reason);
        
        // This would require server-side support for hardware change approvals
        // For now, this is a placeholder for future functionality
        
        Err("Hardware change approval not yet implemented".to_string())
    }
}

#[cfg(test)]
mod tests;

// Re-export the ClientMessage type for external use
pub use crate::websocket_protocol::ClientMessage;
