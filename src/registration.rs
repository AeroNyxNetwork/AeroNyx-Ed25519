// src/registration.rs
// AeroNyx Privacy Network - Node Registration and Management Module
// Version: 1.0.1 - Fixed missing metadata fields
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module handles node registration, authentication, and real-time communication
// with the AeroNyx control plane. It manages WebSocket connections for continuous
// monitoring, heartbeat reporting, and remote management capabilities. The module
// implements hardware fingerprint verification with tolerance for minor changes
// in cloud environments.

use reqwest::{Client, header};
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
use std::collections::HashSet;
use crate::zkp_halo2::{generate_hardware_proof, verify_hardware_proof, SetupParams, Proof};
use crate::websocket_protocol::{
    ServerMessage, ClientMessage, ProofData,
    AttestationVerifyRequest
};

use crate::config::settings::ServerConfig;
use crate::server::metrics::ServerMetricsCollector;
use crate::utils;
use crate::hardware::HardwareInfo;
use crate::remote_management::{RemoteCommand as RemoteMgmtCommand, RemoteManagementHandler, CommandResponse};
use crate::remote_command_handler::{
    RemoteCommandData, 
    RemoteCommandHandler, 
    RemoteCommandConfig, 
    RemoteCommandResponse, 
    RemoteCommandError,
    log_remote_command
};
/// Generic API response wrapper
#[derive(Debug, Deserialize, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
    pub errors: Option<serde_json::Value>,
}

/// Registration confirmation response structure
#[derive(Debug, Deserialize)]
pub struct RegistrationConfirmResponse {
    pub success: bool,
    pub result_code: String,
    pub node: NodeInfo,
    pub security: SecurityInfo,
    pub next_steps: Vec<String>,
}

/// Node information returned from registration
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

/// Security information for the registered node
#[derive(Debug, Deserialize)]
pub struct SecurityInfo {
    pub hardware_fingerprint_generated: bool,
    pub fingerprint_preview: String,
    pub security_level: String,
    pub registration_ip: String,
}

/// WebSocket message types for node communication
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    /// Authentication message sent after connection
    #[serde(rename = "auth")]
    Auth {
        reference_code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        registration_code: Option<String>,
    },

    #[serde(rename = "remote_command")]
    RemoteCommand {
        request_id: String,
        from_session: String,
        command: RemoteCommandData,  
    },
    
    /// Remote command response to server
    #[serde(rename = "remote_command_response")]
    RemoteCommandResponse {
        #[serde(flatten)]  
        response: RemoteCommandResponse,
    },
    
    /// Periodic heartbeat with system metrics
    #[serde(rename = "heartbeat")]
    Heartbeat {
        status: String,
        uptime_seconds: u64,
        metrics: LegacyHeartbeatMetrics,
    },
    
    /// Status update notification
    #[serde(rename = "status_update")]
    StatusUpdate {
        status: String,
    },
    
    /// Ping message for connection health
    #[serde(rename = "ping")]
    Ping {
        timestamp: u64,
    },
    
    /// Response to remote command execution
    #[serde(rename = "command_response")]
    CommandResponse {
        request_id: String,
        response: CommandResponse,
    },
    
    /// Hardware change notification
    #[serde(rename = "hardware_change")]
    HardwareChange {
        old_fingerprint: String,
        new_fingerprint: String,
        changed_components: Vec<String>,
        reason: String,
    },
    
    /// Request for hardware attestation proof
    #[serde(rename = "hardware_attestation_request")]
    HardwareAttestationRequest {
        challenge: Vec<u8>,
        nonce: String,
    },
    
    /// Hardware attestation proof response
    #[serde(rename = "hardware_attestation_proof")]
    HardwareAttestationProof {
        commitment: String,
        proof: Vec<u8>,
        nonce: String,
    },
}

/// System metrics included in heartbeat messages
#[derive(Debug, Serialize, Deserialize)]
pub struct LegacyHeartbeatMetrics {
    pub cpu: f64,
    pub mem: f64,
    pub disk: f64,
    pub net: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<u32>,
}

/// Stored registration data for persistence
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredRegistration {
    pub reference_code: String,
    pub wallet_address: String,
    pub hardware_fingerprint: String,
    pub registered_at: String,
    pub node_type: String,
    #[serde(default)]
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_components: Option<HardwareComponents>,
    /// Zero-knowledge proof commitment (added for ZKP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_commitment: Option<String>,
}

/// Individual hardware components for granular tracking
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HardwareComponents {
    pub mac_addresses: HashSet<String>,
    pub system_uuid: Option<String>,
    pub machine_id: Option<String>,
    pub cpu_model: String,
    pub bios_info: Option<String>,
}

/// Configuration for hardware change tolerance
#[derive(Debug, Clone)]
pub struct HardwareToleranceConfig {
    /// Allow minor hardware changes (e.g., network interface additions)
    pub allow_minor_changes: bool,
    /// Require at least one original MAC address to remain
    pub require_mac_match: bool,
    /// Allow CPU model changes (for cloud provider upgrades)
    pub allow_cpu_change: bool,
    /// Maximum percentage of components that can change
    pub max_change_percentage: f32,
}

impl Default for HardwareToleranceConfig {
    fn default() -> Self {
        Self {
            allow_minor_changes: true,
            require_mac_match: true,
            allow_cpu_change: false,
            max_change_percentage: 0.3, // Allow up to 30% change
        }
    }
}

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
            }
        }
        
        /// Set security mode for remote commands
        pub fn set_remote_security_mode(&mut self, mode: crate::remote_command_handler::SecurityMode) {
            let config = match mode {
                crate::remote_command_handler::SecurityMode::FullAccess => {
                    warn!("Setting remote command handler to FULL ACCESS mode - use with caution!");
                    RemoteCommandConfig::full_access()
                }
                crate::remote_command_handler::SecurityMode::Restricted => {
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
    /// Verify hardware fingerprint with tolerance for minor changes
    pub async fn verify_hardware_fingerprint(&self) -> Result<(), String> {
        if let Some(stored_fingerprint) = &self.hardware_fingerprint {
            info!("Verifying hardware fingerprint...");
            
            let current_hardware = HardwareInfo::collect().await
                .map_err(|e| format!("Failed to collect hardware info: {}", e))?;
            let current_fingerprint = current_hardware.generate_fingerprint();
            
            info!("Hardware summary: {}", current_hardware.generate_fingerprint_summary());
            
            // Exact match - best case
            if &current_fingerprint == stored_fingerprint {
                info!("Hardware fingerprint verified successfully (exact match)");
                return Ok(());
            }
            
            // Check if we should allow minor changes
            if self.tolerance_config.allow_minor_changes {
                match self.check_hardware_similarity(&current_hardware).await {
                    Ok(similarity) => {
                        info!("Hardware similarity score: {:.2}%", similarity * 100.0);
                        
                        if similarity >= (1.0 - self.tolerance_config.max_change_percentage) {
                            warn!("Hardware has minor changes but within tolerance threshold");
                            
                            // Optionally notify about hardware changes
                            if let Err(e) = self.notify_hardware_change(&current_hardware, similarity).await {
                                warn!("Failed to notify hardware change: {}", e);
                            }
                            
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check hardware similarity: {}", e);
                    }
                }
            }
            
            error!("Hardware fingerprint verification failed");
            error!("Expected: {}...", &stored_fingerprint[..16]);
            error!("Current:  {}...", &current_fingerprint[..16]);
            
            // Provide detailed error information
            if self.tolerance_config.require_mac_match {
                if !self.has_matching_mac_addresses(&current_hardware) {
                    error!("No matching MAC addresses found - this appears to be different hardware");
                }
            }
            
            return Err("Hardware has changed beyond acceptable tolerance".to_string());
        } else {
            error!("No hardware fingerprint found in registration data");
            return Err("Missing hardware fingerprint - re-registration required".to_string());
        }
    }

    /// Check hardware similarity score
    async fn check_hardware_similarity(&self, current_hw: &HardwareInfo) -> Result<f32, String> {
        if let Some(stored_components) = &self.hardware_components {
            let mut match_score = 0.0;
            let mut total_components = 0.0;
            
            // Check MAC addresses
            let current_macs: HashSet<String> = current_hw.network.interfaces
                .iter()
                .filter(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
                .map(|iface| iface.mac_address.to_lowercase())
                .collect();
            
            if !stored_components.mac_addresses.is_empty() {
                let matching_macs = stored_components.mac_addresses
                    .intersection(&current_macs)
                    .count();
                
                match_score += matching_macs as f32 / stored_components.mac_addresses.len().max(1) as f32;
                total_components += 1.0;
            }
            
            // Check system UUID
            if stored_components.system_uuid.is_some() {
                if current_hw.system_uuid == stored_components.system_uuid {
                    match_score += 1.0;
                }
                total_components += 1.0;
            }
            
            // Check machine ID
            if stored_components.machine_id.is_some() {
                if current_hw.machine_id == stored_components.machine_id {
                    match_score += 1.0;
                }
                total_components += 1.0;
            }
            
            // Check CPU model (if not allowed to change)
            if !self.tolerance_config.allow_cpu_change {
                if current_hw.cpu.model == stored_components.cpu_model {
                    match_score += 1.0;
                }
                total_components += 1.0;
            }
            
            if total_components > 0.0 {
                Ok(match_score / total_components)
            } else {
                Ok(0.0)
            }
        } else {
            // No detailed components stored, fall back to basic check
            Ok(0.0)
        }
    }

    /// Check if at least one MAC address matches
    fn has_matching_mac_addresses(&self, current_hw: &HardwareInfo) -> bool {
        if let Some(stored_components) = &self.hardware_components {
            let current_macs: HashSet<String> = current_hw.network.interfaces
                .iter()
                .filter(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
                .map(|iface| iface.mac_address.to_lowercase())
                .collect();
            
            !stored_components.mac_addresses.is_disjoint(&current_macs)
        } else {
            false
        }
    }

    /// Notify server about hardware changes
    async fn notify_hardware_change(&self, current_hw: &HardwareInfo, similarity: f32) -> Result<(), String> {
        warn!("Hardware change detected, similarity: {:.2}%", similarity * 100.0);
        
        // In a production system, this would send a notification to the server
        // For now, we just log it
        
        let changed_components = self.detect_changed_components(current_hw);
        info!("Changed components: {:?}", changed_components);
        
        Ok(())
    }

    /// Detect which hardware components have changed
    fn detect_changed_components(&self, current_hw: &HardwareInfo) -> Vec<String> {
        let mut changes = Vec::new();
        
        if let Some(stored) = &self.hardware_components {
            // Check MACs
            let current_macs: HashSet<String> = current_hw.network.interfaces
                .iter()
                .filter(|iface| iface.is_physical)
                .map(|iface| iface.mac_address.to_lowercase())
                .collect();
            
            if stored.mac_addresses != current_macs {
                changes.push("Network interfaces".to_string());
            }
            
            // Check system identifiers
            if stored.system_uuid != current_hw.system_uuid {
                changes.push("System UUID".to_string());
            }
            
            if stored.machine_id != current_hw.machine_id {
                changes.push("Machine ID".to_string());
            }
            
            if stored.cpu_model != current_hw.cpu.model {
                changes.push("CPU model".to_string());
            }
        }
        
        changes
    }

    /// Extract hardware components from HardwareInfo
    fn extract_hardware_components(hw: &HardwareInfo) -> HardwareComponents {
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
    fn save_registration_data(&self, node_info: &NodeInfo, hw_info: &HardwareInfo) -> Result<(), String> {
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

    /// Handle hardware attestation request
    pub async fn handle_attestation_request(
        &self,
        _challenge: Vec<u8>,
        nonce: String,
    ) -> Result<WebSocketMessage, String> {
        info!("Handling hardware attestation request");
        
        // Check if ZKP is enabled
        let zkp_params = self.zkp_params.as_ref()
            .ok_or("ZKP not initialized")?;
        
        // Collect current hardware info
        let current_hw = HardwareInfo::collect().await
            .map_err(|e| format!("Failed to collect hardware info: {}", e))?;
        
        // Load stored commitment
        let reg_data = self.load_registration_file()
            .map_err(|e| format!("Failed to load registration data: {}", e))?;
        
        let commitment_hex = reg_data.hardware_commitment
            .ok_or("No hardware commitment found in registration")?;
        
        let commitment = hex::decode(&commitment_hex)
            .map_err(|e| format!("Invalid commitment format: {}", e))?;
        
        // Verify hardware hasn't changed
        if !current_hw.verify_commitment(&commitment) {
            warn!("Hardware has changed since registration");
            // In production, this might trigger a re-registration flow
        }
        
        // Generate ZKP proof
        let proof = generate_hardware_proof(&current_hw, &commitment, zkp_params)
            .await
            .map_err(|e| format!("Failed to generate proof: {}", e))?;
        
        Ok(WebSocketMessage::HardwareAttestationProof {
            commitment: commitment_hex,
            proof: proof.data,
            nonce,
        })
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
    fn load_registration_file(&self) -> Result<StoredRegistration, String> {
        let reg_file = self.data_dir.join("registration.json");
        let content = fs::read_to_string(&reg_file)
            .map_err(|e| format!("Failed to read registration file: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse registration data: {}", e))
    }

    fn save_registration_file(&self, data: &StoredRegistration) -> Result<(), String> {
        let reg_file = self.data_dir.join("registration.json");
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Failed to serialize registration data: {}", e))?;
        fs::write(&reg_file, json)
            .map_err(|e| format!("Failed to write registration file: {}", e))
    }

    /// Start WebSocket connection for real-time communication (original version for compatibility)
    pub async fn start_websocket_connection(
        &mut self,
        reference_code: String,
        registration_code: Option<String>,
    ) -> Result<(), String> {
        // Collect hardware info if not already cached
        let hardware_info = if let Some(ref hw_info) = self.hardware_info {
            hw_info.clone()
        } else {
            HardwareInfo::collect().await
                .map_err(|e| format!("Failed to collect hardware info: {}", e))?
        };
        
        // Initialize ZKP if not already done
        let setup_params = if let Some(ref params) = self.zkp_params {
            params.as_ref().clone()
        } else {
            let params = self.initialize_zkp().await?;
            self.set_zkp_params(params.clone());
            params
        };
        
        self.start_websocket_connection_with_params(
            reference_code,
            registration_code,
            &hardware_info,
            &setup_params,
        ).await
    }

    /// Start WebSocket connection with explicit hardware info and ZKP params
    pub async fn start_websocket_connection_with_params(
        &mut self,
        reference_code: String,
        registration_code: Option<String>,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
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

        // For registration setup, only do a single connection attempt
        let is_setup_mode = self.registration_code.is_some();
        let max_retries = if is_setup_mode { 1 } else { 5 };
        
        // Connect with retry logic
        let mut retry_count = 0;
        let mut backoff = Duration::from_secs(1);
        
        // Clone for the async task
        let hw_info = hardware_info.clone();
        let params = setup_params.clone();
        
        loop {
            match self.connect_and_run_websocket_v2(&ws_url, &hw_info, &params).await {
                Ok(_) => {
                    info!("WebSocket connection closed normally");
                    
                    if is_setup_mode {
                        // During setup, successful connection is enough
                        return Ok(());
                    }
                    
                    // For normal operation, wait before reconnecting
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    retry_count = 0;
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    retry_count += 1;
                    
                    if retry_count >= max_retries {
                        if is_setup_mode {
                            // During setup, connection failure is not critical
                            warn!("WebSocket test failed, but registration may still be valid");
                            return Ok(());
                        } else {
                            return Err(format!("Failed to establish WebSocket connection after {} attempts", max_retries));
                        }
                    }
                    
                    warn!("Retrying WebSocket connection in {:?} (attempt {}/{})", 
                          backoff, retry_count, max_retries);
                    tokio::time::sleep(backoff).await;
                    
                    // Exponential backoff with jitter
                    backoff = backoff.mul_f32(1.5).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// Internal WebSocket connection handler (original version)
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
        
        // Track last heartbeat time for connection health
        let mut last_heartbeat_ack = std::time::Instant::now();
        let heartbeat_timeout = Duration::from_secs(180); // 3 minutes
        
        loop {
            tokio::select! {
                Some(message) = read.next() => {
                    match message {
                        Ok(Message::Text(text)) => {
                            if let Err(e) = self.handle_websocket_message(&text, &mut write, &mut authenticated, &mut heartbeat_interval, &mut last_heartbeat_ack).await {
                                error!("Failed to handle WebSocket message: {}", e);
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
                        Ok(Message::Pong(_)) => {
                            debug!("Received pong");
                            last_heartbeat_ack = std::time::Instant::now();
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
                        // Check heartbeat timeout
                        if last_heartbeat_ack.elapsed() > heartbeat_timeout {
                            error!("Heartbeat timeout - no response from server");
                            break;
                        }
                        
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

    /// Updated WebSocket connection handler that properly handles initial messages
    async fn connect_and_run_websocket_v2(
        &self,
        ws_url: &str,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        let (ws_stream, _) = connect_async(ws_url)
            .await
            .map_err(|e| format!("WebSocket connection failed: {}", e))?;
        
        info!("WebSocket TCP connection established, waiting for server handshake");
        *self.websocket_connected.write().await = true;
        
        let (mut write, mut read) = ws_stream.split();
        
        // Set up heartbeat interval (30 seconds to match test script)
        let mut heartbeat_interval = time::interval(Duration::from_secs(30));
        heartbeat_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        
        let mut authenticated = false;
        let mut auth_sent = false;
        let metrics_collector = Arc::new(ServerMetricsCollector::new(
            Duration::from_secs(60),
            60,
        ));
        
        // Track last heartbeat acknowledgment
        let mut last_heartbeat_ack = std::time::Instant::now();
        let heartbeat_timeout = Duration::from_secs(90); // 3 missed heartbeats
        
        loop {
            tokio::select! {
                Some(message) = read.next() => {
                    match message {
                        Ok(Message::Text(text)) => {
                            // Add debug logging for ALL messages
                            info!("=== WEBSOCKET MESSAGE RECEIVED ===");
                            info!("Raw message: {}", if text.len() > 500 { 
                                format!("{}... (truncated, total length: {})", &text[..500], text.len()) 
                            } else { 
                                text.clone() 
                            });
                            
                            // First try to parse as structured ServerMessage
                            let handled = if let Ok(server_msg) = serde_json::from_str::<ServerMessage>(&text) {
                                info!("Parsed as ServerMessage");
                                
                                // Check if this is a heartbeat ack before handling
                                let is_heartbeat_ack = matches!(server_msg, ServerMessage::HeartbeatAck { .. });
                                
                                let result = self.handle_server_message(
                                    server_msg,
                                    &mut write,
                                    &mut authenticated,
                                    hardware_info,
                                    setup_params,
                                ).await;
                                
                                // Update timestamp for heartbeat ack
                                if is_heartbeat_ack && result.is_ok() {
                                    last_heartbeat_ack = std::time::Instant::now();
                                }
                                
                                result.is_ok()
                            } else {
                                false
                            };
                            
                            // If structured parsing failed, try generic JSON handling
                            if !handled {
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                    if let Some(msg_type) = json.get("type").and_then(|t| t.as_str()) {
                                        info!("Processing generic message type: {}", msg_type);
                                        
                                        match msg_type {
                                            "connected" | "connection_established" => {
                                                info!("Received connection confirmation from server");
                                                
                                                if !auth_sent {
                                                    // Send authentication using the simplified format
                                                    let auth_code = self.reference_code.clone()
                                                        .or_else(|| self.registration_code.clone())
                                                        .ok_or("No authentication code available")?;
                                                    
                                                    let auth_msg = serde_json::json!({
                                                        "type": "auth",
                                                        "code": auth_code
                                                    });
                                                    
                                                    info!("Sending authentication with code: {}...", 
                                                          &auth_code[..8.min(auth_code.len())]);
                                                    
                                                    write.send(Message::Text(auth_msg.to_string())).await
                                                        .map_err(|e| format!("Failed to send auth: {}", e))?;
                                                    
                                                    auth_sent = true;
                                                }
                                            }
                                            
                                            "auth_success" | "auth_response" => {
                                                let success = json.get("success")
                                                    .and_then(|s| s.as_bool())
                                                    .unwrap_or(true); // Default to true for "auth_success"
                                                
                                                if success {
                                                    info!("Authentication successful");
                                                    authenticated = true;
                                                    last_heartbeat_ack = std::time::Instant::now();
                                                    
                                                    // Update heartbeat interval if provided
                                                    if let Some(interval) = json.get("heartbeat_interval")
                                                        .and_then(|v| v.as_u64()) {
                                                        heartbeat_interval = time::interval(Duration::from_secs(interval));
                                                        info!("Heartbeat interval set to {} seconds", interval);
                                                    }
                                                } else {
                                                    let message = json.get("message")
                                                        .and_then(|m| m.as_str())
                                                        .unwrap_or("Authentication failed");
                                                    error!("Authentication failed: {}", message);
                                                    return Err(format!("Authentication failed: {}", message));
                                                }
                                            }
                                            
                                            "heartbeat_ack" | "heartbeat_response" => {
                                                debug!("Heartbeat acknowledged");
                                                last_heartbeat_ack = std::time::Instant::now();
                                            }
                                            
                                            "challenge_request" | "CHALLENGE_REQUEST" => {
                                                info!("Received ZKP challenge request");
                                                
                                                let challenge_id = json.get("challenge_id")
                                                    .or_else(|| json.get("payload")
                                                        .and_then(|p| p.get("challenge_id")))
                                                    .and_then(|id| id.as_str())
                                                    .unwrap_or("unknown");
                                                
                                                // Generate and send ZKP proof
                                                if let Err(e) = self.handle_zkp_challenge(
                                                    challenge_id,
                                                    hardware_info,
                                                    setup_params,
                                                    &mut write
                                                ).await {
                                                    error!("Failed to handle ZKP challenge: {}", e);
                                                }
                                            }
                                            
                                            "remote_command" => {
                                                info!("=== REMOTE COMMAND DETECTED ===");
                                                info!("Full remote command JSON: {}", serde_json::to_string_pretty(&json).unwrap_or_default());
                                                
                                                // Call the existing handler
                                                if let Err(e) = self.handle_websocket_message(
                                                    &text,
                                                    &mut write,
                                                    &mut authenticated,
                                                    &mut heartbeat_interval,
                                                    &mut last_heartbeat_ack
                                                ).await {
                                                    error!("Failed to handle remote command: {}", e);
                                                }
                                            }
                                            
                                            "remote_auth" => {
                                                info!("=== REMOTE AUTH DETECTED ===");
                                                
                                                // Also handle remote_auth through the legacy handler
                                                if let Err(e) = self.handle_websocket_message(
                                                    &text,
                                                    &mut write,
                                                    &mut authenticated,
                                                    &mut heartbeat_interval,
                                                    &mut last_heartbeat_ack
                                                ).await {
                                                    error!("Failed to handle remote auth: {}", e);
                                                }
                                            }
                                            
                                            "error" => {
                                                let error_code = json.get("error_code")
                                                    .and_then(|c| c.as_str())
                                                    .unwrap_or("unknown");
                                                let message = json.get("message")
                                                    .and_then(|m| m.as_str())
                                                    .unwrap_or("Unknown error");
                                                
                                                error!("Server error [{}]: {}", error_code, message);
                                                
                                                if error_code == "AUTH_TIMEOUT" || 
                                                   error_code == "INVALID_CODE" || 
                                                   error_code == "auth_failed" {
                                                    return Err(format!("Authentication error: {}", message));
                                                }
                                            }
                                            
                                            _ => {
                                                info!("Unhandled message type: {}, trying legacy handler", msg_type);
                                                
                                                // For any other message type, try the legacy handler
                                                if let Err(e) = self.handle_websocket_message(
                                                    &text,
                                                    &mut write,
                                                    &mut authenticated,
                                                    &mut heartbeat_interval,
                                                    &mut last_heartbeat_ack
                                                ).await {
                                                    error!("Legacy handler failed: {}", e);
                                                }
                                            }
                                        }
                                    } else {
                                        warn!("Message without type field: {:?}", json);
                                    }
                                } else {
                                    warn!("Non-JSON message: {}", text);
                                }
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("WebSocket closed by server");
                            break;
                        }
                        Ok(Message::Ping(data)) => {
                            debug!("Received ping, sending pong");
                            if let Err(e) = write.send(Message::Pong(data)).await {
                                error!("Failed to send pong: {}", e);
                                break;
                            }
                        }
                        Ok(Message::Pong(_)) => {
                            debug!("Received pong");
                            last_heartbeat_ack = std::time::Instant::now();
                        }
                        Err(e) => {
                            error!("WebSocket read error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
                
                _ = heartbeat_interval.tick() => {
                    if authenticated {
                        // Check heartbeat timeout
                        if last_heartbeat_ack.elapsed() > heartbeat_timeout {
                            error!("Heartbeat timeout - no response from server for {:?}", 
                                   last_heartbeat_ack.elapsed());
                            break;
                        }
                        
                        // Log remote management status with heartbeat
                        let remote_enabled = *self.remote_management_enabled.read().await;
                        info!("Sending heartbeat - Remote management enabled: {}", remote_enabled);
                        
                        // Send heartbeat in simple format
                        let heartbeat = serde_json::json!({
                            "type": "heartbeat",
                            "metrics": {
                                "cpu": self.get_cpu_usage().await,
                                "memory": self.get_memory_usage().await,
                                "disk": self.get_disk_usage().await,
                                "network": self.get_network_usage().await
                            }
                        });
                        
                        if let Err(e) = write.send(Message::Text(heartbeat.to_string())).await {
                            error!("Failed to send heartbeat: {}", e);
                            break;
                        }
                        
                        info!("Sent heartbeat at {}", std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs());
                    } else if auth_sent && self.start_time.elapsed() > Duration::from_secs(25) {
                        warn!("Not authenticated after 25 seconds despite sending auth");
                    }
                }
                
                // Timeout for initial connection/auth sequence
                _ = tokio::time::sleep(Duration::from_secs(35)) => {
                    if !authenticated && !auth_sent {
                        error!("No server message received within 35 seconds of connection");
                        break;
                    }
                }
            }
        }
        
        *self.websocket_connected.write().await = false;
        
        // Return more accurate error messages
        if authenticated && last_heartbeat_ack.elapsed() > heartbeat_timeout {
            Err("Connection lost: heartbeat timeout".to_string())
        } else if !authenticated && auth_sent {
            Err("WebSocket connection closed without successful authentication".to_string())
        } else if !auth_sent {
            Err("Server did not send initial connection message".to_string())
        } else {
            Ok(())
        }
    }
    /// Handle ZKP challenge
    async fn handle_zkp_challenge(
        &self,
        challenge_id: &str,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
        write: &mut futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
            Message
        >,
    ) -> Result<(), String> {
        use crate::zkp_halo2;
        
        info!("Generating ZKP proof for challenge ID: {}", challenge_id);
        
        // Generate commitment
        let commitment = hardware_info.generate_zkp_commitment();
        
        // Generate proof
        let proof = zkp_halo2::generate_hardware_proof(hardware_info, &commitment, setup_params)
            .await
            .map_err(|e| format!("Failed to generate proof: {}", e))?;
        
        // Send response in the expected format
        let response = serde_json::json!({
            "type": "challenge_response",
            "challenge_id": challenge_id,
            "proof": {
                "data": hex::encode(&proof.data),
                "public_inputs": hex::encode(&proof.public_inputs),
                "timestamp": proof.timestamp,
            }
        });
        
        write.send(Message::Text(response.to_string())).await
            .map_err(|e| format!("Failed to send challenge response: {}", e))?;
        
        info!("Successfully sent ZKP proof for challenge {}", challenge_id);
        Ok(())
    }

    /// Handle server messages with ZKP support
   async fn handle_server_message(
        &self,
        message: ServerMessage,
        write: &mut futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
            Message
        >,
        authenticated: &mut bool,
        hardware_info: &HardwareInfo,
        setup_params: &SetupParams,
    ) -> Result<(), String> {
        use crate::zkp_halo2;
        
        match message {
            ServerMessage::ConnectionEstablished | ServerMessage::Connected { .. } => {
                info!("Connection established, sending authentication");
                
                let auth_code = self.reference_code.clone()
                    .or_else(|| self.registration_code.clone())
                    .ok_or("No authentication code available")?;
                
                let auth_msg = ClientMessage::Auth {
                    code: auth_code,
                };
                
                let auth_json = serde_json::to_string(&auth_msg)
                    .map_err(|e| format!("Failed to serialize auth: {}", e))?;
                write.send(Message::Text(auth_json)).await
                    .map_err(|e| format!("Failed to send auth: {}", e))?;
            }
            
            ServerMessage::AuthSuccess { heartbeat_interval, node_info: _ } => {
                info!("Authentication successful");
                *authenticated = true;
                
                if let Some(interval) = heartbeat_interval {
                    info!("Heartbeat interval: {} seconds", interval);
                }
            }
            
            ServerMessage::AuthResponse { success, message, node_info: _ } => {
                if success {
                    info!("Authentication successful");
                    *authenticated = true;
                } else {
                    let err_msg = message.unwrap_or_else(|| "Authentication failed".to_string());
                    error!("Authentication failed: {}", err_msg);
                    return Err(format!("Authentication failed: {}", err_msg));
                }
            }
            
            ServerMessage::RemoteCommand { request_id, command, from_session } => {
                info!("=== REMOTE COMMAND RECEIVED (ServerMessage) ===");
                info!("Request ID: {}", request_id);
                info!("From session: {}", from_session);
                info!("Command: {:?}", command);
                
                if *self.remote_management_enabled.read().await {
                    match serde_json::from_value::<RemoteCommandData>(command.clone()) {
                        Ok(command_data) => {
                            info!("Processing remote command: type={}", command_data.command_type);
                            
                            // Log the command execution
                            log_remote_command(
                                &from_session,
                                &command_data.command_type,
                                true,
                                &format!("request_id={}", request_id)
                            );
                            
                            // Execute command
                            let handler = self.remote_command_handler.clone();
                            let response = handler.handle_command(
                                request_id.clone(), 
                                command_data
                            ).await;
                            
                            // Build response message
                            let response_msg = if response.success {
                                serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": true,
                                    "result": response.result,
                                    "executed_at": response.executed_at
                                })
                            } else {
                                serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": false,
                                    "error": response.error,
                                    "executed_at": response.executed_at
                                })
                            };
                            
                            // Send response
                            info!("Sending remote command response for request_id: {}", request_id);
                            let response_json = response_msg.to_string();
                            
                            write.send(Message::Text(response_json)).await
                                .map_err(|e| format!("Failed to send response: {}", e))?;
                            
                            info!("Response sent successfully");
                        }
                        Err(e) => {
                            error!("Failed to parse remote command: {}", e);
                            
                            // Send error response
                            let error_response = serde_json::json!({
                                "type": "remote_command_response",
                                "request_id": request_id,
                                "success": false,
                                "error": {
                                    "code": "INVALID_COMMAND",
                                    "message": format!("Failed to parse command: {}", e)
                                }
                            });
                            
                            write.send(Message::Text(error_response.to_string())).await
                                .map_err(|e| format!("Failed to send error response: {}", e))?;
                        }
                    }
                } else {
                    warn!("Remote management is disabled");
                    
                    let error_response = serde_json::json!({
                        "type": "remote_command_response",
                        "request_id": request_id,
                        "success": false,
                        "error": {
                            "code": "REMOTE_MANAGEMENT_DISABLED",
                            "message": "Remote management is disabled on this node"
                        }
                    });
                    
                    write.send(Message::Text(error_response.to_string())).await
                        .map_err(|e| format!("Failed to send error response: {}", e))?;
                }
            }
            
            ServerMessage::RemoteAuth { jwt_token } => {
                info!("Received remote_auth message");
                info!("Remote auth JWT token received, length: {}", jwt_token.len());
                
                // Enable remote management for this session
                *self.remote_management_enabled.write().await = true;
                
                // Send success response
                let success_response = serde_json::json!({
                    "type": "remote_auth_success",
                    "message": "Remote authentication successful"
                });
                
                write.send(Message::Text(success_response.to_string())).await
                    .map_err(|e| format!("Failed to send remote auth response: {}", e))?;
                
                info!("Remote auth success response sent, remote management enabled");
            }
            
            ServerMessage::ChallengeRequest { challenge_id, nonce: _ } => {
                info!("✅ Received ZKP challenge request with ID: {}", challenge_id);
                
                let commitment = hardware_info.generate_zkp_commitment();
                
                match zkp_halo2::generate_hardware_proof(hardware_info, &commitment, setup_params).await {
                    Ok(proof) => {
                        let response = ClientMessage::ChallengeResponse {
                            challenge_id: challenge_id.clone(),
                            proof: ProofData::from(&proof),
                        };
                        
                        let response_json = serde_json::to_string(&response)
                            .map_err(|e| format!("Failed to serialize response: {}", e))?;
                        write.send(Message::Text(response_json)).await
                            .map_err(|e| format!("Failed to send challenge response: {}", e))?;
                        
                        info!("🚀 Successfully sent proof for challenge {}", challenge_id);
                    }
                    Err(e) => {
                        error!("❌ Failed to generate proof: {}", e);
                    }
                }
            }
            
            ServerMessage::ChallengeResponseAck { challenge_id, status, message: _ } => {
                info!("Server acknowledged proof for challenge {}: {}", challenge_id, status);
            }
            
            ServerMessage::HeartbeatAck { received_at: _, next_interval: _ } => {
                debug!("Heartbeat acknowledged");
                // Don't update timestamp here - it needs to be updated in the caller
            }
            
            ServerMessage::Error { error_code, message } => {
                error!("Server error [{}]: {}", error_code, message);
            }
            
            ServerMessage::Unknown => {
                debug!("Received unknown message type");
            }
        }
        
        Ok(())
    }

    
    /// Handle incoming WebSocket messages (legacy version)
    async fn handle_websocket_message(
        &self,
        text: &str,
        write: &mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
        authenticated: &mut bool,
        heartbeat_interval: &mut time::Interval,
        last_heartbeat_ack: &mut std::time::Instant,
    ) -> Result<(), String> {
        debug!("Received WebSocket message: {}", text);
        
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            match json.get("type").and_then(|t| t.as_str()) {
                Some("connection_established") => {
                    info!("WebSocket connection established, sending authentication");
                    
                    let auth_msg = WebSocketMessage::Auth {
                        reference_code: self.reference_code.clone().unwrap(),
                        registration_code: self.registration_code.clone(),
                    };
                    
                    let auth_json = serde_json::to_string(&auth_msg)
                        .map_err(|e| format!("Failed to serialize auth: {}", e))?;
                    
                    write.send(Message::Text(auth_json)).await
                        .map_err(|e| format!("Failed to send auth: {}", e))?;
                }
                
                Some("auth_success") => {
                    info!("WebSocket authentication successful");
                    *authenticated = true;
                    *last_heartbeat_ack = std::time::Instant::now();
                    
                    // Get heartbeat interval from server
                    if let Some(interval_secs) = json.get("heartbeat_interval").and_then(|v| v.as_u64()) {
                        *heartbeat_interval = time::interval(Duration::from_secs(interval_secs));
                        info!("Heartbeat interval set to {} seconds", interval_secs);
                    }
                    
                    // Check for additional auth info
                    if let Some(node_info) = json.get("node_info") {
                        if let Some(status) = node_info.get("status").and_then(|s| s.as_str()) {
                            info!("Node status: {}", status);
                        }
                    }
                }
                
                Some("heartbeat_ack") => {
                    debug!("Heartbeat acknowledged by server");
                    *last_heartbeat_ack = std::time::Instant::now();
                    
                    // Update next heartbeat interval if provided
                    if let Some(next_interval) = json.get("next_interval").and_then(|v| v.as_u64()) {
                        *heartbeat_interval = time::interval(Duration::from_secs(next_interval));
                    }
                }
                
                Some("hardware_attestation_request") => {
                    // Handle ZKP attestation request
                    if self.zkp_params.is_some() {
                        info!("Received hardware attestation request");
                        
                        let challenge = json.get("challenge")
                            .and_then(|c| c.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<u8>>())
                            .unwrap_or_default();
                        
                        let nonce = json.get("nonce")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        
                        match self.handle_attestation_request(challenge, nonce).await {
                            Ok(response_msg) => {
                                let response_json = serde_json::to_string(&response_msg)
                                    .map_err(|e| format!("Failed to serialize attestation response: {}", e))?;
                                
                                write.send(Message::Text(response_json)).await
                                    .map_err(|e| format!("Failed to send attestation proof: {}", e))?;
                                
                                info!("Hardware attestation proof sent successfully");
                            }
                            Err(e) => {
                                error!("Failed to generate attestation proof: {}", e);
                            }
                        }
                    } else {
                        warn!("Received hardware attestation request but ZKP is not enabled");
                    }
                }
                
                Some("error") => {
                    let error_code = json.get("error_code").and_then(|c| c.as_str()).unwrap_or("unknown");
                    let message = json.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                    error!("Server error [{}]: {}", error_code, message);
                    
                    // Handle specific errors
                    match error_code {
                        "hardware_fingerprint_conflict" => {
                            error!("This hardware is already registered with another node");
                            error!("Each physical device can only run one AeroNyx node");
                            return Err("Hardware already registered".to_string());
                        }
                        "auth_failed" => {
                            error!("Authentication failed - invalid reference code");
                            return Err("Authentication failed".to_string());
                        }
                        "node_suspended" => {
                            error!("This node has been suspended");
                            error!("Please contact support for more information");
                            return Err("Node suspended".to_string());
                        }
                        "node_not_found" => {
                            error!("Node not found - registration may have been deleted");
                            return Err("Node not found".to_string());
                        }
                        _ => {}
                    }
                }
                
                Some("command") => {
                    // Handle remote commands if enabled
                    if *self.remote_management_enabled.read().await {
                        self.handle_remote_command(&json, write).await?;
                    } else {
                        warn!("Received remote command but remote management is disabled");
                        
                        // Send error response
                        if let Some(request_id) = json.get("request_id").and_then(|id| id.as_str()) {
                            let error_response = CommandResponse {
                                success: false,
                                message: "Remote management is disabled".to_string(),
                                data: None,
                                error_code: Some("REMOTE_MANAGEMENT_DISABLED".to_string()),
                                execution_time_ms: None,
                            };
                            
                            let response_msg = WebSocketMessage::CommandResponse {
                                request_id: request_id.to_string(),
                                response: error_response,
                            };
                            
                            let response_json = serde_json::to_string(&response_msg)
                                .map_err(|e| format!("Failed to serialize error response: {}", e))?;
                            
                            write.send(Message::Text(response_json)).await
                                .map_err(|e| format!("Failed to send error response: {}", e))?;
                        }
                    }
                }
                
                Some("ping") => {
                    // Respond to server ping
                    if let Some(timestamp) = json.get("timestamp").and_then(|t| t.as_u64()) {
                        let pong = WebSocketMessage::Ping { timestamp };
                        let pong_json = serde_json::to_string(&pong)
                            .map_err(|e| format!("Failed to serialize pong: {}", e))?;
                        
                        write.send(Message::Text(pong_json)).await
                            .map_err(|e| format!("Failed to send pong: {}", e))?;
                    }
                }
                
                Some("config_update") => {
                    // Handle configuration updates from server
                    info!("Received configuration update from server");
                    if let Some(config) = json.get("config") {
                        debug!("New configuration: {:?}", config);
                        // TODO: Apply configuration updates
                    }
                }
                
                Some("remote_command") => {
                    info!("=== REMOTE COMMAND RECEIVED ===");
                    info!("Raw message: {}", text);
                    
                    if *self.remote_management_enabled.read().await {
                        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(text) {
                            // Extract fields
                            let request_id = json_value.get("request_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let from_session = json_value.get("from_session")
                                .and_then(|v| v.as_str());
                            
                            info!("Request ID: {}", request_id);
                            info!("From session: {:?}", from_session);
                            
                            // NOTE: Backend doesn't send node_reference, so we don't check it
                            // The node is already authenticated, so we trust the command
                            
                            if let Some(command_json) = json_value.get("command") {
                                info!("Command JSON: {:?}", command_json);
                                
                                match serde_json::from_value::<RemoteCommandData>(command_json.clone()) {
                                    Ok(command_data) => {
                                        info!("Processing remote command: type={}", command_data.command_type);
                                        
                                        // Log the command execution
                                        if let Some(session_id) = from_session {
                                            log_remote_command(
                                                session_id,
                                                &command_data.command_type,
                                                true,
                                                &format!("request_id={}", request_id)
                                            );
                                        }
                                        
                                        // Execute command
                                        let handler = self.remote_command_handler.clone();
                                        let response = handler.handle_command(
                                            request_id.to_string(), 
                                            command_data
                                        ).await;
                                        
                                        // Build response message
                                        let response_msg = if response.success {
                                            serde_json::json!({
                                                "type": "remote_command_response",
                                                "request_id": request_id,
                                                "success": true,
                                                "result": response.result,
                                                "executed_at": response.executed_at
                                            })
                                        } else {
                                            serde_json::json!({
                                                "type": "remote_command_response",
                                                "request_id": request_id,
                                                "success": false,
                                                "error": response.error,
                                                "executed_at": response.executed_at
                                            })
                                        };
                                        
                                        // Send response
                                        info!("Sending remote command response for request_id: {}", request_id);
                                        let response_json = response_msg.to_string();
                                        
                                        match write.send(Message::Text(response_json)).await {
                                            Ok(_) => info!("Response sent successfully"),
                                            Err(e) => error!("Failed to send response: {}", e),
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse remote command: {}", e);
                                        error!("Command JSON was: {:?}", command_json);
                                        
                                        // Log failed command
                                        if let Some(session_id) = from_session {
                                            log_remote_command(
                                                session_id,
                                                "unknown",
                                                false,
                                                &format!("parse_error={}", e)
                                            );
                                        }
                                        
                                        // Send error response
                                        let error_response = serde_json::json!({
                                            "type": "remote_command_response",
                                            "request_id": request_id,
                                            "success": false,
                                            "error": {
                                                "code": "INVALID_COMMAND",
                                                "message": format!("Failed to parse command: {}", e)
                                            }
                                        });
                                        
                                        let _ = write.send(Message::Text(error_response.to_string())).await;
                                    }
                                }
                            } else {
                                error!("No 'command' field in message");
                                
                                // Send error response
                                let error_response = serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": false,
                                    "error": {
                                        "code": "MISSING_COMMAND",
                                        "message": "Command field is missing"
                                    }
                                });
                                
                                let _ = write.send(Message::Text(error_response.to_string())).await;
                            }
                        } else {
                            error!("Failed to parse JSON message");
                        }
                    } else {
                        warn!("Remote management is disabled");
                        
                        // If remote management is disabled, also send response
                        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(text) {
                            if let Some(request_id) = json_value.get("request_id").and_then(|v| v.as_str()) {
                                let error_response = serde_json::json!({
                                    "type": "remote_command_response",
                                    "request_id": request_id,
                                    "success": false,
                                    "error": {
                                        "code": "REMOTE_MANAGEMENT_DISABLED",
                                        "message": "Remote management is disabled on this node"
                                    }
                                });
                                
                                let _ = write.send(Message::Text(error_response.to_string())).await;
                            }
                        }
                    }
                    
                    info!("=== REMOTE COMMAND PROCESSING COMPLETE ===");
                }


                Some("remote_auth") => {
                    info!("Received remote_auth message");
                    
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(text) {
                        let jwt_token = json_value.get("jwt_token")
                            .and_then(|v| v.as_str());
                        
                        if let Some(token) = jwt_token {
                            info!("Remote auth JWT token received, length: {}", token.len());
                            
                            // TODO: In production, you should verify the JWT token here
                            // For now, we'll accept it and enable remote management
                            
                            // Enable remote management for this session
                            *self.remote_management_enabled.write().await = true;
                            
                            // Send success response
                            let success_response = serde_json::json!({
                                "type": "remote_auth_success",
                                "message": "Remote authentication successful"
                            });
                            
                            write.send(Message::Text(success_response.to_string())).await
                                .map_err(|e| format!("Failed to send remote auth response: {}", e))?;
                            
                            info!("Remote auth success response sent, remote management enabled");
                        } else {
                            // JWT token missing
                            let error_response = serde_json::json!({
                                "type": "error",
                                "error_code": "MISSING_JWT",
                                "message": "JWT token is required for remote authentication"
                            });
                            
                            write.send(Message::Text(error_response.to_string())).await
                                .map_err(|e| format!("Failed to send error response: {}", e))?;
                        }
                    }
                }
                
                Some("status_request") => {
                    // Server requesting current status
                    let status_update = WebSocketMessage::StatusUpdate {
                        status: "active".to_string(),
                    };
                    
                    let status_json = serde_json::to_string(&status_update)
                        .map_err(|e| format!("Failed to serialize status: {}", e))?;
                    
                    write.send(Message::Text(status_json)).await
                        .map_err(|e| format!("Failed to send status update: {}", e))?;
                }
                
                _ => {
                    debug!("Unknown message type: {:?}", json.get("type"));
                }
            }
        } else {
            warn!("Received non-JSON WebSocket message: {}", text);
        }
        
        Ok(())
    }

    /// Handle remote command execution
    async fn handle_remote_command(
        &self,
        json: &serde_json::Value,
        write: &mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
    ) -> Result<(), String> {
        let request_id = json.get("request_id")
            .and_then(|id| id.as_str())
            .unwrap_or("unknown")
            .to_string();
        
        info!("Processing remote command with request ID: {}", request_id);
        
        // Parse remote command data from the command field instead of parameters
        if let Some(command_data) = json.get("command") {
            match serde_json::from_value::<RemoteCommandData>(command_data.clone()) {
                Ok(remote_cmd_data) => {
                    info!("Executing remote command: {:?}", remote_cmd_data);
                    
                    // Use the new remote command handler
                    let handler = self.remote_command_handler.clone();
                    let response = handler.handle_command(
                        request_id.clone(),
                        remote_cmd_data
                    ).await;
                    
                    // Send response back using RemoteCommandResponse
                    let response_msg = WebSocketMessage::RemoteCommandResponse {
                        response,
                    };
                    
                    let response_json = serde_json::to_string(&response_msg)
                        .map_err(|e| format!("Failed to serialize response: {}", e))?;
                    
                    write.send(Message::Text(response_json)).await
                        .map_err(|e| format!("Failed to send command response: {}", e))?;
                }
                Err(e) => {
                    warn!("Invalid remote command format: {}", e);
                    
                    // Send error response
                    let error_response = RemoteCommandResponse {
                        request_id,
                        success: false,
                        result: None,
                        error: Some(crate::remote_command_handler::RemoteCommandError {
                            code: "INVALID_COMMAND".to_string(),
                            message: format!("Invalid command format: {}", e),
                            details: None,
                        }),
                        executed_at: chrono::Utc::now().to_rfc3339(),
                    };
                    
                    let response_msg = WebSocketMessage::RemoteCommandResponse {
                        response: error_response,
                    };
                    
                    let response_json = serde_json::to_string(&response_msg)
                        .map_err(|e| format!("Failed to serialize error response: {}", e))?;
                    
                    write.send(Message::Text(response_json)).await
                        .map_err(|e| format!("Failed to send error response: {}", e))?;
                }
            }
        } else {
            warn!("Remote command missing command data");
            
            // Send error response
            let error_response = RemoteCommandResponse {
                request_id,
                success: false,
                result: None,
                error: Some(crate::remote_command_handler::RemoteCommandError {
                    code: "INVALID_COMMAND".to_string(),
                    message: "Missing command data".to_string(),
                    details: None,
                }),
                executed_at: chrono::Utc::now().to_rfc3339(),
            };
            
            let response_msg = WebSocketMessage::RemoteCommandResponse {
                response: error_response,
            };
            
            let response_json = serde_json::to_string(&response_msg)
                .map_err(|e| format!("Failed to serialize error response: {}", e))?;
            
            write.send(Message::Text(response_json)).await
                .map_err(|e| format!("Failed to send error response: {}", e))?;
        }
        
        Ok(())
    }

    /// Create heartbeat message with system metrics (legacy format)
    async fn create_heartbeat_message(&self, _metrics_collector: &ServerMetricsCollector) -> WebSocketMessage {
        let uptime_seconds = self.start_time.elapsed().as_secs();
        
        let (cpu_usage, mem_usage, disk_usage, net_usage) = tokio::join!(
            self.get_cpu_usage(),
            self.get_memory_usage(),
            self.get_disk_usage(),
            self.get_network_usage()
        );
        
        let temperature = self.get_cpu_temperature().await;
        let processes = self.get_process_count().await;
        
        WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds,
            metrics: LegacyHeartbeatMetrics {  // Changed from HeartbeatMetrics
                cpu: cpu_usage,
                mem: mem_usage,
                disk: disk_usage,
                net: net_usage,
                temperature,
                processes,
            },
        }
    }

    /// Create heartbeat with metrics (new format)
    async fn create_client_heartbeat_message(&self, _metrics_collector: &ServerMetricsCollector) -> ClientMessage {
        let (cpu_usage, mem_usage, disk_usage, net_usage) = tokio::join!(
            self.get_cpu_usage(),
            self.get_memory_usage(),
            self.get_disk_usage(),
            self.get_network_usage()
        );
        
        // Use the websocket_protocol HeartbeatMetrics directly
        ClientMessage::Heartbeat {
            metrics: crate::websocket_protocol::HeartbeatMetrics {
                cpu: cpu_usage,
                memory: mem_usage,
                disk: disk_usage,
                network: net_usage,
            },
            timestamp: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        }
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

    /// Get current CPU usage percentage
    async fn get_cpu_usage(&self) -> f64 {
        if let Ok(result) = tokio::task::spawn_blocking(|| utils::system::get_load_average()).await {
            if let Ok((one_min, _, _)) = result {
                let cpu_count = sys_info::cpu_num().unwrap_or(1) as f64;
                (one_min / cpu_count * 100.0).min(100.0)
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    /// Get current memory usage percentage
    async fn get_memory_usage(&self) -> f64 {
        if let Ok(Ok((total, available))) = tokio::task::spawn_blocking(|| utils::system::get_system_memory()).await {
            let used = total.saturating_sub(available);
            used as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    }

    /// Get current disk usage percentage
    async fn get_disk_usage(&self) -> f64 {
        if let Ok(Ok(usage)) = tokio::task::spawn_blocking(|| utils::system::get_disk_usage()).await {
            usage as f64
        } else {
            0.0
        }
    }

    /// Get current network usage (placeholder implementation)
    async fn get_network_usage(&self) -> f64 {
        // TODO: Implement actual network usage calculation
        // This would track bytes sent/received over time
        10.0
    }

    /// Get CPU temperature if available
    async fn get_cpu_temperature(&self) -> Option<f64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            // Try different thermal zone paths
            let thermal_zones = [
                "/sys/class/thermal/thermal_zone0/temp",
                "/sys/class/thermal/thermal_zone1/temp",
                "/sys/class/hwmon/hwmon0/temp1_input",
            ];
            
            for zone in &thermal_zones {
                if let Ok(temp_str) = fs::read_to_string(zone) {
                    if let Ok(temp_millidegrees) = temp_str.trim().parse::<f64>() {
                        return Some(temp_millidegrees / 1000.0);
                    }
                }
            }
        }
        
        None
    }

    /// Get current process count
    async fn get_process_count(&self) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            if let Ok(entries) = fs::read_dir("/proc") {
                let count = entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| {
                        entry.file_name()
                            .to_str()
                            .map(|name| name.chars().all(|c| c.is_digit(10)))
                            .unwrap_or(false)
                    })
                    .count();
                
                return Some(count as u32);
            }
        }
        
        None
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

    /// Request hardware change approval (for future implementation)
    pub async fn request_hardware_change_approval(&self, reason: &str) -> Result<(), String> {
        info!("Requesting hardware change approval: {}", reason);
        
        // This would require server-side support for hardware change approvals
        // For now, this is a placeholder for future functionality
        
        Err("Hardware change approval not yet implemented".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_websocket_message_serialization() {
        // Test auth message
        let auth = WebSocketMessage::Auth {
            reference_code: "AERO-12345".to_string(),
            registration_code: Some("AERO-REG123".to_string()),
        };
        
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"auth\""));
        assert!(json.contains("AERO-12345"));
        assert!(json.contains("AERO-REG123"));
        
        // Test heartbeat message
        let heartbeat = WebSocketMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds: 3600,
            metrics: LegacyHeartbeatMetrics {
                cpu: 25.5,
                mem: 45.2,
                disk: 60.1,
                net: 10.3,
                temperature: Some(65.0),
                processes: Some(150),
            },
        };
        
        let json = serde_json::to_string(&heartbeat).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
        assert!(json.contains("\"cpu\":25.5"));
        assert!(json.contains("\"temperature\":65.0"));
        
        // Test ZKP attestation message
        let attestation = WebSocketMessage::HardwareAttestationProof {
            commitment: "abc123".to_string(),
            proof: vec![1, 2, 3, 4],
            nonce: "nonce123".to_string(),
        };
        
        let json = serde_json::to_string(&attestation).unwrap();
        assert!(json.contains("\"type\":\"hardware_attestation_proof\""));
        assert!(json.contains("\"commitment\":\"abc123\""));
    }
    
    #[test]
    fn test_hardware_components_extraction() {
        let hw_info = HardwareInfo {
            hostname: "test-node".to_string(),
            cpu: crate::hardware::CpuInfo {
                cores: 4,
                model: "Intel Core i5".to_string(),
                frequency: 2400000000,
                architecture: "x86_64".to_string(),
                vendor_id: Some("GenuineIntel".to_string()),
            },
            memory: crate::hardware::MemoryInfo {
                total: 8000000000,
                available: 4000000000,
            },
            disk: crate::hardware::DiskInfo {
                total: 500000000000,
                available: 250000000000,
                filesystem: "ext4".to_string(),
            },
            network: crate::hardware::NetworkInfo {
                interfaces: vec![
                    crate::hardware::NetworkInterface {
                        name: "eth0".to_string(),
                        ip_address: "192.168.1.100".to_string(),
                        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                        interface_type: "ethernet".to_string(),
                        is_physical: true,
                    },
                    crate::hardware::NetworkInterface {
                        name: "docker0".to_string(),
                        ip_address: "172.17.0.1".to_string(),
                        mac_address: "02:42:ac:11:00:01".to_string(),
                        interface_type: "bridge".to_string(),
                        is_physical: false,
                    },
                ],
                public_ip: "1.2.3.4".to_string(),
            },
            os: crate::hardware::OsInfo {
                os_type: "linux".to_string(),
                version: "22.04".to_string(),
                distribution: "Ubuntu".to_string(),
                kernel: "5.15.0".to_string(),
            },
            system_uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            machine_id: Some("1234567890abcdef".to_string()),
            bios_info: None,
        };
        
        let components = RegistrationManager::extract_hardware_components(&hw_info);
        
        // Should only include physical MAC
        assert_eq!(components.mac_addresses.len(), 1);
        assert!(components.mac_addresses.contains("aa:bb:cc:dd:ee:ff"));
        assert!(!components.mac_addresses.contains("02:42:ac:11:00:01"));
        
        assert_eq!(components.cpu_model, "Intel Core i5");
        assert_eq!(components.system_uuid, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
        assert_eq!(components.machine_id, Some("1234567890abcdef".to_string()));
    }
    
    #[test]
    fn test_tolerance_config() {
        let config = HardwareToleranceConfig::default();
        assert!(config.allow_minor_changes);
        assert!(config.require_mac_match);
        assert!(!config.allow_cpu_change);
        assert_eq!(config.max_change_percentage, 0.3);
    }
    
    #[tokio::test]
    async fn test_registration_manager_creation() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        assert!(manager.reference_code.is_none());
        assert!(manager.wallet_address.is_none());
        assert!(!manager.is_connected().await);
        assert_eq!(manager.api_url, "https://api.aeronyx.com");
        assert!(!manager.has_zkp_enabled());
    }
    
    #[test]
    fn test_client_message_serialization() {
        // Test auth message
        let auth = ClientMessage::Auth {
            reference_code: "AERO-12345".to_string(),
            registration_code: Some("AERO-REG123".to_string()),
        };
        
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"auth\""));
        assert!(json.contains("AERO-12345"));
        
        // Test heartbeat message
        let heartbeat = ClientMessage::Heartbeat {
            status: "active".to_string(),
            uptime_seconds: 3600,
            metrics: WsHeartbeatMetrics {
                cpu: 25.5,
                mem: 45.2,
                disk: 60.1,
                net: 10.3,
                temperature: Some(65.0),
                processes: Some(150),
            },
        };
        
        let json = serde_json::to_string(&heartbeat).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
        assert!(json.contains("\"cpu\":25.5"));
    }
    
    #[test]
    fn test_server_message_deserialization() {
        // Test connection established
        let json = r#"{"type":"connection_established"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMessage::ConnectionEstablished));
        
        // Test auth success
        let json = r#"{"type":"auth_success","heartbeat_interval":60}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::AuthSuccess { heartbeat_interval, .. } => {
                assert_eq!(heartbeat_interval, Some(60));
            }
            _ => panic!("Wrong message type"),
        }
        
        // Test challenge request
        let json = r#"{"type":"challenge_request","payload":{"challenge_id":"test-123","challenge":"AQID","timestamp":1234567890}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::ChallengeRequest { payload } => {
                assert_eq!(payload.challenge_id, "test-123");
            }
            _ => panic!("Wrong message type"),
        }
    }
}
