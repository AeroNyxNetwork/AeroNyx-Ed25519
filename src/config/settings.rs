// Modified src/config/settings.rs
//! Server configuration settings.
//!
//! This module contains the server configuration structures and
//! implementation for loading, parsing, and validating user-provided
//! settings.

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use crate::config::defaults;
use crate::crypto::keys::KeyManager;

/// Error type for configuration-related operations
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid configuration: {0}")]
    Invalid(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Invalid subnet format: {0}")]
    InvalidSubnet(String),
    
    #[error("Invalid socket address: {0}")]
    InvalidSocketAddr(#[from] std::net::AddrParseError),
}

/// Node operation modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum NodeMode {
    /// DePIN compute node only (no VPN functionality)
    #[value(name = "depin-only")]
    #[serde(rename = "depin-only")]
    DePINOnly,
    
    /// VPN server only (traditional VPN functionality)
    #[value(name = "vpn-enabled")]
    #[serde(rename = "vpn-enabled")]
    VPNEnabled,
    
    /// Both DePIN and VPN functionality
    #[value(name = "hybrid")]
    #[serde(rename = "hybrid")]
    Hybrid,
}

impl Default for NodeMode {
    fn default() -> Self {
        NodeMode::DePINOnly
    }
}

/// Command enum for subcommands
#[derive(Parser, Debug, Clone)]
pub enum Command {
    /// Set up node registration
    Setup {
        /// Registration code from API
        #[clap(long, required = true)]
        registration_code: String,
    }
}

/// Command line arguments for the server
#[derive(Parser, Debug, Clone)]
#[clap(
    name = "AeroNyx Privacy Network Node",
    about = "Decentralized privacy compute network node with blockchain integration",
    version,
    author
)]
pub struct ServerArgs {
    /// Node operation mode
    #[clap(long, value_enum, default_value = "depin-only")]
    pub mode: NodeMode,

    /// Server address to listen on (required for VPN modes)
    #[clap(long, default_value = "0.0.0.0:8443")]
    pub listen: String,

    /// TUN device name (required for VPN modes)
    #[clap(long, default_value = defaults::DEFAULT_TUN_NAME)]
    pub tun_name: String,

    /// VPN subnet in CIDR notation (required for VPN modes)
    #[clap(long, default_value = defaults::DEFAULT_SUBNET)]
    pub subnet: String,

    /// Log level
    #[clap(long, default_value = defaults::DEFAULT_LOG_LEVEL)]
    pub log_level: String,

    /// TLS certificate file (required for VPN modes)
    #[clap(long)]
    pub cert_file: Option<String>,

    /// TLS key file (required for VPN modes)
    #[clap(long)]
    pub key_file: Option<String>,

    /// Access control list file
    #[clap(long, default_value = defaults::DEFAULT_ACL_FILE)]
    pub acl_file: String,

    /// Enable traffic obfuscation
    #[clap(long)]
    pub enable_obfuscation: bool,

    /// Traffic obfuscation method (xor, scramblesuit, obfs4)
    #[clap(long, default_value = defaults::DEFAULT_OBFUSCATION_METHOD)]
    pub obfuscation_method: String,

    /// Enable traffic padding
    #[clap(long)]
    pub enable_padding: bool,

    /// Key rotation interval in seconds
    #[clap(long, default_value_t = defaults::DEFAULT_KEY_ROTATION_INTERVAL)]
    pub key_rotation_interval: u64,

    /// Session timeout in seconds
    #[clap(long, default_value_t = defaults::DEFAULT_SESSION_TIMEOUT)]
    pub session_timeout: u64,

    /// Maximum connections per IP
    #[clap(long, default_value_t = defaults::DEFAULT_MAX_CONNECTIONS_PER_IP)]
    pub max_connections_per_ip: usize,
    
    /// Data directory for storage
    #[clap(long, default_value = defaults::DEFAULT_DATA_DIR)]
    pub data_dir: String,
    
    /// Server keypair file
    #[clap(long)]
    pub server_key_file: Option<String>,
    
    /// Configuration file path
    #[clap(long)]
    pub config_file: Option<String>,
    
    /// Registration code from API
    #[clap(long)]
    pub registration_code: Option<String>,
    
    /// Reference code for registered node
    #[clap(long)]
    pub registration_reference_code: Option<String>,
    
    /// Wallet address for rewards
    #[clap(long)]
    pub wallet_address: Option<String>,
    
    /// API server URL
    #[clap(long, default_value = "https://api.aeronyx.network")]
    pub api_url: String,
    
    /// Enable remote management features
    #[clap(long)]
    pub enable_remote_management: bool,
    
    /// Registration setup command
    #[clap(subcommand)]
    pub command: Option<Command>,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Node operation mode
    #[serde(default)]
    pub mode: NodeMode,
    
    /// Server listen address
    pub listen_addr: SocketAddr,
    
    /// TUN device name
    pub tun_name: String,
    
    /// VPN subnet
    pub subnet: String,
    
    /// TLS certificate file
    pub cert_file: PathBuf,
    
    /// TLS key file
    pub key_file: PathBuf,
    
    /// Access control list file
    pub acl_file: PathBuf,
    
    /// Enable traffic obfuscation
    pub enable_obfuscation: bool,
    
    /// Traffic obfuscation method
    pub obfuscation_method: String,
    
    /// Enable traffic padding
    pub enable_padding: bool,
    
    /// Key rotation interval
    pub key_rotation_interval: Duration,
    
    /// Session timeout
    pub session_timeout: Duration,
    
    /// Maximum connections per IP
    pub max_connections_per_ip: usize,
    
    /// Data directory
    pub data_dir: PathBuf,
    
    /// Server keypair path
    pub server_key_file: PathBuf,
    
    /// Registration code from API
    pub registration_code: Option<String>,
    
    /// Reference code for registered node
    pub registration_reference_code: Option<String>,
    
    /// Wallet address for rewards
    pub wallet_address: Option<String>,
    
    /// API server URL
    pub api_url: String,
    
    /// Enable remote management features
    #[serde(default)]
    pub enable_remote_management: bool,
    
    /// Key manager for server keys
    #[serde(skip)]
    pub key_manager: Option<Arc<KeyManager>>,
}

impl ServerConfig {
    /// Create a new server configuration from command line arguments
    pub fn from_args(args: ServerArgs) -> Result<Self, ConfigError> {
        // Use platform-specific default data directory if not specified
        let data_dir = if args.data_dir == defaults::DEFAULT_DATA_DIR {
            defaults::default_data_dir()
        } else {
            PathBuf::from(&args.data_dir)
        };
        
        let reg_file = data_dir.join("registration.json");
        
        let (registration_reference_code, wallet_address) = if reg_file.exists() {
            match fs::read_to_string(&reg_file) {
                Ok(content) => {
                    if let Ok(reg_data) = serde_json::from_str::<serde_json::Value>(&content) {
                        (
                            reg_data.get("reference_code")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .or(args.registration_reference_code),
                            reg_data.get("wallet_address")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .or(args.wallet_address)
                        )
                    } else {
                        (args.registration_reference_code, args.wallet_address)
                    }
                }
                Err(_) => (args.registration_reference_code, args.wallet_address)
            }
        } else {
            (args.registration_reference_code, args.wallet_address)
        };
        
        // Check for configuration file first
        if let Some(config_path) = &args.config_file {
            if let Ok(file_content) = fs::read_to_string(config_path) {
                let mut config: ServerConfig = serde_json::from_str(&file_content)?;
                
                // Override with command line arguments if explicitly provided
                config.mode = args.mode;
                
                if args.listen != "0.0.0.0:8443" {
                    config.listen_addr = args.listen.parse()?;
                }
                
                // Override registration data with loaded values
                if registration_reference_code.is_some() {
                    config.registration_reference_code = registration_reference_code;
                }
                if wallet_address.is_some() {
                    config.wallet_address = wallet_address;
                }
                
                // Validate the config
                config.validate()?;
                return Ok(config);
            }
        }
        
        // Parse listen address based on mode
        let listen_addr = if matches!(args.mode, NodeMode::VPNEnabled | NodeMode::Hybrid) {
            args.listen.parse()?
        } else {
            // For DePIN-only mode, use a local address
            "127.0.0.1:8443".parse().unwrap()
        };
        
        // Determine certificate and key files based on mode
        let (cert_file, key_file) = if matches!(args.mode, NodeMode::VPNEnabled | NodeMode::Hybrid) {
            // For VPN modes, require cert and key files
            match (args.cert_file, args.key_file) {
                (Some(cert), Some(key)) => (PathBuf::from(cert), PathBuf::from(key)),
                _ => return Err(ConfigError::Invalid(
                    "Certificate and key files are required for VPN-enabled modes".to_string()
                )),
            }
        } else {
            // For DePIN-only mode, use dummy paths
            (PathBuf::from("dummy.crt"), PathBuf::from("dummy.key"))
        };
        
        // Determine server key file
        let server_key_file = if let Some(key_file) = args.server_key_file {
            PathBuf::from(key_file)
        } else {
            data_dir.join(defaults::DEFAULT_SERVER_KEY_FILE)
        };
        
        // Create directories if they don't exist
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)?;
        }
        
        let config = Self {
            mode: args.mode,
            listen_addr,
            tun_name: args.tun_name,
            subnet: args.subnet,
            cert_file,
            key_file,
            acl_file: PathBuf::from(args.acl_file),
            enable_obfuscation: args.enable_obfuscation,
            obfuscation_method: args.obfuscation_method,
            enable_padding: args.enable_padding,
            key_rotation_interval: Duration::from_secs(args.key_rotation_interval),
            session_timeout: Duration::from_secs(args.session_timeout),
            max_connections_per_ip: args.max_connections_per_ip,
            data_dir,
            server_key_file,
            registration_code: args.registration_code,
            registration_reference_code,
            wallet_address,
            api_url: args.api_url,
            enable_remote_management: args.enable_remote_management,
            key_manager: None,
        };
        
        // Validate the config
        config.validate()?;
        
        Ok(config)
    }
    
    /// Validate configuration settings
    fn validate(&self) -> Result<(), ConfigError> {
        // Mode-specific validation
        if matches!(self.mode, NodeMode::VPNEnabled | NodeMode::Hybrid) {
            // Validate subnet format for VPN modes
            if !self.subnet.contains('/') {
                return Err(ConfigError::InvalidSubnet(format!(
                    "Invalid subnet format: {}", self.subnet
                )));
            }
            
            // Check that cert and key files exist for VPN modes
            if !self.cert_file.to_string_lossy().contains("dummy") {
                if !self.cert_file.exists() {
                    return Err(ConfigError::Invalid(format!(
                        "Certificate file not found: {:?}", self.cert_file
                    )));
                }
                if !self.key_file.exists() {
                    return Err(ConfigError::Invalid(format!(
                        "Key file not found: {:?}", self.key_file
                    )));
                }
            }
        }
        
        // Validate obfuscation method
        if self.enable_obfuscation {
            match self.obfuscation_method.as_str() {
                "xor" | "scramblesuit" | "obfs4" => (), // Valid methods
                _ => return Err(ConfigError::Invalid(format!(
                    "Invalid obfuscation method: {}", self.obfuscation_method
                ))),
            }
        }
        
        // Validate timeout values
        if self.key_rotation_interval < Duration::from_secs(300) {
            return Err(ConfigError::Invalid(
                "Key rotation interval must be at least 300 seconds".to_string()
            ));
        }
        
        if self.session_timeout < Duration::from_secs(300) {
            return Err(ConfigError::Invalid(
                "Session timeout must be at least 300 seconds".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Check if VPN functionality is enabled
    pub fn is_vpn_enabled(&self) -> bool {
        matches!(self.mode, NodeMode::VPNEnabled | NodeMode::Hybrid)
    }
    
    /// Check if DePIN functionality is enabled
    pub fn is_depin_enabled(&self) -> bool {
        matches!(self.mode, NodeMode::DePINOnly | NodeMode::Hybrid)
    }
    
    /// Save configuration to a file
    pub fn save_to_file(&self, path: &str) -> Result<(), ConfigError> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
    
    /// Load configuration from a file
    pub fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
    
    /// Save registration information to a file (updated to include hardware fingerprint)
    pub fn save_registration(&self, reference_code: &str, wallet_address: &str, hardware_fingerprint: &str) -> Result<(), anyhow::Error> {
        use crate::registration::StoredRegistration;
        use chrono::Utc;
        
        // Create a config directory if it doesn't exist
        if !self.data_dir.exists() {
            std::fs::create_dir_all(&self.data_dir)?;
        }
        
        // Create registration data matching StoredRegistration structure
        let registration_data = StoredRegistration {
            reference_code: reference_code.to_string(),
            wallet_address: wallet_address.to_string(),
            hardware_fingerprint: hardware_fingerprint.to_string(),
            registered_at: chrono::Utc::now().to_rfc3339(),
            node_type: "DePIN".to_string(),
            version: 2,
            hardware_components: None,
            hardware_commitment: None,
        };
        
        // Save to a file in the data directory
        let config_path = self.data_dir.join("registration.json");
        let json = serde_json::to_string_pretty(&registration_data)?;
        
        std::fs::write(&config_path, json)?;
        
        info!("Registration data saved to {:?}", config_path);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_valid_config() {
        let config = ServerConfig {
            mode: NodeMode::Hybrid,
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            tun_name: "tun0".to_string(),
            subnet: "10.7.0.0/24".to_string(),
            cert_file: PathBuf::from("server.crt"),
            key_file: PathBuf::from("server.key"),
            acl_file: PathBuf::from("acl.json"),
            enable_obfuscation: true,
            obfuscation_method: "xor".to_string(),
            enable_padding: true,
            key_rotation_interval: Duration::from_secs(3600),
            session_timeout: Duration::from_secs(86400),
            max_connections_per_ip: 10,
            data_dir: PathBuf::from("/tmp"),
            server_key_file: PathBuf::from("/tmp/server_key.json"),
            registration_code: None,
            registration_reference_code: None,
            wallet_address: None,
            api_url: "https://api.aeronyx.network".to_string(),
            enable_remote_management: false,
            key_manager: None,
        };
        
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_validate_invalid_subnet() {
        let mut config = ServerConfig {
            mode: NodeMode::VPNEnabled,
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            tun_name: "tun0".to_string(),
            subnet: "10.7.0.0".to_string(), // Missing CIDR mask
            cert_file: PathBuf::from("server.crt"),
            key_file: PathBuf::from("server.key"),
            acl_file: PathBuf::from("acl.json"),
            enable_obfuscation: true,
            obfuscation_method: "xor".to_string(),
            enable_padding: true,
            key_rotation_interval: Duration::from_secs(3600),
            session_timeout: Duration::from_secs(86400),
            max_connections_per_ip: 10,
            data_dir: PathBuf::from("/tmp"),
            server_key_file: PathBuf::from("/tmp/server_key.json"),
            registration_code: None,
            registration_reference_code: None,
            wallet_address: None,
            api_url: "https://api.aeronyx.network".to_string(),
            enable_remote_management: false,
            key_manager: None,
        };
        
        assert!(config.validate().is_err());
        
        // Fix the subnet
        config.subnet = "10.7.0.0/24".to_string();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_mode_checks() {
        let mut config = ServerConfig {
            mode: NodeMode::DePINOnly,
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            tun_name: "tun0".to_string(),
            subnet: "10.7.0.0/24".to_string(),
            cert_file: PathBuf::from("dummy.crt"),
            key_file: PathBuf::from("dummy.key"),
            acl_file: PathBuf::from("acl.json"),
            enable_obfuscation: false,
            obfuscation_method: "xor".to_string(),
            enable_padding: false,
            key_rotation_interval: Duration::from_secs(3600),
            session_timeout: Duration::from_secs(86400),
            max_connections_per_ip: 10,
            data_dir: PathBuf::from("/tmp"),
            server_key_file: PathBuf::from("/tmp/server_key.json"),
            registration_code: None,
            registration_reference_code: None,
            wallet_address: None,
            api_url: "https://api.aeronyx.network".to_string(),
            enable_remote_management: false,
            key_manager: None,
        };
        
        // Test DePIN-only mode
        assert!(config.is_depin_enabled());
        assert!(!config.is_vpn_enabled());
        
        // Test VPN-enabled mode
        config.mode = NodeMode::VPNEnabled;
        assert!(!config.is_depin_enabled());
        assert!(config.is_vpn_enabled());
        
        // Test Hybrid mode
        config.mode = NodeMode::Hybrid;
        assert!(config.is_depin_enabled());
        assert!(config.is_vpn_enabled());
    }
    
    #[test]
    fn test_platform_specific_data_dir() {
        let default_dir = defaults::default_data_dir();
        
        #[cfg(target_os = "windows")]
        assert!(default_dir.to_string_lossy().contains("AeroNyx"));
        
        #[cfg(not(target_os = "windows"))]
        assert_eq!(default_dir, PathBuf::from("/var/lib/aeronyx"));
    }
}
