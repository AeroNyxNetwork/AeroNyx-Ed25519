// src/config/settings.rs
//! Server configuration settings.
//!
//! This module contains the server configuration structures and
//! implementation for loading, parsing, and validating user-provided
//! settings.

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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

/// Command line arguments for the server
#[derive(Parser, Debug, Clone)]
#[clap(
    name = "AeroNyx Privacy Network Server",
    about = "Military-grade privacy network with Solana keypair authentication",
    version,
    author
)]
pub struct ServerArgs {
    /// Server address to listen on
    #[clap(long, default_value = "0.0.0.0:8080")]
    pub listen: String,

    /// TUN device name
    #[clap(long, default_value = defaults::DEFAULT_TUN_NAME)]
    pub tun_name: String,

    /// VPN subnet in CIDR notation
    #[clap(long, default_value = defaults::DEFAULT_SUBNET)]
    pub subnet: String,

    /// Log level
    #[clap(long, default_value = defaults::DEFAULT_LOG_LEVEL)]
    pub log_level: String,

    /// TLS certificate file
    #[clap(long, default_value = defaults::DEFAULT_CERT_FILE)]
    pub cert_file: String,

    /// TLS key file
    #[clap(long, default_value = defaults::DEFAULT_KEY_FILE)]
    pub key_file: String,

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
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
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
    
    /// Key manager for server keys
    #[serde(skip)]
    pub key_manager: Option<Arc<KeyManager>>,
}

impl ServerConfig {
    /// Create a new server configuration from command line arguments
    pub fn from_args(args: ServerArgs) -> Result<Self, ConfigError> {
        // Check for configuration file first
        if let Some(config_path) = &args.config_file {
            if let Ok(file_content) = fs::read_to_string(config_path) {
                let mut config: ServerConfig = serde_json::from_str(&file_content)?;
                
                // Override with command line arguments if explicitly provided
                if args.listen != defaults::DEFAULT_LISTEN_ADDRESS {
                    config.listen_addr = args.listen.parse()?;
                }
                
                // Validate the config
                config.validate()?;
                return Ok(config);
            }
        }
        
        // Parse listen address
        let listen_addr = args.listen.parse()?;
        
        // Determine data directory
        let data_dir = PathBuf::from(&args.data_dir);
        
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
            listen_addr,
            tun_name: args.tun_name,
            subnet: args.subnet,
            cert_file: PathBuf::from(args.cert_file),
            key_file: PathBuf::from(args.key_file),
            acl_file: PathBuf::from(args.acl_file),
            enable_obfuscation: args.enable_obfuscation,
            obfuscation_method: args.obfuscation_method,
            enable_padding: args.enable_padding,
            key_rotation_interval: Duration::from_secs(args.key_rotation_interval),
            session_timeout: Duration::from_secs(args.session_timeout),
            max_connections_per_ip: args.max_connections_per_ip,
            data_dir,
            server_key_file,
            key_manager: None,
        };
        
        // Validate the config
        config.validate()?;
        
        Ok(config)
    }
    
    /// Validate configuration settings
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate subnet format
        if !self.subnet.contains('/') {
            return Err(ConfigError::InvalidSubnet(format!(
                "Invalid subnet format: {}", self.subnet
            )));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_valid_config() {
        let config = ServerConfig {
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
            key_manager: None,
        };
        
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_validate_invalid_subnet() {
        let mut config = ServerConfig {
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
            key_manager: None,
        };
        
        assert!(config.validate().is_err());
        
        // Fix the subnet
        config.subnet = "10.7.0.0/24".to_string();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_validate_invalid_obfuscation() {
        let mut config = ServerConfig {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            tun_name: "tun0".to_string(),
            subnet: "10.7.0.0/24".to_string(),
            cert_file: PathBuf::from("server.crt"),
            key_file: PathBuf::from("server.key"),
            acl_file: PathBuf::from("acl.json"),
            enable_obfuscation: true,
            obfuscation_method: "invalid".to_string(), // Invalid method
            enable_padding: true,
            key_rotation_interval: Duration::from_secs(3600),
            session_timeout: Duration::from_secs(86400),
            max_connections_per_ip: 10,
            data_dir: PathBuf::from("/tmp"),
            server_key_file: PathBuf::from("/tmp/server_key.json"),
            key_manager: None,
        };
        
        assert!(config.validate().is_err());
        
        // Fix the obfuscation method
        config.obfuscation_method = "xor".to_string();
        assert!(config.validate().is_ok());
    }
}
