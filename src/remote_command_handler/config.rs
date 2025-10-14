// src/remote_command_handler/config.rs
// ============================================
// Configuration for remote command handler
// ============================================

use std::path::PathBuf;
use std::time::Duration;

/// Security mode for command handler
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityMode {
    /// Full access mode - minimal restrictions
    FullAccess,
    /// Restricted mode - path and command restrictions apply
    Restricted,
}

/// Remote command handler configuration
#[derive(Debug, Clone)]
pub struct RemoteCommandConfig {
    /// Security mode
    pub security_mode: SecurityMode,
    /// Maximum file size for uploads/downloads
    pub max_file_size: u64,
    /// Maximum archive size
    pub max_archive_size: u64,
    /// Default command execution timeout
    pub command_timeout: Duration,
    /// Allowed paths for file operations
    pub allowed_paths: Vec<PathBuf>,
    /// Forbidden commands
    pub forbidden_commands: Vec<String>,
    /// Enable command whitelist
    pub enable_command_whitelist: bool,
    /// Whitelisted commands
    pub command_whitelist: Vec<String>,
    /// Default working directory
    pub working_dir: PathBuf,
    /// Maximum search depth
    pub max_search_depth: u32,
    /// Maximum search results
    pub max_search_results: usize,
}

impl Default for RemoteCommandConfig {
    fn default() -> Self {
        Self {
            security_mode: SecurityMode::Restricted,
            max_file_size: 50 * 1024 * 1024, // 50MB
            max_archive_size: 100 * 1024 * 1024, // 100MB
            command_timeout: Duration::from_secs(60),
            allowed_paths: vec![
                PathBuf::from("/home"),
                PathBuf::from("/var/log/aeronyx"),
                PathBuf::from("/tmp"),
            ],
            forbidden_commands: vec![
                "rm -rf /".to_string(),
                "rm -rf /*".to_string(),
                "format".to_string(),
                "dd".to_string(),
                "mkfs".to_string(),
            ],
            enable_command_whitelist: false,
            command_whitelist: Self::default_whitelist(),
            working_dir: PathBuf::from("/var/aeronyx"),
            max_search_depth: 5,
            max_search_results: 1000,
        }
    }
}

impl RemoteCommandConfig {
    /// Create a full access configuration
    pub fn full_access() -> Self {
        Self {
            security_mode: SecurityMode::FullAccess,
            max_file_size: 500 * 1024 * 1024, // 500MB
            max_archive_size: 1024 * 1024 * 1024, // 1GB
            command_timeout: Duration::from_secs(300),
            allowed_paths: vec![],
            forbidden_commands: vec![
                "rm -rf /".to_string(),
                "rm -rf /*".to_string(),
                ":(){:|:&};:".to_string(), // Fork bomb
            ],
            enable_command_whitelist: false,
            command_whitelist: vec![],
            working_dir: PathBuf::from("/"),
            max_search_depth: 10,
            max_search_results: 10000,
        }
    }
    
    /// Create a restricted configuration with custom paths
    pub fn restricted_with_paths(allowed_paths: Vec<PathBuf>) -> Self {
        let mut config = Self::default();
        config.allowed_paths = allowed_paths;
        config
    }

    /// Get default command whitelist
    fn default_whitelist() -> Vec<String> {
        vec![
            // File operations
            "ls".to_string(),
            "cat".to_string(),
            "head".to_string(),
            "tail".to_string(),
            "grep".to_string(),
            "find".to_string(),
            "stat".to_string(),
            "file".to_string(),
            "wc".to_string(),
            
            // Directory operations
            "pwd".to_string(),
            "mkdir".to_string(),
            "rmdir".to_string(),
            
            // File manipulation
            "cp".to_string(),
            "mv".to_string(),
            "touch".to_string(),
            "chmod".to_string(),
            
            // Archive operations
            "tar".to_string(),
            "zip".to_string(),
            "unzip".to_string(),
            "gzip".to_string(),
            "gunzip".to_string(),
            
            // System info
            "ps".to_string(),
            "top".to_string(),
            "df".to_string(),
            "du".to_string(),
            "free".to_string(),
            "uptime".to_string(),
            "whoami".to_string(),
            "hostname".to_string(),
            "uname".to_string(),
            "date".to_string(),
            
            // Network
            "netstat".to_string(),
            "ss".to_string(),
            "ping".to_string(),
            "curl".to_string(),
            "wget".to_string(),
            
            // Process management
            "kill".to_string(),
            "killall".to_string(),
            "pkill".to_string(),
            
            // Shells
            "sh".to_string(),
            "bash".to_string(),
            
            // Text processing
            "sed".to_string(),
            "awk".to_string(),
            "sort".to_string(),
            "uniq".to_string(),
            "cut".to_string(),
            
            // Others
            "echo".to_string(),
            "which".to_string(),
            "env".to_string(),
        ]
    }
}
