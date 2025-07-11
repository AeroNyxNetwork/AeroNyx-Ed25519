// src/remote_management.rs
// AeroNyx Privacy Network - Remote Management Module
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module provides secure remote management capabilities for AeroNyx nodes.
// It implements a sandboxed environment for executing authorized commands,
// file operations, and system monitoring. All operations are subject to strict
// security policies and access controls to prevent unauthorized access.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Add missing import for Unix permissions
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Remote command types supported by the management interface
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum RemoteCommand {
    /// List directory contents with metadata
    #[serde(rename = "list_directory")]
    ListDirectory { 
        path: String,
        #[serde(default)]
        recursive: bool,
        #[serde(default)]
        include_hidden: bool,
    },
    
    /// Read file content with size limits
    #[serde(rename = "read_file")]
    ReadFile { 
        path: String,
        #[serde(default)]
        offset: Option<u64>,
        #[serde(default)]
        limit: Option<u64>,
    },
    
    /// Delete file with safety checks
    #[serde(rename = "delete_file")]
    DeleteFile { 
        path: String,
        #[serde(default)]
        confirm: bool,
    },
    
    /// Execute system command with restrictions
    #[serde(rename = "execute_command")]
    ExecuteCommand { 
        command: String,
        args: Vec<String>,
        #[serde(default)]
        working_dir: Option<String>,
        #[serde(default)]
        timeout_seconds: Option<u64>,
        #[serde(default)]
        env_vars: Option<HashMap<String, String>>,
    },
    
    /// Get comprehensive system information
    #[serde(rename = "get_system_info")]
    GetSystemInfo {
        #[serde(default)]
        include_network: bool,
        #[serde(default)]
        include_processes: bool,
    },
    
    /// Get list of running processes
    #[serde(rename = "get_process_list")]
    GetProcessList {
        #[serde(default)]
        filter: Option<String>,
        #[serde(default)]
        sort_by: Option<String>,
    },
    
    /// Upload file with validation
    #[serde(rename = "upload_file")]
    UploadFile {
        path: String,
        content: String, // Base64 encoded
        #[serde(default)]
        mode: Option<u32>,
        #[serde(default)]
        overwrite: bool,
    },
    
    /// Download file with compression
    #[serde(rename = "download_file")]
    DownloadFile { 
        path: String,
        #[serde(default)]
        compress: bool,
    },
    
    /// Get service logs
    #[serde(rename = "get_logs")]
    GetLogs {
        #[serde(default)]
        service: Option<String>,
        #[serde(default)]
        lines: Option<u32>,
        #[serde(default)]
        since: Option<String>,
    },
    
    /// Restart service
    #[serde(rename = "restart_service")]
    RestartService {
        service_name: String,
        #[serde(default)]
        force: bool,
    },
    
    /// Update node configuration
    #[serde(rename = "update_config")]
    UpdateConfig {
        config_section: String,
        values: HashMap<String, serde_json::Value>,
        #[serde(default)]
        restart_required: bool,
    },
}

/// Response structure for remote commands
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_time_ms: Option<u64>,
}

/// Security policy for remote management
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Allowed paths for file operations
    pub allowed_paths: Vec<PathBuf>,
    /// Forbidden paths (takes precedence over allowed)
    pub forbidden_paths: Vec<PathBuf>,
    /// Allowed commands for execution
    pub allowed_commands: Vec<String>,
    /// Maximum file size for read/write operations
    pub max_file_size: u64,
    /// Maximum command execution time
    pub max_execution_time: Duration,
    /// Enable dangerous operations (delete, execute)
    pub allow_dangerous_operations: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_paths: vec![
                PathBuf::from("/home"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/log"),
                PathBuf::from("/opt/aeronyx"),
            ],
            forbidden_paths: vec![
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/passwd"),
                PathBuf::from("/root/.ssh"),
                PathBuf::from("/etc/aeronyx/private"),
            ],
            allowed_commands: vec![
                "ls".to_string(),
                "ps".to_string(),
                "df".to_string(),
                "free".to_string(),
                "uptime".to_string(),
                "whoami".to_string(),
                "date".to_string(),
                "cat".to_string(),
                "grep".to_string(),
                "tail".to_string(),
                "head".to_string(),
                "systemctl".to_string(),
                "journalctl".to_string(),
                "netstat".to_string(),
                "ss".to_string(),
                "ip".to_string(),
            ],
            max_file_size: 50 * 1024 * 1024, // 50MB
            max_execution_time: Duration::from_secs(30),
            allow_dangerous_operations: false,
        }
    }
}

/// Remote management handler with security controls
pub struct RemoteManagementHandler {
    /// Security policy
    policy: SecurityPolicy,
    /// Command execution history
    command_history: tokio::sync::Mutex<Vec<CommandHistoryEntry>>,
    /// Rate limiting
    rate_limiter: tokio::sync::Mutex<RateLimiter>,
}

/// Command execution history entry
#[derive(Debug, Clone)]
struct CommandHistoryEntry {
    timestamp: SystemTime,
    command_type: String,
    success: bool,
    execution_time_ms: u64,
}

/// Simple rate limiter
#[derive(Debug)]
struct RateLimiter {
    requests: HashMap<String, Vec<SystemTime>>,
    max_requests_per_minute: usize,
}

impl RateLimiter {
    fn new(max_requests: usize) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests_per_minute: max_requests,
        }
    }
    
    fn check_and_update(&mut self, key: &str) -> bool {
        let now = SystemTime::now();
        let one_minute_ago = now - Duration::from_secs(60);
        
        // Clean old entries
        if let Some(entries) = self.requests.get_mut(key) {
            entries.retain(|&time| time > one_minute_ago);
        }
        
        // Check rate limit
        let entries = self.requests.entry(key.to_string()).or_insert_with(Vec::new);
        if entries.len() >= self.max_requests_per_minute {
            false
        } else {
            entries.push(now);
            true
        }
    }
}

impl RemoteManagementHandler {
    /// Create a new remote management handler with default security policy
    pub fn new() -> Self {
        Self {
            policy: SecurityPolicy::default(),
            command_history: tokio::sync::Mutex::new(Vec::new()),
            rate_limiter: tokio::sync::Mutex::new(RateLimiter::new(60)),
        }
    }
    
    /// Create handler with custom security policy
    pub fn with_policy(policy: SecurityPolicy) -> Self {
        Self {
            policy,
            command_history: tokio::sync::Mutex::new(Vec::new()),
            rate_limiter: tokio::sync::Mutex::new(RateLimiter::new(60)),
        }
    }
    
    /// Handle incoming remote command
    pub async fn handle_command(&self, command: RemoteCommand) -> CommandResponse {
        let start_time = std::time::Instant::now();
        
        // Rate limiting check
        let command_type = self.get_command_type(&command);
        if !self.check_rate_limit(&command_type).await {
            return CommandResponse {
                success: false,
                message: "Rate limit exceeded. Please try again later.".to_string(),
                data: None,
                error_code: Some("RATE_LIMIT_EXCEEDED".to_string()),
                execution_time_ms: None,
            };
        }
        
        // Execute command based on type
        let result = match command {
            RemoteCommand::ListDirectory { path, recursive, include_hidden } => {
                self.list_directory(&path, recursive, include_hidden).await
            }
            RemoteCommand::ReadFile { path, offset, limit } => {
                self.read_file(&path, offset, limit).await
            }
            RemoteCommand::DeleteFile { path, confirm } => {
                self.delete_file(&path, confirm).await
            }
            RemoteCommand::ExecuteCommand { command, args, working_dir, timeout_seconds, env_vars } => {
                self.execute_command(&command, args, working_dir, timeout_seconds, env_vars).await
            }
            RemoteCommand::GetSystemInfo { include_network, include_processes } => {
                self.get_system_info(include_network, include_processes).await
            }
            RemoteCommand::GetProcessList { filter, sort_by } => {
                self.get_process_list(filter, sort_by).await
            }
            RemoteCommand::UploadFile { path, content, mode, overwrite } => {
                self.upload_file(&path, &content, mode, overwrite).await
            }
            RemoteCommand::DownloadFile { path, compress } => {
                self.download_file(&path, compress).await
            }
            RemoteCommand::GetLogs { service, lines, since } => {
                self.get_logs(service, lines, since).await
            }
            RemoteCommand::RestartService { service_name, force } => {
                self.restart_service(&service_name, force).await
            }
            RemoteCommand::UpdateConfig { config_section, values, restart_required } => {
                self.update_config(&config_section, values, restart_required).await
            }
        };
        
        // Record execution
        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        self.record_command_execution(&command_type, result.success, execution_time_ms).await;
        
        // Add execution time to response
        let mut response = result;
        response.execution_time_ms = Some(execution_time_ms);
        
        response
    }
    
    /// Get command type string for logging and rate limiting
    fn get_command_type(&self, command: &RemoteCommand) -> String {
        match command {
            RemoteCommand::ListDirectory { .. } => "list_directory",
            RemoteCommand::ReadFile { .. } => "read_file",
            RemoteCommand::DeleteFile { .. } => "delete_file",
            RemoteCommand::ExecuteCommand { .. } => "execute_command",
            RemoteCommand::GetSystemInfo { .. } => "get_system_info",
            RemoteCommand::GetProcessList { .. } => "get_process_list",
            RemoteCommand::UploadFile { .. } => "upload_file",
            RemoteCommand::DownloadFile { .. } => "download_file",
            RemoteCommand::GetLogs { .. } => "get_logs",
            RemoteCommand::RestartService { .. } => "restart_service",
            RemoteCommand::UpdateConfig { .. } => "update_config",
        }.to_string()
    }
    
    /// Check rate limit for command
    async fn check_rate_limit(&self, command_type: &str) -> bool {
        let mut limiter = self.rate_limiter.lock().await;
        limiter.check_and_update(command_type)
    }
    
    /// Record command execution for auditing
    async fn record_command_execution(&self, command_type: &str, success: bool, execution_time_ms: u64) {
        let mut history = self.command_history.lock().await;
        history.push(CommandHistoryEntry {
            timestamp: SystemTime::now(),
            command_type: command_type.to_string(),
            success,
            execution_time_ms,
        });
        
        // Keep only last 1000 entries
        if history.len() > 1000 {
            history.drain(0..100);
        }
    }
    
    /// Check if a path is allowed according to security policy
    fn is_path_allowed(&self, path: &Path) -> Result<PathBuf, String> {
        // Canonicalize path to prevent directory traversal attacks
        let canonical_path = path.canonicalize()
            .map_err(|e| format!("Invalid path: {}", e))?;
        
        // Check forbidden paths first
        for forbidden in &self.policy.forbidden_paths {
            if canonical_path.starts_with(forbidden) {
                return Err(format!("Access denied: Path is forbidden"));
            }
        }
        
        // Check allowed paths
        let is_allowed = self.policy.allowed_paths.iter()
            .any(|allowed| canonical_path.starts_with(allowed));
        
        if is_allowed {
            Ok(canonical_path)
        } else {
            Err("Access denied: Path not in allowed list".to_string())
        }
    }
    
    /// Check if a command is allowed
    fn is_command_allowed(&self, command: &str) -> bool {
        self.policy.allowed_commands.contains(&command.to_string())
    }
    
    /// List directory contents
    async fn list_directory(&self, path: &str, recursive: bool, include_hidden: bool) -> CommandResponse {
        let path = Path::new(path);
        
        // Security check
        let canonical_path = match self.is_path_allowed(path) {
            Ok(p) => p,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: e,
                    data: None,
                    error_code: Some("ACCESS_DENIED".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        // Check if path exists and is a directory
        let metadata = match fs::metadata(&canonical_path).await {
            Ok(m) => m,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to access path: {}", e),
                    data: None,
                    error_code: Some("PATH_NOT_FOUND".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        if !metadata.is_dir() {
            return CommandResponse {
                success: false,
                message: "Path is not a directory".to_string(),
                data: None,
                error_code: Some("NOT_A_DIRECTORY".to_string()),
                execution_time_ms: None,
            };
        }
        
        // List directory
        match self.list_directory_recursive(&canonical_path, recursive, include_hidden, 0).await {
            Ok(entries) => CommandResponse {
                success: true,
                message: "Directory listed successfully".to_string(),
                data: Some(serde_json::json!({ "entries": entries })),
                error_code: None,
                execution_time_ms: None,
            },
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to list directory: {}", e),
                data: None,
                error_code: Some("LIST_ERROR".to_string()),
                execution_time_ms: None,
            },
        }
    }
    
    /// Recursively list directory contents
    async fn list_directory_recursive(
        &self,
        path: &Path,
        recursive: bool,
        include_hidden: bool,
        depth: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        // Limit recursion depth
        if depth > 5 {
            return Ok(vec![]);
        }
        
        let mut entries = Vec::new();
        let mut dir_stream = fs::read_dir(path).await
            .map_err(|e| format!("Failed to read directory: {}", e))?;
        
        while let Ok(Some(entry)) = dir_stream.next_entry().await {
            let file_name = entry.file_name().to_string_lossy().to_string();
            
            // Skip hidden files if requested
            if !include_hidden && file_name.starts_with('.') {
                continue;
            }
            
            if let Ok(metadata) = entry.metadata().await {
                let mut entry_info = serde_json::json!({
                    "name": file_name,
                    "path": entry.path().to_string_lossy(),
                    "is_dir": metadata.is_dir(),
                    "is_file": metadata.is_file(),
                    "size": metadata.len(),
                    "modified": metadata.modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs()),
                });
                
                // Add permissions on Unix systems
                #[cfg(unix)]
                {
                    entry_info["permissions"] = serde_json::json!(
                        format!("{:o}", metadata.permissions().mode() & 0o777)
                    );
                }
                
                // Add children for directories if recursive
                if recursive && metadata.is_dir() {
                    if let Ok(children) = self.list_directory_recursive(
                        &entry.path(),
                        recursive,
                        include_hidden,
                        depth + 1
                    ).await {
                        entry_info["children"] = serde_json::json!(children);
                    }
                }
                
                entries.push(entry_info);
            }
        }
        
        // Sort entries: directories first, then by name
        entries.sort_by(|a, b| {
            let a_is_dir = a["is_dir"].as_bool().unwrap_or(false);
            let b_is_dir = b["is_dir"].as_bool().unwrap_or(false);
            let a_name = a["name"].as_str().unwrap_or("");
            let b_name = b["name"].as_str().unwrap_or("");
            
            match (a_is_dir, b_is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a_name.cmp(b_name),
            }
        });
        
        Ok(entries)
    }
    
    /// Read file content
    async fn read_file(&self, path: &str, offset: Option<u64>, limit: Option<u64>) -> CommandResponse {
        let path = Path::new(path);
        
        // Security check
        let canonical_path = match self.is_path_allowed(path) {
            Ok(p) => p,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: e,
                    data: None,
                    error_code: Some("ACCESS_DENIED".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        // Check file size
        match fs::metadata(&canonical_path).await {
            Ok(metadata) => {
                if metadata.len() > self.policy.max_file_size {
                    return CommandResponse {
                        success: false,
                        message: format!("File too large. Maximum size: {} bytes", self.policy.max_file_size),
                        data: None,
                        error_code: Some("FILE_TOO_LARGE".to_string()),
                        execution_time_ms: None,
                    };
                }
                
                if !metadata.is_file() {
                    return CommandResponse {
                        success: false,
                        message: "Path is not a file".to_string(),
                        data: None,
                        error_code: Some("NOT_A_FILE".to_string()),
                        execution_time_ms: None,
                    };
                }
            }
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to access file: {}", e),
                    data: None,
                    error_code: Some("FILE_NOT_FOUND".to_string()),
                    execution_time_ms: None,
                };
            }
        }
        
        // Read file with offset and limit
        match self.read_file_with_options(&canonical_path, offset, limit).await {
            Ok((content, total_size)) => {
                // Try to detect if file is binary
                let is_binary = content.iter().take(1000).any(|&b| b == 0);
                
                let response_data = if is_binary {
                    serde_json::json!({
                        "content": base64::encode(&content),
                        "encoding": "base64",
                        "size": content.len(),
                        "total_size": total_size,
                        "offset": offset.unwrap_or(0),
                    })
                } else {
                    // Clone content before moving it
                    match String::from_utf8(content.clone()) {
                        Ok(text) => serde_json::json!({
                            "content": text,
                            "encoding": "utf8",
                            "size": text.len(),
                            "total_size": total_size,
                            "offset": offset.unwrap_or(0),
                        }),
                        Err(_) => serde_json::json!({
                            "content": base64::encode(&content),
                            "encoding": "base64",
                            "size": content.len(),
                            "total_size": total_size,
                            "offset": offset.unwrap_or(0),
                        }),
                    }
                };
                
                CommandResponse {
                    success: true,
                    message: "File read successfully".to_string(),
                    data: Some(response_data),
                    error_code: None,
                    execution_time_ms: None,
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to read file: {}", e),
                data: None,
                error_code: Some("READ_ERROR".to_string()),
                execution_time_ms: None,
            },
        }
    }
    
    /// Read file with offset and limit options
    async fn read_file_with_options(
        &self,
        path: &Path,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<(Vec<u8>, u64), String> {
        use tokio::io::{AsyncSeekExt, SeekFrom};
        
        let mut file = fs::File::open(path).await
            .map_err(|e| format!("Failed to open file: {}", e))?;
        
        let metadata = file.metadata().await
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;
        let total_size = metadata.len();
        
        // Seek to offset if specified
        if let Some(offset) = offset {
            file.seek(SeekFrom::Start(offset)).await
                .map_err(|e| format!("Failed to seek: {}", e))?;
        }
        
        // Determine read size
        let read_limit = limit.unwrap_or(self.policy.max_file_size)
            .min(self.policy.max_file_size);
        
        // Read file content
        let mut buffer = vec![0; read_limit as usize];
        let bytes_read = file.read(&mut buffer).await
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        buffer.truncate(bytes_read);
        Ok((buffer, total_size))
    }
    
    /// Delete file with confirmation
    async fn delete_file(&self, path: &str, confirm: bool) -> CommandResponse {
        if !self.policy.allow_dangerous_operations {
            return CommandResponse {
                success: false,
                message: "Delete operations are disabled by security policy".to_string(),
                data: None,
                error_code: Some("OPERATION_DISABLED".to_string()),
                execution_time_ms: None,
            };
        }
        
        if !confirm {
            return CommandResponse {
                success: false,
                message: "Delete operation requires confirmation".to_string(),
                data: None,
                error_code: Some("CONFIRMATION_REQUIRED".to_string()),
                execution_time_ms: None,
            };
        }
        
        let path = Path::new(path);
        
        // Security check
        let canonical_path = match self.is_path_allowed(path) {
            Ok(p) => p,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: e,
                    data: None,
                    error_code: Some("ACCESS_DENIED".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        // Additional safety check - don't delete directories
        match fs::metadata(&canonical_path).await {
            Ok(metadata) => {
                if metadata.is_dir() {
                    return CommandResponse {
                        success: false,
                        message: "Cannot delete directories. Use recursive delete if needed.".to_string(),
                        data: None,
                        error_code: Some("IS_DIRECTORY".to_string()),
                        execution_time_ms: None,
                    };
                }
            }
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to access file: {}", e),
                    data: None,
                    error_code: Some("FILE_NOT_FOUND".to_string()),
                    execution_time_ms: None,
                };
            }
        }
        
        // Delete file
        match fs::remove_file(&canonical_path).await {
            Ok(_) => {
                info!("File deleted: {:?}", canonical_path);
                CommandResponse {
                    success: true,
                    message: "File deleted successfully".to_string(),
                    data: Some(serde_json::json!({
                        "deleted_path": canonical_path.to_string_lossy()
                    })),
                    error_code: None,
                    execution_time_ms: None,
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to delete file: {}", e),
                data: None,
                error_code: Some("DELETE_ERROR".to_string()),
                execution_time_ms: None,
            },
        }
    }
    
    /// Execute system command with restrictions
    async fn execute_command(
        &self,
        command: &str,
        args: Vec<String>,
        working_dir: Option<String>,
        timeout_seconds: Option<u64>,
        env_vars: Option<HashMap<String, String>>,
    ) -> CommandResponse {
        if !self.policy.allow_dangerous_operations {
            return CommandResponse {
                success: false,
                message: "Command execution is disabled by security policy".to_string(),
                data: None,
                error_code: Some("OPERATION_DISABLED".to_string()),
                execution_time_ms: None,
            };
        }
        
        if !self.is_command_allowed(command) {
            return CommandResponse {
                success: false,
                message: format!("Command '{}' is not allowed", command),
                data: None,
                error_code: Some("COMMAND_NOT_ALLOWED".to_string()),
                execution_time_ms: None,
            };
        }
        
        // Validate arguments for common injection patterns
        for arg in &args {
            if arg.contains("&&") || arg.contains("||") || arg.contains(";") || 
               arg.contains("|") || arg.contains("$") || arg.contains("`") {
                return CommandResponse {
                    success: false,
                    message: "Invalid characters in command arguments".to_string(),
                    data: None,
                    error_code: Some("INVALID_ARGUMENTS".to_string()),
                    execution_time_ms: None,
                };
            }
        }
        
        let mut cmd = Command::new(command);
        cmd.args(&args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        // Set working directory if specified and allowed
        if let Some(dir) = working_dir {
            let path = Path::new(&dir);
            if self.is_path_allowed(path).is_ok() {
                cmd.current_dir(dir);
            }
        }
        
        // Set environment variables if specified
        if let Some(vars) = env_vars {
            for (key, value) in vars {
                // Only allow safe environment variables
                if key.starts_with("AERONYX_") || key == "PATH" || key == "HOME" {
                    cmd.env(key, value);
                }
            }
        }
        
        // Execute with timeout
        let timeout = Duration::from_secs(
            timeout_seconds.unwrap_or(30).min(self.policy.max_execution_time.as_secs())
        );
        
        let start_time = std::time::Instant::now();
        
        // Spawn command (sync)
        let output_result = cmd.output();
        
        match tokio::time::timeout(timeout, async {
            tokio::task::spawn_blocking(move || output_result)
                .await
                .map_err(|e| format!("Failed to execute command: {}", e))?
                .map_err(|e| format!("Command execution failed: {}", e))
        }).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                info!("Command executed: {} {:?}", command, args);
                
                CommandResponse {
                    success: output.status.success(),
                    message: if output.status.success() {
                        "Command executed successfully".to_string()
                    } else {
                        format!("Command failed with exit code: {:?}", output.status.code())
                    },
                    data: Some(serde_json::json!({
                        "stdout": stdout,
                        "stderr": stderr,
                        "exit_code": output.status.code(),
                        "execution_time_ms": start_time.elapsed().as_millis(),
                    })),
                    error_code: if output.status.success() { None } else { Some("COMMAND_FAILED".to_string()) },
                    execution_time_ms: None,
                }
            }
            Ok(Err(e)) => CommandResponse {
                success: false,
                message: e,
                data: None,
                error_code: Some("EXECUTION_ERROR".to_string()),
                execution_time_ms: None,
            },
            Err(_) => CommandResponse {
                success: false,
                message: format!("Command execution timed out after {} seconds", timeout.as_secs()),
                data: None,
                error_code: Some("TIMEOUT".to_string()),
                execution_time_ms: None,
            },
        }
    }
    
    /// Get comprehensive system information
    async fn get_system_info(&self, include_network: bool, include_processes: bool) -> CommandResponse {
        let mut info = serde_json::json!({
            "hostname": gethostname::gethostname().to_string_lossy(),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "uptime": self.get_system_uptime().await,
        });
        
        // CPU information
        if let Ok(cpu_info) = self.get_cpu_info().await {
            info["cpu"] = cpu_info;
        }
        
        // Memory information
        if let Ok(mem_info) = self.get_memory_info().await {
            info["memory"] = mem_info;
        }
        
        // Disk information
        if let Ok(disk_info) = self.get_disk_info().await {
            info["disk"] = disk_info;
        }
        
        // Network information (if requested)
        if include_network {
            if let Ok(net_info) = self.get_network_info().await {
                info["network"] = net_info;
            }
        }
        
        // Process count (if requested)
        if include_processes {
            if let Ok(proc_count) = self.get_process_count().await {
                info["process_count"] = proc_count.into();
            }
        }
        
        // Load average
        if let Ok(load) = sys_info::loadavg() {
            info["load_average"] = serde_json::json!({
                "one": load.one,
                "five": load.five,
                "fifteen": load.fifteen,
            });
        }
        
        CommandResponse {
            success: true,
            message: "System information retrieved".to_string(),
            data: Some(info),
            error_code: None,
            execution_time_ms: None,
        }
    }
    
    /// Get system uptime in seconds
    async fn get_system_uptime(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(uptime_str) = fs::read_to_string("/proc/uptime").await {
                if let Some(uptime) = uptime_str.split_whitespace().next() {
                    if let Ok(uptime_secs) = uptime.parse::<f64>() {
                        return uptime_secs as u64;
                    }
                }
            }
        }
        
        // Fallback
        0
    }
    
    /// Get CPU information
    async fn get_cpu_info(&self) -> Result<serde_json::Value, String> {
        let cpu_count = sys_info::cpu_num().unwrap_or(0);
        let cpu_speed = sys_info::cpu_speed().unwrap_or(0);
        
        let mut cpu_info = serde_json::json!({
            "count": cpu_count,
            "speed_mhz": cpu_speed,
        });
        
        // Try to get CPU model on Linux
        #[cfg(target_os = "linux")]
        {
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo").await {
                for line in cpuinfo.lines() {
                    if line.starts_with("model name") {
                        if let Some(model) = line.split(':').nth(1) {
                            cpu_info["model"] = serde_json::Value::String(model.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(cpu_info)
    }
    
    /// Get memory information
    async fn get_memory_info(&self) -> Result<serde_json::Value, String> {
        let mem_info = sys_info::mem_info()
            .map_err(|e| format!("Failed to get memory info: {}", e))?;
        
        Ok(serde_json::json!({
            "total_kb": mem_info.total,
            "free_kb": mem_info.free,
            "available_kb": mem_info.avail,
            "buffers_kb": mem_info.buffers,
            "cached_kb": mem_info.cached,
            "usage_percent": ((mem_info.total - mem_info.avail) as f64 / mem_info.total as f64 * 100.0),
        }))
    }
    
    /// Get disk information
    async fn get_disk_info(&self) -> Result<serde_json::Value, String> {
        let disk_info = sys_info::disk_info()
            .map_err(|e| format!("Failed to get disk info: {}", e))?;
        
        Ok(serde_json::json!({
            "total_kb": disk_info.total,
            "free_kb": disk_info.free,
            "usage_percent": ((disk_info.total - disk_info.free) as f64 / disk_info.total as f64 * 100.0),
        }))
    }
    
    /// Get network information
    async fn get_network_info(&self) -> Result<serde_json::Value, String> {
        // This is a simplified version - could be expanded
        let mut interfaces = Vec::new();
        
        #[cfg(target_os = "linux")]
        {
            if let Ok(mut entries) = fs::read_dir("/sys/class/net").await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let if_name = entry.file_name().to_string_lossy().to_string();
                    let mut if_info = serde_json::json!({
                        "name": if_name,
                    });
                    
                    // Try to read interface state
                    let state_path = entry.path().join("operstate");
                    if let Ok(state) = fs::read_to_string(state_path).await {
                        if_info["state"] = serde_json::Value::String(state.trim().to_string());
                    }
                    
                    // Try to read MAC address
                    let addr_path = entry.path().join("address");
                    if let Ok(addr) = fs::read_to_string(addr_path).await {
                        if_info["mac_address"] = serde_json::Value::String(addr.trim().to_string());
                    }
                    
                    interfaces.push(if_info);
                }
            }
        }
        
        Ok(serde_json::json!({
            "interfaces": interfaces,
        }))
    }
    
    /// Get process count
    async fn get_process_count(&self) -> Result<u32, String> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(mut entries) = fs::read_dir("/proc").await {
                let mut count = 0;
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if entry.file_name()
                        .to_str()
                        .map(|name| name.chars().all(|c| c.is_digit(10)))
                        .unwrap_or(false) {
                        count += 1;
                    }
                }
                
                return Ok(count);
            }
        }
        
        Ok(0)
    }
    
    /// Get process list with optional filtering
    async fn get_process_list(&self, filter: Option<String>, sort_by: Option<String>) -> CommandResponse {
        // Use ps command for process listing
        let args = vec!["aux".to_string()];
        
        // Execute ps command (sync)
        let output = match Command::new("ps")
            .args(&args)
            .output() {
            Ok(output) => output,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to get process list: {}", e),
                    data: None,
                    error_code: Some("COMMAND_ERROR".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        
        if lines.is_empty() {
            return CommandResponse {
                success: false,
                message: "No process information available".to_string(),
                data: None,
                error_code: Some("NO_DATA".to_string()),
                execution_time_ms: None,
            };
        }
        
        // Parse ps output
        let mut processes = Vec::new();
        
        for line in lines.iter().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 11 {
                let process_name = parts[10..].join(" ");
                
                // Apply filter if specified
                if let Some(ref filter_str) = filter {
                    if !process_name.to_lowercase().contains(&filter_str.to_lowercase()) &&
                       !parts[0].contains(filter_str) {  // Also check user
                        continue;
                    }
                }
                
                let process_info = serde_json::json!({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "vsz": parts[4],
                    "rss": parts[5],
                    "tty": parts[6],
                    "stat": parts[7],
                    "start": parts[8],
                    "time": parts[9],
                    "command": process_name,
                });
                
                processes.push(process_info);
            }
        }
        
        // Sort if requested
        if let Some(sort_field) = sort_by {
            processes.sort_by(|a, b| {
                match sort_field.as_str() {
                    "cpu" => {
                        let a_cpu = a["cpu"].as_str().unwrap_or("0").parse::<f64>().unwrap_or(0.0);
                        let b_cpu = b["cpu"].as_str().unwrap_or("0").parse::<f64>().unwrap_or(0.0);
                        b_cpu.partial_cmp(&a_cpu).unwrap_or(std::cmp::Ordering::Equal)
                    }
                    "mem" => {
                        let a_mem = a["mem"].as_str().unwrap_or("0").parse::<f64>().unwrap_or(0.0);
                        let b_mem = b["mem"].as_str().unwrap_or("0").parse::<f64>().unwrap_or(0.0);
                        b_mem.partial_cmp(&a_mem).unwrap_or(std::cmp::Ordering::Equal)
                    }
                    "pid" => {
                        let a_pid = a["pid"].as_str().unwrap_or("0").parse::<u32>().unwrap_or(0);
                        let b_pid = b["pid"].as_str().unwrap_or("0").parse::<u32>().unwrap_or(0);
                        a_pid.cmp(&b_pid)
                    }
                    _ => std::cmp::Ordering::Equal,
                }
            });
        }
        
        CommandResponse {
            success: true,
            message: format!("Found {} processes", processes.len()),
            data: Some(serde_json::json!({
                "processes": processes,
                "count": processes.len(),
                "filter": filter,
                "sort_by": sort_by,
            })),
            error_code: None,
            execution_time_ms: None,
        }
    }
    
    /// Upload file with validation
    async fn upload_file(&self, path: &str, content: &str, mode: Option<u32>, overwrite: bool) -> CommandResponse {
        let path = Path::new(path);
        
        // Security check
        let canonical_path = match self.is_path_allowed(path.parent().unwrap_or(Path::new("/"))) {
            Ok(_) => {
                // For new files, we can't canonicalize, so we check the parent
                match path.parent() {
                    Some(parent) => {
                        match parent.canonicalize() {
                            Ok(canonical_parent) => canonical_parent.join(path.file_name().unwrap()),
                            Err(e) => {
                                return CommandResponse {
                                    success: false,
                                    message: format!("Invalid parent directory: {}", e),
                                    data: None,
                                    error_code: Some("INVALID_PATH".to_string()),
                                    execution_time_ms: None,
                                };
                            }
                        }
                    }
                    None => {
                        return CommandResponse {
                            success: false,
                            message: "Invalid path".to_string(),
                            data: None,
                            error_code: Some("INVALID_PATH".to_string()),
                            execution_time_ms: None,
                        };
                    }
                }
            }
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: e,
                    data: None,
                    error_code: Some("ACCESS_DENIED".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        // Check if file exists and overwrite is not allowed
        if canonical_path.exists() && !overwrite {
            return CommandResponse {
                success: false,
                message: "File already exists. Set overwrite=true to replace.".to_string(),
                data: None,
                error_code: Some("FILE_EXISTS".to_string()),
                execution_time_ms: None,
            };
        }
        
        // Decode base64 content
        let decoded = match base64::decode(content) {
            Ok(d) => d,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to decode base64 content: {}", e),
                    data: None,
                    error_code: Some("INVALID_CONTENT".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        // Check size limit
        if decoded.len() > self.policy.max_file_size as usize {
            return CommandResponse {
                success: false,
                message: format!("File too large. Maximum size: {} bytes", self.policy.max_file_size),
                data: None,
                error_code: Some("FILE_TOO_LARGE".to_string()),
                execution_time_ms: None,
            };
        }
        
        // Write file
        match fs::write(&canonical_path, &decoded).await {
            Ok(_) => {
                // Set file permissions if specified
                if let Some(mode) = mode {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let permissions = std::fs::Permissions::from_mode(mode);
                        if let Err(e) = fs::set_permissions(&canonical_path, permissions).await {
                            warn!("Failed to set file permissions: {}", e);
                        }
                    }
                }
                
                info!("File uploaded: {:?}, size: {} bytes", canonical_path, decoded.len());
                
                CommandResponse {
                    success: true,
                    message: "File uploaded successfully".to_string(),
                    data: Some(serde_json::json!({
                        "path": canonical_path.to_string_lossy(),
                        "size": decoded.len(),
                        "mode": mode,
                    })),
                    error_code: None,
                    execution_time_ms: None,
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to write file: {}", e),
                data: None,
                error_code: Some("WRITE_ERROR".to_string()),
                execution_time_ms: None,
            },
        }
    }
    
    /// Download file with optional compression
    async fn download_file(&self, path: &str, compress: bool) -> CommandResponse {
        let path = Path::new(path);
        
        // Security check
        let canonical_path = match self.is_path_allowed(path) {
            Ok(p) => p,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: e,
                    data: None,
                    error_code: Some("ACCESS_DENIED".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        // Check file size
        let metadata = match fs::metadata(&canonical_path).await {
            Ok(m) => m,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to access file: {}", e),
                    data: None,
                    error_code: Some("FILE_NOT_FOUND".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        if !metadata.is_file() {
            return CommandResponse {
                success: false,
                message: "Path is not a file".to_string(),
                data: None,
                error_code: Some("NOT_A_FILE".to_string()),
                execution_time_ms: None,
            };
        }
        
        if metadata.len() > self.policy.max_file_size {
            return CommandResponse {
                success: false,
                message: format!("File too large. Maximum size: {} bytes", self.policy.max_file_size),
                data: None,
                error_code: Some("FILE_TOO_LARGE".to_string()),
                execution_time_ms: None,
            };
        }
        
        // Read file
        match fs::read(&canonical_path).await {
            Ok(content) => {
                let (encoded_content, encoding) = if compress {
                    // Compress with gzip
                    use flate2::Compression;
                    use flate2::write::GzEncoder;
                    use std::io::Write;
                    
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    match encoder.write_all(&content) {
                        Ok(_) => {
                            match encoder.finish() {
                                Ok(compressed) => {
                                    (base64::encode(&compressed), "gzip+base64")
                                }
                                Err(_) => {
                                    (base64::encode(&content), "base64")
                                }
                            }
                        }
                        Err(_) => {
                            (base64::encode(&content), "base64")
                        }
                    }
                } else {
                    (base64::encode(&content), "base64")
                };
                
                CommandResponse {
                    success: true,
                    message: "File downloaded successfully".to_string(),
                    data: Some(serde_json::json!({
                        "content": encoded_content,
                        "encoding": encoding,
                        "size": content.len(),
                        "compressed": compress,
                        "filename": canonical_path.file_name().map(|n| n.to_string_lossy()),
                    })),
                    error_code: None,
                    execution_time_ms: None,
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to read file: {}", e),
                data: None,
                error_code: Some("READ_ERROR".to_string()),
                execution_time_ms: None,
            },
        }
    }
    
    /// Get service logs
    async fn get_logs(&self, service: Option<String>, lines: Option<u32>, since: Option<String>) -> CommandResponse {
        let service_name = service.unwrap_or_else(|| "aeronyx-vpn".to_string());
        
        // Build journalctl command
        let mut args = vec!["-u".to_string(), service_name.clone()];
        
        if let Some(n) = lines {
            args.push("-n".to_string());
            args.push(n.to_string());
        } else {
            args.push("-n".to_string());
            args.push("100".to_string());
        }
        
        if let Some(since_time) = since {
            args.push("--since".to_string());
            args.push(since_time);
        }
        
        args.push("--no-pager".to_string());
        
        // Execute journalctl (sync)
        let output = match Command::new("journalctl")
            .args(&args)
            .output() {
            Ok(output) => output,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to execute journalctl: {}", e),
                    data: None,
                    error_code: Some("COMMAND_ERROR".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        if output.status.success() {
            // Parse log lines
            let log_lines: Vec<&str> = stdout.lines().collect();
            
            CommandResponse {
                success: true,
                message: format!("Retrieved {} log lines", log_lines.len()),
                data: Some(serde_json::json!({
                    "service": service_name,
                    "logs": log_lines,
                    "line_count": log_lines.len(),
                })),
                error_code: None,
                execution_time_ms: None,
            }
        } else {
            CommandResponse {
                success: false,
                message: format!("Failed to get logs: {}", stderr),
                data: None,
                error_code: Some("LOGS_ERROR".to_string()),
                execution_time_ms: None,
            }
        }
    }
    
    /// Restart a service
    async fn restart_service(&self, service_name: &str, force: bool) -> CommandResponse {
        if !self.policy.allow_dangerous_operations {
            return CommandResponse {
                success: false,
                message: "Service restart is disabled by security policy".to_string(),
                data: None,
                error_code: Some("OPERATION_DISABLED".to_string()),
                execution_time_ms: None,
            };
        }
        
        // Whitelist of services that can be restarted
        let allowed_services = vec![
            "aeronyx-vpn",
            "aeronyx-node",
            "nginx",
            "docker",
        ];
        
        if !allowed_services.contains(&service_name) {
            return CommandResponse {
                success: false,
                message: format!("Service '{}' is not allowed to be restarted", service_name),
                data: None,
                error_code: Some("SERVICE_NOT_ALLOWED".to_string()),
                execution_time_ms: None,
            };
        }
        
        let action = if force { "restart" } else { "reload" };
        
        // Execute systemctl (sync)
        let output = match Command::new("systemctl")
            .args(&[action, service_name])
            .output() {
            Ok(output) => output,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to execute systemctl: {}", e),
                    data: None,
                    error_code: Some("COMMAND_ERROR".to_string()),
                    execution_time_ms: None,
                };
            }
        };
        
        if output.status.success() {
            info!("Service {} {}ed successfully", service_name, action);
            
            CommandResponse {
                success: true,
                message: format!("Service {} {}ed successfully", service_name, action),
                data: Some(serde_json::json!({
                    "service": service_name,
                    "action": action,
                })),
                error_code: None,
                execution_time_ms: None,
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            CommandResponse {
                success: false,
                message: format!("Failed to {} service: {}", action, stderr),
                data: None,
                error_code: Some("SERVICE_ERROR".to_string()),
                execution_time_ms: None,
            }
        }
    }
    
    /// Update node configuration (placeholder for future implementation)
    async fn update_config(
        &self,
        config_section: &str,
        values: HashMap<String, serde_json::Value>,
        _restart_required: bool,
    ) -> CommandResponse {
        // This is a placeholder for future configuration management
        warn!("Configuration update requested for section: {}", config_section);
        warn!("Values: {:?}", values);
        
        CommandResponse {
            success: false,
            message: "Configuration update not yet implemented".to_string(),
            data: None,
            error_code: Some("NOT_IMPLEMENTED".to_string()),
            execution_time_ms: None,
        }
    }
    
    /// Get command execution history
    pub async fn get_command_history(&self, limit: usize) -> Vec<serde_json::Value> {
        let history = self.command_history.lock().await;
        history.iter()
            .rev()
            .take(limit)
            .map(|entry| {
                serde_json::json!({
                    "timestamp": entry.timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    "command_type": entry.command_type,
                    "success": entry.success,
                    "execution_time_ms": entry.execution_time_ms,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_security_policy() {
        let policy = SecurityPolicy::default();
        assert!(!policy.allow_dangerous_operations);
        assert_eq!(policy.max_file_size, 50 * 1024 * 1024);
        assert!(policy.allowed_commands.contains(&"ls".to_string()));
        assert!(!policy.allowed_commands.contains(&"rm".to_string()));
    }
    
    #[tokio::test]
    async fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(5);
        
        // Should allow first 5 requests
        for i in 0..5 {
            assert!(limiter.check_and_update("test"), "Request {} should be allowed", i);
        }
        
        // 6th request should be denied
        assert!(!limiter.check_and_update("test"), "6th request should be denied");
        
        // Different key should be allowed
        assert!(limiter.check_and_update("other"), "Different key should be allowed");
    }
    
    #[tokio::test]
    async fn test_path_validation() {
        let handler = RemoteManagementHandler::new();
        
        // Test allowed path
        assert!(handler.is_path_allowed(Path::new("/tmp/test.txt")).is_ok());
        
        // Test forbidden path
        assert!(handler.is_path_allowed(Path::new("/etc/shadow")).is_err());
        
        // Test path outside allowed directories
        assert!(handler.is_path_allowed(Path::new("/root/secret")).is_err());
    }
    
    #[tokio::test]
    async fn test_command_validation() {
        let handler = RemoteManagementHandler::new();
        
        assert!(handler.is_command_allowed("ls"));
        assert!(handler.is_command_allowed("ps"));
        assert!(!handler.is_command_allowed("rm"));
        assert!(!handler.is_command_allowed("chmod"));
    }
    
    #[tokio::test]
    async fn test_list_directory() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create test files
        fs::write(temp_path.join("file1.txt"), "test1").await.unwrap();
        fs::write(temp_path.join("file2.txt"), "test2").await.unwrap();
        fs::create_dir(temp_path.join("subdir")).await.unwrap();
        
        // Create handler with custom policy
        let mut policy = SecurityPolicy::default();
        policy.allowed_paths.push(temp_path.to_path_buf());
        let handler = RemoteManagementHandler::with_policy(policy);
        
        // Test directory listing
        let response = handler.list_directory(temp_path.to_str().unwrap(), false, true).await;
        
        assert!(response.success);
        assert!(response.data.is_some());
        
        if let Some(data) = response.data {
            let entries = data["entries"].as_array().unwrap();
            assert_eq!(entries.len(), 3);
            
            // Check that we have the expected files
            let names: Vec<String> = entries.iter()
                .map(|e| e["name"].as_str().unwrap().to_string())
                .collect();
            
            assert!(names.contains(&"file1.txt".to_string()));
            assert!(names.contains(&"file2.txt".to_string()));
            assert!(names.contains(&"subdir".to_string()));
        }
    }
    
    #[tokio::test]
    async fn test_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let test_file = temp_path.join("test.txt");
        
        // Create handler with custom policy
        let mut policy = SecurityPolicy::default();
        policy.allowed_paths.push(temp_path.to_path_buf());
        policy.allow_dangerous_operations = true;
        let handler = RemoteManagementHandler::with_policy(policy);
        
        // Test upload
        let content = base64::encode(b"Hello, World!");
        let upload_response = handler.upload_file(
            test_file.to_str().unwrap(),
            &content,
            Some(0o644),
            false
        ).await;
        
        assert!(upload_response.success);
        assert!(test_file.exists());
        
        // Test read
        let read_response = handler.read_file(test_file.to_str().unwrap(), None, None).await;
        assert!(read_response.success);
        
        if let Some(data) = read_response.data {
            assert_eq!(data["content"].as_str().unwrap(), "Hello, World!");
            assert_eq!(data["encoding"].as_str().unwrap(), "utf8");
        }
        
        // Test download
        let download_response = handler.download_file(test_file.to_str().unwrap(), false).await;
        assert!(download_response.success);
        
        if let Some(data) = download_response.data {
            let downloaded_content = base64::decode(data["content"].as_str().unwrap()).unwrap();
            assert_eq!(downloaded_content, b"Hello, World!");
        }
        
        // Test delete
        let delete_response = handler.delete_file(test_file.to_str().unwrap(), true).await;
        assert!(delete_response.success);
        assert!(!test_file.exists());
    }
}
