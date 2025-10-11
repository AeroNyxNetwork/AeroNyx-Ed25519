// src/remote_command_handler.rs
// AeroNyx Privacy Network - Remote Command Handler
// Version: 1.0.0
//
// This module handles remote commands received from the backend via WebSocket

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};
use std::pin::Pin;
use std::future::Future;

/// Remote command received from server
#[derive(Debug, Deserialize,Serialize)]
pub struct RemoteCommandData {
    #[serde(rename = "type")]
    pub command_type: String,
    pub cmd: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub timeout: Option<u64>,
    pub env: Option<HashMap<String, String>>,
    pub path: Option<String>,
    pub content: Option<String>,
    pub mode: Option<String>,
    pub overwrite: Option<bool>,
    pub max_size: Option<u64>,
    pub include_hidden: Option<bool>,
    pub recursive: Option<bool>,
    pub categories: Option<Vec<String>>,
}

/// Remote command response
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteCommandResponse {
    pub request_id: String,
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<RemoteCommandError>,
    pub executed_at: String,
}

/// Error structure for remote commands
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteCommandError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Remote command handler configuration
#[derive(Debug, Clone)]
pub struct RemoteCommandConfig {
    /// Security mode
    pub security_mode: SecurityMode,
    /// Maximum file size for uploads/downloads
    pub max_file_size: u64,
    /// Default command execution timeout
    pub command_timeout: Duration,
    /// Allowed paths for file operations (only used in Restricted mode)
    pub allowed_paths: Vec<PathBuf>,
    /// Forbidden commands (always enforced)
    pub forbidden_commands: Vec<String>,
    /// Enable command whitelist (only used in Restricted mode)
    pub enable_command_whitelist: bool,
    /// Whitelisted commands (only used in Restricted mode)
    pub command_whitelist: Vec<String>,
    /// Default working directory
    pub working_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityMode {
    /// Full access mode - no restrictions (use with caution)
    FullAccess,
    /// Restricted mode - path and command restrictions apply
    Restricted,
}

impl Default for RemoteCommandConfig {
    fn default() -> Self {
        Self {
            security_mode: SecurityMode::Restricted, // Default to restricted for safety
            max_file_size: 50 * 1024 * 1024, // 50MB
            command_timeout: Duration::from_secs(60),
            allowed_paths: vec![
                PathBuf::from("/home"),
                PathBuf::from("/var/log/aeronyx"),
                PathBuf::from("/tmp"),
            ],
            forbidden_commands: vec![
                "rm -rf /".to_string(),
                "format".to_string(),
                "dd".to_string(),
                "mkfs".to_string(),
            ],
            enable_command_whitelist: false,
            command_whitelist: vec![
                "ls".to_string(),
                "cat".to_string(),
                "grep".to_string(),
                "tail".to_string(),
                "ps".to_string(),
                "df".to_string(),
                "free".to_string(),
                "uptime".to_string(),
                "whoami".to_string(),
                "pwd".to_string(),
                "echo".to_string(),
                "date".to_string(),
                "sh".to_string(),
                "bash".to_string(),
                "head".to_string(),
            ],
            working_dir: PathBuf::from("/var/aeronyx"),
        }
    }
}


impl RemoteCommandConfig {
    /// Create a full access configuration (use with caution!)
    pub fn full_access() -> Self {
        Self {
            security_mode: SecurityMode::FullAccess,
            max_file_size: 100 * 1024 * 1024, // 100MB
            command_timeout: Duration::from_secs(300), // 5 minutes
            allowed_paths: vec![], // Not used in full access mode
            forbidden_commands: vec![
                // Still forbid the most dangerous commands even in full access
                "rm -rf /".to_string(),
                "rm -rf /*".to_string(),
                ":(){:|:&};:".to_string(), // Fork bomb
            ],
            enable_command_whitelist: false,
            command_whitelist: vec![], // Not used in full access mode
            working_dir: PathBuf::from("/"),
        }
    }
    
    /// Create a restricted configuration with custom paths
    pub fn restricted_with_paths(allowed_paths: Vec<PathBuf>) -> Self {
        let mut config = Self::default();
        config.allowed_paths = allowed_paths;
        config
    }
}

/// Remote command handler
pub struct RemoteCommandHandler {
    config: RemoteCommandConfig,
}

impl RemoteCommandHandler {
    /// Create a new remote command handler
    pub fn new(config: RemoteCommandConfig) -> Self {
        Self { config }
    }

    /// Handle incoming command
    pub async fn handle_command(
        &self,
        request_id: String,
        command: RemoteCommandData,
    ) -> RemoteCommandResponse {
        let _start_time = std::time::Instant::now();
        
        let result = match command.command_type.as_str() {
            "execute" => self.handle_execute(command).await,
            "upload" => self.handle_upload(command).await,
            "download" => self.handle_download(command).await,
            "list" => self.handle_list(command).await,
            "system_info" => self.handle_system_info(command).await,
            _ => Err(self.create_error(
                "UNKNOWN_COMMAND",
                format!("Unknown command type: {}", command.command_type),
                None,
            )),
        };
        
        match result {
            Ok(data) => RemoteCommandResponse {
                request_id,
                success: true,
                result: Some(data),
                error: None,
                executed_at: chrono::Utc::now().to_rfc3339(),
            },
            Err(error) => RemoteCommandResponse {
                request_id,
                success: false,
                result: None,
                error: Some(error),
                executed_at: chrono::Utc::now().to_rfc3339(),
            },
        }
    }

    /// Validate and normalize path
    fn validate_path(&self, path_str: &str) -> Result<PathBuf, RemoteCommandError> {
        let path = Path::new(path_str);
        
        // Convert to absolute path
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.config.working_dir.join(path)
        };

        // Canonicalize to resolve symlinks and normalize
        let canonical = absolute_path.canonicalize().unwrap_or(absolute_path);

        // In FullAccess mode, allow any path except critical system paths
        if self.config.security_mode == SecurityMode::FullAccess {
            // Still protect critical system paths
            let critical_paths = [
                "/proc",
                "/sys", 
                "/dev",
                "/boot/grub",
            ];
            
            for critical in &critical_paths {
                if canonical.starts_with(critical) {
                    return Err(self.create_error(
                        "PERMISSION_DENIED",
                        format!("Access to {} is forbidden for safety", critical),
                        Some(serde_json::json!({ "path": path_str })),
                    ));
                }
            }
            
            return Ok(canonical);
        }

        // In Restricted mode, check against allowed paths
        let is_allowed = self.config.allowed_paths.iter().any(|allowed| {
            canonical.starts_with(allowed)
        });

        if !is_allowed {
            return Err(self.create_error(
                "PERMISSION_DENIED",
                "Path is outside allowed directories".to_string(),
                Some(serde_json::json!({ "path": path_str })),
            ));
        }

        Ok(canonical)
    }
    
    /// Check if command is whitelisted (only enforced in Restricted mode)
    fn is_command_whitelisted(&self, cmd: &str) -> bool {
        // In FullAccess mode, all commands are allowed (except forbidden ones)
        if self.config.security_mode == SecurityMode::FullAccess {
            return true;
        }
        
        self.config.command_whitelist.contains(&cmd.to_string())
    }

    /// Execute system command with restrictions
    async fn handle_execute(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let cmd = command.cmd.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'cmd' field".to_string(), None)
        })?;
    
        // Security check: forbidden commands
        if self.is_command_forbidden(&cmd, &command.args) {
            return Err(self.create_error(
                "PERMISSION_DENIED",
                "This command is forbidden for security reasons".to_string(),
                Some(serde_json::json!({ "command": cmd })),
            ));
        }
    
        // Security check: whitelist
        if self.config.enable_command_whitelist && !self.is_command_whitelisted(&cmd) {
            return Err(self.create_error(
                "PERMISSION_DENIED",
                "Command not in whitelist".to_string(),
                Some(serde_json::json!({ "command": cmd })),
            ));
        }
    
        // Prepare command
        let mut process = Command::new(&cmd);
        
        // Handle special cases for interactive commands
        let mut args = command.args.unwrap_or_default();
        let mut use_pipe_limit = false;
        
        match cmd.as_str() {
            "top" => {
                // Force batch mode for top
                if !args.contains(&"-b".to_string()) {
                    args.insert(0, "-b".to_string());
                }
                // Limit iterations
                if !args.iter().any(|arg| arg.starts_with("-n")) {
                    args.push("-n".to_string());
                    args.push("1".to_string());
                }
                // Pipe through head to limit output
                use_pipe_limit = true;
            }
            "ps" => {
                // If no args provided, use sensible defaults
                if args.is_empty() {
                    args.push("aux".to_string());
                }
                // For -x flag which shows all user processes, we need to limit output
                if args.contains(&"-x".to_string()) || args.contains(&"aux".to_string()) {
                    // Mark that we should use pipe limiting
                    use_pipe_limit = true;
                    warn!("ps command typically produces large output, will limit results");
                }
            }
            "htop" => {
                // htop doesn't have a good batch mode, suggest using top instead
                return Err(self.create_error(
                    "UNSUPPORTED_COMMAND",
                    "htop is interactive only. Use 'top -b -n 1' instead".to_string(),
                    None,
                ));
            }
            _ => {}
        }
        
        if !args.is_empty() {
            process.args(&args);
        }
    
        // Set working directory
        let cwd = if let Some(cwd_str) = command.cwd {
            self.validate_path(&cwd_str)?
        } else {
            self.config.working_dir.clone()
        };
        process.current_dir(&cwd);
    
        // Set environment variables
        if let Some(env) = command.env {
            for (key, value) in env {
                process.env(key, value);
            }
        }
    
        // Set up process
        process.stdout(Stdio::piped());
        process.stderr(Stdio::piped());
    
        // Execute with timeout
        let timeout_duration = Duration::from_secs(command.timeout.unwrap_or(30));
        let start = std::time::Instant::now();
    
        match timeout(timeout_duration, process.output()).await {
            Ok(Ok(output)) => {
                let execution_time_ms = start.elapsed().as_millis() as u64;
                
                let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let mut truncated = false;
                
                // Check output size and truncate if necessary
                const MAX_OUTPUT_SIZE: usize = 32 * 1024; // 32KB limit per output
                const MAX_TOTAL_SIZE: usize = 50 * 1024; // 50KB total limit for WebSocket safety
                
                // First check total size
                let total_output_size = output.stdout.len() + output.stderr.len();
                
                if total_output_size > MAX_TOTAL_SIZE {
                    // For very large outputs, provide a summary and truncate aggressively
                    info!("Large command output: {} bytes total, truncating to fit message limit", total_output_size);
                    
                    // Calculate proportional sizes
                    let stdout_ratio = output.stdout.len() as f64 / total_output_size as f64;
                    let stderr_ratio = output.stderr.len() as f64 / total_output_size as f64;
                    
                    let stdout_limit = (MAX_TOTAL_SIZE as f64 * stdout_ratio * 0.9) as usize;
                    let stderr_limit = (MAX_TOTAL_SIZE as f64 * stderr_ratio * 0.9) as usize;
                    
                    if output.stdout.len() > stdout_limit {
                        stdout.truncate(stdout_limit);
                        stdout.push_str(&format!("\n\n[OUTPUT TRUNCATED - Original size: {} bytes]", output.stdout.len()));
                        truncated = true;
                    }
                    
                    if output.stderr.len() > stderr_limit {
                        stderr.truncate(stderr_limit);
                        stderr.push_str(&format!("\n\n[ERROR OUTPUT TRUNCATED - Original size: {} bytes]", output.stderr.len()));
                        truncated = true;
                    }
                } else {
                    // Normal truncation for individual outputs
                    if stdout.len() > MAX_OUTPUT_SIZE {
                        stdout.truncate(MAX_OUTPUT_SIZE);
                        stdout.push_str("\n\n[OUTPUT TRUNCATED - Exceeded 64KB limit]");
                        truncated = true;
                    }
                    
                    if stderr.len() > MAX_OUTPUT_SIZE {
                        stderr.truncate(MAX_OUTPUT_SIZE);
                        stderr.push_str("\n\n[ERROR OUTPUT TRUNCATED - Exceeded 64KB limit]");
                        truncated = true;
                    }
                }
                
                // Additional suggestions for large outputs
                if truncated {
                    let suggestions = match cmd.as_str() {
                        "ps" => {
                            if use_pipe_limit {
                                Some("Output was truncated. For more control, try 'ps aux | head -20' or 'ps aux | grep <process_name>'")
                            } else {
                                Some("Consider using 'ps aux | head -20' or filtering with grep")
                            }
                        }
                        "top" => Some("Output captured from single iteration. Use 'top -b -n 1 | head -30' for less output"),
                        "find" => Some("Consider adding '-maxdepth 2' or piping to 'head -50'"),
                        "ls" => Some("Try 'ls | head -50' or use more specific paths"),
                        "cat" => Some("For large files, use 'head -100' or 'tail -100' instead"),
                        _ => Some("Consider using pipes with 'head', 'tail', or 'grep' to limit output"),
                    };
                    
                    if let Some(suggestion) = suggestions {
                        stderr.push_str(&format!("\n\nSuggestion: {}", suggestion));
                    }
                }
                
                let mut response_json = serde_json::json!({
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": output.status.code().unwrap_or(-1),
                    "execution_time_ms": execution_time_ms,
                    "truncated": truncated,
                    "original_stdout_size": output.stdout.len(),
                    "original_stderr_size": output.stderr.len(),
                    "total_output_size": total_output_size,
                });
                
                // Add command alternatives if output was truncated
                if truncated {
                    if let Some(alternatives) = self.get_command_alternatives(&cmd, &args) {
                        response_json["alternatives"] = serde_json::json!(alternatives);
                        response_json["message"] = serde_json::json!(
                            "Output was truncated due to size limits. Try one of the suggested alternatives."
                        );
                    }
                }
                
                Ok(response_json)
            }
            Ok(Err(e)) => Err(self.create_error(
                "SYSTEM_ERROR",
                format!("Failed to execute command: {}", e),
                None,
            )),
            Err(_) => Err(self.create_error(
                "TIMEOUT",
                format!("Command execution timeout after {} seconds", timeout_duration.as_secs()),
                None,
            )),
        }
    }

    /// Handle file upload
    async fn handle_upload(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let content = command.content.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'content' field".to_string(), None)
        })?;

        // Validate path
        let full_path = self.validate_path(&path)?;

        // Decode base64 content
        let decoded = base64::decode(&content).map_err(|e| {
            self.create_error("INVALID_COMMAND", format!("Invalid base64 content: {}", e), None)
        })?;

        // Check file size
        if decoded.len() > self.config.max_file_size as usize {
            return Err(self.create_error(
                "FILE_TOO_LARGE",
                format!("File size {} exceeds maximum allowed size {}", 
                    decoded.len(), self.config.max_file_size),
                None,
            ));
        }

        // Check if file exists and overwrite is not allowed
        if full_path.exists() && !command.overwrite.unwrap_or(false) {
            return Err(self.create_error(
                "FILE_EXISTS",
                "File already exists and overwrite is not allowed".to_string(),
                Some(serde_json::json!({ "path": path })),
            ));
        }

        // Create parent directory if needed
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to create directory: {}", e), None)
            })?;
        }

        // Write file
        fs::write(&full_path, &decoded).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to write file: {}", e), None)
        })?;

        // Set file permissions if specified
        #[cfg(unix)]
        if let Some(mode_str) = command.mode {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mode) = u32::from_str_radix(&mode_str, 8) {
                let permissions = std::fs::Permissions::from_mode(mode);
                fs::set_permissions(&full_path, permissions).await.ok();
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "bytes_written": decoded.len(),
            "path": full_path.display().to_string(),
        }))
    }

    /// Handle file download
    async fn handle_download(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        // Validate path
        let full_path = self.validate_path(&path)?;

        // Check if file exists
        if !full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("File not found: {}", path),
                None,
            ));
        }

        // Get file metadata
        let metadata = fs::metadata(&full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get file metadata: {}", e), None)
        })?;

        // Check if it's a file
        if !metadata.is_file() {
            return Err(self.create_error(
                "INVALID_PATH",
                "Path is not a file".to_string(),
                Some(serde_json::json!({ "path": path })),
            ));
        }

        // Check file size
        let max_size = command.max_size.unwrap_or(self.config.max_file_size);
        if metadata.len() > max_size {
            return Err(self.create_error(
                "FILE_TOO_LARGE",
                format!("File size {} exceeds maximum allowed size {}", metadata.len(), max_size),
                None,
            ));
        }

        // Read file
        let content = fs::read(&full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to read file: {}", e), None)
        })?;

        // Encode to base64
        let encoded = base64::encode(&content);

        // Get MIME type
        let mime_type = mime_guess::from_path(&full_path)
            .first_or_octet_stream()
            .to_string();

        // Get modification time
        let modified = metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| chrono::Utc::now() - chrono::Duration::seconds(d.as_secs() as i64))
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        Ok(serde_json::json!({
            "content": encoded,
            "size": content.len(),
            "mime_type": mime_type,
            "modified": modified,
        }))
    }

    /// Handle directory listing
    async fn handle_list(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        // Validate path
        let full_path = self.validate_path(&path)?;

        // Check if directory exists
        if !full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Directory not found: {}", path),
                None,
            ));
        }

        // Check if it's a directory
        if !full_path.is_dir() {
            return Err(self.create_error(
                "INVALID_PATH",
                "Path is not a directory".to_string(),
                Some(serde_json::json!({ "path": path })),
            ));
        }

        let include_hidden = command.include_hidden.unwrap_or(false);
        let recursive = command.recursive.unwrap_or(false);

        // List directory
        let entries = self.list_directory(&full_path, include_hidden, recursive, 0).await?;

        Ok(serde_json::json!({
            "entries": entries,
            "total": entries.len(),
        }))
    }

    /// Recursively list directory contents
    fn list_directory<'a>(
        &'a self,
        path: &'a Path,
        include_hidden: bool,
        recursive: bool,
        depth: u32,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<serde_json::Value>, RemoteCommandError>> + Send + 'a>> {
        Box::pin(async move {
            // Limit recursion depth
            if depth > 5 {
                return Ok(vec![]);
            }

            let mut entries = Vec::new();
            let mut dir_stream = fs::read_dir(path).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to read directory: {}", e), None)
            })?;

            while let Ok(Some(entry)) = dir_stream.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();

                // Skip hidden files if not requested
                if !include_hidden && name.starts_with('.') {
                    continue;
                }

                let metadata = match entry.metadata().await {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let file_type = if metadata.is_dir() {
                    "directory"
                } else if metadata.is_file() {
                    "file"
                } else {
                    "other"
                };

                let mut entry_info = serde_json::json!({
                    "name": name,
                    "type": file_type,
                    "size": metadata.len(),
                });

                // Add permissions and ownership info on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    use std::os::unix::fs::PermissionsExt;
                    
                    entry_info["permissions"] = serde_json::json!(
                        format!("{:o}", metadata.permissions().mode() & 0o777)
                    );
                    entry_info["owner"] = serde_json::json!(metadata.uid());
                    entry_info["group"] = serde_json::json!(metadata.gid());
                }

                // Add modification time
                if let Ok(modified) = metadata.modified() {
                    if let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                        let dt = chrono::Utc::now() - chrono::Duration::seconds(duration.as_secs() as i64);
                        entry_info["modified"] = serde_json::json!(dt.to_rfc3339());
                    }
                }

                // Recursively list subdirectories
                if recursive && metadata.is_dir() {
                    let sub_path = entry.path();
                    if let Ok(sub_entries) = self.list_directory(&sub_path, include_hidden, true, depth + 1).await {
                        entry_info["entries"] = serde_json::json!(sub_entries);
                    }
                }

                entries.push(entry_info);
            }

            Ok(entries)
        })
    }

    /// Handle system info request
    async fn handle_system_info(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let categories = command.categories.unwrap_or_else(|| {
            vec!["cpu".to_string(), "memory".to_string(), "disk".to_string()]
        });

        let mut result = serde_json::json!({});

        for category in categories {
            match category.as_str() {
                "cpu" => {
                    result["cpu"] = self.get_cpu_info().await?;
                }
                "memory" => {
                    result["memory"] = self.get_memory_info().await?;
                }
                "disk" => {
                    result["disk"] = self.get_disk_info().await?;
                }
                "network" => {
                    result["network"] = self.get_network_info().await?;
                }
                "process" => {
                    result["process"] = self.get_process_info().await?;
                }
                _ => {
                    warn!("Unknown system info category: {}", category);
                }
            }
        }

        Ok(result)
    }

    /// Get CPU information
    async fn get_cpu_info(&self) -> Result<serde_json::Value, RemoteCommandError> {
        let load = sys_info::loadavg().map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get load average: {}", e), None)
        })?;

        let cpu_num = sys_info::cpu_num().unwrap_or(1) as u64;
        let cpu_speed = sys_info::cpu_speed().unwrap_or(0) as u64;

        // Get CPU usage percentage (simple estimation based on load average)
        let usage_percent = (load.one / cpu_num as f64 * 100.0).min(100.0);

        Ok(serde_json::json!({
            "usage_percent": usage_percent,
            "load_average": [load.one, load.five, load.fifteen],
            "cores": cpu_num,
            "speed_mhz": cpu_speed,
        }))
    }

    /// Get memory information
    async fn get_memory_info(&self) -> Result<serde_json::Value, RemoteCommandError> {
        let mem = sys_info::mem_info().map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get memory info: {}", e), None)
        })?;

        Ok(serde_json::json!({
            "total": mem.total * 1024, // Convert from KB to bytes
            "used": (mem.total - mem.avail) * 1024,
            "free": mem.avail * 1024,
            "percent": ((mem.total - mem.avail) as f64 / mem.total as f64 * 100.0),
        }))
    }

    /// Get disk information
    async fn get_disk_info(&self) -> Result<serde_json::Value, RemoteCommandError> {
        let disk = sys_info::disk_info().map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get disk info: {}", e), None)
        })?;

        Ok(serde_json::json!({
            "total": disk.total * 1024, // Convert from KB to bytes
            "used": (disk.total - disk.free) * 1024,
            "free": disk.free * 1024,
            "percent": ((disk.total - disk.free) as f64 / disk.total as f64 * 100.0),
        }))
    }

    /// Get network information
    async fn get_network_info(&self) -> Result<serde_json::Value, RemoteCommandError> {
        use pnet::datalink;

        let mut interfaces = serde_json::json!({});

        for interface in datalink::interfaces() {
            if interface.is_loopback() {
                continue;
            }

            let mut if_info = serde_json::json!({});

            // Get IP addresses
            for ip in &interface.ips {
                if let Some(ip_addr) = ip.ip().to_string().split('/').next() {
                    if_info["ip"] = serde_json::json!(ip_addr);
                    break;
                }
            }

            // Note: Getting actual RX/TX bytes requires platform-specific code
            // For now, we'll set placeholder values
            if_info["rx_bytes"] = serde_json::json!(0);
            if_info["tx_bytes"] = serde_json::json!(0);

            interfaces[interface.name] = if_info;
        }

        Ok(serde_json::json!({
            "interfaces": interfaces,
        }))
    }

    /// Get process information
    async fn get_process_info(&self) -> Result<serde_json::Value, RemoteCommandError> {
        let pid = std::process::id();
        
        // Get simple uptime (would need to store start time for accurate calculation)
        let uptime_seconds = 0u64; // Placeholder
        
        // Get memory usage
        let mem_info = sys_info::mem_info().unwrap_or(sys_info::MemInfo {
            total: 0,
            free: 0,
            avail: 0,
            buffers: 0,
            cached: 0,
            swap_total: 0,
            swap_free: 0,
        });
        let memory_mb = (mem_info.total - mem_info.avail) / 1024; // Convert KB to MB

        Ok(serde_json::json!({
            "pid": pid,
            "uptime_seconds": uptime_seconds,
            "cpu_percent": 0.0, // Would need more complex calculation
            "memory_mb": memory_mb,
        }))
    }

    /// Get command alternatives for large output commands
    fn get_command_alternatives(&self, cmd: &str, args: &[String]) -> Option<Vec<String>> {
        match cmd {
            "ps" => {
                if args.contains(&"-x".to_string()) {
                    Some(vec![
                        "ps -x | head -20  # Show first 20 processes".to_string(),
                        "ps -x | grep <name>  # Filter by process name".to_string(),
                        "ps -xo pid,comm,pcpu,pmem | head -20  # Show specific columns".to_string(),
                    ])
                } else if args.contains(&"aux".to_string()) {
                    Some(vec![
                        "ps aux | head -20  # Show first 20 processes".to_string(),
                        "ps aux | grep <name>  # Filter by process name".to_string(),
                        "ps aux --sort=-pcpu | head -10  # Top 10 by CPU usage".to_string(),
                        "ps aux --sort=-pmem | head -10  # Top 10 by memory usage".to_string(),
                    ])
                } else {
                    None
                }
            }
            "top" => Some(vec![
                "top -b -n 1 | head -30  # Show first 30 lines".to_string(),
                "top -b -n 1 -o %CPU | head -20  # Sort by CPU usage".to_string(),
                "top -b -n 1 -o %MEM | head -20  # Sort by memory usage".to_string(),
            ]),
            "ls" => {
                if args.iter().any(|arg| arg == "-la" || arg == "-lR") {
                    Some(vec![
                        "ls -la | head -50  # Show first 50 files".to_string(),
                        "ls -la | grep <pattern>  # Filter by name".to_string(),
                        "find . -maxdepth 1 -ls  # Alternative with size limits".to_string(),
                    ])
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Check if command is forbidden
    fn is_command_forbidden(&self, cmd: &str, args: &Option<Vec<String>>) -> bool {
        let full_command = if let Some(args) = args {
            format!("{} {}", cmd, args.join(" "))
        } else {
            cmd.to_string()
        };

        self.config.forbidden_commands.iter().any(|forbidden| {
            full_command.contains(forbidden)
        })
    }

    /// Create error response
    fn create_error(
        &self,
        code: &str,
        message: String,
        details: Option<serde_json::Value>,
    ) -> RemoteCommandError {
        RemoteCommandError {
            code: code.to_string(),
            message,
            details,
        }
    }
}

/// Log remote command execution
pub fn log_remote_command(
    session_id: &str,
    command_type: &str,
    success: bool,
    details: &str,
) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let result = if success { "success" } else { "failed" };
    
    match command_type {
        "execute" => {
            info!("[{}] REMOTE_CMD: session={}, {}, result={}", 
                timestamp, session_id, details, result);
        }
        "upload" => {
            info!("[{}] REMOTE_UPLOAD: session={}, {}, result={}", 
                timestamp, session_id, details, result);
        }
        "download" => {
            info!("[{}] REMOTE_DOWNLOAD: session={}, {}, result={}", 
                timestamp, session_id, details, result);
        }
        "list" => {
            info!("[{}] REMOTE_LIST: session={}, {}, result={}", 
                timestamp, session_id, details, result);
        }
        "system_info" => {
            info!("[{}] REMOTE_SYSINFO: session={}, {}, result={}", 
                timestamp, session_id, details, result);
        }
        _ => {
            info!("[{}] REMOTE_{}: session={}, {}, result={}", 
                timestamp, command_type.to_uppercase(), session_id, details, result);
        }
    }
    
    if !success && command_type == "execute" {
        if details.contains("FORBIDDEN_COMMAND") {
            error!("[{}] REMOTE_ERROR: session={}, cmd={}, error=FORBIDDEN_COMMAND", 
                timestamp, session_id, details);
        }
    }
}
