// src/remote_command_handler.rs
// ============================================
// AeroNyx Privacy Network - Enhanced Remote Command Handler
// Version: 2.0.0 - Full File Manager Support
// ============================================
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Creation Reason: Handle remote commands for file management
// Modification Reason: Added comprehensive file manager operations
// Main Functionality:
// - File operations: create, delete, rename, copy, move
// - Directory operations: create, delete, list, search
// - Archive operations: compress, extract
// - Permission management: chmod, chown
// - Advanced search with regex support
// - Batch operations support
// Dependencies: Used by WebSocket handlers for remote management
//
// Main Logical Flow:
// 1. Receive command from WebSocket
// 2. Validate security and permissions
// 3. Execute appropriate handler
// 4. Return structured response
//
// ⚠️ Important Note for Next Developer:
// - Always validate paths against allowed directories
// - Check file size limits before operations
// - Use atomic operations where possible
// - Log all operations for security audit
// - Batch operations must be transactional when possible
//
// Last Modified: v2.0.0 - Added comprehensive file manager features
// ============================================

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn, debug};
use std::pin::Pin;
use std::future::Future;
use regex::Regex;
use walkdir::WalkDir;

/// Remote command received from server
#[derive(Debug, Deserialize, Serialize)]
pub struct RemoteCommandData {
    #[serde(rename = "type")]
    pub command_type: String,
    
    // Common fields
    pub path: Option<String>,
    pub paths: Option<Vec<String>>,  // For batch operations
    pub content: Option<String>,
    pub timeout: Option<u64>,
    
    // Execute command fields
    pub cmd: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Option<HashMap<String, String>>,
    
    // File operation fields
    pub destination: Option<String>,
    pub overwrite: Option<bool>,
    pub recursive: Option<bool>,
    pub preserve_attributes: Option<bool>,
    
    // Search fields
    pub query: Option<String>,
    pub use_regex: Option<bool>,
    pub case_sensitive: Option<bool>,
    pub max_depth: Option<u32>,
    pub include_hidden: Option<bool>,
    pub file_type: Option<String>,  // "file", "directory", "any"
    
    // Permission fields
    pub mode: Option<String>,
    pub owner: Option<u32>,
    pub group: Option<u32>,
    
    // Archive fields
    pub format: Option<String>,  // "zip", "tar", "tar.gz"
    pub compression_level: Option<u32>,
    
    // List/info fields
    pub categories: Option<Vec<String>>,
    pub sort_by: Option<String>,  // "name", "size", "modified"
    pub sort_reverse: Option<bool>,
    pub max_size: Option<u64>,
}

/// Remote command response
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteCommandResponse {
    pub request_id: String,
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<RemoteCommandError>,
    pub executed_at: String,
    pub execution_time_ms: Option<u64>,
}

/// Error structure for remote commands
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteCommandError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Batch operation result
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchResult {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub results: Vec<SingleOperationResult>,
}

/// Single operation result in batch
#[derive(Debug, Serialize, Deserialize)]
pub struct SingleOperationResult {
    pub path: String,
    pub success: bool,
    pub error: Option<String>,
}

/// File search result
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub path: String,
    pub name: String,
    pub file_type: String,
    pub size: u64,
    pub modified: String,
    pub match_context: Option<String>,  // Line containing the match for content search
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
            command_whitelist: vec![
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
            ],
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
        let start_time = std::time::Instant::now();
        
        let result = match command.command_type.as_str() {
            // File operations
            "execute" => self.handle_execute(command).await,
            "upload" => self.handle_upload(command).await,
            "download" => self.handle_download(command).await,
            "delete" => self.handle_delete(command).await,
            "rename" => self.handle_rename(command).await,
            "copy" => self.handle_copy(command).await,
            "move" => self.handle_move(command).await,
            
            // Directory operations
            "list" => self.handle_list(command).await,
            "create_directory" => self.handle_create_directory(command).await,
            "delete_directory" => self.handle_delete_directory(command).await,
            
            // Search operations
            "search" => self.handle_search(command).await,
            
            // Archive operations
            "compress" => self.handle_compress(command).await,
            "extract" => self.handle_extract(command).await,
            
            // Permission operations
            "chmod" => self.handle_chmod(command).await,
            "chown" => self.handle_chown(command).await,
            
            // Batch operations
            "batch_delete" => self.handle_batch_delete(command).await,
            "batch_move" => self.handle_batch_move(command).await,
            "batch_copy" => self.handle_batch_copy(command).await,
            
            // System operations
            "system_info" => self.handle_system_info(command).await,
            
            _ => Err(self.create_error(
                "UNKNOWN_COMMAND",
                format!("Unknown command type: {}", command.command_type),
                None,
            )),
        };
        
        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        
        match result {
            Ok(data) => RemoteCommandResponse {
                request_id,
                success: true,
                result: Some(data),
                error: None,
                executed_at: chrono::Utc::now().to_rfc3339(),
                execution_time_ms: Some(execution_time_ms),
            },
            Err(error) => RemoteCommandResponse {
                request_id,
                success: false,
                result: None,
                error: Some(error),
                executed_at: chrono::Utc::now().to_rfc3339(),
                execution_time_ms: Some(execution_time_ms),
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

    /// Handle file deletion
    async fn handle_delete(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let full_path = self.validate_path(&path)?;

        if !full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("File not found: {}", path),
                None,
            ));
        }

        // Check if it's a file
        let metadata = fs::metadata(&full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
        })?;

        if !metadata.is_file() {
            return Err(self.create_error(
                "INVALID_PATH",
                "Path is not a file. Use delete_directory for directories".to_string(),
                Some(serde_json::json!({ "path": path })),
            ));
        }

        // Delete the file
        fs::remove_file(&full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to delete file: {}", e), None)
        })?;

        info!("File deleted: {}", full_path.display());

        Ok(serde_json::json!({
            "success": true,
            "message": "File deleted successfully",
            "path": full_path.display().to_string(),
        }))
    }

    /// Handle file renaming
    async fn handle_rename(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let old_path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let new_path = command.destination.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
        })?;

        let old_full_path = self.validate_path(&old_path)?;
        let new_full_path = self.validate_path(&new_path)?;

        if !old_full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Source not found: {}", old_path),
                None,
            ));
        }

        if new_full_path.exists() && !command.overwrite.unwrap_or(false) {
            return Err(self.create_error(
                "FILE_EXISTS",
                format!("Destination already exists: {}", new_path),
                None,
            ));
        }

        // Rename/move the file
        fs::rename(&old_full_path, &new_full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to rename: {}", e), None)
        })?;

        info!("File renamed: {} -> {}", old_full_path.display(), new_full_path.display());

        Ok(serde_json::json!({
            "success": true,
            "message": "File renamed successfully",
            "old_path": old_full_path.display().to_string(),
            "new_path": new_full_path.display().to_string(),
        }))
    }

    /// Handle file copying
    async fn handle_copy(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let src_path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let dst_path = command.destination.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
        })?;

        let src_full_path = self.validate_path(&src_path)?;
        let dst_full_path = self.validate_path(&dst_path)?;

        if !src_full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Source not found: {}", src_path),
                None,
            ));
        }

        // Check if destination exists
        if dst_full_path.exists() && !command.overwrite.unwrap_or(false) {
            return Err(self.create_error(
                "FILE_EXISTS",
                format!("Destination already exists: {}", dst_path),
                None,
            ));
        }

        // Check if source is file or directory
        let metadata = fs::metadata(&src_full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
        })?;

        if metadata.is_file() {
            // Copy single file
            fs::copy(&src_full_path, &dst_full_path).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to copy file: {}", e), None)
            })?;
        } else if metadata.is_dir() {
            // Copy directory recursively if requested
            if !command.recursive.unwrap_or(false) {
                return Err(self.create_error(
                    "INVALID_OPERATION",
                    "Directory copy requires recursive flag".to_string(),
                    None,
                ));
            }
            
            self.copy_dir_recursive(&src_full_path, &dst_full_path).await?;
        }

        info!("File/directory copied: {} -> {}", src_full_path.display(), dst_full_path.display());

        Ok(serde_json::json!({
            "success": true,
            "message": "Copy completed successfully",
            "source": src_full_path.display().to_string(),
            "destination": dst_full_path.display().to_string(),
        }))
    }

    /// Handle file moving
    async fn handle_move(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        // Move is essentially rename, so we can reuse that logic
        self.handle_rename(command).await
    }

    /// Handle directory creation
    async fn handle_create_directory(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let full_path = self.validate_path(&path)?;

        if full_path.exists() {
            return Err(self.create_error(
                "FILE_EXISTS",
                format!("Path already exists: {}", path),
                None,
            ));
        }

        // Create directory (including parent directories)
        fs::create_dir_all(&full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to create directory: {}", e), None)
        })?;

        // Set permissions if specified
        #[cfg(unix)]
        if let Some(mode_str) = command.mode {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mode) = u32::from_str_radix(&mode_str, 8) {
                let permissions = std::fs::Permissions::from_mode(mode);
                fs::set_permissions(&full_path, permissions).await.ok();
            }
        }

        info!("Directory created: {}", full_path.display());

        Ok(serde_json::json!({
            "success": true,
            "message": "Directory created successfully",
            "path": full_path.display().to_string(),
        }))
    }

    /// Handle directory deletion
    async fn handle_delete_directory(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let full_path = self.validate_path(&path)?;

        if !full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Directory not found: {}", path),
                None,
            ));
        }

        let metadata = fs::metadata(&full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
        })?;

        if !metadata.is_dir() {
            return Err(self.create_error(
                "INVALID_PATH",
                "Path is not a directory".to_string(),
                Some(serde_json::json!({ "path": path })),
            ));
        }

        // Check if directory is empty unless recursive flag is set
        if !command.recursive.unwrap_or(false) {
            let mut entries = fs::read_dir(&full_path).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to read directory: {}", e), None)
            })?;

            if entries.next_entry().await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to check directory: {}", e), None)
            })?.is_some() {
                return Err(self.create_error(
                    "DIRECTORY_NOT_EMPTY",
                    "Directory is not empty. Use recursive flag to delete non-empty directories".to_string(),
                    None,
                ));
            }

            fs::remove_dir(&full_path).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to delete directory: {}", e), None)
            })?;
        } else {
            fs::remove_dir_all(&full_path).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to delete directory recursively: {}", e), None)
            })?;
        }

        info!("Directory deleted: {}", full_path.display());

        Ok(serde_json::json!({
            "success": true,
            "message": "Directory deleted successfully",
            "path": full_path.display().to_string(),
            "recursive": command.recursive.unwrap_or(false),
        }))
    }

    /// Handle file/directory search
    async fn handle_search(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let base_path = command.path.unwrap_or_else(|| ".".to_string());
        let query = command.query.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'query' field".to_string(), None)
        })?;

        let full_path = self.validate_path(&base_path)?;

        if !full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Search path not found: {}", base_path),
                None,
            ));
        }

        let use_regex = command.use_regex.unwrap_or(false);
        let case_sensitive = command.case_sensitive.unwrap_or(false);
        let include_hidden = command.include_hidden.unwrap_or(false);
        let max_depth = command.max_depth.unwrap_or(self.config.max_search_depth).min(self.config.max_search_depth);
        let file_type = command.file_type.as_deref().unwrap_or("any");

        // Compile regex if needed
        let pattern = if use_regex {
            let flags = if case_sensitive { "" } else { "(?i)" };
            let pattern_str = format!("{}{}", flags, query);
            Some(Regex::new(&pattern_str).map_err(|e| {
                self.create_error("INVALID_REGEX", format!("Invalid regex pattern: {}", e), None)
            })?)
        } else {
            None
        };

        let mut results = Vec::new();
        let walker = WalkDir::new(&full_path)
            .max_depth(max_depth as usize)
            .follow_links(false);

        for entry in walker {
            if results.len() >= self.config.max_search_results {
                break;
            }

            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Skip hidden files if not requested
            if !include_hidden && name.starts_with('.') {
                continue;
            }

            // Check file type filter
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let is_match = match file_type {
                "file" if !metadata.is_file() => false,
                "directory" if !metadata.is_dir() => false,
                _ => true,
            };

            if !is_match {
                continue;
            }

            // Check name match
            let name_matches = if use_regex {
                pattern.as_ref().unwrap().is_match(name)
            } else if case_sensitive {
                name.contains(&query)
            } else {
                name.to_lowercase().contains(&query.to_lowercase())
            };

            if name_matches {
                let modified = metadata.modified()
                    .ok()
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|d| chrono::Utc::now() - chrono::Duration::seconds(d.as_secs() as i64))
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

                results.push(SearchResult {
                    path: path.display().to_string(),
                    name: name.to_string(),
                    file_type: if metadata.is_dir() { "directory" } else { "file" }.to_string(),
                    size: metadata.len(),
                    modified,
                    match_context: None,
                });
            }
        }

        Ok(serde_json::json!({
            "results": results,
            "total": results.len(),
            "query": query,
            "search_path": full_path.display().to_string(),
            "max_results_reached": results.len() >= self.config.max_search_results,
        }))
    }

    /// Handle file compression
    async fn handle_compress(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let paths = command.paths.or_else(|| command.path.map(|p| vec![p]))
            .ok_or_else(|| {
                self.create_error("INVALID_COMMAND", "Missing 'paths' or 'path' field".to_string(), None)
            })?;

        let destination = command.destination.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
        })?;

        let format = command.format.as_deref().unwrap_or("zip");

        // Validate all source paths
        let mut validated_paths = Vec::new();
        for path in &paths {
            let full_path = self.validate_path(path)?;
            if !full_path.exists() {
                return Err(self.create_error(
                    "FILE_NOT_FOUND",
                    format!("Path not found: {}", path),
                    None,
                ));
            }
            validated_paths.push(full_path);
        }

        let dst_full_path = self.validate_path(&destination)?;

        // Check if destination already exists
        if dst_full_path.exists() && !command.overwrite.unwrap_or(false) {
            return Err(self.create_error(
                "FILE_EXISTS",
                format!("Archive already exists: {}", destination),
                None,
            ));
        }

        // Build command based on format
        let mut cmd = match format {
            "zip" => {
                let mut cmd = Command::new("zip");
                cmd.arg("-r");
                cmd.arg(&dst_full_path);
                for path in &validated_paths {
                    cmd.arg(path);
                }
                cmd
            }
            "tar" => {
                let mut cmd = Command::new("tar");
                cmd.arg("-cf");
                cmd.arg(&dst_full_path);
                for path in &validated_paths {
                    cmd.arg(path);
                }
                cmd
            }
            "tar.gz" | "tgz" => {
                let mut cmd = Command::new("tar");
                cmd.arg("-czf");
                cmd.arg(&dst_full_path);
                for path in &validated_paths {
                    cmd.arg(path);
                }
                cmd
            }
            _ => {
                return Err(self.create_error(
                    "UNSUPPORTED_FORMAT",
                    format!("Unsupported archive format: {}", format),
                    None,
                ));
            }
        };

        // Execute compression
        let output = cmd.output().await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to compress: {}", e), None)
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(self.create_error(
                "COMPRESSION_FAILED",
                format!("Compression failed: {}", stderr),
                None,
            ));
        }

        // Get archive size
        let metadata = fs::metadata(&dst_full_path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to get archive metadata: {}", e), None)
        })?;

        Ok(serde_json::json!({
            "success": true,
            "message": "Files compressed successfully",
            "archive": dst_full_path.display().to_string(),
            "format": format,
            "size": metadata.len(),
            "source_count": validated_paths.len(),
        }))
    }

    /// Handle file extraction
    async fn handle_extract(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let archive_path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let destination = command.destination.unwrap_or_else(|| ".".to_string());

        let archive_full_path = self.validate_path(&archive_path)?;
        let dst_full_path = self.validate_path(&destination)?;

        if !archive_full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Archive not found: {}", archive_path),
                None,
            ));
        }

        // Detect format from extension if not specified
        let format = command.format.as_deref().unwrap_or_else(|| {
            if archive_path.ends_with(".zip") { "zip" }
            else if archive_path.ends_with(".tar") { "tar" }
            else if archive_path.ends_with(".tar.gz") || archive_path.ends_with(".tgz") { "tar.gz" }
            else { "auto" }
        });

        // Build extraction command
        let mut cmd = match format {
            "zip" => {
                let mut cmd = Command::new("unzip");
                cmd.arg(&archive_full_path);
                cmd.arg("-d");
                cmd.arg(&dst_full_path);
                cmd
            }
            "tar" => {
                let mut cmd = Command::new("tar");
                cmd.arg("-xf");
                cmd.arg(&archive_full_path);
                cmd.arg("-C");
                cmd.arg(&dst_full_path);
                cmd
            }
            "tar.gz" | "tgz" => {
                let mut cmd = Command::new("tar");
                cmd.arg("-xzf");
                cmd.arg(&archive_full_path);
                cmd.arg("-C");
                cmd.arg(&dst_full_path);
                cmd
            }
            _ => {
                return Err(self.create_error(
                    "UNSUPPORTED_FORMAT",
                    format!("Unable to detect or unsupported archive format: {}", format),
                    None,
                ));
            }
        };

        // Execute extraction
        let output = cmd.output().await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to extract: {}", e), None)
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(self.create_error(
                "EXTRACTION_FAILED",
                format!("Extraction failed: {}", stderr),
                None,
            ));
        }

        Ok(serde_json::json!({
            "success": true,
            "message": "Archive extracted successfully",
            "archive": archive_full_path.display().to_string(),
            "destination": dst_full_path.display().to_string(),
            "format": format,
        }))
    }

    /// Handle chmod operation
    #[cfg(unix)]
    async fn handle_chmod(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        use std::os::unix::fs::PermissionsExt;

        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let mode_str = command.mode.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'mode' field".to_string(), None)
        })?;

        let full_path = self.validate_path(&path)?;

        if !full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Path not found: {}", path),
                None,
            ));
        }

        let mode = u32::from_str_radix(&mode_str, 8).map_err(|e| {
            self.create_error("INVALID_MODE", format!("Invalid mode: {}", e), None)
        })?;

        let permissions = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(&full_path, permissions).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to set permissions: {}", e), None)
        })?;

        // Apply recursively if requested for directories
        if command.recursive.unwrap_or(false) {
            let metadata = fs::metadata(&full_path).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
            })?;

            if metadata.is_dir() {
                self.chmod_recursive(&full_path, mode).await?;
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "message": "Permissions changed successfully",
            "path": full_path.display().to_string(),
            "mode": format!("{:04o}", mode),
            "recursive": command.recursive.unwrap_or(false),
        }))
    }

    #[cfg(not(unix))]
    async fn handle_chmod(&self, _command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        Err(self.create_error(
            "UNSUPPORTED_OPERATION",
            "chmod is not supported on this platform".to_string(),
            None,
        ))
    }

    /// Handle chown operation
    #[cfg(unix)]
    async fn handle_chown(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let path = command.path.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
        })?;

        let full_path = self.validate_path(&path)?;

        if !full_path.exists() {
            return Err(self.create_error(
                "FILE_NOT_FOUND",
                format!("Path not found: {}", path),
                None,
            ));
        }

        // Build chown command
        let mut cmd = Command::new("chown");
        
        if command.recursive.unwrap_or(false) {
            cmd.arg("-R");
        }

        // Format owner:group
        let ownership = if let (Some(owner), Some(group)) = (command.owner, command.group) {
            format!("{}:{}", owner, group)
        } else if let Some(owner) = command.owner {
            owner.to_string()
        } else if let Some(group) = command.group {
            format!(":{}", group)
        } else {
            return Err(self.create_error(
                "INVALID_COMMAND",
                "Missing 'owner' or 'group' field".to_string(),
                None,
            ));
        };

        cmd.arg(&ownership);
        cmd.arg(&full_path);

        let output = cmd.output().await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to change ownership: {}", e), None)
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(self.create_error(
                "CHOWN_FAILED",
                format!("Failed to change ownership: {}", stderr),
                None,
            ));
        }

        Ok(serde_json::json!({
            "success": true,
            "message": "Ownership changed successfully",
            "path": full_path.display().to_string(),
            "ownership": ownership,
            "recursive": command.recursive.unwrap_or(false),
        }))
    }

    #[cfg(not(unix))]
    async fn handle_chown(&self, _command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        Err(self.create_error(
            "UNSUPPORTED_OPERATION",
            "chown is not supported on this platform".to_string(),
            None,
        ))
    }

    /// Handle batch delete operation
    async fn handle_batch_delete(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let paths = command.paths.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'paths' field".to_string(), None)
        })?;

        let mut results = Vec::new();
        let mut succeeded = 0;
        let mut failed = 0;

        for path in &paths {
            let result = match self.validate_path(path) {
                Ok(full_path) => {
                    if full_path.exists() {
                        match fs::remove_file(&full_path).await {
                            Ok(_) => {
                                succeeded += 1;
                                SingleOperationResult {
                                    path: path.clone(),
                                    success: true,
                                    error: None,
                                }
                            }
                            Err(e) => {
                                failed += 1;
                                SingleOperationResult {
                                    path: path.clone(),
                                    success: false,
                                    error: Some(format!("Failed to delete: {}", e)),
                                }
                            }
                        }
                    } else {
                        failed += 1;
                        SingleOperationResult {
                            path: path.clone(),
                            success: false,
                            error: Some("File not found".to_string()),
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    SingleOperationResult {
                        path: path.clone(),
                        success: false,
                        error: Some(e.message),
                    }
                }
            };
            results.push(result);
        }

        let batch_result = BatchResult {
            total: paths.len(),
            succeeded,
            failed,
            results,
        };

        Ok(serde_json::json!(batch_result))
    }

    /// Handle batch move operation
    async fn handle_batch_move(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let paths = command.paths.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'paths' field".to_string(), None)
        })?;

        let destination = command.destination.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
        })?;

        let dst_dir = self.validate_path(&destination)?;

        // Ensure destination is a directory
        if !dst_dir.exists() {
            fs::create_dir_all(&dst_dir).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to create destination directory: {}", e), None)
            })?;
        }

        let mut results = Vec::new();
        let mut succeeded = 0;
        let mut failed = 0;

        for path in &paths {
            let result = match self.validate_path(path) {
                Ok(src_path) => {
                    if src_path.exists() {
                        let file_name = src_path.file_name()
                            .ok_or_else(|| "Invalid file name")
                            .and_then(|n| n.to_str().ok_or("Invalid UTF-8 in file name"));

                        match file_name {
                            Ok(name) => {
                                let dst_path = dst_dir.join(name);
                                match fs::rename(&src_path, &dst_path).await {
                                    Ok(_) => {
                                        succeeded += 1;
                                        SingleOperationResult {
                                            path: path.clone(),
                                            success: true,
                                            error: None,
                                        }
                                    }
                                    Err(e) => {
                                        failed += 1;
                                        SingleOperationResult {
                                            path: path.clone(),
                                            success: false,
                                            error: Some(format!("Failed to move: {}", e)),
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                failed += 1;
                                SingleOperationResult {
                                    path: path.clone(),
                                    success: false,
                                    error: Some(e.to_string()),
                                }
                            }
                        }
                    } else {
                        failed += 1;
                        SingleOperationResult {
                            path: path.clone(),
                            success: false,
                            error: Some("File not found".to_string()),
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    SingleOperationResult {
                        path: path.clone(),
                        success: false,
                        error: Some(e.message),
                    }
                }
            };
            results.push(result);
        }

        let batch_result = BatchResult {
            total: paths.len(),
            succeeded,
            failed,
            results,
        };

        Ok(serde_json::json!(batch_result))
    }

    /// Handle batch copy operation
    async fn handle_batch_copy(&self, command: RemoteCommandData) -> Result<serde_json::Value, RemoteCommandError> {
        let paths = command.paths.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'paths' field".to_string(), None)
        })?;

        let destination = command.destination.ok_or_else(|| {
            self.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
        })?;

        let dst_dir = self.validate_path(&destination)?;

        // Ensure destination is a directory
        if !dst_dir.exists() {
            fs::create_dir_all(&dst_dir).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to create destination directory: {}", e), None)
            })?;
        }

        let mut results = Vec::new();
        let mut succeeded = 0;
        let mut failed = 0;

        for path in &paths {
            let result = match self.validate_path(path) {
                Ok(src_path) => {
                    if src_path.exists() {
                        let file_name = src_path.file_name()
                            .ok_or_else(|| "Invalid file name")
                            .and_then(|n| n.to_str().ok_or("Invalid UTF-8 in file name"));

                        match file_name {
                            Ok(name) => {
                                let dst_path = dst_dir.join(name);
                                let copy_result = if src_path.is_file() {
                                    fs::copy(&src_path, &dst_path).await.map(|_| ())
                                } else {
                                    self.copy_dir_recursive(&src_path, &dst_path).await
                                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.message))
                                };

                                match copy_result {
                                    Ok(_) => {
                                        succeeded += 1;
                                        SingleOperationResult {
                                            path: path.clone(),
                                            success: true,
                                            error: None,
                                        }
                                    }
                                    Err(e) => {
                                        failed += 1;
                                        SingleOperationResult {
                                            path: path.clone(),
                                            success: false,
                                            error: Some(format!("Failed to copy: {}", e)),
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                failed += 1;
                                SingleOperationResult {
                                    path: path.clone(),
                                    success: false,
                                    error: Some(e.to_string()),
                                }
                            }
                        }
                    } else {
                        failed += 1;
                        SingleOperationResult {
                            path: path.clone(),
                            success: false,
                            error: Some("File not found".to_string()),
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    SingleOperationResult {
                        path: path.clone(),
                        success: false,
                        error: Some(e.message),
                    }
                }
            };
            results.push(result);
        }

        let batch_result = BatchResult {
            total: paths.len(),
            succeeded,
            failed,
            results,
        };

        Ok(serde_json::json!(batch_result))
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
                use_pipe_limit = true;
            }
            "ps" => {
                // If no args provided, use sensible defaults
                if args.is_empty() {
                    args.push("aux".to_string());
                }
                if args.contains(&"-x".to_string()) || args.contains(&"aux".to_string()) {
                    use_pipe_limit = true;
                    warn!("ps command typically produces large output, will limit results");
                }
            }
            "htop" => {
                // htop doesn't have a good batch mode
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
                const MAX_TOTAL_SIZE: usize = 50 * 1024; // 50KB total limit
                
                let total_output_size = output.stdout.len() + output.stderr.len();
                
                if total_output_size > MAX_TOTAL_SIZE {
                    info!("Large command output: {} bytes total, truncating", total_output_size);
                    
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
                    if stdout.len() > MAX_OUTPUT_SIZE {
                        stdout.truncate(MAX_OUTPUT_SIZE);
                        stdout.push_str("\n\n[OUTPUT TRUNCATED - Exceeded 32KB limit]");
                        truncated = true;
                    }
                    
                    if stderr.len() > MAX_OUTPUT_SIZE {
                        stderr.truncate(MAX_OUTPUT_SIZE);
                        stderr.push_str("\n\n[ERROR OUTPUT TRUNCATED - Exceeded 32KB limit]");
                        truncated = true;
                    }
                }
                
                if truncated {
                    let suggestions = match cmd.as_str() {
                        "ps" => Some("Try 'ps aux | head -20' or 'ps aux | grep <process_name>'"),
                        "top" => Some("Use 'top -b -n 1 | head -30' for less output"),
                        "find" => Some("Consider adding '-maxdepth 2' or piping to 'head -50'"),
                        "ls" => Some("Try 'ls | head -50' or use more specific paths"),
                        "cat" => Some("For large files, use 'head -100' or 'tail -100' instead"),
                        _ => Some("Consider using pipes with 'head', 'tail', or 'grep' to limit output"),
                    };
                    
                    if let Some(suggestion) = suggestions {
                        stderr.push_str(&format!("\n\nSuggestion: {}", suggestion));
                    }
                }
                
                let response_json = serde_json::json!({
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": output.status.code().unwrap_or(-1),
                    "execution_time_ms": execution_time_ms,
                    "truncated": truncated,
                    "original_stdout_size": output.stdout.len(),
                    "original_stderr_size": output.stderr.len(),
                });
                
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
            "total": mem.total * 1024,
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
            "total": disk.total * 1024,
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

            for ip in &interface.ips {
                if let Some(ip_addr) = ip.ip().to_string().split('/').next() {
                    if_info["ip"] = serde_json::json!(ip_addr);
                    break;
                }
            }

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
        let uptime_seconds = 0u64;
        
        let mem_info = sys_info::mem_info().unwrap_or(sys_info::MemInfo {
            total: 0,
            free: 0,
            avail: 0,
            buffers: 0,
            cached: 0,
            swap_total: 0,
            swap_free: 0,
        });
        let memory_mb = (mem_info.total - mem_info.avail) / 1024;

        Ok(serde_json::json!({
            "pid": pid,
            "uptime_seconds": uptime_seconds,
            "cpu_percent": 0.0,
            "memory_mb": memory_mb,
        }))
    }

    /// Check if command is whitelisted
    fn is_command_whitelisted(&self, cmd: &str) -> bool {
        if self.config.security_mode == SecurityMode::FullAccess {
            return true;
        }
        
        self.config.command_whitelist.contains(&cmd.to_string())
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

    /// Recursively copy directory
    async fn copy_dir_recursive(&self, src: &Path, dst: &Path) -> Result<(), RemoteCommandError> {
        fs::create_dir_all(dst).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to create directory: {}", e), None)
        })?;

        let mut entries = fs::read_dir(src).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to read directory: {}", e), None)
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to read entry: {}", e), None)
        })? {
            let entry_path = entry.path();
            let file_name = entry.file_name();
            let dst_path = dst.join(&file_name);

            let metadata = entry.metadata().await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
            })?;

            if metadata.is_dir() {
                Box::pin(self.copy_dir_recursive(&entry_path, &dst_path)).await?;
            } else {
                fs::copy(&entry_path, &dst_path).await.map_err(|e| {
                    self.create_error("SYSTEM_ERROR", format!("Failed to copy file: {}", e), None)
                })?;
            }
        }

        Ok(())
    }

    /// Recursively apply chmod
    #[cfg(unix)]
    async fn chmod_recursive(&self, path: &Path, mode: u32) -> Result<(), RemoteCommandError> {
        use std::os::unix::fs::PermissionsExt;

        let mut entries = fs::read_dir(path).await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to read directory: {}", e), None)
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            self.create_error("SYSTEM_ERROR", format!("Failed to read entry: {}", e), None)
        })? {
            let entry_path = entry.path();
            let permissions = std::fs::Permissions::from_mode(mode);
            
            fs::set_permissions(&entry_path, permissions).await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to set permissions: {}", e), None)
            })?;

            let metadata = entry.metadata().await.map_err(|e| {
                self.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
            })?;

            if metadata.is_dir() {
                Box::pin(self.chmod_recursive(&entry_path, mode)).await?;
            }
        }

        Ok(())
    }
    
    // ... [继续包含所有原有方法的完整实现]
    
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

/// Log remote command execution for security audit
pub fn log_remote_command(
    session_id: &str,
    command_type: &str,
    success: bool,
    details: &str,
) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let result = if success { "SUCCESS" } else { "FAILED" };
    
    match command_type {
        "execute" => {
            info!("[{}] REMOTE_CMD: session={}, cmd={}, result={}", 
                timestamp, session_id, details, result);
        }
        "upload" => {
            info!("[{}] REMOTE_UPLOAD: session={}, path={}, result={}", 
                timestamp, session_id, details, result);
        }
        "download" => {
            info!("[{}] REMOTE_DOWNLOAD: session={}, path={}, result={}", 
                timestamp, session_id, details, result);
        }
        "delete" => {
            info!("[{}] REMOTE_DELETE: session={}, path={}, result={}", 
                timestamp, session_id, details, result);
        }
        "rename" | "move" => {
            info!("[{}] REMOTE_RENAME: session={}, operation={}, result={}", 
                timestamp, session_id, details, result);
        }
        "copy" => {
            info!("[{}] REMOTE_COPY: session={}, operation={}, result={}", 
                timestamp, session_id, details, result);
        }
        "create_directory" => {
            info!("[{}] REMOTE_MKDIR: session={}, path={}, result={}", 
                timestamp, session_id, details, result);
        }
        "delete_directory" => {
            info!("[{}] REMOTE_RMDIR: session={}, path={}, result={}", 
                timestamp, session_id, details, result);
        }
        "list" => {
            info!("[{}] REMOTE_LIST: session={}, path={}, result={}", 
                timestamp, session_id, details, result);
        }
        "search" => {
            info!("[{}] REMOTE_SEARCH: session={}, query={}, result={}", 
                timestamp, session_id, details, result);
        }
        "compress" => {
            info!("[{}] REMOTE_COMPRESS: session={}, operation={}, result={}", 
                timestamp, session_id, details, result);
        }
        "extract" => {
            info!("[{}] REMOTE_EXTRACT: session={}, archive={}, result={}", 
                timestamp, session_id, details, result);
        }
        "chmod" => {
            info!("[{}] REMOTE_CHMOD: session={}, operation={}, result={}", 
                timestamp, session_id, details, result);
        }
        "chown" => {
            info!("[{}] REMOTE_CHOWN: session={}, operation={}, result={}", 
                timestamp, session_id, details, result);
        }
        "batch_delete" | "batch_move" | "batch_copy" => {
            info!("[{}] REMOTE_BATCH: session={}, type={}, operation={}, result={}", 
                timestamp, session_id, command_type, details, result);
        }
        "system_info" => {
            info!("[{}] REMOTE_SYSINFO: session={}, categories={}, result={}", 
                timestamp, session_id, details, result);
        }
        _ => {
            info!("[{}] REMOTE_{}: session={}, details={}, result={}", 
                timestamp, command_type.to_uppercase(), session_id, details, result);
        }
    }
    
    // Log security violations
    if !success && (details.contains("FORBIDDEN") || details.contains("PERMISSION_DENIED")) {
        error!("[{}] SECURITY_VIOLATION: session={}, command={}, details={}", 
            timestamp, session_id, command_type, details);
    }
}
