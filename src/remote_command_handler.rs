// src/remote_command_handler.rs
// ============================================
// AeroNyx Privacy Network - Enhanced Remote Command Handler
// Version: 2.0.1 - Modularized Architecture
// ============================================
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Main entry point for remote command handling
// Maintains backward compatibility with v2.0.0
//
// Module Structure:
// - models: Data structures and types
// - config: Configuration and security settings
// - validation: Path and command validation
// - handlers: Command execution handlers
//   - file_ops: File operations (copy, move, delete, etc.)
//   - dir_ops: Directory operations
//   - archive_ops: Compression and extraction
//   - system_ops: System information
//   - batch_ops: Batch operations
// - utils: Helper functions
// ============================================

use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;

// Re-export public types for backward compatibility
pub use models::*;
pub use config::*;

// Internal modules
mod models;
mod config;
mod validation;
mod handlers;
mod utils;

use handlers::{
    file_ops, dir_ops, archive_ops, system_ops, batch_ops, execute_ops
};

/// Remote command handler
pub struct RemoteCommandHandler {
    config: RemoteCommandConfig,
}

impl RemoteCommandHandler {
    /// Create a new remote command handler
    pub fn new(config: RemoteCommandConfig) -> Self {
        Self { config }
    }

    /// Handle incoming command - Main entry point
    pub async fn handle_command(
        &self,
        request_id: String,
        command: RemoteCommandData,
    ) -> RemoteCommandResponse {
        let start_time = std::time::Instant::now();
        
        let result = self.dispatch_command(command).await;
        
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

    /// Dispatch command to appropriate handler
    async fn dispatch_command(
        &self,
        command: RemoteCommandData,
    ) -> Result<serde_json::Value, RemoteCommandError> {
        match command.command_type.as_str() {
            // Execute operations
            "execute" => execute_ops::handle_execute(self, command).await,
            
            // File operations
            "upload" => file_ops::handle_upload(self, command).await,
            "download" => file_ops::handle_download(self, command).await,
            "delete" => file_ops::handle_delete(self, command).await,
            "rename" => file_ops::handle_rename(self, command).await,
            "copy" => file_ops::handle_copy(self, command).await,
            "move" => file_ops::handle_move(self, command).await,
            
            // Directory operations
            "list" => dir_ops::handle_list(self, command).await,
            "create_directory" => dir_ops::handle_create_directory(self, command).await,
            "delete_directory" => dir_ops::handle_delete_directory(self, command).await,
            "search" => dir_ops::handle_search(self, command).await,
            
            // Archive operations
            "compress" => archive_ops::handle_compress(self, command).await,
            "extract" => archive_ops::handle_extract(self, command).await,
            
            // Permission operations
            "chmod" => file_ops::handle_chmod(self, command).await,
            "chown" => file_ops::handle_chown(self, command).await,
            
            // Batch operations
            "batch_delete" => batch_ops::handle_batch_delete(self, command).await,
            "batch_move" => batch_ops::handle_batch_move(self, command).await,
            "batch_copy" => batch_ops::handle_batch_copy(self, command).await,
            
            // System operations
            "system_info" => system_ops::handle_system_info(self, command).await,
            
            _ => Err(self.create_error(
                "UNKNOWN_COMMAND",
                format!("Unknown command type: {}", command.command_type),
                None,
            )),
        }
    }

    /// Get configuration (used by handlers)
    pub(crate) fn config(&self) -> &RemoteCommandConfig {
        &self.config
    }

    /// Validate path (used by handlers)
    pub(crate) fn validate_path(
        &self,
        path_str: &str,
    ) -> Result<PathBuf, RemoteCommandError> {
        validation::validate_path(&self.config, path_str, self)
    }

    /// Check if command is whitelisted (used by handlers)
    pub(crate) fn is_command_whitelisted(&self, cmd: &str) -> bool {
        validation::is_command_whitelisted(&self.config, cmd)
    }

    /// Check if command is forbidden (used by handlers)
    pub(crate) fn is_command_forbidden(
        &self,
        cmd: &str,
        args: &Option<Vec<String>>,
    ) -> bool {
        validation::is_command_forbidden(&self.config, cmd, args)
    }

    /// Create error response (used by handlers)
    pub(crate) fn create_error(
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
/// Maintains backward compatibility with v2.0.0
pub fn log_remote_command(
    session_id: &str,
    command_type: &str,
    success: bool,
    details: &str,
) {
    utils::logging::log_remote_command(session_id, command_type, success, details);
}
