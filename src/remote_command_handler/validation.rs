// src/remote_command_handler/validation.rs
// ============================================
// Path and command validation
// ============================================

use std::path::{Path, PathBuf, Component};
use crate::remote_command_handler::{RemoteCommandConfig, RemoteCommandError, SecurityMode};

/// Validate and normalize path
pub fn validate_path(
    config: &RemoteCommandConfig,
    path_str: &str,
    error_creator: &dyn ErrorCreator,
) -> Result<PathBuf, RemoteCommandError> {
    let path = Path::new(path_str);
    
    // Convert to absolute path
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        config.working_dir.join(path)
    };

    // Canonicalize to resolve symlinks and normalize
    let canonical = match absolute_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // If file doesn't exist, try to canonicalize parent directory
            if let Some(parent) = absolute_path.parent() {
                let canonical_parent = parent.canonicalize()
                    .map_err(|e| error_creator.create_error(
                        "INVALID_PATH",
                        format!("Parent directory does not exist: {}", e),
                        None
                    ))?;
                
                if let Some(file_name) = absolute_path.file_name() {
                    canonical_parent.join(file_name)
                } else {
                    return Err(error_creator.create_error(
                        "INVALID_PATH",
                        "Invalid path".to_string(),
                        None
                    ));
                }
            } else {
                return Err(error_creator.create_error(
                    "INVALID_PATH",
                    "Cannot resolve path".to_string(),
                    None
                ));
            }
        }
    };

    // In FullAccess mode, allow any path except critical system paths
    if config.security_mode == SecurityMode::FullAccess {
        let critical_paths = ["/proc", "/sys", "/dev", "/boot/grub"];
        
        for critical in &critical_paths {
            if canonical.starts_with(critical) {
                return Err(error_creator.create_error(
                    "PERMISSION_DENIED",
                    format!("Access to {} is forbidden for system stability", critical),
                    Some(serde_json::json!({ "path": path_str })),
                ));
            }
        }
        
        return Ok(canonical);
    }

    // In Restricted mode, check against allowed paths
    let is_allowed = config.allowed_paths.iter().any(|allowed| {
        canonical.starts_with(allowed)
    });

    if !is_allowed {
        return Err(error_creator.create_error(
            "PERMISSION_DENIED",
            "Path is outside allowed directories".to_string(),
            Some(serde_json::json!({ 
                "path": path_str,
                "canonical": canonical.display().to_string()
            })),
        ));
    }

    Ok(canonical)
}

/// Check if command is whitelisted
pub fn is_command_whitelisted(config: &RemoteCommandConfig, cmd: &str) -> bool {
    if config.security_mode == SecurityMode::FullAccess {
        return true;
    }
    
    config.command_whitelist.contains(&cmd.to_string())
}

/// Check if command is forbidden
pub fn is_command_forbidden(
    config: &RemoteCommandConfig,
    cmd: &str,
    args: &Option<Vec<String>>,
) -> bool {
    let full_command = if let Some(args) = args {
        format!("{} {}", cmd, args.join(" "))
    } else {
        cmd.to_string()
    };

    config.forbidden_commands.iter().any(|forbidden| {
        full_command.contains(forbidden)
    })
}

/// Trait for creating errors (allows handler to implement)
pub trait ErrorCreator {
    fn create_error(
        &self,
        code: &str,
        message: String,
        details: Option<serde_json::Value>,
    ) -> RemoteCommandError;
}

// Implement for RemoteCommandHandler
impl ErrorCreator for crate::remote_command_handler::RemoteCommandHandler {
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
