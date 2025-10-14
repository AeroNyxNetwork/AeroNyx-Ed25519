// src/remote_command_handler/handlers/file_ops.rs
// ============================================
// File operations handlers
// ============================================

use tokio::fs;
use tokio::process::Command;
use tracing::info;
use crate::remote_command_handler::{
    RemoteCommandData, RemoteCommandError, RemoteCommandHandler,
};
use super::common;

/// Handle file upload
pub async fn handle_upload(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let content = command.content.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'content' field".to_string(), None)
    })?;

    let full_path = handler.validate_path(&path)?;

    // Decode base64 content
    let decoded = base64::decode(&content).map_err(|e| {
        handler.create_error("INVALID_COMMAND", format!("Invalid base64 content: {}", e), None)
    })?;

    // Check file size
    if decoded.len() > handler.config().max_file_size as usize {
        return Err(handler.create_error(
            "FILE_TOO_LARGE",
            format!("File size {} exceeds maximum allowed size {}", 
                decoded.len(), handler.config().max_file_size),
            None,
        ));
    }

    // Check if file exists and overwrite is not allowed
    if full_path.exists() && !command.overwrite.unwrap_or(false) {
        return Err(handler.create_error(
            "FILE_EXISTS",
            "File already exists and overwrite is not allowed".to_string(),
            Some(serde_json::json!({ "path": path })),
        ));
    }

    // Create parent directory if needed
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to create directory: {}", e), None)
        })?;
    }

    // Write to temporary file first, then rename (atomic operation)
    let temp_path = full_path.with_extension(".tmp");
    fs::write(&temp_path, &decoded).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to write file: {}", e), None)
    })?;

    // Atomic rename
    if let Err(e) = fs::rename(&temp_path, &full_path).await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(handler.create_error("SYSTEM_ERROR", format!("Failed to finalize upload: {}", e), None));
    }

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
pub async fn handle_download(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let full_path = handler.validate_path(&path)?;

    if !full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("File not found: {}", path),
            None,
        ));
    }

    let metadata = fs::metadata(&full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get file metadata: {}", e), None)
    })?;

    if !metadata.is_file() {
        return Err(handler.create_error(
            "INVALID_PATH",
            "Path is not a file".to_string(),
            Some(serde_json::json!({ "path": path })),
        ));
    }

    let max_size = command.max_size.unwrap_or(handler.config().max_file_size);
    if metadata.len() > max_size {
        return Err(handler.create_error(
            "FILE_TOO_LARGE",
            format!("File size {} exceeds maximum allowed size {}", metadata.len(), max_size),
            None,
        ));
    }

    let content = fs::read(&full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to read file: {}", e), None)
    })?;

    let encoded = base64::encode(&content);
    let mime_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();
    let modified = common::format_modified_time(metadata.modified());

    Ok(serde_json::json!({
        "content": encoded,
        "size": content.len(),
        "mime_type": mime_type,
        "modified": modified,
    }))
}

/// Handle file deletion
pub async fn handle_delete(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let full_path = handler.validate_path(&path)?;

    if !full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("File not found: {}", path),
            None,
        ));
    }

    let metadata = fs::metadata(&full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
    })?;

    if !metadata.is_file() {
        return Err(handler.create_error(
            "INVALID_PATH",
            "Path is not a file. Use delete_directory for directories".to_string(),
            Some(serde_json::json!({ "path": path })),
        ));
    }

    fs::remove_file(&full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to delete file: {}", e), None)
    })?;

    info!("File deleted: {}", full_path.display());

    Ok(serde_json::json!({
        "success": true,
        "message": "File deleted successfully",
        "path": full_path.display().to_string(),
    }))
}

/// Handle file renaming
pub async fn handle_rename(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let old_path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let new_path = command.destination.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
    })?;

    let old_full_path = handler.validate_path(&old_path)?;
    let new_full_path = handler.validate_path(&new_path)?;

    if !old_full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("Source not found: {}", old_path),
            None,
        ));
    }

    if new_full_path.exists() && !command.overwrite.unwrap_or(false) {
        return Err(handler.create_error(
            "FILE_EXISTS",
            format!("Destination already exists: {}", new_path),
            None,
        ));
    }

    fs::rename(&old_full_path, &new_full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to rename: {}", e), None)
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
pub async fn handle_copy(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let src_path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let dst_path = command.destination.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
    })?;

    let src_full_path = handler.validate_path(&src_path)?;
    let dst_full_path = handler.validate_path(&dst_path)?;

    if !src_full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("Source not found: {}", src_path),
            None,
        ));
    }

    if dst_full_path.exists() && !command.overwrite.unwrap_or(false) {
        return Err(handler.create_error(
            "FILE_EXISTS",
            format!("Destination already exists: {}", dst_path),
            None,
        ));
    }

    let metadata = fs::metadata(&src_full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
    })?;

    if metadata.is_file() {
        // Copy to temp then rename for atomicity
        let temp_path = dst_full_path.with_extension(".tmp");
        fs::copy(&src_full_path, &temp_path).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to copy file: {}", e), None)
        })?;
        
        if let Err(e) = fs::rename(&temp_path, &dst_full_path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(handler.create_error("SYSTEM_ERROR", format!("Failed to finalize copy: {}", e), None));
        }
    } else if metadata.is_dir() {
        if !command.recursive.unwrap_or(false) {
            return Err(handler.create_error(
                "INVALID_OPERATION",
                "Directory copy requires recursive flag".to_string(),
                None,
            ));
        }
        
        let error_fn = |msg: String| handler.create_error("SYSTEM_ERROR", msg, None);
        common::copy_dir_recursive(&src_full_path, &dst_full_path, &error_fn).await?;
    }

    info!("File/directory copied: {} -> {}", src_full_path.display(), dst_full_path.display());

    Ok(serde_json::json!({
        "success": true,
        "message": "Copy completed successfully",
        "source": src_full_path.display().to_string(),
        "destination": dst_full_path.display().to_string(),
    }))
}

/// Handle file moving (same as rename)
pub async fn handle_move(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    handle_rename(handler, command).await
}

/// Handle chmod operation
#[cfg(unix)]
pub async fn handle_chmod(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    use std::os::unix::fs::PermissionsExt;

    let path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let mode_str = command.mode.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'mode' field".to_string(), None)
    })?;

    let full_path = handler.validate_path(&path)?;

    if !full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("Path not found: {}", path),
            None,
        ));
    }

    let mode = u32::from_str_radix(&mode_str, 8).map_err(|e| {
        handler.create_error("INVALID_MODE", format!("Invalid mode: {}", e), None)
    })?;

    let permissions = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(&full_path, permissions).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to set permissions: {}", e), None)
    })?;

    if command.recursive.unwrap_or(false) {
        let metadata = fs::metadata(&full_path).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
        })?;

        if metadata.is_dir() {
            let error_fn = |msg: String| handler.create_error("SYSTEM_ERROR", msg, None);
            common::chmod_recursive(&full_path, mode, &error_fn).await?;
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
pub async fn handle_chmod(
    handler: &RemoteCommandHandler,
    _command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    Err(handler.create_error(
        "UNSUPPORTED_OPERATION",
        "chmod is not supported on this platform".to_string(),
        None,
    ))
}

/// Handle chown operation
#[cfg(unix)]
pub async fn handle_chown(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let full_path = handler.validate_path(&path)?;

    if !full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("Path not found: {}", path),
            None,
        ));
    }

    let mut cmd = Command::new("chown");
    
    if command.recursive.unwrap_or(false) {
        cmd.arg("-R");
    }

    let ownership = if let (Some(owner), Some(group)) = (command.owner, command.group) {
        format!("{}:{}", owner, group)
    } else if let Some(owner) = command.owner {
        owner.to_string()
    } else if let Some(group) = command.group {
        format!(":{}", group)
    } else {
        return Err(handler.create_error(
            "INVALID_COMMAND",
            "Missing 'owner' or 'group' field".to_string(),
            None,
        ));
    };

    cmd.arg(&ownership);
    cmd.arg(&full_path);

    let output = cmd.output().await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to change ownership: {}", e), None)
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(handler.create_error(
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
pub async fn handle_chown(
    handler: &RemoteCommandHandler,
    _command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    Err(handler.create_error(
        "UNSUPPORTED_OPERATION",
        "chown is not supported on this platform".to_string(),
        None,
    ))
}
