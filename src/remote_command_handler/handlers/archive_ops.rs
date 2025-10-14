// src/remote_command_handler/handlers/archive_ops.rs
// ============================================
// Archive operations (compress/extract)
// ============================================

use tokio::fs;
use tokio::process::Command;
use crate::remote_command_handler::{
    RemoteCommandData, RemoteCommandError, RemoteCommandHandler,
};

/// Handle file compression
pub async fn handle_compress(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let paths = command.paths.or_else(|| command.path.map(|p| vec![p]))
        .ok_or_else(|| {
            handler.create_error("INVALID_COMMAND", "Missing 'paths' or 'path' field".to_string(), None)
        })?;

    let destination = command.destination.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
    })?;

    let format = command.format.as_deref().unwrap_or("zip");

    // Validate all source paths
    let mut validated_paths = Vec::new();
    for path in &paths {
        let full_path = handler.validate_path(path)?;
        if !full_path.exists() {
            return Err(handler.create_error(
                "FILE_NOT_FOUND",
                format!("Path not found: {}", path),
                None,
            ));
        }
        validated_paths.push(full_path);
    }

    let dst_full_path = handler.validate_path(&destination)?;

    if dst_full_path.exists() && !command.overwrite.unwrap_or(false) {
        return Err(handler.create_error(
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
            return Err(handler.create_error(
                "UNSUPPORTED_FORMAT",
                format!("Unsupported archive format: {}", format),
                None,
            ));
        }
    };

    let output = cmd.output().await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to compress: {}", e), None)
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(handler.create_error(
            "COMPRESSION_FAILED",
            format!("Compression failed: {}", stderr),
            None,
        ));
    }

    let metadata = fs::metadata(&dst_full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get archive metadata: {}", e), None)
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
pub async fn handle_extract(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let archive_path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let destination = command.destination.unwrap_or_else(|| ".".to_string());

    let archive_full_path = handler.validate_path(&archive_path)?;
    let dst_full_path = handler.validate_path(&destination)?;

    if !archive_full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("Archive not found: {}", archive_path),
            None,
        ));
    }

    let format = command.format.as_deref().unwrap_or_else(|| {
        if archive_path.ends_with(".zip") { "zip" }
        else if archive_path.ends_with(".tar") { "tar" }
        else if archive_path.ends_with(".tar.gz") || archive_path.ends_with(".tgz") { "tar.gz" }
        else { "auto" }
    });

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
            return Err(handler.create_error(
                "UNSUPPORTED_FORMAT",
                format!("Unable to detect or unsupported archive format: {}", format),
                None,
            ));
        }
    };

    let output = cmd.output().await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to extract: {}", e), None)
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(handler.create_error(
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
