// src/remote_command_handler/handlers/dir_ops.rs
// ============================================
// Directory operations handlers
// ============================================

use tokio::fs;
use tracing::info;
use regex::Regex;
use walkdir::WalkDir;
use std::time::SystemTime;
use crate::remote_command_handler::{
    RemoteCommandData, RemoteCommandError, RemoteCommandHandler, SearchResult,
};
use super::common;

/// Handle directory listing
pub async fn handle_list(
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
            format!("Directory not found: {}", path),
            None,
        ));
    }

    if !full_path.is_dir() {
        return Err(handler.create_error(
            "INVALID_PATH",
            "Path is not a directory".to_string(),
            Some(serde_json::json!({ "path": path })),
        ));
    }

    let include_hidden = command.include_hidden.unwrap_or(false);
    let recursive = command.recursive.unwrap_or(false);

    let entries = list_directory_iterative(&full_path, include_hidden, recursive, handler).await?;

    Ok(serde_json::json!({
        "entries": entries,
        "total": entries.len(),
    }))
}

/// Iteratively list directory to avoid stack overflow
async fn list_directory_iterative(
    path: &std::path::Path,
    include_hidden: bool,
    recursive: bool,
    handler: &RemoteCommandHandler,
) -> Result<Vec<serde_json::Value>, RemoteCommandError> {
    use std::collections::VecDeque;

    let mut entries = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back((path.to_path_buf(), 0u32));

    const MAX_DEPTH: u32 = 5;

    while let Some((current_path, depth)) = queue.pop_front() {
        if depth > MAX_DEPTH {
            continue;
        }

        let mut dir_stream = fs::read_dir(&current_path).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to read directory: {}", e), None)
        })?;

        while let Ok(Some(entry)) = dir_stream.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();

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

            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                entry_info["permissions"] = serde_json::json!(
                    format!("{:o}", metadata.permissions().mode() & 0o777)
                );
                entry_info["owner"] = serde_json::json!(metadata.uid());
                entry_info["group"] = serde_json::json!(metadata.gid());
            }

            if let Ok(modified) = metadata.modified() {
                entry_info["modified"] = serde_json::json!(
                    common::format_modified_time(Ok(modified))
                );
            }

            if recursive && metadata.is_dir() {
                queue.push_back((entry.path(), depth + 1));
            }

            entries.push(entry_info);
        }
    }

    Ok(entries)
}

/// Handle directory creation
pub async fn handle_create_directory(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let path = command.path.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'path' field".to_string(), None)
    })?;

    let full_path = handler.validate_path(&path)?;

    if full_path.exists() {
        return Err(handler.create_error(
            "FILE_EXISTS",
            format!("Path already exists: {}", path),
            None,
        ));
    }

    fs::create_dir_all(&full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to create directory: {}", e), None)
    })?;

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
pub async fn handle_delete_directory(
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
            format!("Directory not found: {}", path),
            None,
        ));
    }

    let metadata = fs::metadata(&full_path).await.map_err(|e| {
        handler.create_error("SYSTEM_ERROR", format!("Failed to get metadata: {}", e), None)
    })?;

    if !metadata.is_dir() {
        return Err(handler.create_error(
            "INVALID_PATH",
            "Path is not a directory".to_string(),
            Some(serde_json::json!({ "path": path })),
        ));
    }

    if !command.recursive.unwrap_or(false) {
        let mut entries = fs::read_dir(&full_path).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to read directory: {}", e), None)
        })?;

        if entries.next_entry().await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to check directory: {}", e), None)
        })?.is_some() {
            return Err(handler.create_error(
                "DIRECTORY_NOT_EMPTY",
                "Directory is not empty. Use recursive flag to delete non-empty directories".to_string(),
                None,
            ));
        }

        fs::remove_dir(&full_path).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to delete directory: {}", e), None)
        })?;
    } else {
        fs::remove_dir_all(&full_path).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to delete directory recursively: {}", e), None)
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
pub async fn handle_search(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let base_path = command.path.unwrap_or_else(|| ".".to_string());
    let query = command.query.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'query' field".to_string(), None)
    })?;

    let full_path = handler.validate_path(&base_path)?;

    if !full_path.exists() {
        return Err(handler.create_error(
            "FILE_NOT_FOUND",
            format!("Search path not found: {}", base_path),
            None,
        ));
    }

    let use_regex = command.use_regex.unwrap_or(false);
    let case_sensitive = command.case_sensitive.unwrap_or(false);
    let include_hidden = command.include_hidden.unwrap_or(false);
    let max_depth = command.max_depth
        .unwrap_or(handler.config().max_search_depth)
        .min(handler.config().max_search_depth);
    let file_type = command.file_type.as_deref().unwrap_or("any");

    let pattern = if use_regex {
        let flags = if case_sensitive { "" } else { "(?i)" };
        let pattern_str = format!("{}{}", flags, query);
        Some(Regex::new(&pattern_str).map_err(|e| {
            handler.create_error("INVALID_REGEX", format!("Invalid regex pattern: {}", e), None)
        })?)
    } else {
        None
    };

    let mut results = Vec::new();
    let walker = WalkDir::new(&full_path)
        .max_depth(max_depth as usize)
        .follow_links(false);

    for entry in walker {
        if results.len() >= handler.config().max_search_results {
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

        if !include_hidden && name.starts_with('.') {
            continue;
        }

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

        let name_matches = if use_regex {
            pattern.as_ref().unwrap().is_match(name)
        } else if case_sensitive {
            name.contains(&query)
        } else {
            name.to_lowercase().contains(&query.to_lowercase())
        };

        if name_matches {
            let modified = common::format_modified_time(metadata.modified());

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
        "max_results_reached": results.len() >= handler.config().max_search_results,
    }))
}
