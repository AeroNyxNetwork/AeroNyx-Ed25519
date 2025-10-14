// src/remote_command_handler/handlers/common.rs
// ============================================
// Common utilities for handlers
// ============================================

use std::path::Path;
use std::time::SystemTime;
use tokio::fs;
use crate::remote_command_handler::RemoteCommandError;

/// Recursively copy directory using iterative approach to prevent stack overflow
pub async fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
) -> Result<(), String> {
    use std::collections::VecDeque;
    
    fs::create_dir_all(dst).await.map_err(|e| {
        format!("Failed to create directory: {}", e)
    })?;

    let mut queue = VecDeque::new();
    queue.push_back((src.to_path_buf(), dst.to_path_buf()));
    
    let mut depth = 0;
    const MAX_DEPTH: usize = 100;

    while let Some((src_dir, dst_dir)) = queue.pop_front() {
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(format!("Directory nesting exceeds maximum depth of {}", MAX_DEPTH));
        }

        let mut entries = fs::read_dir(&src_dir).await.map_err(|e| {
            format!("Failed to read directory: {}", e)
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            format!("Failed to read entry: {}", e)
        })? {
            let entry_path = entry.path();
            let file_name = entry.file_name();
            let dst_path = dst_dir.join(&file_name);

            let metadata = entry.metadata().await.map_err(|e| {
                format!("Failed to get metadata: {}", e)
            })?;

            if metadata.is_dir() {
                fs::create_dir_all(&dst_path).await.map_err(|e| {
                    format!("Failed to create directory: {}", e)
                })?;
                queue.push_back((entry_path, dst_path));
            } else {
                fs::copy(&entry_path, &dst_path).await.map_err(|e| {
                    format!("Failed to copy file: {}", e)
                })?;
            }
        }
    }

    Ok(())
}

/// Recursively apply chmod (Unix only)
#[cfg(unix)]
pub async fn chmod_recursive(
    path: &Path,
    mode: u32,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    use std::collections::VecDeque;

    let mut queue = VecDeque::new();
    queue.push_back(path.to_path_buf());

    while let Some(current_path) = queue.pop_front() {
        let metadata = fs::metadata(&current_path).await.map_err(|e| {
            format!("Failed to get metadata: {}", e)
        })?;

        let permissions = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(&current_path, permissions).await.map_err(|e| {
            format!("Failed to set permissions: {}", e)
        })?;

        if metadata.is_dir() {
            let mut entries = fs::read_dir(&current_path).await.map_err(|e| {
                format!("Failed to read directory: {}", e)
            })?;

            while let Some(entry) = entries.next_entry().await.map_err(|e| {
                format!("Failed to read entry: {}", e)
            })? {
                queue.push_back(entry.path());
            }
        }
    }

    Ok(())
}

/// Format modification time to RFC3339
pub fn format_modified_time(modified: Result<SystemTime, std::io::Error>) -> String {
    modified
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| {
            let dt = chrono::Utc::now() - chrono::Duration::seconds(d.as_secs() as i64);
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
}
