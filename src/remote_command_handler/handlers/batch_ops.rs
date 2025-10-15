// src/remote_command_handler/handlers/batch_ops.rs
// ============================================
// Batch operations handlers
// ============================================

use tokio::fs;
use crate::remote_command_handler::{
    RemoteCommandData, RemoteCommandError, RemoteCommandHandler,
    BatchResult, SingleOperationResult,
};
use super::common;

/// Handle batch delete operation
pub async fn handle_batch_delete(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let paths = command.paths.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'paths' field".to_string(), None)
    })?;

    let mut results = Vec::new();
    let mut succeeded = 0;
    let mut failed = 0;

    for path in &paths {
        let result = match handler.validate_path(path) {
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
pub async fn handle_batch_move(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let paths = command.paths.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'paths' field".to_string(), None)
    })?;

    let destination = command.destination.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
    })?;

    let dst_dir = handler.validate_path(&destination)?;

    if !dst_dir.exists() {
        fs::create_dir_all(&dst_dir).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to create destination directory: {}", e), None)
        })?;
    }

    let mut results = Vec::new();
    let mut succeeded = 0;
    let mut failed = 0;

    for path in &paths {
        let result = match handler.validate_path(path) {
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
pub async fn handle_batch_copy(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let paths = command.paths.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'paths' field".to_string(), None)
    })?;

    let destination = command.destination.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'destination' field".to_string(), None)
    })?;

    let dst_dir = handler.validate_path(&destination)?;

    if !dst_dir.exists() {
        fs::create_dir_all(&dst_dir).await.map_err(|e| {
            handler.create_error("SYSTEM_ERROR", format!("Failed to create destination directory: {}", e), None)
        })?;
    }

    let mut results = Vec::new();
    let mut succeeded = 0;
    let mut failed = 0;

    for path in &paths {
        let result = match handler.validate_path(path) {
            Ok(src_path) => {
                if src_path.exists() {
                    let file_name = src_path.file_name()
                        .ok_or_else(|| "Invalid file name")
                        .and_then(|n| n.to_str().ok_or("Invalid UTF-8 in file name"));

                    match file_name {
                        Ok(name) => {
                            let dst_path = dst_dir.join(name);
                            let copy_result = if src_path.is_file() {
                                fs::copy(&src_path, &dst_path).await
                                    .map(|_| ())
                                    .map_err(|e| format!("Failed to copy: {}", e))
                            } else {
                                common::copy_dir_recursive(&src_path, &dst_path).await
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
                                        error: Some(e),
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
