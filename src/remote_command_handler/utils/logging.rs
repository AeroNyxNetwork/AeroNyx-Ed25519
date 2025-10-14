// src/remote_command_handler/utils/logging.rs
// ============================================
// Logging utilities
// ============================================

use tracing::{info, error};

/// Sanitize log input to prevent log injection
fn sanitize_log_input(input: &str) -> String {
    input
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
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
    
    let safe_session_id = sanitize_log_input(session_id);
    let safe_command_type = sanitize_log_input(command_type);
    let safe_details = sanitize_log_input(details);
    
    match command_type {
        "execute" => {
            info!("[{}] REMOTE_CMD: session={}, cmd={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "upload" => {
            info!("[{}] REMOTE_UPLOAD: session={}, path={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "download" => {
            info!("[{}] REMOTE_DOWNLOAD: session={}, path={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "delete" => {
            info!("[{}] REMOTE_DELETE: session={}, path={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "rename" | "move" => {
            info!("[{}] REMOTE_RENAME: session={}, operation={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "copy" => {
            info!("[{}] REMOTE_COPY: session={}, operation={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "create_directory" => {
            info!("[{}] REMOTE_MKDIR: session={}, path={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "delete_directory" => {
            info!("[{}] REMOTE_RMDIR: session={}, path={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "list" => {
            info!("[{}] REMOTE_LIST: session={}, path={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "search" => {
            info!("[{}] REMOTE_SEARCH: session={}, query={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "compress" => {
            info!("[{}] REMOTE_COMPRESS: session={}, operation={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "extract" => {
            info!("[{}] REMOTE_EXTRACT: session={}, archive={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "chmod" => {
            info!("[{}] REMOTE_CHMOD: session={}, operation={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "chown" => {
            info!("[{}] REMOTE_CHOWN: session={}, operation={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        "batch_delete" | "batch_move" | "batch_copy" => {
            info!("[{}] REMOTE_BATCH: session={}, type={}, operation={}, result={}", 
                timestamp, safe_session_id, safe_command_type, safe_details, result);
        }
        "system_info" => {
            info!("[{}] REMOTE_SYSINFO: session={}, categories={}, result={}", 
                timestamp, safe_session_id, safe_details, result);
        }
        _ => {
            info!("[{}] REMOTE_{}: session={}, details={}, result={}", 
                timestamp, safe_command_type.to_uppercase(), safe_session_id, safe_details, result);
        }
    }
    
    // Log security violations
    if !success && (details.contains("FORBIDDEN") || details.contains("PERMISSION_DENIED")) {
        error!("[{}] SECURITY_VIOLATION: session={}, command={}, details={}", 
            timestamp, safe_session_id, safe_command_type, safe_details);
    }
}
