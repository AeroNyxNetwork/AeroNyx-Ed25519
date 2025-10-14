// src/remote_command_handler/handlers/execute_ops.rs
// ============================================
// Command execution handler
// ============================================

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::info;
use crate::remote_command_handler::{
    RemoteCommandData, RemoteCommandError, RemoteCommandHandler,
};

/// Execute system command with restrictions
pub async fn handle_execute(
    handler: &RemoteCommandHandler,
    command: RemoteCommandData,
) -> Result<serde_json::Value, RemoteCommandError> {
    let cmd = command.cmd.ok_or_else(|| {
        handler.create_error("INVALID_COMMAND", "Missing 'cmd' field".to_string(), None)
    })?;

    // Security check: forbidden commands
    if handler.is_command_forbidden(&cmd, &command.args) {
        return Err(handler.create_error(
            "PERMISSION_DENIED",
            "This command is forbidden for security reasons".to_string(),
            Some(serde_json::json!({ "command": cmd })),
        ));
    }

    // Security check: whitelist
    if handler.config().enable_command_whitelist && !handler.is_command_whitelisted(&cmd) {
        return Err(handler.create_error(
            "PERMISSION_DENIED",
            "Command not in whitelist".to_string(),
            Some(serde_json::json!({ "command": cmd })),
        ));
    }

    // Prepare command
    let mut process = Command::new(&cmd);
    
    // Handle special cases for interactive commands
    let mut args = command.args.unwrap_or_default();
    
    match cmd.as_str() {
        "top" => {
            if !args.contains(&"-b".to_string()) {
                args.insert(0, "-b".to_string());
            }
            if !args.iter().any(|arg| arg.starts_with("-n")) {
                args.push("-n".to_string());
                args.push("1".to_string());
            }
        }
        "ps" => {
            if args.is_empty() {
                args.push("aux".to_string());
            }
        }
        "htop" => {
            return Err(handler.create_error(
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
        handler.validate_path(&cwd_str)?
    } else {
        handler.config().working_dir.clone()
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
            
            const MAX_OUTPUT_SIZE: usize = 32 * 1024;
            const MAX_TOTAL_SIZE: usize = 50 * 1024;
            
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
        Ok(Err(e)) => Err(handler.create_error(
            "SYSTEM_ERROR",
            format!("Failed to execute command: {}", e),
            None,
        )),
        Err(_) => Err(handler.create_error(
            "TIMEOUT",
            format!("Command execution timeout after {} seconds", timeout_duration.as_secs()),
            None,
        )),
    }
}
