use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RemoteCommand {
    #[serde(rename = "list_directory")]
    ListDirectory { path: String },
    
    #[serde(rename = "read_file")]
    ReadFile { path: String },
    
    #[serde(rename = "delete_file")]
    DeleteFile { path: String },
    
    #[serde(rename = "execute_command")]
    ExecuteCommand { 
        command: String,
        args: Vec<String>,
        #[serde(default)]
        working_dir: Option<String>,
    },
    
    #[serde(rename = "get_system_info")]
    GetSystemInfo,
    
    #[serde(rename = "get_process_list")]
    GetProcessList,
    
    #[serde(rename = "upload_file")]
    UploadFile {
        path: String,
        content: String, // Base64 encoded
    },
    
    #[serde(rename = "download_file")]
    DownloadFile { path: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

pub struct RemoteManagementHandler {
    allowed_paths: Vec<PathBuf>,
    allowed_commands: Vec<String>,
}

impl RemoteManagementHandler {
    pub fn new() -> Self {
        Self {
            // Configure allowed paths for security
            allowed_paths: vec![
                PathBuf::from("/home"),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/log"),
            ],
            // Configure allowed commands
            allowed_commands: vec![
                "ls".to_string(),
                "ps".to_string(),
                "df".to_string(),
                "free".to_string(),
                "uptime".to_string(),
                "whoami".to_string(),
                "date".to_string(),
                "cat".to_string(),
                "grep".to_string(),
                "tail".to_string(),
                "head".to_string(),
            ],
        }
    }

    pub async fn handle_command(&self, command: RemoteCommand) -> CommandResponse {
        match command {
            RemoteCommand::ListDirectory { path } => self.list_directory(&path).await,
            RemoteCommand::ReadFile { path } => self.read_file(&path).await,
            RemoteCommand::DeleteFile { path } => self.delete_file(&path).await,
            RemoteCommand::ExecuteCommand { command, args, working_dir } => {
                self.execute_command(&command, args, working_dir).await
            }
            RemoteCommand::GetSystemInfo => self.get_system_info().await,
            RemoteCommand::GetProcessList => self.get_process_list().await,
            RemoteCommand::UploadFile { path, content } => self.upload_file(&path, &content).await,
            RemoteCommand::DownloadFile { path } => self.download_file(&path).await,
        }
    }

    fn is_path_allowed(&self, path: &Path) -> bool {
        let path = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => return false,
        };

        self.allowed_paths.iter().any(|allowed| {
            path.starts_with(allowed)
        })
    }

    fn is_command_allowed(&self, command: &str) -> bool {
        self.allowed_commands.contains(&command.to_string())
    }

    async fn list_directory(&self, path: &str) -> CommandResponse {
        let path = Path::new(path);
        
        if !self.is_path_allowed(path) {
            return CommandResponse {
                success: false,
                message: "Access denied: Path not allowed".to_string(),
                data: None,
            };
        }

        match fs::read_dir(path).await {
            Ok(mut entries) => {
                let mut files = Vec::new();
                
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Ok(metadata) = entry.metadata().await {
                        files.push(serde_json::json!({
                            "name": entry.file_name().to_string_lossy(),
                            "is_dir": metadata.is_dir(),
                            "size": metadata.len(),
                            "modified": metadata.modified().ok().map(|t| {
                                t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                            }),
                        }));
                    }
                }

                CommandResponse {
                    success: true,
                    message: "Directory listed successfully".to_string(),
                    data: Some(serde_json::json!({ "files": files })),
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to list directory: {}", e),
                data: None,
            },
        }
    }

    async fn read_file(&self, path: &str) -> CommandResponse {
        let path = Path::new(path);
        
        if !self.is_path_allowed(path) {
            return CommandResponse {
                success: false,
                message: "Access denied: Path not allowed".to_string(),
                data: None,
            };
        }

        // Limit file size to prevent memory issues
        const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB

        match fs::metadata(path).await {
            Ok(metadata) => {
                if metadata.len() > MAX_FILE_SIZE {
                    return CommandResponse {
                        success: false,
                        message: format!("File too large. Maximum size: {} bytes", MAX_FILE_SIZE),
                        data: None,
                    };
                }
            }
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to get file metadata: {}", e),
                    data: None,
                };
            }
        }

        match fs::read_to_string(path).await {
            Ok(content) => CommandResponse {
                success: true,
                message: "File read successfully".to_string(),
                data: Some(serde_json::json!({ "content": content })),
            },
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to read file: {}", e),
                data: None,
            },
        }
    }

    async fn delete_file(&self, path: &str) -> CommandResponse {
        let path = Path::new(path);
        
        if !self.is_path_allowed(path) {
            return CommandResponse {
                success: false,
                message: "Access denied: Path not allowed".to_string(),
                data: None,
            };
        }

        // Additional safety check - don't delete directories
        match fs::metadata(path).await {
            Ok(metadata) => {
                if metadata.is_dir() {
                    return CommandResponse {
                        success: false,
                        message: "Cannot delete directories".to_string(),
                        data: None,
                    };
                }
            }
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to get file metadata: {}", e),
                    data: None,
                };
            }
        }

        match fs::remove_file(path).await {
            Ok(_) => CommandResponse {
                success: true,
                message: "File deleted successfully".to_string(),
                data: None,
            },
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to delete file: {}", e),
                data: None,
            },
        }
    }

    async fn execute_command(&self, command: &str, args: Vec<String>, working_dir: Option<String>) -> CommandResponse {
        if !self.is_command_allowed(command) {
            return CommandResponse {
                success: false,
                message: format!("Command '{}' not allowed", command),
                data: None,
            };
        }

        let mut cmd = Command::new(command);
        cmd.args(&args);

        if let Some(dir) = working_dir {
            let path = Path::new(&dir);
            if self.is_path_allowed(path) {
                cmd.current_dir(dir);
            }
        }

        match cmd.output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                CommandResponse {
                    success: output.status.success(),
                    message: if output.status.success() {
                        "Command executed successfully".to_string()
                    } else {
                        format!("Command failed with exit code: {:?}", output.status.code())
                    },
                    data: Some(serde_json::json!({
                        "stdout": stdout,
                        "stderr": stderr,
                        "exit_code": output.status.code(),
                    })),
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to execute command: {}", e),
                data: None,
            },
        }
    }

    async fn get_system_info(&self) -> CommandResponse {
        let info = serde_json::json!({
            "hostname": gethostname::gethostname().to_string_lossy(),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpu_count": sys_info::cpu_num().unwrap_or(0),
            "memory": {
                "total": sys_info::mem_info().map(|m| m.total).unwrap_or(0),
                "available": sys_info::mem_info().map(|m| m.avail).unwrap_or(0),
            },
            "load_average": sys_info::loadavg().map(|l| {
                serde_json::json!({
                    "one": l.one,
                    "five": l.five,
                    "fifteen": l.fifteen,
                })
            }).unwrap_or(serde_json::json!(null)),
            "uptime": sys_info::os_release().ok(),
        });

        CommandResponse {
            success: true,
            message: "System info retrieved".to_string(),
            data: Some(info),
        }
    }

    async fn get_process_list(&self) -> CommandResponse {
        match Command::new("ps").args(&["aux"]).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                CommandResponse {
                    success: true,
                    message: "Process list retrieved".to_string(),
                    data: Some(serde_json::json!({ "processes": stdout })),
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to get process list: {}", e),
                data: None,
            },
        }
    }

    async fn upload_file(&self, path: &str, content: &str) -> CommandResponse {
        let path = Path::new(path);
        
        if !self.is_path_allowed(path) {
            return CommandResponse {
                success: false,
                message: "Access denied: Path not allowed".to_string(),
                data: None,
            };
        }

        // Decode base64 content
        let decoded = match base64::decode(content) {
            Ok(d) => d,
            Err(e) => {
                return CommandResponse {
                    success: false,
                    message: format!("Failed to decode base64 content: {}", e),
                    data: None,
                };
            }
        };

        match fs::write(path, decoded).await {
            Ok(_) => CommandResponse {
                success: true,
                message: "File uploaded successfully".to_string(),
                data: None,
            },
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to write file: {}", e),
                data: None,
            },
        }
    }

    async fn download_file(&self, path: &str) -> CommandResponse {
        let path = Path::new(path);
        
        if !self.is_path_allowed(path) {
            return CommandResponse {
                success: false,
                message: "Access denied: Path not allowed".to_string(),
                data: None,
            };
        }

        match fs::read(path).await {
            Ok(content) => {
                let encoded = base64::encode(&content);
                CommandResponse {
                    success: true,
                    message: "File downloaded successfully".to_string(),
                    data: Some(serde_json::json!({
                        "content": encoded,
                        "size": content.len(),
                    })),
                }
            }
            Err(e) => CommandResponse {
                success: false,
                message: format!("Failed to read file: {}", e),
                data: None,
            },
        }
    }
}
