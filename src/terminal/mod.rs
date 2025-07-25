// src/terminal/mod.rs
// AeroNyx Privacy Network - Web Terminal Implementation
// Version: 1.0.1 - Thread-Safe

use portable_pty::{native_pty_system, CommandBuilder, PtySize, MasterPty, ChildKiller};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn, debug};
use std::io::{Read, Write};
use tokio::task;

/// Terminal session manager
pub struct TerminalSessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<TerminalSession>>>>,
}

/// Individual terminal session - made thread-safe
pub struct TerminalSession {
    pub session_id: String,
    pub size: Arc<Mutex<PtySize>>,
    pub created_at: std::time::Instant,
    // Use blocking tasks for PTY operations
    pty_handle: Arc<Mutex<PtyHandle>>,
}

// Internal handle for PTY operations
struct PtyHandle {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn ChildKiller + Send + Sync>,
}

// We manually implement Send + Sync for TerminalSession
unsafe impl Send for TerminalSession {}
unsafe impl Sync for TerminalSession {}

/// Terminal WebSocket message types
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum TerminalMessage {
    /// Initialize new terminal session
    #[serde(rename = "term_init")]
    Init {
        session_id: String,
        rows: u16,
        cols: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        env: Option<HashMap<String, String>>,
    },
    
    /// Terminal input from client
    #[serde(rename = "term_input")]
    Input {
        session_id: String,
        data: String, // Base64 encoded
    },
    
    /// Terminal output to client
    #[serde(rename = "term_output")]
    Output {
        session_id: String,
        data: String, // Base64 encoded
    },
    
    /// Resize terminal
    #[serde(rename = "term_resize")]
    Resize {
        session_id: String,
        rows: u16,
        cols: u16,
    },
    
    /// Close terminal session
    #[serde(rename = "term_close")]
    Close {
        session_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    
    /// Terminal session started successfully
    #[serde(rename = "term_ready")]
    Ready {
        session_id: String,
    },
    
    /// Error occurred
    #[serde(rename = "term_error")]
    Error {
        session_id: String,
        error: String,
    },
}

impl TerminalSessionManager {
    /// Create a new terminal session manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create a new terminal session
    pub async fn create_session(
        &self,
        session_id: String,
        rows: u16,
        cols: u16,
        cwd: Option<String>,
        env: Option<HashMap<String, String>>,
    ) -> Result<(), String> {
        info!("Creating new terminal session: {}", session_id);
        
        // Validate parameters
        if rows < 10 || rows > 200 {
            return Err("Invalid rows: must be between 10 and 200".to_string());
        }
        if cols < 40 || cols > 400 {
            return Err("Invalid cols: must be between 40 and 400".to_string());
        }
        
        // Check session limit
        {
            let sessions = self.sessions.read().await;
            if sessions.len() >= 10 {
                return Err("Session limit exceeded".to_string());
            }
            if sessions.contains_key(&session_id) {
                return Err("Session already exists".to_string());
            }
        }
        
        // Validate working directory
        if let Some(ref cwd_path) = cwd {
            if !std::path::Path::new(cwd_path).exists() {
                return Err(format!("Working directory does not exist: {}", cwd_path));
            }
        }
        
        // Create PTY in blocking task
        let session_id_clone = session_id.clone();
        let pty_result = task::spawn_blocking(move || {
            // Get PTY system
            let pty_system = native_pty_system();
            
            // Create PTY pair with specified size
            let pty_size = PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            };
            
            let pair = pty_system
                .openpty(pty_size)
                .map_err(|e| format!("Failed to create PTY: {}", e))?;
            
            // Configure command
            let mut cmd = CommandBuilder::new(
                std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string())
            );
            cmd.arg("-l"); // Login shell
            
            // Set working directory if specified
            if let Some(cwd) = cwd {
                cmd.cwd(cwd);
            }
            
            // Set environment variables
            if let Some(env_vars) = env {
                for (key, value) in env_vars {
                    cmd.env(key, value);
                }
            }
            
            // Set some default environment variables
            cmd.env("TERM", "xterm-256color");
            cmd.env("COLORTERM", "truecolor");
            
            // Spawn the shell
            let child = pair.slave
                .spawn_command(cmd)
                .map_err(|e| format!("Failed to spawn shell: {}", e))?;
            
            Ok::<(Box<dyn MasterPty + Send>, Box<dyn ChildKiller + Send + Sync>, PtySize), String>((
                pair.master,
                child,
                pty_size,
            ))
        }).await.map_err(|e| format!("Failed to create PTY task: {}", e))??;
        
        let (master, child, pty_size) = pty_result;
        
        // Create session
        let session = Arc::new(TerminalSession {
            session_id: session_id.clone(),
            size: Arc::new(Mutex::new(pty_size)),
            created_at: std::time::Instant::now(),
            pty_handle: Arc::new(Mutex::new(PtyHandle {
                master,
                child,
            })),
        });
        
        // Store session
        self.sessions.write().await.insert(session_id.clone(), session);
        
        info!("Terminal session created successfully: {}", session_id);
        Ok(())
    }
    
    /// Write input to terminal
    pub async fn write_to_terminal(
        &self,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        let session_clone = session.clone();
        let data = data.to_vec();
        
        // Write in blocking task
        task::spawn_blocking(move || {
            let handle = session_clone.pty_handle.blocking_lock();
            let master = &handle.master;
            
            // Get writer from master
            let mut writer = master.take_writer()
                .map_err(|e| format!("Failed to get writer: {}", e))?;
            
            writer.write_all(&data)
                .map_err(|e| format!("Failed to write to terminal: {}", e))?;
            writer.flush()
                .map_err(|e| format!("Failed to flush terminal: {}", e))?;
            
            Ok::<(), String>(())
        }).await.map_err(|e| format!("Failed to write task: {}", e))??;
        
        Ok(())
    }
    
    /// Read output from terminal (non-blocking)
    pub async fn read_from_terminal(
        &self,
        session_id: &str,
        buffer_size: usize,
    ) -> Result<Vec<u8>, String> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        let session_clone = session.clone();
        
        // Read in blocking task
        task::spawn_blocking(move || {
            let handle = session_clone.pty_handle.blocking_lock();
            let master = &handle.master;
            
            // Get reader from master
            let mut reader = master.try_clone_reader()
                .map_err(|e| format!("Failed to get reader: {}", e))?;
            
            let mut buffer = vec![0u8; buffer_size];
            
            // Set non-blocking mode
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                use nix::fcntl::{fcntl, FcntlArg, OFlag};
                
                let fd = reader.as_raw_fd();
                let flags = fcntl(fd, FcntlArg::F_GETFL)
                    .map_err(|e| format!("Failed to get flags: {}", e))?;
                fcntl(fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK))
                    .map_err(|e| format!("Failed to set non-blocking: {}", e))?;
            }
            
            // Try to read
            match reader.read(&mut buffer) {
                Ok(n) => {
                    buffer.truncate(n);
                    Ok(buffer)
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available
                    Ok(vec![])
                }
                Err(e) => Err(format!("Failed to read from terminal: {}", e)),
            }
        }).await.map_err(|e| format!("Failed to read task: {}", e))?
    }
    
    /// Resize terminal
    pub async fn resize_terminal(
        &self,
        session_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<(), String> {
        // Validate parameters
        if rows < 10 || rows > 200 {
            return Err("Invalid rows: must be between 10 and 200".to_string());
        }
        if cols < 40 || cols > 400 {
            return Err("Invalid cols: must be between 40 and 400".to_string());
        }
        
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        let new_size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        
        let session_clone = session.clone();
        
        // Resize in blocking task
        task::spawn_blocking(move || {
            let handle = session_clone.pty_handle.blocking_lock();
            handle.master
                .resize(new_size)
                .map_err(|e| format!("Failed to resize terminal: {}", e))?;
            Ok::<(), String>(())
        }).await.map_err(|e| format!("Failed to resize task: {}", e))??;
        
        // Update size
        let mut size = session.size.lock().await;
        *size = new_size;
        
        debug!("Terminal {} resized to {}x{}", session_id, cols, rows);
        Ok(())
    }
    
    /// Close terminal session
    pub async fn close_session(&self, session_id: &str) -> Result<(), String> {
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };
        
        if let Some(session) = session {
            // Kill the child process in blocking task
            let session_clone = session.clone();
            task::spawn_blocking(move || {
                let mut handle = session_clone.pty_handle.blocking_lock();
                if let Err(e) = handle.child.kill() {
                    warn!("Failed to kill terminal process: {}", e);
                }
            }).await.ok();
            
            info!("Terminal session closed: {}", session_id);
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }
    
    /// Clean up stale sessions
    pub async fn cleanup_stale_sessions(&self, max_age: std::time::Duration) {
        let sessions_to_remove = {
            let sessions = self.sessions.read().await;
            let now = std::time::Instant::now();
            
            sessions
                .iter()
                .filter(|(_, session)| now.duration_since(session.created_at) > max_age)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        };
        
        for session_id in sessions_to_remove {
            if let Err(e) = self.close_session(&session_id).await {
                warn!("Failed to close stale session {}: {}", session_id, e);
            } else {
                info!("Cleaned up stale terminal session: {}", session_id);
            }
        }
    }
    
    /// Get session count
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
    
    /// Check if session exists
    pub async fn has_session(&self, session_id: &str) -> bool {
        self.sessions.read().await.contains_key(session_id)
    }
}

/// Handle terminal WebSocket messages
pub async fn handle_terminal_message(
    manager: &Arc<TerminalSessionManager>,
    message: TerminalMessage,
) -> Result<Option<TerminalMessage>, String> {
    match message {
        TerminalMessage::Init { session_id, rows, cols, cwd, env } => {
            match manager.create_session(session_id.clone(), rows, cols, cwd, env).await {
                Ok(()) => Ok(Some(TerminalMessage::Ready { session_id })),
                Err(e) => Ok(Some(TerminalMessage::Error { session_id, error: e }))
            }
        }
        
        TerminalMessage::Input { session_id, data } => {
            // Decode base64 input
            let decoded = base64::decode(&data)
                .map_err(|e| format!("Failed to decode input: {}", e))?;
            
            // Check input size
            if decoded.len() > 4096 {
                return Ok(Some(TerminalMessage::Error {
                    session_id,
                    error: "Input too large (max 4096 bytes)".to_string()
                }));
            }
            
            match manager.write_to_terminal(&session_id, &decoded).await {
                Ok(()) => Ok(None),
                Err(e) => Ok(Some(TerminalMessage::Error { session_id, error: e }))
            }
        }
        
        TerminalMessage::Resize { session_id, rows, cols } => {
            match manager.resize_terminal(&session_id, rows, cols).await {
                Ok(()) => Ok(None),
                Err(e) => Ok(Some(TerminalMessage::Error { session_id, error: e }))
            }
        }
        
        TerminalMessage::Close { session_id, .. } => {
            match manager.close_session(&session_id).await {
                Ok(()) => Ok(None),
                Err(e) => Ok(Some(TerminalMessage::Error { session_id, error: e }))
            }
        }
        
        _ => Err("Unexpected message type".to_string()),
    }
}

/// Terminal output reader task
pub async fn terminal_output_reader(
    manager: Arc<TerminalSessionManager>,
    session_id: String,
    tx: tokio::sync::mpsc::Sender<TerminalMessage>,
) {
    info!("Starting output reader for terminal session: {}", session_id);
    
    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;
    let mut buffer = Vec::with_capacity(4096);
    let mut last_send = std::time::Instant::now();
    
    loop {
        // Small delay to prevent busy-waiting
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Check if session still exists
        if !manager.has_session(&session_id).await {
            info!("Session {} no longer exists, stopping output reader", session_id);
            break;
        }
        
        match manager.read_from_terminal(&session_id, 4096).await {
            Ok(data) => {
                if !data.is_empty() {
                    consecutive_errors = 0;
                    buffer.extend_from_slice(&data);
                    
                    // Send if buffer is large enough or timeout
                    let should_send = buffer.len() >= 4096 ||
                        last_send.elapsed() > tokio::time::Duration::from_millis(50) ||
                        buffer.contains(&b'\n');
                    
                    if should_send && !buffer.is_empty() {
                        // Split into chunks if too large
                        for chunk in buffer.chunks(1024 * 1024) { // 1MB chunks
                            let encoded = base64::encode(chunk);
                            let message = TerminalMessage::Output {
                                session_id: session_id.clone(),
                                data: encoded,
                            };
                            
                            if tx.send(message).await.is_err() {
                                error!("Failed to send terminal output - channel closed");
                                break;
                            }
                        }
                        
                        buffer.clear();
                        last_send = std::time::Instant::now();
                    }
                }
            }
            Err(e) => {
                // Check if it's a "session not found" error
                if e.contains("Session not found") {
                    info!("Session {} ended", session_id);
                    
                    // Send any remaining buffered data
                    if !buffer.is_empty() {
                        let encoded = base64::encode(&buffer);
                        let _ = tx.send(TerminalMessage::Output {
                            session_id: session_id.clone(),
                            data: encoded,
                        }).await;
                    }
                    
                    // Send process exit message
                    let _ = tx.send(TerminalMessage::Error {
                        session_id: session_id.clone(),
                        error: "Process exited".to_string(),
                    }).await;
                    
                    break;
                }
                
                consecutive_errors += 1;
                
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    error!("Too many consecutive errors reading terminal output: {}", e);
                    
                    // Send error message
                    let _ = tx.send(TerminalMessage::Error {
                        session_id: session_id.clone(),
                        error: format!("Terminal read error: {}", e),
                    }).await;
                    
                    break;
                }
                
                // Brief pause before retry
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
        
        // Send buffered data after timeout
        if !buffer.is_empty() && last_send.elapsed() > tokio::time::Duration::from_millis(50) {
            let encoded = base64::encode(&buffer);
            let message = TerminalMessage::Output {
                session_id: session_id.clone(),
                data: encoded,
            };
            
            if tx.send(message).await.is_err() {
                error!("Failed to send terminal output - channel closed");
                break;
            }
            
            buffer.clear();
            last_send = std::time::Instant::now();
        }
    }
    
    info!("Output reader stopped for terminal session: {}", session_id);
}
