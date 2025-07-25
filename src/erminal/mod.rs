// src/terminal/mod.rs
// AeroNyx Privacy Network - Web Terminal Implementation
// Version: 1.0.0

use portable_pty::{native_pty_system, CommandBuilder, PtySize, MasterPty, ChildKiller};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn, debug};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::{Read, Write};

/// Terminal session manager
pub struct TerminalSessionManager {
    sessions: Arc<RwLock<HashMap<String, TerminalSession>>>,
}

/// Individual terminal session
pub struct TerminalSession {
    pub session_id: String,
    pub pty_master: Box<dyn MasterPty + Send>,
    pub child: Box<dyn ChildKiller + Send + Sync>,
    pub size: PtySize,
    pub created_at: std::time::Instant,
    reader: Arc<Mutex<Box<dyn Read + Send>>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
}

/// Terminal WebSocket message types
#[derive(Debug, Serialize, Deserialize)]
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
        let mut cmd = CommandBuilder::new("bash");
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
        
        // Get reader and writer
        let reader = pair.master
            .try_clone_reader()
            .map_err(|e| format!("Failed to clone reader: {}", e))?;
        
        let writer = pair.master
            .try_clone_writer()
            .map_err(|e| format!("Failed to clone writer: {}", e))?;
        
        // Create session
        let session = TerminalSession {
            session_id: session_id.clone(),
            pty_master: pair.master,
            child,
            size: pty_size,
            created_at: std::time::Instant::now(),
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
        };
        
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
        
        let mut writer = session.writer.lock().await;
        writer.write_all(data)
            .map_err(|e| format!("Failed to write to terminal: {}", e))?;
        writer.flush()
            .map_err(|e| format!("Failed to flush terminal: {}", e))?;
        
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
        
        let mut reader = session.reader.lock().await;
        let mut buffer = vec![0u8; buffer_size];
        
        // Use non-blocking read
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
    }
    
    /// Resize terminal
    pub async fn resize_terminal(
        &self,
        session_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        let new_size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        
        session.pty_master
            .resize(new_size)
            .map_err(|e| format!("Failed to resize terminal: {}", e))?;
        
        session.size = new_size;
        
        debug!("Terminal {} resized to {}x{}", session_id, cols, rows);
        Ok(())
    }
    
    /// Close terminal session
    pub async fn close_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(mut session) = sessions.remove(session_id) {
            // Kill the child process
            if let Err(e) = session.child.kill() {
                warn!("Failed to kill terminal process: {}", e);
            }
            
            info!("Terminal session closed: {}", session_id);
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }
    
    /// Clean up stale sessions
    pub async fn cleanup_stale_sessions(&self, max_age: std::time::Duration) {
        let mut sessions = self.sessions.write().await;
        let now = std::time::Instant::now();
        
        let stale_sessions: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.created_at) > max_age)
            .map(|(id, _)| id.clone())
            .collect();
        
        for session_id in stale_sessions {
            if let Some(mut session) = sessions.remove(&session_id) {
                if let Err(e) = session.child.kill() {
                    warn!("Failed to kill stale terminal process: {}", e);
                }
                info!("Cleaned up stale terminal session: {}", session_id);
            }
        }
    }
    
    /// Get session count
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

/// Handle terminal WebSocket messages
pub async fn handle_terminal_message(
    manager: &TerminalSessionManager,
    message: TerminalMessage,
) -> Result<Option<TerminalMessage>, String> {
    match message {
        TerminalMessage::Init { session_id, rows, cols, cwd, env } => {
            manager.create_session(session_id.clone(), rows, cols, cwd, env).await?;
            Ok(Some(TerminalMessage::Ready { session_id }))
        }
        
        TerminalMessage::Input { session_id, data } => {
            // Decode base64 input
            let decoded = base64::decode(&data)
                .map_err(|e| format!("Failed to decode input: {}", e))?;
            
            manager.write_to_terminal(&session_id, &decoded).await?;
            Ok(None) // No immediate response
        }
        
        TerminalMessage::Resize { session_id, rows, cols } => {
            manager.resize_terminal(&session_id, rows, cols).await?;
            Ok(None)
        }
        
        TerminalMessage::Close { session_id, .. } => {
            manager.close_session(&session_id).await?;
            Ok(None)
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
    
    loop {
        // Small delay to prevent busy-waiting
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        match manager.read_from_terminal(&session_id, 4096).await {
            Ok(data) => {
                if !data.is_empty() {
                    consecutive_errors = 0; // Reset error counter
                    
                    let encoded = base64::encode(&data);
                    let message = TerminalMessage::Output {
                        session_id: session_id.clone(),
                        data: encoded,
                    };
                    
                    if tx.send(message).await.is_err() {
                        error!("Failed to send terminal output - channel closed");
                        break;
                    }
                }
            }
            Err(e) => {
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
    }
    
    info!("Output reader stopped for terminal session: {}", session_id);
    
    // Clean up the session
    if let Err(e) = manager.close_session(&session_id).await {
        error!("Failed to close terminal session {}: {}", session_id, e);
    }
}
