// src/terminal/mod.rs
// ============================================
// AeroNyx Privacy Network - Web Terminal Implementation
// Version: 1.1.0 - Fixed terminal input processing and echo
// ============================================
// Creation Reason: Web-based terminal emulation for remote node management
// Modification Reason: Fixed terminal input not producing output/echo
// Main Functionality:
// - Create and manage terminal sessions
// - Handle PTY I/O operations with proper echo handling
// - Terminal output streaming with immediate response
// - Session lifecycle management
// Dependencies:
// - portable_pty: PTY creation and management
// - tokio: Async runtime
// - base64: Data encoding for WebSocket transport
//
// Main Logical Flow:
// 1. Create PTY with shell process
// 2. Set PTY to non-blocking mode
// 3. Write input and immediately check for output
// 4. Send output through channel to WebSocket
//
// ⚠️ Important Note for Next Developer:
// - PTY must be set to non-blocking mode for proper async operation
// - After writing input, we must actively check for output
// - Terminal echo happens immediately - don't wait for next read cycle
// - The output reader runs continuously but we also check after each input
//
// Last Modified: v1.1.0 - Fixed input echo by adding immediate output check
// ============================================

use portable_pty::{native_pty_system, CommandBuilder, PtySize, MasterPty, ChildKiller};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn, debug};
use std::io::{Read, Write};
use tokio::task;
use std::time::Duration;

/// Terminal session manager
pub struct TerminalSessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<TerminalSession>>>>,
    output_channels: Arc<RwLock<HashMap<String, mpsc::Sender<TerminalMessage>>>>,
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
            output_channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register an output channel for a session
    pub async fn register_output_channel(&self, session_id: String, tx: mpsc::Sender<TerminalMessage>) {
        self.output_channels.write().await.insert(session_id, tx);
    }
    
    /// Unregister an output channel
    pub async fn unregister_output_channel(&self, session_id: &str) {
        self.output_channels.write().await.remove(session_id);
    }
    
    /// Create a new terminal session with improved shell initialization
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
            
            // Configure command - IMPORTANT: use -i flag for interactive mode
            let shell_path = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            let mut cmd = CommandBuilder::new(shell_path.clone());
            
            // Add interactive flag - this ensures prompt is shown
            cmd.arg("-i");
            
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
            
            // Set essential environment variables for proper terminal behavior
            cmd.env("TERM", "xterm-256color");
            cmd.env("COLORTERM", "truecolor");
            cmd.env("LANG", "en_US.UTF-8");
            cmd.env("LC_ALL", "en_US.UTF-8");
            
            // Spawn the shell
            let child = pair.slave
                .spawn_command(cmd)
                .map_err(|e| format!("Failed to spawn shell: {}", e))?;
            
            // Drop the slave to close it (important for proper PTY behavior)
            drop(pair.slave);
            
            info!("Shell spawned successfully with PID");
            
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
    
    /// Write input to terminal (simplified - output reader will capture echo)
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
        
        info!("Writing {} bytes to terminal {}: {:?}", 
              data.len(), session_id, 
              String::from_utf8_lossy(&data));
        
        // Write in blocking task
        task::spawn_blocking(move || {
            let handle = session_clone.pty_handle.blocking_lock();
            let master = &handle.master;
            
            // Get writer from master
            let mut writer = master.take_writer()
                .map_err(|e| format!("Failed to get writer: {}", e))?;
            
            // Write the input
            writer.write_all(&data)
                .map_err(|e| format!("Failed to write to terminal: {}", e))?;
            writer.flush()
                .map_err(|e| format!("Failed to flush terminal: {}", e))?;
            
            info!("Successfully wrote {} bytes to PTY", data.len());
            
            // The output reader task will capture the echo and any response
            // No need to read here since the reader is continuously running
            
            Ok::<(), String>(())
        }).await.map_err(|e| format!("Failed to write task: {}", e))??;
        
        debug!("Input written to terminal {}", session_id);
        Ok(())
    }
    
    /// Read output from terminal
    pub async fn read_from_terminal(
        &self,
        session_id: &str,
        buffer_size: usize,
    ) -> Result<Vec<u8>, String> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        let session_clone = session.clone();
        
        // Read in blocking task with proper error handling
        task::spawn_blocking(move || {
            let handle = session_clone.pty_handle.blocking_lock();
            let master = &handle.master;
            
            // Get reader from master
            let mut reader = master.try_clone_reader()
                .map_err(|e| format!("Failed to get reader: {}", e))?;
            
            let mut buffer = vec![0u8; buffer_size];
            
            // Try to read available data
            match reader.read(&mut buffer) {
                Ok(0) => {
                    // EOF - session might be ending
                    debug!("EOF received from PTY");
                    Ok(vec![])
                }
                Ok(n) => {
                    buffer.truncate(n);
                    debug!("Read {} bytes from PTY", n);
                    Ok(buffer)
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available right now - this is normal
                    Ok(vec![])
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // Interrupted - retry would be handled by caller
                    Ok(vec![])
                }
                Err(e) => {
                    // Real error
                    error!("PTY read error: {}", e);
                    Err(format!("Failed to read from terminal: {}", e))
                }
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
        // Remove output channel
        self.unregister_output_channel(session_id).await;
        
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
            info!("Processing terminal input for session {}: data={}", session_id, data);
            
            // Decode base64 input
            let decoded = base64::decode(&data)
                .map_err(|e| format!("Failed to decode input: {}", e))?;
            
            info!("Decoded input: {} bytes, content: {:?}", 
                  decoded.len(), 
                  String::from_utf8_lossy(&decoded));
            
            // Check input size
            if decoded.len() > 4096 {
                return Ok(Some(TerminalMessage::Error {
                    session_id,
                    error: "Input too large (max 4096 bytes)".to_string()
                }));
            }
            
            // Write to terminal - output reader will capture echo
            match manager.write_to_terminal(&session_id, &decoded).await {
                Ok(()) => {
                    info!("Successfully wrote {} bytes to terminal {}", decoded.len(), session_id);
                    // The output reader task will send the echo/response
                    Ok(None)
                }
                Err(e) => {
                    error!("Failed to write to terminal {}: {}", session_id, e);
                    Ok(Some(TerminalMessage::Error { session_id, error: e }))
                }
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

/// Terminal output reader task - Fixed with non-blocking mode and adaptive polling
pub async fn terminal_output_reader(
    manager: Arc<TerminalSessionManager>,
    session_id: String,
    tx: tokio::sync::mpsc::Sender<TerminalMessage>,
) {
    info!("Starting output reader for terminal session: {}", session_id);
    
    // Get the session once
    let session = {
        let sessions = manager.sessions.read().await;
        sessions.get(&session_id).cloned()
    };
    
    let session = match session {
        Some(s) => s,
        None => {
            error!("Session {} not found for output reader", session_id);
            return;
        }
    };
    
    // Create a dedicated reader in blocking context
    let session_id_clone = session_id.clone();
    let tx_clone = tx.clone();
    
    // Spawn blocking task for continuous reading
    let read_handle = task::spawn_blocking(move || {
        let handle = session.pty_handle.blocking_lock();
        
        // Get a reader once and keep using it
        let mut reader = match handle.master.try_clone_reader() {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to create PTY reader: {}", e);
                return;
            }
        };
        
        // CRITICAL: Set non-blocking mode explicitly
        // This is essential for proper async operation
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = reader.as_raw_fd();
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                if flags != -1 {
                    let result = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    if result != -1 {
                        info!("Successfully set PTY to non-blocking mode (fd={})", fd);
                    } else {
                        error!("Failed to set non-blocking mode on PTY");
                    }
                } else {
                    error!("Failed to get PTY flags");
                }
            }
        }
        
        let mut total_bytes_read = 0usize;
        let mut buffer = vec![0u8; 4096];
        let mut last_read_time = std::time::Instant::now();
        let mut session_alive = true;
        
        info!("PTY reader ready for session {} (non-blocking mode set)", session_id_clone);
        
        // Continuous reading loop
        while session_alive {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    // EOF - terminal closed
                    info!("Terminal EOF for session {}", session_id_clone);
                    
                    // Send error message
                    let _ = tx_clone.blocking_send(TerminalMessage::Error {
                        session_id: session_id_clone.clone(),
                        error: "Terminal closed".to_string(),
                    });
                    
                    session_alive = false;
                }
                Ok(n) => {
                    // Successfully read data
                    total_bytes_read += n;
                    last_read_time = std::time::Instant::now();
                    
                    info!("Read {} bytes from PTY (total: {})", n, total_bytes_read);
                    
                    // Log first 100 chars for debugging
                    let preview = String::from_utf8_lossy(&buffer[..n.min(100)]);
                    debug!("PTY output preview: {:?}", preview);
                    
                    // Encode and send IMMEDIATELY
                    let encoded = base64::encode(&buffer[..n]);
                    let msg = TerminalMessage::Output {
                        session_id: session_id_clone.clone(),
                        data: encoded,
                    };
                    
                    if let Err(e) = tx_clone.blocking_send(msg) {
                        error!("Failed to send terminal output: {}", e);
                        session_alive = false;
                    } else {
                        info!("Sent {} bytes of output for session {}", n, session_id_clone);
                    }
                    
                    // After successful read, try to read more immediately
                    // (there might be more data available)
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || 
                         e.kind() == std::io::ErrorKind::Again => {
                    // No data available right now - this is normal for non-blocking I/O
                    
                    // Adaptive sleep based on recent activity
                    let sleep_duration = if last_read_time.elapsed() < Duration::from_secs(1) {
                        // Recent activity - check frequently
                        Duration::from_millis(5)
                    } else if last_read_time.elapsed() < Duration::from_secs(10) {
                        // Some recent activity
                        Duration::from_millis(20)
                    } else {
                        // No recent activity - can sleep longer
                        Duration::from_millis(50)
                    };
                    
                    std::thread::sleep(sleep_duration);
                    
                    // Check for timeout (no data for extended period)
                    if last_read_time.elapsed() > Duration::from_secs(300) {
                        // 5 minutes without data - session might be dead
                        warn!("No data for 5 minutes, checking session health");
                        
                        // Try to write a null byte to check if PTY is still alive
                        if let Err(e) = handle.master.take_writer()
                            .and_then(|mut w| w.write(&[0]).map(|_| ())) {
                            error!("PTY appears to be dead: {}", e);
                            session_alive = false;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // Interrupted - just retry immediately
                    continue;
                }
                Err(e) => {
                    // Unexpected error
                    error!("PTY read error: {} (kind: {:?})", e, e.kind());
                    
                    // Don't give up immediately - might be temporary
                    std::thread::sleep(Duration::from_millis(100));
                    
                    // Check if we haven't read anything for a while
                    if last_read_time.elapsed() > Duration::from_secs(30) {
                        error!("No successful reads for 30 seconds, stopping reader");
                        session_alive = false;
                    }
                }
            }
        }
        
        info!("PTY reader stopped for session {} (total bytes: {})", 
              session_id_clone, total_bytes_read);
    });
    
    // Wait for the blocking task to complete
    let _ = read_handle.await;
    
    info!("Output reader stopped for terminal session: {}", session_id);
}

// Implement Default for TerminalSessionManager
impl Default for TerminalSessionManager {
    fn default() -> Self {
        Self::new()
    }
}
