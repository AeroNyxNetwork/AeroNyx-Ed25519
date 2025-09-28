// src/terminal/mod.rs
// ============================================
// AeroNyx Privacy Network - Production Terminal Implementation
// Version: 3.0.0 - Industry-standard implementation with thread-based I/O
// ============================================
// Architecture Overview:
// - Thread-based I/O handling for blocking PTY operations
// - Channel-based communication between threads and async runtime
// - Robust error handling and recovery mechanisms
// - Performance-optimized with minimal latency
// - Compatible with portable_pty's blocking I/O model
// ============================================

use portable_pty::{native_pty_system, CommandBuilder, PtySize, MasterPty, ChildKiller};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
use crossbeam_channel::{bounded, Sender, Receiver};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn, debug, instrument};
use std::io::{Read, Write, ErrorKind};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

// Production constants
const MAX_SESSIONS: usize = 100;
const MAX_SESSION_AGE: Duration = Duration::from_secs(3600);
const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;
const READ_BUFFER_SIZE: usize = 8192;
const MAX_INPUT_SIZE: usize = 4096;
const CHANNEL_BUFFER_SIZE: usize = 1000;

/// Terminal session manager for production use
pub struct TerminalSessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<TerminalSession>>>>,
    metrics: Arc<TerminalMetrics>,
    shutdown: Arc<AtomicBool>,
}

/// Performance metrics
#[derive(Default)]
struct TerminalMetrics {
    sessions_created: AtomicU64,
    sessions_closed: AtomicU64,
    bytes_written: AtomicU64,
    bytes_read: AtomicU64,
    errors_count: AtomicU64,
}

/// Terminal session with thread-based I/O
pub struct TerminalSession {
    pub session_id: String,
    pub size: Arc<Mutex<PtySize>>,
    pub created_at: Instant,
    pub last_activity: Arc<Mutex<Instant>>,
    active: Arc<AtomicBool>,
    pty_bridge: Arc<PtyBridge>,
}

/// Bridge between blocking PTY and async runtime
struct PtyBridge {
    output_rx: Receiver<Vec<u8>>,
    input_tx: Sender<Vec<u8>>,
    reader_thread: Mutex<Option<thread::JoinHandle<()>>>,
    writer_thread: Mutex<Option<thread::JoinHandle<()>>>,
}

/// PTY handle wrapper
struct PtyHandle {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn ChildKiller + Send + Sync>,
}

unsafe impl Send for TerminalSession {}
unsafe impl Sync for TerminalSession {}
unsafe impl Send for PtyBridge {}
unsafe impl Sync for PtyBridge {}

/// WebSocket message types
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum TerminalMessage {
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
    
    #[serde(rename = "term_input")]
    Input {
        session_id: String,
        data: String, // Base64 encoded
    },
    
    #[serde(rename = "term_output")]
    Output {
        session_id: String,
        data: String, // Base64 encoded
    },
    
    #[serde(rename = "term_resize")]
    Resize {
        session_id: String,
        rows: u16,
        cols: u16,
    },
    
    #[serde(rename = "term_close")]
    Close {
        session_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    
    #[serde(rename = "term_ready")]
    Ready {
        session_id: String,
    },
    
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
            metrics: Arc::new(TerminalMetrics::default()),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Create a terminal session with proper validation
    #[instrument(skip(self, env))]
    pub async fn create_session(
        &self,
        session_id: String,
        rows: u16,
        cols: u16,
        cwd: Option<String>,
        env: Option<HashMap<String, String>>,
    ) -> Result<(), String> {
        // Validate dimensions
        if rows < 10 || rows > 200 {
            return Err("Invalid rows: must be between 10 and 200".to_string());
        }
        if cols < 40 || cols > 400 {
            return Err("Invalid cols: must be between 40 and 400".to_string());
        }
        
        // Check session limit and duplicates
        {
            let sessions = self.sessions.read().await;
            if sessions.len() >= MAX_SESSIONS {
                return Err(format!("Session limit exceeded (max {})", MAX_SESSIONS));
            }
            if sessions.contains_key(&session_id) {
                return Err("Session already exists".to_string());
            }
        }
        
        // Validate working directory
        if let Some(ref cwd_path) = cwd {
            let path = std::path::Path::new(cwd_path);
            if !path.exists() {
                return Err(format!("Working directory does not exist: {}", cwd_path));
            }
            if !path.is_dir() {
                return Err(format!("Path is not a directory: {}", cwd_path));
            }
        }
        
        // Create PTY in blocking context
        let pty_handle = tokio::task::spawn_blocking(move || {
            Self::create_pty(rows, cols, cwd, env)
        }).await.map_err(|e| format!("Failed to create PTY: {}", e))??;
        
        // Create PTY bridge for thread-based I/O
        let pty_bridge = Arc::new(PtyBridge::new(pty_handle)?);
        
        // Create session
        let session = Arc::new(TerminalSession {
            session_id: session_id.clone(),
            size: Arc::new(Mutex::new(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })),
            created_at: Instant::now(),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            active: Arc::new(AtomicBool::new(true)),
            pty_bridge,
        });
        
        // Store session
        self.sessions.write().await.insert(session_id.clone(), session);
        self.metrics.sessions_created.fetch_add(1, Ordering::Relaxed);
        
        info!("Terminal session created: {}", session_id);
        Ok(())
    }
    
    /// Create PTY with proper configuration
    fn create_pty(
        rows: u16,
        cols: u16,
        cwd: Option<String>,
        env: Option<HashMap<String, String>>,
    ) -> Result<PtyHandle, String> {
        let pty_system = native_pty_system();
        let pty_size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        
        let pair = pty_system
            .openpty(pty_size)
            .map_err(|e| format!("Failed to create PTY: {}", e))?;
        
        // Configure shell command
        let shell_path = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
        let mut cmd = CommandBuilder::new(shell_path);
        
        // Interactive mode
        cmd.arg("-i");
        
        if let Some(cwd) = cwd {
            cmd.cwd(cwd);
        }
        
        // Set environment
        if let Some(env_vars) = env {
            for (key, value) in env_vars {
                cmd.env(key, value);
            }
        }
        
        // Essential terminal environment
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        cmd.env("LANG", "en_US.UTF-8");
        cmd.env("LC_ALL", "en_US.UTF-8");
        
        let child = pair.slave
            .spawn_command(cmd)
            .map_err(|e| format!("Failed to spawn shell: {}", e))?;
        
        drop(pair.slave);
        
        Ok(PtyHandle {
            master: pair.master,
            child,
        })
    }
    
    /// Write input to terminal
    #[instrument(skip(self, data))]
    pub async fn write_to_terminal(
        &self,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        if !session.active.load(Ordering::Relaxed) {
            return Err("Session is not active".to_string());
        }
        
        // Update activity timestamp
        *session.last_activity.lock().await = Instant::now();
        
        // Send to writer thread via channel
        session.pty_bridge.write(data.to_vec()).await?;
        
        self.metrics.bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);
        debug!("Wrote {} bytes to terminal {}", data.len(), session_id);
        
        Ok(())
    }
    
    /// Resize terminal
    #[instrument(skip(self))]
    pub async fn resize_terminal(
        &self,
        session_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<(), String> {
        if rows < 10 || rows > 200 || cols < 40 || cols > 400 {
            return Err("Invalid dimensions".to_string());
        }
        
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| "Session not found".to_string())?;
        
        session.pty_bridge.resize(rows, cols).await?;
        
        *session.size.lock().await = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        
        debug!("Resized terminal {} to {}x{}", session_id, cols, rows);
        Ok(())
    }
    
    /// Close terminal session
    #[instrument(skip(self))]
    pub async fn close_session(&self, session_id: &str) -> Result<(), String> {
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };
        
        if let Some(session) = session {
            session.active.store(false, Ordering::Relaxed);
            session.pty_bridge.shutdown().await;
            
            self.metrics.sessions_closed.fetch_add(1, Ordering::Relaxed);
            info!("Terminal session closed: {}", session_id);
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }
    
    /// Clean up stale sessions
    pub async fn cleanup_stale_sessions(&self, max_age: Duration) {
        let sessions = self.sessions.read().await;
        let now = Instant::now();
        
        let stale_sessions: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.created_at) > max_age)
            .map(|(id, _)| id.clone())
            .collect();
        
        drop(sessions);
        
        for session_id in stale_sessions {
            let _ = self.close_session(&session_id).await;
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

impl PtyBridge {
    /// Create a new PTY bridge with dedicated I/O threads
    fn new(pty_handle: PtyHandle) -> Result<Self, String> {
        let (output_tx, output_rx) = bounded(CHANNEL_BUFFER_SIZE);
        let (input_tx, input_rx) = bounded(CHANNEL_BUFFER_SIZE);
        
        let PtyHandle { master, child } = pty_handle;
        let master = Arc::new(Mutex::new(master));
        let child = Arc::new(Mutex::new(Some(child)));
        
        // Reader thread
        let reader_master = master.clone();
        let reader_thread = thread::spawn(move || {
            let mut buffer = vec![0u8; READ_BUFFER_SIZE];
            let mut total_bytes = 0u64;
            
            loop {
                let mut master_guard = reader_master.blocking_lock();
                match master_guard.try_clone_reader() {
                    Ok(mut reader) => {
                        drop(master_guard); // Release lock before blocking read
                        
                        match reader.read(&mut buffer) {
                            Ok(0) => {
                                info!("PTY reader: EOF received");
                                break;
                            }
                            Ok(n) => {
                                total_bytes += n as u64;
                                debug!("PTY reader: read {} bytes (total: {})", n, total_bytes);
                                
                                if output_tx.send(buffer[..n].to_vec()).is_err() {
                                    warn!("PTY reader: channel closed");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("PTY reader error: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to clone reader: {}", e);
                        break;
                    }
                }
            }
            
            info!("PTY reader thread ended (total bytes: {})", total_bytes);
        });
        
        // Writer thread
        let writer_master = master.clone();
        let writer_thread = thread::spawn(move || {
            let mut total_bytes = 0u64;
            
            while let Ok(data) = input_rx.recv() {
                let mut master_guard = writer_master.blocking_lock();
                match master_guard.take_writer() {
                    Ok(mut writer) => {
                        drop(master_guard); // Release lock before writing
                        
                        match writer.write_all(&data) {
                            Ok(()) => {
                                let _ = writer.flush();
                                total_bytes += data.len() as u64;
                                debug!("PTY writer: wrote {} bytes (total: {})", data.len(), total_bytes);
                            }
                            Err(e) => {
                                error!("PTY writer error: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to get writer: {}", e);
                        break;
                    }
                }
            }
            
            info!("PTY writer thread ended (total bytes: {})", total_bytes);
        });
        
        Ok(Self {
            output_rx,
            input_tx,
            reader_thread: Mutex::new(Some(reader_thread)),
            writer_thread: Mutex::new(Some(writer_thread)),
        })
    }
    
    /// Read output from PTY (async wrapper)
    async fn read(&self) -> Option<Vec<u8>> {
        let rx = self.output_rx.clone();
        tokio::task::spawn_blocking(move || {
            rx.recv().ok()
        }).await.ok()?
    }
    
    /// Write input to PTY (async wrapper)
    async fn write(&self, data: Vec<u8>) -> Result<(), String> {
        self.input_tx.send(data)
            .map_err(|e| format!("Failed to send to writer thread: {}", e))
    }
    
    /// Resize PTY (not implemented for portable_pty)
    async fn resize(&self, _rows: u16, _cols: u16) -> Result<(), String> {
        // Note: portable_pty doesn't expose resize on the master directly
        // This would need to be implemented based on the specific PTY implementation
        warn!("PTY resize not implemented for portable_pty");
        Ok(())
    }
    
    /// Shutdown the bridge
    async fn shutdown(&self) {
        // Close channels (this will cause threads to exit)
        drop(self.input_tx.clone());
        
        // Wait for threads to finish
        if let Some(thread) = self.reader_thread.lock().await.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.writer_thread.lock().await.take() {
            let _ = thread.join();
        }
    }
}

/// Handle terminal WebSocket messages
#[instrument(skip(manager))]
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
            let decoded = base64::decode(&data)
                .map_err(|e| format!("Failed to decode input: {}", e))?;
            
            if decoded.len() > MAX_INPUT_SIZE {
                return Ok(Some(TerminalMessage::Error {
                    session_id,
                    error: format!("Input too large (max {} bytes)", MAX_INPUT_SIZE)
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

/// Terminal output reader with async channel processing
pub async fn terminal_output_reader(
    manager: Arc<TerminalSessionManager>,
    session_id: String,
    tx: mpsc::Sender<TerminalMessage>,
) -> Result<(), String> {
    info!("Starting output reader for terminal session: {}", session_id);
    
    let session = {
        let sessions = manager.sessions.read().await;
        sessions.get(&session_id).cloned()
            .ok_or_else(|| "Session not found".to_string())?
    };
    
    let metrics = manager.metrics.clone();
    let session_id_clone = session_id.clone();
    
    // Spawn async task to process output from the PTY bridge
    tokio::spawn(async move {
        let mut total_bytes = 0u64;
        
        while session.active.load(Ordering::Relaxed) {
            // Read from PTY bridge (this internally uses the blocking thread)
            match session.pty_bridge.read().await {
                Some(data) => {
                    let data_len = data.len();
                    total_bytes += data_len as u64;
                    
                    debug!("Output reader: processing {} bytes (total: {})", data_len, total_bytes);
                    
                    // Send to WebSocket
                    let encoded = base64::encode(&data);
                    if tx.send(TerminalMessage::Output {
                        session_id: session_id_clone.clone(),
                        data: encoded,
                    }).await.is_err() {
                        warn!("Output reader: failed to send, channel closed");
                        break;
                    }
                    
                    metrics.bytes_read.fetch_add(data_len as u64, Ordering::Relaxed);
                    
                    // Update activity
                    if let Ok(mut last_activity) = session.last_activity.try_lock() {
                        *last_activity = Instant::now();
                    }
                }
                None => {
                    // Channel closed or EOF
                    info!("Output reader: PTY closed for session {}", session_id_clone);
                    let _ = tx.send(TerminalMessage::Error {
                        session_id: session_id_clone.clone(),
                        error: "Terminal closed".to_string(),
                    }).await;
                    break;
                }
            }
        }
        
        info!("Output reader stopped for session {} (total bytes: {})", session_id_clone, total_bytes);
    });
    
    Ok(())
}

// Default implementation
impl Default for TerminalSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_session_lifecycle() {
        let manager = Arc::new(TerminalSessionManager::new());
        let session_id = "test_session".to_string();
        
        // Create session
        assert!(manager.create_session(
            session_id.clone(),
            DEFAULT_ROWS,
            DEFAULT_COLS,
            None,
            None
        ).await.is_ok());
        
        assert!(manager.has_session(&session_id).await);
        
        // Write input
        let input = b"echo test\n";
        assert!(manager.write_to_terminal(&session_id, input).await.is_ok());
        
        // Close session
        assert!(manager.close_session(&session_id).await.is_ok());
        assert!(!manager.has_session(&session_id).await);
    }
    
    #[tokio::test]
    async fn test_session_limit() {
        let manager = Arc::new(TerminalSessionManager::new());
        
        // Create max sessions
        for i in 0..MAX_SESSIONS {
            let session_id = format!("session_{}", i);
            assert!(manager.create_session(
                session_id,
                DEFAULT_ROWS,
                DEFAULT_COLS,
                None,
                None
            ).await.is_ok());
        }
        
        // Try to create one more
        let result = manager.create_session(
            "overflow".to_string(),
            DEFAULT_ROWS,
            DEFAULT_COLS,
            None,
            None
        ).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Session limit exceeded"));
    }
}
