// src/terminal/mod.rs
// ============================================
// AeroNyx Privacy Network - Web Terminal Implementation
// Version: 2.0.0 - Production-grade implementation
// ============================================
// Architecture:
// - Non-blocking I/O with adaptive polling
// - Graceful error handling and recovery
// - Comprehensive logging and metrics
// - Memory-efficient buffer management
// - Thread-safe session management
//
// Performance characteristics:
// - Sub-millisecond input latency
// - Efficient CPU usage with adaptive polling
// - Memory bounded by session limits
// - Automatic cleanup of stale sessions
// ============================================

use portable_pty::{native_pty_system, CommandBuilder, PtySize, MasterPty, ChildKiller};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn, debug, instrument, span, Level};
use std::io::{Read, Write, ErrorKind};
use tokio::task::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// Constants for production use
const MAX_SESSIONS: usize = 100;
const MAX_SESSION_AGE: Duration = Duration::from_secs(3600); // 1 hour
const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;
const MAX_ROWS: u16 = 200;
const MIN_ROWS: u16 = 10;
const MAX_COLS: u16 = 400;
const MIN_COLS: u16 = 40;
const READ_BUFFER_SIZE: usize = 8192;
const MAX_INPUT_SIZE: usize = 4096;
const WRITE_RETRY_COUNT: usize = 3;
const WRITE_RETRY_DELAY: Duration = Duration::from_millis(10);

// Polling intervals for optimal performance
const POLL_INTERVAL_ACTIVE: Duration = Duration::from_millis(1);
const POLL_INTERVAL_IDLE: Duration = Duration::from_millis(10);
const POLL_INTERVAL_INACTIVE: Duration = Duration::from_millis(50);
const ACTIVITY_THRESHOLD: Duration = Duration::from_millis(500);
const IDLE_THRESHOLD: Duration = Duration::from_secs(5);

/// Terminal session manager with production-grade features
pub struct TerminalSessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<TerminalSession>>>>,
    output_channels: Arc<RwLock<HashMap<String, mpsc::Sender<TerminalMessage>>>>,
    metrics: Arc<TerminalMetrics>,
    cleanup_handle: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
}

/// Metrics for monitoring terminal performance
#[derive(Default)]
struct TerminalMetrics {
    sessions_created: AtomicU64,
    sessions_closed: AtomicU64,
    bytes_written: AtomicU64,
    bytes_read: AtomicU64,
    errors_count: AtomicU64,
}

/// Individual terminal session with comprehensive state tracking
pub struct TerminalSession {
    pub session_id: String,
    pub size: Arc<Mutex<PtySize>>,
    pub created_at: Instant,
    pub last_activity: Arc<Mutex<Instant>>,
    pub user_info: Option<String>,
    pty_handle: Arc<Mutex<PtyHandle>>,
    reader_handle: Mutex<Option<JoinHandle<()>>>,
    active: Arc<AtomicBool>,
}

/// Internal PTY handle with proper resource management
struct PtyHandle {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn ChildKiller + Send + Sync>,
}

// Ensure thread safety
unsafe impl Send for TerminalSession {}
unsafe impl Sync for TerminalSession {}

/// Terminal WebSocket message types with comprehensive coverage
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
    
    #[serde(rename = "term_ping")]
    Ping {
        session_id: String,
    },
    
    #[serde(rename = "term_pong")]
    Pong {
        session_id: String,
    },
}

impl TerminalSessionManager {
    /// Create a new terminal session manager with full initialization
    pub fn new() -> Arc<Self> {
        let manager = Arc::new(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            output_channels: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(TerminalMetrics::default()),
            cleanup_handle: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
        });
        
        // Start cleanup task
        let manager_clone = manager.clone();
        let cleanup_handle = tokio::spawn(async move {
            manager_clone.cleanup_task().await;
        });
        
        // Store cleanup handle
        let manager_clone = manager.clone();
        tokio::spawn(async move {
            *manager_clone.cleanup_handle.lock().await = Some(cleanup_handle);
        });
        
        manager
    }
    
    /// Cleanup task that runs periodically
    async fn cleanup_task(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        while !self.shutdown.load(Ordering::Relaxed) {
            interval.tick().await;
            self.cleanup_stale_sessions(MAX_SESSION_AGE).await;
        }
    }
    
    /// Shutdown the manager gracefully
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        
        // Close all sessions
        let sessions = self.sessions.read().await;
        let session_ids: Vec<String> = sessions.keys().cloned().collect();
        drop(sessions);
        
        for session_id in session_ids {
            let _ = self.close_session(&session_id).await;
        }
        
        // Wait for cleanup task
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            let _ = handle.await;
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
    
    /// Create a new terminal session with comprehensive validation
    #[instrument(skip(self, env))]
    pub async fn create_session(
        &self,
        session_id: String,
        rows: u16,
        cols: u16,
        cwd: Option<String>,
        env: Option<HashMap<String, String>>,
    ) -> Result<(), String> {
        // Validate parameters
        if rows < MIN_ROWS || rows > MAX_ROWS {
            return Err(format!("Invalid rows: must be between {} and {}", MIN_ROWS, MAX_ROWS));
        }
        if cols < MIN_COLS || cols > MAX_COLS {
            return Err(format!("Invalid cols: must be between {} and {}", MIN_COLS, MAX_COLS));
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
        
        // Create PTY in blocking task
        let pty_result = task::spawn_blocking(move || {
            Self::create_pty(rows, cols, cwd, env)
        }).await.map_err(|e| format!("Failed to create PTY task: {}", e))??;
        
        let (master, child, pty_size) = pty_result;
        
        // Create session
        let session = Arc::new(TerminalSession {
            session_id: session_id.clone(),
            size: Arc::new(Mutex::new(pty_size)),
            created_at: Instant::now(),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            user_info: None,
            pty_handle: Arc::new(Mutex::new(PtyHandle { master, child })),
            reader_handle: Mutex::new(None),
            active: Arc::new(AtomicBool::new(true)),
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
    ) -> Result<(Box<dyn MasterPty + Send>, Box<dyn ChildKiller + Send + Sync>, PtySize), String> {
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
        
        // Interactive mode for proper terminal behavior
        cmd.arg("-i");
        
        if let Some(cwd) = cwd {
            cmd.cwd(cwd);
        }
        
        // Set environment variables
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
        
        // Close slave side
        drop(pair.slave);
        
        Ok((pair.master, child, pty_size))
    }
    
    /// Write input to terminal with retry logic
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
        
        let session_clone = session.clone();
        let data = data.to_vec();
        
        debug!("Writing {} bytes to terminal {}", data.len(), session_id);
        
        // Write with retry logic
        let result = task::spawn_blocking(move || {
            Self::write_with_retry(session_clone, data)
        }).await.map_err(|e| format!("Write task failed: {}", e))?;
        
        if result.is_ok() {
            self.metrics.bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        
        result
    }
    
    /// Write to PTY with retry logic
    fn write_with_retry(session: Arc<TerminalSession>, data: Vec<u8>) -> Result<(), String> {
        let mut attempts = 0;
        
        while attempts < WRITE_RETRY_COUNT {
            let handle = session.pty_handle.blocking_lock();
            match handle.master.take_writer() {
                Ok(mut writer) => {
                    match writer.write_all(&data) {
                        Ok(_) => {
                            let _ = writer.flush();
                            *session.last_activity.blocking_lock() = Instant::now();
                            return Ok(());
                        }
                        Err(e) if e.kind() == ErrorKind::Interrupted => {
                            attempts += 1;
                            std::thread::sleep(WRITE_RETRY_DELAY);
                            continue;
                        }
                        Err(e) => return Err(format!("Write failed: {}", e)),
                    }
                }
                Err(e) => return Err(format!("Failed to get writer: {}", e)),
            }
        }
        
        Err(format!("Failed to write after {} attempts", WRITE_RETRY_COUNT))
    }
    
    /// Resize terminal with validation
    #[instrument(skip(self))]
    pub async fn resize_terminal(
        &self,
        session_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<(), String> {
        if rows < MIN_ROWS || rows > MAX_ROWS {
            return Err(format!("Invalid rows: must be between {} and {}", MIN_ROWS, MAX_ROWS));
        }
        if cols < MIN_COLS || cols > MAX_COLS {
            return Err(format!("Invalid cols: must be between {} and {}", MIN_COLS, MAX_COLS));
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
        
        task::spawn_blocking(move || {
            let handle = session_clone.pty_handle.blocking_lock();
            handle.master
                .resize(new_size)
                .map_err(|e| format!("Failed to resize terminal: {}", e))?;
            Ok::<(), String>(())
        }).await.map_err(|e| format!("Resize task failed: {}", e))??;
        
        *session.size.lock().await = new_size;
        *session.last_activity.lock().await = Instant::now();
        
        debug!("Terminal {} resized to {}x{}", session_id, cols, rows);
        Ok(())
    }
    
    /// Close terminal session with cleanup
    #[instrument(skip(self))]
    pub async fn close_session(&self, session_id: &str) -> Result<(), String> {
        self.unregister_output_channel(session_id).await;
        
        let session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id)
        };
        
        if let Some(session) = session {
            // Mark as inactive
            session.active.store(false, Ordering::Relaxed);
            
            // Stop reader if running
            if let Some(handle) = session.reader_handle.lock().await.take() {
                handle.abort();
            }
            
            // Kill the child process
            let session_clone = session.clone();
            task::spawn_blocking(move || {
                let mut handle = session_clone.pty_handle.blocking_lock();
                if let Err(e) = handle.child.kill() {
                    warn!("Failed to kill terminal process: {}", e);
                }
            }).await.ok();
            
            self.metrics.sessions_closed.fetch_add(1, Ordering::Relaxed);
            info!("Terminal session closed: {}", session_id);
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }
    
    /// Clean up stale sessions
    async fn cleanup_stale_sessions(&self, max_age: Duration) {
        let sessions_to_remove = {
            let sessions = self.sessions.read().await;
            let now = Instant::now();
            
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
                info!("Cleaned up stale session: {}", session_id);
            }
        }
    }
    
    /// Get session count
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
    
    /// Check if session exists and is active
    pub async fn has_session(&self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.read().await.get(session_id) {
            session.active.load(Ordering::Relaxed)
        } else {
            false
        }
    }
    
    /// Get metrics
    pub fn metrics(&self) -> TerminalStats {
        TerminalStats {
            sessions_created: self.metrics.sessions_created.load(Ordering::Relaxed),
            sessions_closed: self.metrics.sessions_closed.load(Ordering::Relaxed),
            bytes_written: self.metrics.bytes_written.load(Ordering::Relaxed),
            bytes_read: self.metrics.bytes_read.load(Ordering::Relaxed),
            errors_count: self.metrics.errors_count.load(Ordering::Relaxed),
        }
    }
}

/// Terminal statistics for monitoring
#[derive(Debug, Clone)]
pub struct TerminalStats {
    pub sessions_created: u64,
    pub sessions_closed: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub errors_count: u64,
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
        
        TerminalMessage::Ping { session_id } => {
            Ok(Some(TerminalMessage::Pong { session_id }))
        }
        
        _ => Err("Unexpected message type".to_string()),
    }
}

/// High-performance terminal output reader with adaptive polling
pub async fn terminal_output_reader(
    manager: Arc<TerminalSessionManager>,
    session_id: String,
    tx: mpsc::Sender<TerminalMessage>,
) -> Result<(), String> {
    let span = span!(Level::INFO, "output_reader", session_id = %session_id);
    let _enter = span.enter();
    
    info!("Starting output reader for session");
    
    let session = {
        let sessions = manager.sessions.read().await;
        sessions.get(&session_id).cloned()
            .ok_or_else(|| "Session not found".to_string())?
    };
    
    let session_id_clone = session_id.clone();
    let tx_clone = tx.clone();
    let metrics = manager.metrics.clone();
    let active = session.active.clone();
    let last_activity = session.last_activity.clone();
    
    let reader_handle = task::spawn_blocking(move || {
        output_reader_loop(
            session,
            session_id_clone,
            tx_clone,
            metrics,
            active,
            last_activity
        )
    });
    
    // Store reader handle
    {
        let sessions = manager.sessions.read().await;
        if let Some(session) = sessions.get(&session_id) {
            *session.reader_handle.lock().await = Some(reader_handle);
        }
    }
    
    Ok(())
}

/// Core output reading loop with optimized performance
fn output_reader_loop(
    session: Arc<TerminalSession>,
    session_id: String,
    tx: mpsc::Sender<TerminalMessage>,
    metrics: Arc<TerminalMetrics>,
    active: Arc<AtomicBool>,
    last_activity: Arc<Mutex<Instant>>,
) {
    let handle = session.pty_handle.blocking_lock();
    
    let mut reader = match handle.master.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create PTY reader: {}", e);
            return;
        }
    };
    
    // Set non-blocking mode on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = reader.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            if flags != -1 {
                let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                debug!("Set PTY to non-blocking mode");
            }
        }
    }
    
    let mut buffer = vec![0u8; READ_BUFFER_SIZE];
    let mut total_bytes = 0u64;
    let mut last_read = Instant::now();
    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 100;
    
    info!("Reader initialized and running");
    
    while active.load(Ordering::Relaxed) {
        match reader.read(&mut buffer) {
            Ok(0) => {
                info!("EOF received, terminal closed");
                let _ = tx.blocking_send(TerminalMessage::Error {
                    session_id: session_id.clone(),
                    error: "Terminal closed".to_string(),
                });
                break;
            }
            
            Ok(n) => {
                // Successfully read data
                total_bytes += n as u64;
                last_read = Instant::now();
                consecutive_errors = 0;
                *last_activity.blocking_lock() = last_read;
                
                debug!("Read {} bytes (total: {})", n, total_bytes);
                
                // Send output immediately
                let encoded = base64::encode(&buffer[..n]);
                if tx.blocking_send(TerminalMessage::Output {
                    session_id: session_id.clone(),
                    data: encoded,
                }).is_err() {
                    warn!("Failed to send output, channel closed");
                    break;
                }
                
                metrics.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
            }
            
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Again => {
                // No data available - adaptive polling
                let elapsed = last_read.elapsed();
                let sleep_duration = if elapsed < ACTIVITY_THRESHOLD {
                    POLL_INTERVAL_ACTIVE
                } else if elapsed < IDLE_THRESHOLD {
                    POLL_INTERVAL_IDLE
                } else {
                    POLL_INTERVAL_INACTIVE
                };
                
                std::thread::sleep(sleep_duration);
            }
            
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                // Interrupted - retry immediately
                continue;
            }
            
            Err(e) => {
                consecutive_errors += 1;
                
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    error!("Too many consecutive errors: {}", e);
                    metrics.errors_count.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.blocking_send(TerminalMessage::Error {
                        session_id: session_id.clone(),
                        error: format!("Terminal read error: {}", e),
                    });
                    break;
                }
                
                warn!("Read error (#{}/{}): {}", consecutive_errors, MAX_CONSECUTIVE_ERRORS, e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    
    info!("Output reader stopped (total bytes: {})", total_bytes);
}

// Implement Default for production use
impl Default for TerminalSessionManager {
    fn default() -> Self {
        panic!("Use TerminalSessionManager::new() instead of default()")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_session_creation() {
        let manager = TerminalSessionManager::new();
        let session_id = "test_session_1".to_string();
        
        let result = manager.create_session(
            session_id.clone(),
            DEFAULT_ROWS,
            DEFAULT_COLS,
            None,
            None
        ).await;
        
        assert!(result.is_ok());
        assert!(manager.has_session(&session_id).await);
        
        // Cleanup
        let _ = manager.close_session(&session_id).await;
        manager.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_input_validation() {
        let manager = TerminalSessionManager::new();
        
        // Test invalid rows
        let result = manager.create_session(
            "test_invalid".to_string(),
            5, // Too small
            DEFAULT_COLS,
            None,
            None
        ).await;
        
        assert!(result.is_err());
        
        manager.shutdown().await;
    }
    
    #[tokio::test]
    async fn test_metrics() {
        let manager = TerminalSessionManager::new();
        let initial_stats = manager.metrics();
        
        assert_eq!(initial_stats.sessions_created, 0);
        assert_eq!(initial_stats.sessions_closed, 0);
        
        let session_id = "test_metrics".to_string();
        let _ = manager.create_session(
            session_id.clone(),
            DEFAULT_ROWS,
            DEFAULT_COLS,
            None,
            None
        ).await;
        
        let stats = manager.metrics();
        assert_eq!(stats.sessions_created, 1);
        
        let _ = manager.close_session(&session_id).await;
        let final_stats = manager.metrics();
        assert_eq!(final_stats.sessions_closed, 1);
        
        manager.shutdown().await;
    }
}
