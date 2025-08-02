// src/terminal_manager.rs
// AeroNyx Privacy Network - Terminal Manager Module
// Version: 1.0.0
//
// This module provides PTY-based terminal session management for remote access

use anyhow::{Result, anyhow};
use portable_pty::{native_pty_system, CommandBuilder, PtySize, MasterPty, Child};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tracing::{info, warn, error, debug};
use std::path::PathBuf;

/// Terminal session information
pub struct TerminalSession {
    pub session_id: String,
    pub user: String,
    pub pty_master: Box<dyn MasterPty + Send>,
    pub child: Box<dyn Child + Send + Sync>,
    pub size: PtySize,
    pub created_at: std::time::Instant,
    pub last_activity: std::time::Instant,
    pub read_task: Option<JoinHandle<()>>,
}

/// Terminal manager for handling multiple PTY sessions
pub struct TerminalManager {
    sessions: Arc<RwLock<HashMap<String, Arc<Mutex<TerminalSession>>>>>,
    max_sessions_per_user: usize,
    session_timeout: std::time::Duration,
}

impl TerminalManager {
    /// Create a new terminal manager
    pub fn new(max_sessions_per_user: usize, session_timeout_minutes: u64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions_per_user,
            session_timeout: std::time::Duration::from_secs(session_timeout_minutes * 60),
        }
    }

    /// Create a new terminal session
    pub async fn create_session(
        &self,
        session_id: String,
        user: String,
        rows: u16,
        cols: u16,
        cwd: Option<String>,
        env: Option<HashMap<String, String>>,
    ) -> Result<()> {
        // Check session limit for user
        let session_count = self.count_user_sessions(&user).await;
        if session_count >= self.max_sessions_per_user {
            return Err(anyhow!("Maximum number of sessions ({}) reached for user", self.max_sessions_per_user));
        }

        // Check if session already exists
        if self.sessions.read().await.contains_key(&session_id) {
            return Err(anyhow!("Session {} already exists", session_id));
        }

        info!("Creating terminal session {} for user {}", session_id, user);

        // Create PTY
        let pty_system = native_pty_system();
        let pty_size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        let pty_pair = pty_system.openpty(pty_size)?;

        // Build command
        let mut cmd = CommandBuilder::new(std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string()));
        
        // Set working directory
        if let Some(cwd_path) = cwd {
            let path = PathBuf::from(&cwd_path);
            if path.exists() && path.is_dir() {
                cmd.cwd(path);
            } else {
                warn!("Invalid working directory: {}, using default", cwd_path);
            }
        }

        // Set environment variables
        if let Some(env_vars) = env {
            for (key, value) in env_vars {
                // Only allow safe environment variables
                if Self::is_safe_env_var(&key) {
                    cmd.env(key, value);
                }
            }
        }

        // Set some default environment variables
        cmd.env("TERM", "xterm-256color");
        cmd.env("LANG", "en_US.UTF-8");

        // Spawn the child process
        let child = pty_pair.slave.spawn_command(cmd)?;
        drop(pty_pair.slave); // Close slave side in parent

        let session = TerminalSession {
            session_id: session_id.clone(),
            user: user.clone(),
            pty_master: pty_pair.master,
            child,
            size: pty_size,
            created_at: std::time::Instant::now(),
            last_activity: std::time::Instant::now(),
            read_task: None,
        };

        let session_arc = Arc::new(Mutex::new(session));
        self.sessions.write().await.insert(session_id.clone(), session_arc.clone());

        info!("Terminal session {} created successfully", session_id);
        Ok(())
    }

    /// Start reading from terminal output
    pub async fn start_reading<F>(
        &self,
        session_id: String,
        mut output_handler: F,
    ) -> Result<()>
    where
        F: FnMut(Vec<u8>) + Send + 'static,
    {
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(&session_id)
            .ok_or_else(|| anyhow!("Session {} not found", session_id))?
            .clone();
        drop(sessions);

        let session_id_clone = session_id.clone();
        let sessions_clone = self.sessions.clone();

        // Spawn a task to read from the PTY
        let read_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            
            loop {
                let mut session = session_arc.lock().await;
                
                // Try to get a reader from the master PTY
                let reader_result = session.pty_master.try_clone_reader();
                drop(session); // Release lock while reading
                
                match reader_result {
                    Ok(mut reader) => {
                        // Convert to async reader
                        let mut async_reader = tokio::io::BufReader::new(
                            tokio_util::compat::FuturesAsyncReadCompatExt::compat(reader)
                        );
                        
                        match async_reader.read(&mut buffer).await {
                            Ok(0) => {
                                // EOF - terminal closed
                                info!("Terminal session {} closed (EOF)", session_id_clone);
                                break;
                            }
                            Ok(n) => {
                                // Update last activity
                                if let Some(session) = sessions_clone.read().await.get(&session_id_clone) {
                                    session.lock().await.last_activity = std::time::Instant::now();
                                }
                                
                                // Send output to handler
                                output_handler(buffer[..n].to_vec());
                            }
                            Err(e) => {
                                error!("Error reading from terminal {}: {}", session_id_clone, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to clone PTY reader for session {}: {}", session_id_clone, e);
                        break;
                    }
                }
                
                // Small delay to prevent busy loop
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            
            // Clean up session when read loop exits
            info!("Cleaning up terminal session {}", session_id_clone);
            sessions_clone.write().await.remove(&session_id_clone);
        });

        // Store the read task handle
        let mut session = session_arc.lock().await;
        session.read_task = Some(read_task);
        
        Ok(())
    }

    /// Write input to terminal
    pub async fn write_input(&self, session_id: &str, data: &[u8]) -> Result<()> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(session_id)
            .ok_or_else(|| anyhow!("Session {} not found", session_id))?
            .clone();
        drop(sessions);

        let mut session = session_arc.lock().await;
        session.last_activity = std::time::Instant::now();

        // Get a writer from the master PTY
        let mut writer = session.pty_master.take_writer()?;
        
        // Write data
        writer.write_all(data)?;
        writer.flush()?;

        debug!("Wrote {} bytes to terminal {}", data.len(), session_id);
        Ok(())
    }

    /// Resize terminal
    pub async fn resize_terminal(&self, session_id: &str, rows: u16, cols: u16) -> Result<()> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(session_id)
            .ok_or_else(|| anyhow!("Session {} not found", session_id))?
            .clone();
        drop(sessions);

        let mut session = session_arc.lock().await;
        let new_size = PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        };

        session.pty_master.resize(new_size)?;
        session.size = new_size;
        session.last_activity = std::time::Instant::now();

        info!("Resized terminal {} to {}x{}", session_id, cols, rows);
        Ok(())
    }

    /// Close terminal session
    pub async fn close_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session_arc) = sessions.remove(session_id) {
            let mut session = session_arc.lock().await;
            
            // Cancel read task if running
            if let Some(task) = session.read_task.take() {
                task.abort();
            }
            
            // Try to kill the child process
            if let Err(e) = session.child.kill() {
                warn!("Failed to kill child process for session {}: {}", session_id, e);
            }
            
            info!("Closed terminal session {}", session_id);
            Ok(())
        } else {
            Err(anyhow!("Session {} not found", session_id))
        }
    }

    /// Clean up inactive sessions
    pub async fn cleanup_inactive_sessions(&self) {
        let now = std::time::Instant::now();
        let mut sessions_to_close = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (session_id, session_arc) in sessions.iter() {
                let session = session_arc.lock().await;
                if now.duration_since(session.last_activity) > self.session_timeout {
                    sessions_to_close.push(session_id.clone());
                }
            }
        }

        for session_id in sessions_to_close {
            info!("Closing inactive terminal session {}", session_id);
            if let Err(e) = self.close_session(&session_id).await {
                error!("Failed to close inactive session {}: {}", session_id, e);
            }
        }
    }

    /// Count sessions for a specific user
    async fn count_user_sessions(&self, user: &str) -> usize {
        let sessions = self.sessions.read().await;
        let mut count = 0;
        
        for (_, session_arc) in sessions.iter() {
            let session = session_arc.lock().await;
            if session.user == user {
                count += 1;
            }
        }
        
        count
    }

    /// Check if environment variable is safe to set
    fn is_safe_env_var(key: &str) -> bool {
        const SAFE_ENV_VARS: &[&str] = &[
            "TERM",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TZ",
            "USER",
            "HOME",
            "SHELL",
            "EDITOR",
            "VISUAL",
            "PAGER",
        ];
        
        SAFE_ENV_VARS.contains(&key) || key.starts_with("AERONYX_")
    }

    /// Get session info
    pub async fn get_session_info(&self, session_id: &str) -> Result<(String, u16, u16)> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(session_id)
            .ok_or_else(|| anyhow!("Session {} not found", session_id))?;
        
        let session = session_arc.lock().await;
        Ok((session.user.clone(), session.size.rows, session.size.cols))
    }

    /// List all active sessions
    pub async fn list_sessions(&self) -> Vec<(String, String, std::time::Duration)> {
        let sessions = self.sessions.read().await;
        let now = std::time::Instant::now();
        let mut result = Vec::new();
        
        for (session_id, session_arc) in sessions.iter() {
            let session = session_arc.lock().await;
            let duration = now.duration_since(session.created_at);
            result.push((session_id.clone(), session.user.clone(), duration));
        }
        
        result
    }
}

/// Start periodic cleanup task
pub fn start_cleanup_task(manager: Arc<TerminalManager>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            manager.cleanup_inactive_sessions().await;
        }
    })
}
