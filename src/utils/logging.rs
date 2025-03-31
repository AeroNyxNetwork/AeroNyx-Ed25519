// src/utils/logging.rs
//! Logging utilities for the application.
//!
//! This module provides functions for initializing and configuring
//! the logging system.

use std::io;
use std::path::Path;
use tracing_subscriber::{fmt, EnvFilter, prelude::*};
use tracing_appender::rolling;

/// Initialize the logging system with console output
pub fn init_logging(log_level: &str) -> io::Result<()> {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::new(log_level),
    };
    
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_line_number(true)
        .with_file(true)
        .with_thread_names(true)
        .init();
    
    Ok(())
}

/// Sets up file-based logging in addition to console output
pub fn init_file_logging(log_level: &str, log_file: &str) -> io::Result<()> {
    let filter = EnvFilter::new(log_level);
    
    // Simple file-based writer
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
        
    let file_writer = std::sync::Mutex::new(file);
    
    fmt()
        .with_env_filter(filter)
        .with_writer(move || std::io::BufWriter::new(file_writer.lock().unwrap()))
        .init();
    
    Ok(())
}

/// Log a security event
pub fn log_security_event(event_type: &str, details: &str) {
    tracing::warn!(
        security_event = true,
        event_type = event_type,
        details = details,
        "Security event: {} - {}",
        event_type,
        details
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_init_logging() {
        // Just make sure it doesn't panic
        let result = init_logging("debug");
        assert!(result.is_ok());
    }
}
