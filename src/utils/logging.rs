// src/utils/logging.rs
//! Logging utilities for the application.
//!
//! This module provides functions for initializing and configuring
//! the logging system.

use std::io;
use std::path::Path;
// Import Layer trait explicitly and EnvFilter via filter module
use tracing_subscriber::{fmt, filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, Layer as TracingLayer, filter::LevelFilter}; // Corrected line 10
// Removed unused NonBlocking import (type name not directly used)
use tracing_appender::rolling;
// Removed unused MakeWriterExt import // Corrected line 13


// Keep the _guard return type for file logging to ensure flushing
pub type LoggerGuard = tracing_appender::non_blocking::WorkerGuard;

/// Initialize the logging system with console output
pub fn init_logging(log_level: &str) -> io::Result<()> {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(_) => EnvFilter::new(log_level),
    };

    // Configure console logging layer
    let console_layer = fmt::layer()
        .with_target(true)
        .with_line_number(true)
        .with_file(true)
        .with_thread_names(true)
        .with_writer(io::stdout);

    // Initialize the subscriber with the console layer and filter
    tracing_subscriber::registry()
        .with(console_layer.with_filter(filter)) // Apply filter to the layer
        .try_init()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to initialize logging: {}", e)))?;

    Ok(())
}

/// Sets up file-based logging in addition to console output
/// Returns a guard that must be kept alive for logs to be flushed.
 pub fn init_file_logging(log_level: &str, log_file: &str) -> io::Result<LoggerGuard> {
     let filter = EnvFilter::new(log_level);
     // Parse log level for max_level setting
     let max_level = match log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO, // Default to INFO
     };


     // --- Configure File Appender ---
     let log_path = Path::new(log_file);
     let log_dir = log_path.parent().unwrap_or_else(|| Path::new("."));
     // Correctly handle OsStr conversion
     let log_filename_prefix = log_path.file_stem().unwrap_or_else(|| std::ffi::OsStr::new("aeronyx"));


     // Use rolling file appender
     let file_appender = rolling::daily(log_dir, log_filename_prefix);


    // --- Create Non-Blocking Writer ---
    // Wrap the file appender in a NonBlocking writer for performance.
    let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);


    // --- Configure File Logging Layer ---
    // Apply max_level here to the layer
    // Assumes Cargo.toml versions are aligned for MakeWriter trait.
    let file_layer = fmt::layer()
        .with_target(true)
        .with_line_number(true)
        .with_file(true)
        .with_thread_names(true)
        .with_writer(non_blocking_writer) // Use the non-blocking writer
        .with_ansi(false); // Disable ANSI colors for file logs


    // --- Configure Console Logging Layer (Optional) ---
    let console_layer = fmt::layer()
        .with_writer(io::stdout)
        .with_ansi(true);


    // --- Initialize Subscriber ---
    // Combine layers and set the global default subscriber.
    // Assumes compatible tracing crates for with_filter on layer.
    tracing_subscriber::registry()
        .with(filter) // Apply filter globally
        .with(file_layer.with_filter(max_level)) // Filter layer by max level
        .with(console_layer.with_filter(max_level)) // Filter layer by max level
        .try_init()
        .map_err(|e| io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to set global default subscriber: {}", e)
        ))?;


     Ok(guard) // Return the guard
}


/// Log a security event with structured fields
pub fn log_security_event(event_type: &str, details: &str) {
    tracing::warn!(
        security_event.type = event_type,
        security_event.details = details,
        "Security event: [{}] {}",
        event_type,
        details
    );
}

#[cfg(test)]
mod tests {
    use super::*;
     use tempfile::tempdir;

    #[test]
    fn test_init_logging() {
        // Use tracing_test::traced_test for isolated tests
        // #[tracing_test::traced_test]
        fn inner_test() {
            let _ = init_logging("debug");
            tracing::info!("Console logging initialized (test)");
        }
        inner_test(); // Call the inner function
    }

     #[tokio::test] // Use tokio::test for async
     async fn test_init_file_logging() { // Mark test as async
         let temp_dir = tempdir().unwrap();
         let log_file = temp_dir.path().join("test_app.log");

         // Initialize file logging and keep the guard
         let _guard = init_file_logging("trace", log_file.to_str().unwrap()).expect("Failed to init file logging");

         // Log some messages
         tracing::info!(test_id = 1, "Info message to file");
         tracing::warn!(test_id = 2, "Warning message to file");
         tracing::error!(test_id = 3, "Error message to file");

         // Drop the guard explicitly to ensure flush (or let it drop at end of scope)
         // drop(_guard); // This happens automatically at end of scope

         // Give a small amount of time for logs to potentially flush
         tokio::time::sleep(std::time::Duration::from_millis(100)).await; // Use tokio sleep

         // Check log file content
         match std::fs::read_to_string(&log_file) {
             Ok(content) => {
                 assert!(content.contains("Info message to file"));
                 assert!(content.contains("test_id=1"));
                 assert!(content.contains("Warning message to file"));
                 assert!(content.contains("test_id=2"));
                 assert!(content.contains("Error message to file"));
                 assert!(content.contains("test_id=3"));
             }
             Err(e) => {
                 // Fail the test if the file couldn't be read
                  panic!("Log file content check failed: {}", e);
             }
         }
     }

     #[test]
     fn test_log_security_event() {
        // Use tracing_subscriber::fmt::test::capture to check logs
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer() // Capture logs
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_security_event("AUTH_FAILURE", "Invalid password for user 'test'");
            // In a real test with test_writer, you would assert on the captured output here.
        });
     }
}
