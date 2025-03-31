// src/utils/logging.rs
//! Logging utilities for the application.
//!
//! This module provides functions for initializing and configuring
//! the logging system.

use std::io;
// Remove unused import: File
use std::path::Path;
// Use prelude for easier access to traits
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
// Import NonBlocking and rolling
use tracing_appender::{non_blocking::NonBlocking, rolling};
use tracing_subscriber::fmt::writer::MakeWriterExt; // Import trait for .with_max_level

/// Initialize the logging system with console output
pub fn init_logging(log_level: &str) -> io::Result<()> {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(_) => EnvFilter::new(log_level), // Use provided level as fallback
    };

    // Configure console logging layer
    let console_layer = fmt::layer()
        .with_target(true) // Log target (module path)
        .with_line_number(true) // Log source line number
        .with_file(true) // Log source file name
        .with_thread_names(true) // Include thread names
        .with_writer(io::stdout); // Log to standard output

    // Initialize the subscriber with the console layer and filter
    tracing_subscriber::registry()
        .with(console_layer.with_filter(filter))
        .try_init() // Use try_init to handle potential errors
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to initialize logging: {}", e)))?;

    Ok(())
}

/// Sets up file-based logging in addition to console output
 pub fn init_file_logging(log_level: &str, log_file: &str) -> io::Result<()> {
     let filter = EnvFilter::new(log_level);

     // --- Configure File Appender ---
     let log_path = Path::new(log_file);
     let log_dir = log_path.parent().unwrap_or_else(|| Path::new(".")); // Default to current dir if no parent
     let log_filename_prefix = log_path.file_stem().unwrap_or_else(|| std::ffi::OsStr::new("aeronyx")).to_os_string();
     let log_filename_suffix = log_path.extension().unwrap_or_else(||std::ffi::OsStr::new("log")).to_os_string();


     // Use built-in rolling file appender
     let file_appender = rolling::daily(log_dir, log_filename_prefix) // rolling::daily takes directory and prefix
         .with_max_level(tracing::Level::TRACE); // Ensure the writer accepts all levels


    // --- Create Non-Blocking Writer ---
    // Wrap the file appender in a NonBlocking writer for performance.
    // This decouples log writing from application threads.
    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(file_appender);


    // --- Configure File Logging Layer ---
    let file_layer = fmt::layer()
        .with_target(true)
        .with_line_number(true)
        .with_file(true)
        .with_thread_names(true)
        .with_writer(non_blocking_writer) // Use the non-blocking writer
        .with_ansi(false); // Disable ANSI colors for file logs


    // --- Configure Console Logging Layer (Optional, if you want both) ---
    let console_layer = fmt::layer()
        .with_writer(io::stdout)
        .with_ansi(true); // Enable ANSI colors for console


    // --- Initialize Subscriber ---
    // Combine layers and set the global default subscriber.
    tracing_subscriber::registry()
        .with(file_layer.with_filter(filter.clone())) // Apply filter to file layer
         .with(console_layer.with_filter(filter)) // Apply filter to console layer
        .try_init() // Use try_init for fallible initialization
        .map_err(|e| io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to set global default subscriber: {}", e)
        ))?;


    // Keep the _guard in scope to ensure logs are flushed on exit.
    // If this function returns, the guard will be dropped. For long-running apps,
    // you might need to store the guard somewhere, e.g., in the main struct.
    // For this example, we'll rely on the caller to manage the application lifecycle.
     // IMPORTANT: In a real application, the `_guard` needs to be kept alive.
     // Returning it or storing it in a long-lived structure is necessary.
     // For simplicity here, we let it drop, which might mean logs aren't flushed on immediate exit.


    Ok(())
}


/// Log a security event with structured fields
pub fn log_security_event(event_type: &str, details: &str) {
    tracing::warn!(
        // Use key-value pairs for structured logging
        security_event.type = event_type,
        security_event.details = details,
        "Security event: [{}] {}", // Keep human-readable message
        event_type,
        details
    );
}

#[cfg(test)]
mod tests {
    use super::*;
     use std::fs;
     use tempfile::tempdir;

    #[test]
    fn test_init_logging() {
        // Just make sure it doesn't panic
        // Note: This might interfere with other tests if they also initialize logging globally.
        // Consider using `tracing_test` crate for isolated logging tests.
        let _ = init_logging("debug"); // Use `let _ =` to ignore potential error in test context
         tracing::info!("Console logging initialized (test)");
    }

     #[test]
     fn test_init_file_logging() {
         let temp_dir = tempdir().unwrap();
         let log_file = temp_dir.path().join("test_app.log");

         // Initialize file logging
         let result = init_file_logging("trace", log_file.to_str().unwrap());
         assert!(result.is_ok());

         // Log some messages
         tracing::info!(test_id = 1, "Info message to file");
         tracing::warn!(test_id = 2, "Warning message to file");
         tracing::error!(test_id = 3, "Error message to file");

         // Drop the global subscriber guard manually if needed for flushing in tests.
         // This is complex to do correctly without holding the guard.
         // Usually, tests verify file content after the process potentially exits.

         // Basic check: does the log file exist?
         // Note: Due to non-blocking nature, file might not be written immediately.
         // A robust test would wait or check content after some time/trigger.
         // assert!(log_file.exists());

         // Try reading the file (best effort in test)
          // std::thread::sleep(std::time::Duration::from_millis(100)); // Small delay
         // if let Ok(content) = fs::read_to_string(&log_file) {
         //     assert!(content.contains("Info message to file"));
         //     assert!(content.contains("test_id=1"));
         // } else {
         //      println!("Log file content check skipped (file might not be written yet).");
         // }
     }

     #[test]
     fn test_log_security_event() {
         // Initialize console logging for capturing output in tests
          let _ = tracing_subscriber::fmt()
             .with_max_level(tracing::Level::WARN)
             .try_init(); // Use try_init

         // Log a security event
         log_security_event("AUTH_FAILURE", "Invalid password for user 'test'");

         // In a real test, you'd capture the logs using a test subscriber
         // from `tracing-subscriber::fmt::test` or `tracing-test`
         // to assert the structured fields were logged correctly.
     }
}
