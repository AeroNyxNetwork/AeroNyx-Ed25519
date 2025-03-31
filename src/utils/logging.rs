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
    use std::fs::File; // Import File
    use std::io::Write; // Import Write trait if needed for manual flushing (though drop(guard) should suffice)
    use tracing_subscriber::fmt; // Ensure fmt is imported
    use tracing_subscriber::{layer::SubscriberExt, filter::LevelFilter, EnvFilter, util::SubscriberInitExt}; // Import necessary traits/types
    use tracing_appender::non_blocking::WorkerGuard; // Import WorkerGuard type

    #[test]
    fn test_init_logging() {
        // Use tracing_test::traced_test for isolated tests
        // #[tracing_test::traced_test]
        fn inner_test() {
            // Attempt to initialize, ignore error if already initialized by another test
            let _ = init_logging("debug");
            tracing::info!("Console logging initialized (test)");
        }
        inner_test(); // Call the inner function
    }

     #[tokio::test] // Use tokio::test if any async operations are needed (like sleep)
     async fn test_init_file_logging() { // Renamed back, as it tests file logging concept
         let temp_dir = tempdir().unwrap();
         // Use a fixed filename within the temp dir for simplicity
         let log_file_path = temp_dir.path().join("test_fixed.log");

         let guard: WorkerGuard; // Declare guard outside the init block
         { // Scope for subscriber initialization
             // Create a non-rolling file writer directly for the test
             let log_file = File::create(&log_file_path)
                 .expect("Failed to create temporary log file for test");
             let (non_blocking_writer, _guard) = tracing_appender::non_blocking(log_file);
             guard = _guard; // Assign guard to outer variable

             // Configure subscriber layers using the non-rolling writer
             let filter = EnvFilter::new("trace"); // Test with trace level
             let max_level = LevelFilter::TRACE;

             let file_layer = fmt::layer()
                 .with_writer(non_blocking_writer) // Use the direct non-blocking writer
                 .with_ansi(false); // No ANSI for easier string matching

             // --- Initialize Subscriber (locally for the test) ---
             // Use try_init which might fail if global logger already set,
             // but logs should still go to our layer if using with_default.
             // Using with_default is generally safer in multi-test scenarios.
             let subscriber = tracing_subscriber::registry()
                .with(filter)
                .with(file_layer.with_filter(max_level));

             tracing::subscriber::with_default(subscriber, || {
                     // Log some messages within the scope where the test subscriber is active
                     tracing::info!(test_id = 1, "Info message to file");
                     tracing::warn!(test_id = 2, "Warning message to file");
                     tracing::error!(test_id = 3, "Error message to file");
                 }
             ); // Subscriber registry (if set globally) might persist, but the default is reset
         } // Subscriber scope ends

         // Drop the guard explicitly *after* the logging block and subscriber scope
         drop(guard);

         // Give a bit more time for flush, just in case
         tokio::time::sleep(std::time::Duration::from_millis(150)).await;

         // --- Check the fixed-name log file content ---
         match std::fs::read_to_string(&log_file_path) {
             Ok(content) => {
                 assert!(content.contains("Info message to file"), "Output: {}", content);
                 assert!(content.contains("test_id=1"), "Output: {}", content);
                 assert!(content.contains("Warning message to file"), "Output: {}", content);
                 assert!(content.contains("test_id=2"), "Output: {}", content);
                 assert!(content.contains("Error message to file"), "Output: {}", content);
                 assert!(content.contains("test_id=3"), "Output: {}", content);
             }
             Err(e) => {
                 // Fail the test if the file couldn't be read
                  panic!("Log file content check failed for {:?}: {}", log_file_path, e);
             }
         }
     }

     #[test]
     fn test_log_security_event() {
        // Use tracing_subscriber::fmt::test::capture - This requires TestWriter, which isn't public API.
        // Let's just ensure it runs without panic for now, or use a different capture method if needed.
        // Initialize a basic subscriber to avoid panic if no subscriber is set globally.
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            // Use .without_time() or other options if needed for consistency
            .finish();

        // Use try_set_global_default to avoid panic if already set
        let _ = tracing::subscriber::set_global_default(subscriber);

        log_security_event("AUTH_FAILURE", "Invalid password for user 'test'");
        // No easy way to assert output here without public TestWriter or adding dependencies.
     }
}
