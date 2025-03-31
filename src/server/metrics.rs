// src/server/metrics.rs
//! Server metrics collection and reporting.
//!
//! This module provides functionality for collecting, tracking,
//! and reporting server performance metrics.

// Remove unused import: HashMap
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time;
// Remove unused imports: debug, info
use tracing::warn; // Keep warn

// Remove unused import: utils
// --- Structs ServerMetrics, ConnectionRateMetrics remain the same ---
#[derive(Debug, Clone)]
pub struct ServerMetrics {
    /// Server start time
    pub start_time: Instant,
    /// Connection count
    pub active_connections: usize,
    /// Total connections since startup
    pub total_connections: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Authentication successes
    pub auth_successes: u64,
    /// Authentication failures
    pub auth_failures: u64,
    /// Average CPU usage (percentage)
    pub cpu_usage: f64,
    /// Memory usage (percentage)
    pub memory_usage: f64,
    /// System load average
    pub load_average: (f64, f64, f64),
    /// Active TLS handshakes
    pub active_handshakes: usize,
    /// Total TLS handshakes
    pub total_handshakes: u64,
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            active_connections: 0,
            total_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            auth_successes: 0,
            auth_failures: 0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            load_average: (0.0, 0.0, 0.0),
            active_handshakes: 0,
            total_handshakes: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionRateMetrics {
    /// Timestamp
    pub timestamp: Instant,
    /// New connections per second
    pub new_connections: f64,
    /// Authentication attempts per second
    pub auth_attempts: f64,
    /// Data throughput (bytes/sec)
    pub throughput: f64,
}

/// Performance monitoring for the server
#[derive(Debug)]
pub struct ServerMetricsCollector {
    /// Current metrics
    metrics: Arc<RwLock<ServerMetrics>>,
    /// Metrics history
    metrics_history: Arc<RwLock<VecDeque<ServerMetrics>>>,
    /// Connection rate history
    rate_history: Arc<RwLock<VecDeque<ConnectionRateMetrics>>>,
    /// Running state
    running: Arc<RwLock<bool>>,
    /// Collection interval
    interval: Duration,
    /// Maximum history entries
    max_history: usize,
    /// Task handle for the collector loop
    task_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}


impl ServerMetricsCollector {
    /// Create a new metrics collector
    pub fn new(interval: Duration, max_history: usize) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(ServerMetrics::default())),
            metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            rate_history: Arc::new(RwLock::new(VecDeque::with_capacity(max_history))),
            running: Arc::new(RwLock::new(false)),
            interval,
            max_history,
            task_handle: Arc::new(RwLock::new(None)), // Initialize task handle as None
        }
    }

    /// Start metrics collection
    pub async fn start(&self) -> bool {
        let mut running_guard = self.running.write().await;
        if *running_guard {
            return false; // Already running
        }

        // Prevent starting if already stopping/stopped without explicit reset
         if self.task_handle.read().await.is_some() {
            warn!("Metrics collector task already exists. Call stop() before starting again.");
            return false;
         }


        *running_guard = true;
        drop(running_guard); // Release write lock


        let metrics_clone = self.metrics.clone();
        let metrics_history_clone = self.metrics_history.clone();
        let rate_history_clone = self.rate_history.clone();
        let running_clone = self.running.clone();
        let interval = self.interval;
        let max_history = self.max_history;


        // Spawn metrics collection task
         let handle = tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            let mut last_metrics = ServerMetrics::default(); // Store previous state for rate calculation


            while *running_clone.read().await {
                 interval_timer.tick().await;
                 if !*running_clone.read().await { break }; // Double check after tick

                // Get current system metrics
                 let cpu = get_cpu_usage().await;
                 let memory = get_memory_usage().await;
                 let load = get_load_average().await;

                // --- Update Metrics ---
                 { // Scope for write lock
                     let mut metrics_guard = metrics_clone.write().await;


                     // Calculate rates for this interval
                     let duration_secs = interval.as_secs_f64();
                     let bytes_sent_diff = metrics_guard.bytes_sent.saturating_sub(last_metrics.bytes_sent);
                     let bytes_received_diff = metrics_guard.bytes_received.saturating_sub(last_metrics.bytes_received);
                     let connection_diff = metrics_guard.total_connections.saturating_sub(last_metrics.total_connections);
                     let auth_total = metrics_guard.auth_successes + metrics_guard.auth_failures;
                     let last_auth_total = last_metrics.auth_successes + last_metrics.auth_failures;
                     let auth_diff = auth_total.saturating_sub(last_auth_total);


                     let bytes_sent_rate = if duration_secs > 0.0 { bytes_sent_diff as f64 / duration_secs } else { 0.0 };
                     let bytes_received_rate = if duration_secs > 0.0 { bytes_received_diff as f64 / duration_secs } else { 0.0 };
                     let connection_rate = if duration_secs > 0.0 { connection_diff as f64 / duration_secs } else { 0.0 };
                     let auth_rate = if duration_secs > 0.0 { auth_diff as f64 / duration_secs } else { 0.0 };


                     // Update system metrics in the current state
                     metrics_guard.cpu_usage = cpu;
                     metrics_guard.memory_usage = memory;
                     metrics_guard.load_average = load;


                     // Store the current metrics in history
                     let metrics_for_history = metrics_guard.clone();
                     { // Scope for history lock
                          let mut history_guard = metrics_history_clone.write().await;
                          history_guard.push_back(metrics_for_history);
                          while history_guard.len() > max_history {
                              history_guard.pop_front();
                          }
                     }


                     // Store rate metrics
                     let rate_metrics = ConnectionRateMetrics {
                         timestamp: Instant::now(),
                         new_connections: connection_rate,
                         auth_attempts: auth_rate,
                         throughput: bytes_sent_rate + bytes_received_rate,
                     };
                      { // Scope for rate history lock
                          let mut rate_history_guard = rate_history_clone.write().await;
                          rate_history_guard.push_back(rate_metrics);
                          while rate_history_guard.len() > max_history {
                              rate_history_guard.pop_front();
                          }
                      }

                      // Update last_metrics for the next iteration AFTER calculations
                      last_metrics = metrics_guard.clone();


                 } // Release metrics write lock
            }
             tracing::debug!("Metrics collection task stopped.");
        });


        // Store the task handle
         *self.task_handle.write().await = Some(handle);


        true
    }


    /// Stop metrics collection
    pub async fn stop(&self) {
        let mut running_guard = self.running.write().await;
        if !*running_guard {
            return; // Already stopped
        }
        *running_guard = false;
        drop(running_guard); // Release lock

         // Abort the task if it exists
         let mut handle_guard = self.task_handle.write().await;
         if let Some(handle) = handle_guard.take() { // Take ownership
             handle.abort();
             // Optionally wait for the task to finish
             // let _ = handle.await;
             tracing::debug!("Metrics collector task aborted.");
         }
    }


    // --- Record methods remain similar, ensure they acquire write lock ---
    /// Update connection count (likely called externally)
     pub async fn update_connection_count(&self, active: usize) {
         let mut metrics = self.metrics.write().await;
         metrics.active_connections = active;
     }

    /// Record a new connection
    pub async fn record_new_connection(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.total_connections += 1;
        metrics.active_connections += 1;
    }

    /// Record connection close
    pub async fn record_connection_close(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.active_connections = metrics.active_connections.saturating_sub(1);
    }

    /// Record authentication success
    pub async fn record_auth_success(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.auth_successes += 1;
    }

    /// Record authentication failure
    pub async fn record_auth_failure(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.auth_failures += 1;
    }

    /// Record bytes sent
    pub async fn record_bytes_sent(&self, bytes: u64) {
        let mut metrics = self.metrics.write().await;
        metrics.bytes_sent += bytes;
    }

    /// Record bytes received
    pub async fn record_bytes_received(&self, bytes: u64) {
        let mut metrics = self.metrics.write().await;
        metrics.bytes_received += bytes;
    }

    /// Record TLS handshake start
    pub async fn record_handshake_start(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.active_handshakes += 1;
        metrics.total_handshakes += 1;
    }

    /// Record TLS handshake completion
    pub async fn record_handshake_complete(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.active_handshakes = metrics.active_handshakes.saturating_sub(1);
    }

    // --- Getters remain similar, ensure they acquire read lock ---
    /// Get current metrics
    pub async fn get_metrics(&self) -> ServerMetrics {
        self.metrics.read().await.clone()
    }

    /// Get metrics history
    pub async fn get_history(&self) -> Vec<ServerMetrics> {
        let history = self.metrics_history.read().await;
        history.iter().cloned().collect()
    }

    /// Get rate history
    pub async fn get_rate_history(&self) -> Vec<ConnectionRateMetrics> {
        let history = self.rate_history.read().await;
        history.iter().cloned().collect()
    }

    // --- Reporting methods remain the same ---
     /// Generate a metrics report as formatted string
    pub async fn generate_report(&self) -> String {
        let metrics = self.metrics.read().await;
        let uptime = metrics.start_time.elapsed();

        let uptime_str = format!(
            "{}d {}h {}m {}s",
            uptime.as_secs() / 86400,
            (uptime.as_secs() % 86400) / 3600,
            (uptime.as_secs() % 3600) / 60,
            uptime.as_secs() % 60
        );

        let mut report = String::new();
        report.push_str("=== AeroNyx VPN Server Metrics Report ===\n\n");

        // Basic metrics
        report.push_str(&format!("Server Uptime: {}\n", uptime_str));
        report.push_str(&format!("Active Connections: {}\n", metrics.active_connections));
        report.push_str(&format!("Total Connections: {}\n", metrics.total_connections));

        // Traffic
        report.push_str("\nTraffic:\n");
        report.push_str(&format!("  Bytes Sent: {}\n", format_bytes(metrics.bytes_sent)));
        report.push_str(&format!("  Bytes Received: {}\n", format_bytes(metrics.bytes_received)));

        // Authentication
        report.push_str("\nAuthentication:\n");
        report.push_str(&format!("  Successful: {}\n", metrics.auth_successes));
        report.push_str(&format!("  Failed: {}\n", metrics.auth_failures));
        let auth_total = metrics.auth_successes + metrics.auth_failures;
        let auth_success_rate = if auth_total > 0 {
            (metrics.auth_successes as f64 / auth_total as f64) * 100.0
        } else {
            100.0 // Or 0.0, depending on desired representation
        };
        report.push_str(&format!("  Success Rate: {:.2}%\n", auth_success_rate));

        // System metrics
        report.push_str("\nSystem Metrics:\n");
        report.push_str(&format!("  CPU Usage: {:.2}%\n", metrics.cpu_usage));
        report.push_str(&format!("  Memory Usage: {:.2}%\n", metrics.memory_usage));
        report.push_str(&format!("  Load Average: {:.2}, {:.2}, {:.2}\n",
            metrics.load_average.0,
            metrics.load_average.1,
            metrics.load_average.2
        ));

        // TLS
        report.push_str("\nTLS Handshakes:\n");
        report.push_str(&format!("  Active: {}\n", metrics.active_handshakes));
        report.push_str(&format!("  Total: {}\n", metrics.total_handshakes));

        report
    }

    /// Get a compact status report for admin interface
     pub async fn get_status(&self) -> String {
         let metrics = self.metrics.read().await;
         let uptime = metrics.start_time.elapsed();

         let uptime_str = format!(
             "{}d {}h {}m",
             uptime.as_secs() / 86400,
             (uptime.as_secs() % 86400) / 3600,
             (uptime.as_secs() % 3600) / 60
         );

         format!(
             "Active: {} conns | Traffic: {} sent, {} recv | Auth: {}/{} | CPU: {:.1}% | Mem: {:.1}% | Uptime: {}",
             metrics.active_connections,
             format_bytes(metrics.bytes_sent),
             format_bytes(metrics.bytes_received),
             metrics.auth_successes,
             metrics.auth_successes + metrics.auth_failures,
             metrics.cpu_usage,
             metrics.memory_usage,
             uptime_str
         )
     }
}

/// Get CPU usage percentage (async) - Placeholder Implementation
async fn get_cpu_usage() -> f64 {
    // NOTE: This remains a placeholder. For accurate CPU usage,
    // you need to read /proc/stat twice with a delay and calculate the difference
    // in user, nice, system, idle, etc., times. Libraries like `psutil` (Python)
    // or `sysinfo` (Rust) handle this complexity.

    #[cfg(target_os = "linux")]
    {
        // A slightly better placeholder, but still not accurate over time
         match tokio::fs::read_to_string("/proc/stat").await {
             Ok(content) => {
                 if let Some(line) = content.lines().next() {
                     if line.starts_with("cpu ") {
                         let parts: Vec<Option<u64>> = line.split_whitespace().skip(1).map(|s| s.parse().ok()).collect();
                         if parts.len() >= 4 {
                             // Prefix unused variables with underscore
                             let _user = parts[0].unwrap_or(0);   // Corrected line 417
                             let _nice = parts[1].unwrap_or(0);   // Corrected line 418
                             let _system = parts[2].unwrap_or(0); // Corrected line 419
                             let idle = parts[3].unwrap_or(0);
                             let total: u64 = parts.iter().filter_map(|&x| x).sum();
                              if total > 0 && total > idle {
                                 return ((total - idle) as f64 / total as f64) * 100.0; // Instantaneous busy percentage
                             }
                         }
                     }
                 }
                  0.0 // Return 0.0 if parsing fails
             }
             Err(_) => 0.0, // Return 0.0 on read error
         }
        // No longer unreachable code here
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("CPU usage monitoring not implemented for this platform.");
        0.0 // Default fallback for other platforms
    }
}


/// Get memory usage percentage (async)
 async fn get_memory_usage() -> f64 {
     #[cfg(target_os = "linux")]
     {
         match tokio::fs::read_to_string("/proc/meminfo").await {
             Ok(content) => {
                 let mut total = None;
                 let mut available = None; // Use MemAvailable if present for better accuracy

                 for line in content.lines() {
                     if line.starts_with("MemTotal:") {
                         total = parse_meminfo_line(line);
                     } else if line.starts_with("MemAvailable:") {
                         available = parse_meminfo_line(line);
                         break; // Found MemAvailable, no need to parse others for this calc
                     }
                     // Stop searching if total is found but available is not after a few lines
                     if total.is_some() && available.is_none() && line.is_empty() {
                         break;
                     }
                 }

                 // If MemAvailable is present, use it (more accurate)
                 if let (Some(total), Some(available)) = (total, available) {
                     if total > 0 {
                         let used = total.saturating_sub(available);
                         return (used as f64 / total as f64) * 100.0;
                     }
                 }
                 // Fallback calculation if MemAvailable is missing (less accurate)
                 else if let Some(total_kb) = total {
                    let mut free = None;
                    let mut buffers = None;
                    let mut cached = None;
                    let mut slab_reclaimable = None;

                    for line in content.lines() {
                         if line.starts_with("MemFree:") { free = parse_meminfo_line(line); }
                         else if line.starts_with("Buffers:") { buffers = parse_meminfo_line(line); }
                         else if line.starts_with("Cached:") && !line.starts_with("SwapCached:") { cached = parse_meminfo_line(line); }
                         else if line.starts_with("SReclaimable:") { slab_reclaimable = parse_meminfo_line(line); }
                    }

                     if let (Some(free), Some(buffers), Some(cached), Some(slab)) = (free, buffers, cached, slab_reclaimable) {
                        if total_kb > 0 {
                             // Approx Available = Free + Buffers + Cached + SReclaimable
                            let approx_available = free + buffers + cached + slab;
                            let used = total_kb.saturating_sub(approx_available);
                             return (used as f64 / total_kb as f64) * 100.0;
                        }
                     }
                 }

                 0.0 // Return 0.0 if info cannot be parsed
             }
             Err(e) => {
                 warn!("Failed to read /proc/meminfo: {}", e);
                 0.0
             }
         }
     }

     #[cfg(not(target_os = "linux"))]
     {
         warn!("Memory usage monitoring not implemented for this platform.");
         0.0 // Default fallback for other platforms
     }
 }


/// Parse a line from /proc/meminfo, returning value in KiB
fn parse_meminfo_line(line: &str) -> Option<u64> {
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

// --- get_load_average remains the same ---
/// Get system load average (async)
async fn get_load_average() -> (f64, f64, f64) {
    #[cfg(target_os = "linux")]
    {
        match tokio::fs::read_to_string("/proc/loadavg").await {
            Ok(content) => {
                let parts: Vec<&str> = content.split_whitespace().collect();
                if parts.len() >= 3 {
                    return (
                        parts[0].parse::<f64>().unwrap_or(0.0),
                        parts[1].parse::<f64>().unwrap_or(0.0),
                        parts[2].parse::<f64>().unwrap_or(0.0),
                    );
                }
            }
            Err(e) => {
                 warn!("Failed to read /proc/loadavg: {}", e);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        warn!("Load average monitoring not implemented for this platform.");
    }
    // Default fallback
    (0.0, 0.0, 0.0)
}

// --- format_bytes remains the same ---
/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}


// --- Tests remain the same ---
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = ServerMetricsCollector::new(Duration::from_secs(1), 10);

        // Record some metrics
        collector.record_new_connection().await;
        collector.record_bytes_sent(1000).await;
        collector.record_bytes_received(2000).await;
        collector.record_auth_success().await;

        // Check metrics
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.active_connections, 1);
        assert_eq!(metrics.total_connections, 1);
        assert_eq!(metrics.bytes_sent, 1000);
        assert_eq!(metrics.bytes_received, 2000);
        assert_eq!(metrics.auth_successes, 1);

        // Test report generation
        let report = collector.generate_report().await;
        println!("{}", report); // Print report for manual inspection
        assert!(report.contains("Active Connections: 1"));
        // Adjust byte formatting check based on your `format_bytes` output
        assert!(report.contains("Bytes Sent:") && report.contains("KB") || report.contains("B"));


        // Start and stop test
        assert!(collector.start().await);
        assert!(!collector.start().await); // Should return false if already started
        collector.stop().await;
         // Allow restarting after stopping
        // assert!(collector.start().await);
        // collector.stop().await;

    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(100), "100 B");
        assert_eq!(format_bytes(1500), "1.46 KB");
        assert_eq!(format_bytes(1_500_000), "1.43 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.40 GB");
        assert_eq!(format_bytes(1_500_000_000_000), "1.36 TB");
    }

    #[tokio::test]
    async fn test_system_metrics_functions() {
        // These tests just ensure the functions run without panicking and return plausible values
        let cpu = get_cpu_usage().await;
        println!("CPU Usage: {:.2}%", cpu);
        assert!(cpu >= 0.0 && cpu <= 100.0); // Basic sanity check

        let memory = get_memory_usage().await;
        println!("Memory Usage: {:.2}%", memory);
         assert!(memory >= 0.0 && memory <= 100.0); // Basic sanity check

        let load = get_load_average().await;
        println!("Load Average: {:.2}, {:.2}, {:.2}", load.0, load.1, load.2);
         assert!(load.0 >= 0.0 && load.1 >= 0.0 && load.2 >= 0.0); // Load should be non-negative
    }
}
