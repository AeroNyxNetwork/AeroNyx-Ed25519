// src/server/metrics.rs
//! Server metrics collection and reporting.
//!
//! This module provides functionality for collecting, tracking,
//! and reporting server performance metrics.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, info};

use crate::utils;

/// Server performance metrics
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

/// Connection rate metrics
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
        }
    }

    /// Start metrics collection
    pub async fn start(&self) -> bool {
        let mut running = self.running.write().await;
        if *running {
            return false;
        }

        *running = true;
        drop(running);

        let metrics = self.metrics.clone();
        let metrics_history = self.metrics_history.clone();
        let rate_history = self.rate_history.clone();
        let running = self.running.clone();
        let interval = self.interval;
        let max_history = self.max_history;

        // Spawn metrics collection task
        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            let mut last_bytes_sent = 0;
            let mut last_bytes_received = 0;
            let mut last_total_connections = 0;
            let mut last_auth_attempts = 0;

            while *running.read().await {
                interval_timer.tick().await;

                // Get current system metrics
                let cpu = get_cpu_usage().await;
                let memory = get_memory_usage().await;
                let load = get_load_average().await;

                // Update system metrics
                {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.cpu_usage = cpu;
                    metrics_guard.memory_usage = memory;
                    metrics_guard.load_average = load;

                    // Calculate rates for this interval
                    let duration_secs = interval.as_secs_f64();
                    let bytes_sent_rate = (metrics_guard.bytes_sent - last_bytes_sent) as f64 / duration_secs;
                    let bytes_received_rate = (metrics_guard.bytes_received - last_bytes_received) as f64 / duration_secs;
                    let connection_rate = (metrics_guard.total_connections - last_total_connections) as f64 / duration_secs;
                    let auth_rate = ((metrics_guard.auth_successes + metrics_guard.auth_failures) - last_auth_attempts) as f64 / duration_secs;

                    // Update last values
                    last_bytes_sent = metrics_guard.bytes_sent;
                    last_bytes_received = metrics_guard.bytes_received;
                    last_total_connections = metrics_guard.total_connections;
                    last_auth_attempts = metrics_guard.auth_successes + metrics_guard.auth_failures;

                    // Store the current metrics in history
                    let metrics_clone = metrics_guard.clone();
                    
                    let mut history_guard = metrics_history.write().await;
                    history_guard.push_back(metrics_clone);

                    // Trim history if needed
                    while history_guard.len() > max_history {
                        history_guard.pop_front();
                    }

                    // Store rate metrics
                    let rate_metrics = ConnectionRateMetrics {
                        timestamp: Instant::now(),
                        new_connections: connection_rate,
                        auth_attempts: auth_rate,
                        throughput: bytes_sent_rate + bytes_received_rate,
                    };

                    let mut rate_history_guard = rate_history.write().await;
                    rate_history_guard.push_back(rate_metrics);

                    // Trim rate history if needed
                    while rate_history_guard.len() > max_history {
                        rate_history_guard.pop_front();
                    }
                }
            }
        });

        true
    }

    /// Stop metrics collection
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Update connection count
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
        if metrics.active_connections > 0 {
            metrics.active_connections -= 1;
        }
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
        if metrics.active_handshakes > 0 {
            metrics.active_handshakes -= 1;
        }
    }

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
        let auth_success_rate = if metrics.auth_successes + metrics.auth_failures > 0 {
            (metrics.auth_successes as f64 / (metrics.auth_successes + metrics.auth_failures) as f64) * 100.0
        } else {
            0.0
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
            "Active: {} conns | Traffic: {} sent, {} recv | Auth: {}/{} | Uptime: {}",
            metrics.active_connections,
            format_bytes(metrics.bytes_sent),
            format_bytes(metrics.bytes_received),
            metrics.auth_successes,
            metrics.auth_successes + metrics.auth_failures,
            uptime_str
        )
    }
}

/// Get CPU usage percentage (async)
async fn get_cpu_usage() -> f64 {
    // This is a simplistic implementation
    // In a real application, you'd want to use a library like sysinfo
    // or implement proper /proc/stat parsing
    
    #[cfg(target_os = "linux")]
    {
        match tokio::fs::read_to_string("/proc/stat").await {
            Ok(content) => {
                let lines: Vec<&str> = content.lines().collect();
                if lines.is_empty() || !lines[0].starts_with("cpu ") {
                    return 0.0;
                }
                
                // Very simple calculation - just for demonstration
                // Real implementation would track previous measurements
                // and calculate difference over time
                return 25.0; // Placeholder value
            }
            Err(_) => 0.0,
        }
    }
    
    // Default fallback for other platforms
    0.0
}

/// Get memory usage percentage (async)
async fn get_memory_usage() -> f64 {
    // Simplified implementation
    #[cfg(target_os = "linux")]
    {
        match tokio::fs::read_to_string("/proc/meminfo").await {
            Ok(content) => {
                let mut total = None;
                let mut free = None;
                let mut buffers = None;
                let mut cached = None;
                
                for line in content.lines() {
                    if line.starts_with("MemTotal:") {
                        total = parse_meminfo_line(line);
                    } else if line.starts_with("MemFree:") {
                        free = parse_meminfo_line(line);
                    } else if line.starts_with("Buffers:") {
                        buffers = parse_meminfo_line(line);
                    } else if line.starts_with("Cached:") && !line.starts_with("SwapCached:") {
                        cached = parse_meminfo_line(line);
                    }
                    
                    if total.is_some() && free.is_some() && buffers.is_some() && cached.is_some() {
                        break;
                    }
                }
                
                if let (Some(total), Some(free), Some(buffers), Some(cached)) = (total, free, buffers, cached) {
                    if total > 0 {
                        let used = total - free - buffers - cached;
                        return (used as f64 / total as f64) * 100.0;
                    }
                }
                
                return 0.0;
            }
            Err(_) => 0.0,
        }
    }
    
    // Default fallback for other platforms
    0.0
}

/// Parse a line from /proc/meminfo
fn parse_meminfo_line(line: &str) -> Option<u64> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse::<u64>().ok()
    } else {
        None
    }
}

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
            Err(_) => {}
        }
    }
    
    // Default fallback for other platforms
    (0.0, 0.0, 0.0)
}

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
        assert!(report.contains("Active Connections: 1"));
        assert!(report.contains("Bytes Sent: 1000 B"));
    }
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(100), "100 B");
        assert_eq!(format_bytes(1500), "1.46 KB");
        assert_eq!(format_bytes(1500000), "1.43 MB");
        assert_eq!(format_bytes(1500000000), "1.40 GB");
        assert_eq!(format_bytes(1500000000000), "1.36 TB");
    }
}
