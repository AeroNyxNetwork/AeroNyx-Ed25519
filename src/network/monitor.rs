// src/network/monitor.rs
//! Network monitoring functionality.
//!
//! This module provides tools for monitoring network performance,
//! tracking traffic statistics, and detecting anomalies.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time;
use tracing::{debug, info, warn};

/// Network statistics data
#[derive(Debug, Clone)]
pub struct NetworkStats {
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Current send rate (bytes/sec)
    pub send_rate: f64,
    /// Current receive rate (bytes/sec)
    pub receive_rate: f64,
    /// Connection latency in milliseconds
    pub latency_ms: f64,
    /// Packet loss percentage (0-100)
    pub packet_loss: f64,
    /// Measurement timestamp
    pub timestamp: Instant,
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            send_rate: 0.0,
            receive_rate: 0.0,
            latency_ms: 0.0,
            packet_loss: 0.0,
            timestamp: Instant::now(),
        }
    }
}

/// Client-specific network statistics
#[derive(Debug, Clone)]
pub struct ClientStats {
    /// Client identifier
    pub client_id: String,
    /// Network statistics
    pub stats: NetworkStats,
    /// Rate limiting applied
    pub rate_limited: bool,
    /// Current bandwidth limit (bytes/sec, 0 = unlimited)
    pub bandwidth_limit: u64,
}

/// Traffic anomaly detection result
#[derive(Debug, Clone)]
pub struct TrafficAnomaly {
    /// Type of anomaly
    pub anomaly_type: String,
    /// Source (client ID or IP)
    pub source: String,
    /// Detection time
    pub detected_at: Instant,
    /// Anomaly details
    pub details: String,
    /// Severity (1-5, where 5 is most severe)
    pub severity: u8,
}

/// Network monitor for tracking performance and security metrics
#[derive(Debug)]
pub struct NetworkMonitor {
    /// Global network statistics
    stats: Arc<Mutex<NetworkStats>>,
    /// Client-specific statistics
    client_stats: Arc<Mutex<HashMap<String, ClientStats>>>,
    /// History of network statistics
    stats_history: Arc<Mutex<VecDeque<NetworkStats>>>,
    /// Detected anomalies
    anomalies: Arc<Mutex<VecDeque<TrafficAnomaly>>>,
    /// Maximum history size
    max_history: usize,
    /// Running state
    running: Arc<Mutex<bool>>,
    /// Monitoring interval
    interval: Duration,
    /// Rate samples for latency
    latency_samples: Arc<Mutex<VecDeque<f64>>>,
    /// Packet loss samples
    packet_loss_samples: Arc<Mutex<VecDeque<f64>>>,
    /// Bytes sent since last measurement
    bytes_sent_interval: Arc<Mutex<u64>>,
    /// Bytes received since last measurement
    bytes_received_interval: Arc<Mutex<u64>>,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(interval: Duration, max_history: usize) -> Self {
        Self {
            stats: Arc::new(Mutex::new(NetworkStats::default())),
            client_stats: Arc::new(Mutex::new(HashMap::new())),
            stats_history: Arc::new(Mutex::new(VecDeque::with_capacity(max_history))),
            anomalies: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            max_history,
            running: Arc::new(Mutex::new(false)),
            interval,
            latency_samples: Arc::new(Mutex::new(VecDeque::with_capacity(20))),
            packet_loss_samples: Arc::new(Mutex::new(VecDeque::with_capacity(10))),
            bytes_sent_interval: Arc::new(Mutex::new(0)),
            bytes_received_interval: Arc::new(Mutex::new(0)),
        }
    }
    
    /// Start the network monitor
    pub async fn start(&self) -> bool {
        let mut running_guard = self.running.lock().await;
        if *running_guard {
            return false;
        }
        
        *running_guard = true;
        drop(running_guard);
        
        // Clone necessary references for the monitoring task
        let stats = self.stats.clone();
        let client_stats = self.client_stats.clone();
        let stats_history = self.stats_history.clone();
        let running = self.running.clone();
        let max_history = self.max_history;
        let interval = self.interval;
        let bytes_sent_interval = self.bytes_sent_interval.clone();
        let bytes_received_interval = self.bytes_received_interval.clone();
        let latency_samples = self.latency_samples.clone();
        let packet_loss_samples = self.packet_loss_samples.clone();
        let anomalies = self.anomalies.clone();
        
        // Spawn background monitoring task
        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            
            while *running.lock().await {
                interval_timer.tick().await;
                
                // Update stats
                let now = Instant::now();
                
                // Calculate rates
                let bytes_sent = *bytes_sent_interval.lock().await;
                let bytes_received = *bytes_received_interval.lock().await;
                
                let send_rate = bytes_sent as f64 / interval.as_secs_f64();
                let receive_rate = bytes_received as f64 / interval.as_secs_f64();
                
                // Reset interval counters
                *bytes_sent_interval.lock().await = 0;
                *bytes_received_interval.lock().await = 0;
                
                // Calculate averages
                let avg_latency = {
                    let samples = latency_samples.lock().await;
                    if samples.is_empty() {
                        0.0
                    } else {
                        samples.iter().sum::<f64>() / samples.len() as f64
                    }
                };
                
                let avg_packet_loss = {
                    let samples = packet_loss_samples.lock().await;
                    if samples.is_empty() {
                        0.0
                    } else {
                        samples.iter().sum::<f64>() / samples.len() as f64
                    }
                };
                
                // Update global stats
                {
                    let mut stats_guard = stats.lock().await;
                    stats_guard.send_rate = send_rate;
                    stats_guard.receive_rate = receive_rate;
                    stats_guard.latency_ms = avg_latency;
                    stats_guard.packet_loss = avg_packet_loss;
                    stats_guard.timestamp = now;
                    
                    // Add to history
                    let mut history_guard = stats_history.lock().await;
                    history_guard.push_back(stats_guard.clone());
                    
                    // Trim history if needed
                    while history_guard.len() > max_history {
                        history_guard.pop_front();
                    }
                }
                
                // Check for anomalies
                detect_anomalies(&client_stats, &anomalies).await;
            }
        });
        
        true
    }
    
    /// Stop the network monitor
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        *running = false;
    }
    
    /// Record sent bytes
    pub async fn record_sent(&self, bytes: u64) {
        // Update global stats
        {
            let mut stats = self.stats.lock().await;
            stats.bytes_sent += bytes;
            stats.packets_sent += 1;
        }
        
        // Update interval counter
        {
            let mut interval_counter = self.bytes_sent_interval.lock().await;
            *interval_counter += bytes;
        }
    }
    
    /// Record received bytes
    pub async fn record_received(&self, bytes: u64) {
        // Update global stats
        {
            let mut stats = self.stats.lock().await;
            stats.bytes_received += bytes;
            stats.packets_received += 1;
        }
        
        // Update interval counter
        {
            let mut interval_counter = self.bytes_received_interval.lock().await;
            *interval_counter += bytes;
        }
    }
    
    /// Record client traffic metrics
    pub async fn record_client_traffic(&self, client_id: &str, bytes_sent: u64, bytes_received: u64) -> bool {
        let mut client_stats_map = self.client_stats.lock().await;
        
        let client_stat = client_stats_map.entry(client_id.to_string()).or_insert_with(|| {
            ClientStats {
                client_id: client_id.to_string(),
                stats: NetworkStats::default(),
                rate_limited: false,
                bandwidth_limit: 0,
            }
        });
        
        client_stat.stats.bytes_sent += bytes_sent;
        client_stat.stats.bytes_received += bytes_received;
        
        if bytes_sent > 0 {
            client_stat.stats.packets_sent += 1;
        }
        
        if bytes_received > 0 {
            client_stat.stats.packets_received += 1;
        }
        
        // Update rates (simple EMA with 0.3 alpha)
        let alpha = 0.3;
        let now = Instant::now();
        let elapsed = now.duration_since(client_stat.stats.timestamp).as_secs_f64();
        
        if elapsed > 0.0 {
            let send_rate = bytes_sent as f64 / elapsed;
            let receive_rate = bytes_received as f64 / elapsed;
            
            client_stat.stats.send_rate = (alpha * send_rate) + ((1.0 - alpha) * client_stat.stats.send_rate);
            client_stat.stats.receive_rate = (alpha * receive_rate) + ((1.0 - alpha) * client_stat.stats.receive_rate);
            client_stat.stats.timestamp = now;
        }
        
        true
    }
    
    /// Record latency measurement for a client
    pub async fn record_latency(&self, client_id: &str, latency_ms: f64) -> bool {
        // Update global latency samples
        {
            let mut samples = self.latency_samples.lock().await;
            samples.push_back(latency_ms);
            while samples.len() > 20 {
                samples.pop_front();
            }
        }
        
        // Update client-specific latency
        {
            let mut client_stats_map = self.client_stats.lock().await;
            
            if let Some(client_stat) = client_stats_map.get_mut(client_id) {
                client_stat.stats.latency_ms = latency_ms;
            }
        }
        
        true
    }
    
    /// Record packet loss sample (0.0-1.0)
    pub async fn record_packet_loss(&self, loss: f64) {
        let mut samples = self.packet_loss_samples.lock().await;
        samples.push_back(loss);
        while samples.len() > 10 {
            samples.pop_front();
        }
    }
    
    /// Get current stats
    pub async fn get_stats(&self) -> NetworkStats {
        self.stats.lock().await.clone()
    }
    
    /// Get stats history
    pub async fn get_history(&self) -> Vec<NetworkStats> {
        let history = self.stats_history.lock().await;
        history.iter().cloned().collect()
    }
    
    /// Get client stats
    pub async fn get_client_stats(&self, client_id: &str) -> Option<ClientStats> {
        let client_stats_map = self.client_stats.lock().await;
        client_stats_map.get(client_id).cloned()
    }
    
    /// Get all client stats
    pub async fn get_all_client_stats(&self) -> HashMap<String, ClientStats> {
        let client_stats_map = self.client_stats.lock().await;
        client_stats_map.clone()
    }
    
    /// Set bandwidth limit for a client (0 = unlimited)
    pub async fn set_bandwidth_limit(&self, client_id: &str, limit: u64) {
        let mut client_stats_map = self.client_stats.lock().await;
        
        if let Some(client_stat) = client_stats_map.get_mut(client_id) {
            client_stat.bandwidth_limit = limit;
            debug!("Set bandwidth limit for client {} to {} bytes/sec", client_id, limit);
        } else {
            // Create a new entry if client doesn't exist yet
            client_stats_map.insert(client_id.to_string(), ClientStats {
                client_id: client_id.to_string(),
                stats: NetworkStats::default(),
                rate_limited: false,
                bandwidth_limit: limit,
            });
            debug!("Created new client stats entry with bandwidth limit {} bytes/sec for client {}", limit, client_id);
        }
    }
    
    /// Check if a client exceeds their bandwidth limit
    pub async fn check_bandwidth_limit(&self, client_id: &str, bytes: u64, duration: Duration) -> bool {
        let mut client_stats_map = self.client_stats.lock().await;
        
        if let Some(client_stat) = client_stats_map.get_mut(client_id) {
            if client_stat.bandwidth_limit == 0 {
                // No limit
                return false;
            }
            
            // Calculate current rate
            let rate = bytes as f64 / duration.as_secs_f64();
            
            // Check if rate exceeds limit
            let exceeded = rate > client_stat.bandwidth_limit as f64;
            
            // Update rate limited flag
            client_stat.rate_limited = exceeded;
            
            if exceeded {
                debug!(
                    "Client {} exceeded bandwidth limit: {} > {} bytes/sec",
                    client_id, rate, client_stat.bandwidth_limit
                );
            }
            
            exceeded
        } else {
            // No stats for this client yet, not rate limited
            false
        }
    }
    
    /// Get recent anomalies within a time window
    pub async fn get_anomalies(&self, window: Duration) -> Vec<TrafficAnomaly> {
        let anomalies = self.anomalies.lock().await;
        let now = Instant::now();
        
        anomalies
            .iter()
            .filter(|a| now.duration_since(a.detected_at) < window)
            .cloned()
            .collect()
    }
    
    /// Generate a network health report
    pub async fn generate_report(&self) -> String {
        let stats = self.stats.lock().await;
        let history = self.stats_history.lock().await;
        
        let mut report = String::new();
        report.push_str("=== AeroNyx VPN Network Health Report ===\n\n");
        
        // Current metrics
        report.push_str(&format!("Current throughput: {} in, {} out\n",
            format_bytes(stats.receive_rate as u64),
            format_bytes(stats.send_rate as u64)));
            
        report.push_str(&format!("Latency: {:.2} ms\n", stats.latency_ms));
        report.push_str(&format!("Packet loss: {:.2}%\n", stats.packet_loss * 100.0));
        report.push_str(&format!("Total traffic: {} received, {} sent\n",
            format_bytes(stats.bytes_received),
            format_bytes(stats.bytes_sent)));
            
        // Connection quality assessment
        let quality_score = calculate_connection_quality(&stats);
        
        report.push_str(&format!("\nConnection quality: {}/100\n", quality_score));
        report.push_str(&connection_quality_description(quality_score));
        
        // If we have history, show trends
        if history.len() > 1 {
            report.push_str("\nNetwork trends:\n");
            
            let first = &history[0];
            let last = &history[history.len() - 1];
            
            let latency_trend = last.latency_ms - first.latency_ms;
            let packet_loss_trend = last.packet_loss - first.packet_loss;
            let throughput_trend = last.receive_rate - first.receive_rate;
            
            report.push_str(&format!("  Latency: {}{:.2} ms\n",
                if latency_trend > 0.0 { "+" } else { "" }, latency_trend));
                
            report.push_str(&format!("  Packet loss: {}{:.2}%\n",
                if packet_loss_trend > 0.0 { "+" } else { "" }, packet_loss_trend * 100.0));
                
            report.push_str(&format!("  Throughput: {}{}/s\n",
                if throughput_trend > 0.0 { "+" } else { "" }, 
                format_bytes(throughput_trend.abs() as u64)));
        }
        
        // Anomalies
        let recent_anomalies = self.get_anomalies(Duration::from_secs(3600)).await;
        if !recent_anomalies.is_empty() {
            report.push_str("\nRecent anomalies:\n");
            for anomaly in &recent_anomalies {
                report.push_str(&format!("  [{}] {}: {} (severity: {})\n",
                    anomaly.source,
                    anomaly.anomaly_type,
                    anomaly.details,
                    anomaly.severity));
            }
        }
        
        report
    }
    
    /// Run a network performance test
    pub async fn run_performance_test(&self, duration: Duration) -> NetworkStats {
        info!("Starting network performance test for {} seconds", duration.as_secs());
        
        // Reset counters
        {
            let mut stats = self.stats.lock().await;
            stats.bytes_sent = 0;
            stats.bytes_received = 0;
            stats.packets_sent = 0;
            stats.packets_received = 0;
        }
        
        // Wait for the test duration
        tokio::time::sleep(duration).await;
        
        // Get results
        let final_stats = self.stats.lock().await.clone();
        
        info!("Performance test completed: {} in, {} out, {:.2}ms latency",
            format_bytes(final_stats.bytes_received),
            format_bytes(final_stats.bytes_sent),
            final_stats.latency_ms);
            
        final_stats
    }
}

/// Helper function to detect network anomalies
async fn detect_anomalies(
    client_stats: &Arc<Mutex<HashMap<String, ClientStats>>>,
    anomalies: &Arc<Mutex<VecDeque<TrafficAnomaly>>>
) {
    let clients = client_stats.lock().await;
    let mut new_anomalies = Vec::new();
    
    for (client_id, stats) in clients.iter() {
        // Check for high latency
        // Check for high latency
        if stats.stats.latency_ms > 200.0 {
            new_anomalies.push(TrafficAnomaly {
                anomaly_type: "High Latency".to_string(),
                source: client_id.clone(),
                detected_at: Instant::now(),
                details: format!("{:.2} ms latency detected", stats.stats.latency_ms),
                severity: 2,
            });
        }
        
        // Check for significant packet loss
        if stats.stats.packet_loss > 0.05 {
            new_anomalies.push(TrafficAnomaly {
                anomaly_type: "Packet Loss".to_string(),
                source: client_id.clone(),
                detected_at: Instant::now(),
                details: format!("{:.2}% packet loss detected", stats.stats.packet_loss * 100.0),
                severity: 3,
            });
        }
        
        // Check for unusually high bandwidth usage
        if stats.stats.send_rate > 10_000_000.0 || stats.stats.receive_rate > 10_000_000.0 {
            new_anomalies.push(TrafficAnomaly {
                anomaly_type: "High Bandwidth".to_string(),
                source: client_id.clone(),
                detected_at: Instant::now(),
                details: format!(
                    "Unusual bandwidth: {} in, {} out",
                    format_bytes(stats.stats.receive_rate as u64),
                    format_bytes(stats.stats.send_rate as u64)
                ),
                severity: 4,
            });
        }
    }
    
    // Add new anomalies to the log
    if !new_anomalies.is_empty() {
        let mut anomalies_lock = anomalies.lock().await;
        
        for anomaly in new_anomalies {
            warn!(
                "Network anomaly detected: [{}] {} - {} (severity: {})",
                anomaly.source, anomaly.anomaly_type, anomaly.details, anomaly.severity
            );
            
            anomalies_lock.push_back(anomaly);
            
            // Limit size
            if anomalies_lock.len() > 100 {
                anomalies_lock.pop_front();
            }
        }
    }
}

/// Calculate a connection quality score (0-100)
fn calculate_connection_quality(stats: &NetworkStats) -> u8 {
    // Start with a perfect score
    let mut score = 100.0;
    
    // Deduct for high latency
    if stats.latency_ms > 50.0 {
        let latency_penalty = ((stats.latency_ms - 50.0) / 5.0).min(40.0);
        score -= latency_penalty;
    }
    
    // Deduct for packet loss
    score -= (stats.packet_loss * 200.0).min(50.0);
    
    // Deduct for low throughput
    if stats.send_rate < 1_000_000.0 || stats.receive_rate < 1_000_000.0 {
        // Less than 1 MB/s is considered low for a VPN
        let throughput_penalty = 10.0;
        score -= throughput_penalty;
    }
    
    // Ensure score is in range 0-100
    score = score.max(0.0).min(100.0);
    
    score as u8
}

/// Get a human-readable description of connection quality
fn connection_quality_description(score: u8) -> String {
    match score {
        90..=100 => "Excellent: Your connection is performing optimally with low latency and high throughput.".to_string(),
        75..=89 => "Good: Your connection is stable and suitable for most applications.".to_string(),
        50..=74 => "Fair: Your connection may experience occasional issues, particularly with latency-sensitive applications.".to_string(),
        25..=49 => "Poor: Your connection is experiencing significant issues that may impact performance.".to_string(),
        _ => "Critical: Your connection is severely degraded and may be unstable.".to_string(),
    }
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
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
    async fn test_record_traffic() {
        let monitor = NetworkMonitor::new(Duration::from_secs(1), 10);
        
        // Record some traffic
        monitor.record_sent(1000).await;
        monitor.record_received(2000).await;
        
        // Check global stats
        let stats = monitor.get_stats().await;
        assert_eq!(stats.bytes_sent, 1000);
        assert_eq!(stats.bytes_received, 2000);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
    }
    
    #[tokio::test]
    async fn test_client_traffic() {
        let monitor = NetworkMonitor::new(Duration::from_secs(1), 10);
        let client_id = "test-client";
        
        // Record client traffic
        assert!(monitor.record_client_traffic(client_id, 1000, 2000).await);
        
        // Check client stats
        let client_stats = monitor.get_client_stats(client_id).await.unwrap();
        assert_eq!(client_stats.stats.bytes_sent, 1000);
        assert_eq!(client_stats.stats.bytes_received, 2000);
    }
    
    #[tokio::test]
    async fn test_bandwidth_limit() {
        let monitor = NetworkMonitor::new(Duration::from_secs(1), 10);
        let client_id = "limited-client";

        // Set a bandwidth limit
        monitor.set_bandwidth_limit(client_id, 1000).await; // 1000 bytes/sec

        // Test exceeding the limit
        let exceeded = monitor.check_bandwidth_limit(client_id, 2000, Duration::from_secs(1)).await;
        assert!(exceeded);

        // --- FIX: Check rate limited flag *immediately* after exceeding ---
        let client_stats_after_exceed = monitor.get_client_stats(client_id).await.unwrap();
        assert!(client_stats_after_exceed.rate_limited, "Flag should be true after exceeding limit");
        // --- End of FIX ---

        // Test within the limit
        let within_limit = monitor.check_bandwidth_limit(client_id, 500, Duration::from_secs(1)).await;
        assert!(!within_limit);

        // Check that rate limited flag was set back to false after the within_limit check
        let client_stats_after_within = monitor.get_client_stats(client_id).await.unwrap();
        // This assertion should now reflect the state AFTER the within_limit check
        assert!(!client_stats_after_within.rate_limited, "Flag should be false after a check within the limit");
    }
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(100), "100 B");
        assert_eq!(format_bytes(1500), "1.46 KB");
        assert_eq!(format_bytes(1500000), "1.43 MB");
        assert_eq!(format_bytes(1500000000), "1.40 GB");
    }
    
    #[test]
    fn test_connection_quality() {
        // Excellent connection
        let excellent = NetworkStats {
            latency_ms: 20.0,
            packet_loss: 0.0,
            send_rate: 5_000_000.0,
            receive_rate: 5_000_000.0,
            ..NetworkStats::default()
        };
        assert!(calculate_connection_quality(&excellent) >= 90);
        
        // Poor connection
        let poor = NetworkStats {
            latency_ms: 300.0,
            packet_loss: 0.1,
            send_rate: 500_000.0,
            receive_rate: 500_000.0,
            ..NetworkStats::default()
        };
        assert!(calculate_connection_quality(&poor) < 50);
    }
}
