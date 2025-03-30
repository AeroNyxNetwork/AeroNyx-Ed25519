use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time;

/// Network quality metrics
#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    /// Round-trip time in milliseconds
    pub rtt: f64,
    /// Jitter in milliseconds
    pub jitter: f64,
    /// Packet loss percentage
    pub packet_loss: f64,
    /// Upload throughput in bytes per second
    pub upload_throughput: f64,
    /// Download throughput in bytes per second
    pub download_throughput: f64,
    /// Connection stability score (0-100)
    pub stability_score: u8,
    /// Timestamp of measurement
    pub timestamp: Instant,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            rtt: 0.0,
            jitter: 0.0,
            packet_loss: 0.0,
            upload_throughput: 0.0,
            download_throughput: 0.0,
            stability_score: 100,
            timestamp: Instant::now(),
        }
    }
}

/// Network quality monitor
#[derive(Debug)]
pub struct NetworkMonitor {
    /// Current metrics
    metrics: Arc<Mutex<NetworkMetrics>>,
    /// Historical metrics
    history: Arc<Mutex<VecDeque<NetworkMetrics>>>,
    /// Maximum history size
    max_history: usize,
    /// Monitoring interval
    interval: Duration,
    /// Running flag
    running: Arc<Mutex<bool>>,
    /// Bytes sent since last measurement
    bytes_sent: Arc<Mutex<u64>>,
    /// Bytes received since last measurement
    bytes_received: Arc<Mutex<u64>>,
    /// Ping samples for RTT calculation
    rtt_samples: Arc<Mutex<VecDeque<f64>>>,
    /// Packet loss samples
    packet_loss_samples: Arc<Mutex<VecDeque<f64>>>,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(interval: Duration, max_history: usize) -> Self {
        Self {
            metrics: Arc::new(Mutex::new(NetworkMetrics::default())),
            history: Arc::new(Mutex::new(VecDeque::with_capacity(max_history))),
            max_history,
            interval,
            running: Arc::new(Mutex::new(false)),
            bytes_sent: Arc::new(Mutex::new(0)),
            bytes_received: Arc::new(Mutex::new(0)),
            rtt_samples: Arc::new(Mutex::new(VecDeque::with_capacity(20))),
            packet_loss_samples: Arc::new(Mutex::new(VecDeque::with_capacity(10))),
        }
    }

    /// Start the network monitor
    pub async fn start(&self) -> bool {
        let mut running_guard = self.running.lock().await;
        if *running_guard {
            return false;
        }

        *running_guard = true;
        drop(running_guard); // Release the lock

        // Clone necessary references for the monitoring task
        let metrics = self.metrics.clone();
        let history = self.history.clone();
        let running = self.running.clone();
        let interval = self.interval;
        let max_history = self.max_history;
        let bytes_sent = self.bytes_sent.clone();
        let bytes_received = self.bytes_received.clone();
        let rtt_samples = self.rtt_samples.clone();
        let packet_loss_samples = self.packet_loss_samples.clone();

        // Spawn the monitoring task
        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            let mut last_bytes_sent = 0;
            let mut last_bytes_received = 0;
            let mut last_time = Instant::now();

            while *running.lock().await {
                interval_timer.tick().await;
                let now = Instant::now();
                let elapsed = now.duration_since(last_time).as_secs_f64();

                if elapsed <= 0.0 {
                    continue;
                }

                // Calculate throughput
                let current_bytes_sent = *bytes_sent.lock().await;
                let current_bytes_received = *bytes_received.lock().await;
                
                let upload_throughput = (current_bytes_sent - last_bytes_sent) as f64 / elapsed;
                let download_throughput = (current_bytes_received - last_bytes_received) as f64 / elapsed;

                last_bytes_sent = current_bytes_sent;
                last_bytes_received = current_bytes_received;
                last_time = now;

                // Calculate RTT and jitter
                let rtt_values = rtt_samples.lock().await;
                let (avg_rtt, jitter) = if !rtt_values.is_empty() {
                    let avg = rtt_values.iter().sum::<f64>() / rtt_values.len() as f64;
                    
                    // Calculate jitter as average deviation
                    let jitter = if rtt_values.len() > 1 {
                        let sum_variance = rtt_values.iter()
                            .map(|&rtt| (rtt - avg).abs())
                            .sum::<f64>();
                        sum_variance / rtt_values.len() as f64
                    } else {
                        0.0
                    };
                    
                    (avg, jitter)
                } else {
                    (0.0, 0.0)
                };
                drop(rtt_values);

                // Calculate packet loss
                let packet_loss = {
                    let loss_samples = packet_loss_samples.lock().await;
                    if !loss_samples.is_empty() {
                        loss_samples.iter().sum::<f64>() / loss_samples.len() as f64
                    } else {
                        0.0
                    }
                };

                // Calculate stability score
                let stability_score = {
                    // Start with perfect score
                    let mut score = 100.0;
                    
                    // Penalize for high RTT (>100ms)
                    if avg_rtt > 100.0 {
                        score -= (avg_rtt - 100.0).min(50.0);
                    }
                    
                    // Penalize for high jitter (>20ms)
                    if jitter > 20.0 {
                        score -= (jitter - 20.0).min(25.0);
                    }
                    
                    // Heavily penalize for packet loss
                    score -= (packet_loss * 200.0).min(50.0);
                    
                    // Clamp to 0-100 range
                    score.max(0.0).min(100.0) as u8
                };

                // Update current metrics
                let new_metrics = NetworkMetrics {
                    rtt: avg_rtt,
                    jitter,
                    packet_loss,
                    upload_throughput,
                    download_throughput,
                    stability_score,
                    timestamp: now,
                };

                // Update metrics and history
                {
                    let mut metrics_guard = metrics.lock().await;
                    *metrics_guard = new_metrics.clone();
                }

                {
                    let mut history_guard = history.lock().await;
                    history_guard.push_back(new_metrics);
                    while history_guard.len() > max_history {
                        history_guard.pop_front();
                    }
                }
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
        let mut sent = self.bytes_sent.lock().await;
        *sent += bytes;
    }

    /// Record received bytes
    pub async fn record_received(&self, bytes: u64) {
        let mut received = self.bytes_received.lock().await;
        *received += bytes;
    }

    /// Record RTT sample
    pub async fn record_rtt(&self, rtt_ms: f64) {
        let mut samples = self.rtt_samples.lock().await;
        samples.push_back(rtt_ms);
        while samples.len() > 20 {
            samples.pop_front();
        }
    }

    /// Record packet loss sample (0.0-1.0)
    pub async fn record_packet_loss(&self, loss: f64) {
        let mut samples = self.packet_loss_samples.lock().await;
        samples.push_back(loss);
        while samples.len() > 10 {
            samples.pop_front();
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> NetworkMetrics {
        self.metrics.lock().await.clone()
    }

    /// Get historical metrics
    pub async fn get_history(&self) -> Vec<NetworkMetrics> {
        self.history.lock().await.iter().cloned().collect()
    }

    /// Generate a connection quality report
    pub async fn generate_report(&self) -> String {
        let metrics = self.metrics.lock().await;
        let history = self.history.lock().await;
        
        let mut report = String::new();
        report.push_str("=== AeroNyx VPN Network Quality Report ===\n\n");
        
        // Current metrics
        report.push_str(&format!("Connection Latency: {:.2} ms\n", metrics.rtt));
        report.push_str(&format!("Jitter: {:.2} ms\n", metrics.jitter));
        report.push_str(&format!("Packet Loss: {:.2}%\n", metrics.packet_loss * 100.0));
        report.push_str(&format!("Upload Throughput: {}/s\n", format_bytes(metrics.upload_throughput as u64)));
        report.push_str(&format!("Download Throughput: {}/s\n", format_bytes(metrics.download_throughput as u64)));
        report.push_str(&format!("Connection Stability: {}/100\n", metrics.stability_score));
        
        // Connection quality assessment
        report.push_str("\nConnection Quality: ");
        if metrics.stability_score >= 90 {
            report.push_str("Excellent\n");
            report.push_str("Your connection is performing at optimal levels. Perfect for high-demand applications like video conferencing, gaming, and streaming.\n");
        } else if metrics.stability_score >= 75 {
            report.push_str("Good\n");
            report.push_str("Your connection is stable and should handle most applications well. Minor issues might occur during peak usage times.\n");
        } else if metrics.stability_score >= 50 {
            report.push_str("Fair\n");
            report.push_str("Your connection is functional but experiencing some instability. You may notice occasional disruptions during demanding tasks.\n");
        } else if metrics.stability_score >= 25 {
            report.push_str("Poor\n");
            report.push_str("Your connection has significant issues. You'll likely experience frequent disruptions and poor performance for most applications.\n");
        } else {
            report.push_str("Very Poor\n");
            report.push_str("Your connection is critically unstable. Basic connectivity may be challenging, and most applications will not function reliably.\n");
        }
        
        // Historical trends if available
        if history.len() > 1 {
            report.push_str("\nTrends (past ");
            report.push_str(&format!("{} minutes):\n", (self.interval.as_secs() * history.len() as u64) / 60));
            
            // Calculate trends
            let first_metrics = &history[0];
            let last_metrics = &history[history.len() - 1];
            
            let rtt_trend = last_metrics.rtt - first_metrics.rtt;
            let jitter_trend = last_metrics.jitter - first_metrics.jitter;
            let packet_loss_trend = last_metrics.packet_loss - first_metrics.packet_loss;
            let stability_trend = last_metrics.stability_score as i32 - first_metrics.stability_score as i32;
            
            // Report trends
            report.push_str(&format!("Latency Trend: {}{:.2} ms\n", 
                if rtt_trend > 0.0 { "+" } else { "" }, 
                rtt_trend));
                
            report.push_str(&format!("Jitter Trend: {}{:.2} ms\n", 
                if jitter_trend > 0.0 { "+" } else { "" }, 
                jitter_trend));
                
            report.push_str(&format!("Packet Loss Trend: {}{:.2}%\n", 
                if packet_loss_trend > 0.0 { "+" } else { "" }, 
                packet_loss_trend * 100.0));
                
            report.push_str(&format!("Stability Trend: {}{} points\n", 
                if stability_trend > 0 { "+" } else { "" }, 
                stability_trend));
                
            // Add trend analysis
            if stability_trend < -10 {
                report.push_str("\nWarning: Your connection quality is significantly deteriorating.\n");
            } else if stability_trend > 10 {
                report.push_str("\nGood news: Your connection quality is improving noticeably.\n");
            }
        }
        
        // Recommendations based on metrics
        report.push_str("\nRecommendations:\n");
        
        if metrics.rtt > 200.0 {
            report.push_str("- High latency detected. Consider connecting to a closer server or check for network congestion.\n");
        }
        
        if metrics.jitter > 50.0 {
            report.push_str("- High jitter detected. Your network connection is unstable. Try using a wired connection instead of Wi-Fi if possible.\n");
        }
        
        if metrics.packet_loss > 0.05 {
            report.push_str("- Significant packet loss detected. Check for network interference, congestion, or hardware issues.\n");
        }
        
        if metrics.upload_throughput < 50000.0 || metrics.download_throughput < 50000.0 {
            report.push_str("- Low throughput detected. Your VPN performance may be limited by your internet connection or server capacity.\n");
        }
        
        if metrics.stability_score < 50 {
            report.push_str("- Connection stability is poor. If this persists, try reconnecting or switching to a different server.\n");
        }
        
        // Add security assessment
        report.push_str("\nSecurity Assessment:\n");
        report.push_str("- Your connection is using military-grade encryption with perfect forward secrecy.\n");
        report.push_str("- All traffic is secured with ChaCha20-Poly1305 AEAD authenticated encryption.\n");
        
        if metrics.stability_score < 30 {
            report.push_str("- Warning: Unstable connections may increase vulnerability to certain timing attacks.\n");
            report.push_str("  Consider improving your connection quality for optimal security.\n");
        } else {
            report.push_str("- Your connection stability is sufficient for maintaining a secure encrypted tunnel.\n");
        }
        
        // Add timestamp
        report.push_str(&format!("\nReport generated at: {}\n", 
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
        
        report
    }

  /// Run a network benchmark test
    pub async fn run_benchmark(&self, duration_secs: u64) -> Result<NetworkMetrics, String> {
        // Check if monitor is running
        if !*self.running.lock().await {
            return Err("Network monitor must be running to benchmark".to_string());
        }
        
        // Reset counters
        {
            let mut sent = self.bytes_sent.lock().await;
            *sent = 0;
        }
        {
            let mut received = self.bytes_received.lock().await;
            *received = 0;
        }
        
        // Clear samples
        {
            let mut rtt = self.rtt_samples.lock().await;
            rtt.clear();
        }
        {
            let mut loss = self.packet_loss_samples.lock().await;
            loss.clear();
        }
        
        // Sleep for benchmark duration
        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
        
        // Get latest metrics
        let metrics = self.metrics.lock().await.clone();
        
        Ok(metrics)
    }
    
    /// Check if server connection is healthy
    pub async fn is_connection_healthy(&self) -> bool {
        let metrics = self.metrics.lock().await;
        
        // Define thresholds for a healthy connection
        let max_acceptable_rtt = 300.0; // ms
        let max_acceptable_jitter = 100.0; // ms
        let max_acceptable_packet_loss = 0.1; // 10%
        let min_acceptable_stability = 40; // out of 100
        
        // Check if current metrics are within acceptable ranges
        metrics.rtt <= max_acceptable_rtt &&
        metrics.jitter <= max_acceptable_jitter &&
        metrics.packet_loss <= max_acceptable_packet_loss &&
        metrics.stability_score >= min_acceptable_stability
    }
    
    /// Detect network issues and provide diagnostics
    pub async fn diagnose_issues(&self) -> Vec<String> {
        let metrics = self.metrics.lock().await;
        let mut issues = Vec::new();
        
        // Check for high latency
        if metrics.rtt > 200.0 {
            issues.push(format!("High latency detected: {:.2} ms", metrics.rtt));
        }
        
        // Check for excessive jitter
        if metrics.jitter > 50.0 {
            issues.push(format!("High connection jitter: {:.2} ms", metrics.jitter));
        }
        
        // Check for packet loss
        if metrics.packet_loss > 0.03 {
            issues.push(format!("Packet loss detected: {:.2}%", metrics.packet_loss * 100.0));
        }
        
        // Check for low throughput
        if metrics.download_throughput < 100000.0 {
            issues.push(format!("Low download speed: {}/s", 
                format_bytes(metrics.download_throughput as u64)));
        }
        
        if metrics.upload_throughput < 50000.0 {
            issues.push(format!("Low upload speed: {}/s", 
                format_bytes(metrics.upload_throughput as u64)));
        }
        
        // Check overall stability
        if metrics.stability_score < 50 {
            issues.push(format!("Poor connection stability: {}/100", metrics.stability_score));
        }
        
        issues
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
    async fn test_record_and_retrieve_metrics() {
        let monitor = NetworkMonitor::new(Duration::from_secs(1), 10);
        
        // Record some test data
        monitor.record_sent(1000).await;
        monitor.record_received(2000).await;
        monitor.record_rtt(50.0).await;
        monitor.record_packet_loss(0.01).await;
        
        // Start the monitor
        monitor.start().await;
        
        // Wait for at least one measurement cycle
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Get metrics
        let metrics = monitor.get_metrics().await;
        
        // Verify the metrics are recorded
        assert!(metrics.rtt > 0.0);
        assert!(metrics.stability_score > 0);
        
        // Stop the monitor
        monitor.stop().await;
    }
    
    #[tokio::test]
    async fn test_generate_report() {
        let monitor = NetworkMonitor::new(Duration::from_secs(1), 10);
        
        // Record some test data
        monitor.record_rtt(100.0).await;
        monitor.record_jitter(10.0).await;
        monitor.record_packet_loss(0.02).await;
        
        // Get report
        let report = monitor.generate_report().await;
        
        // Verify report contains expected sections
        assert!(report.contains("Connection Latency"));
        assert!(report.contains("Jitter"));
        assert!(report.contains("Packet Loss"));
        assert!(report.contains("Connection Quality"));
    }
}
