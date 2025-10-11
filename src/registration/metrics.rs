// src/registration/metrics.rs
// ============================================
// AeroNyx Privacy Network - System Metrics Collection Module
// Version: 1.3.0 - Complete network rate tracking implementation
// ============================================
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// Creation Reason: System metrics collection for node monitoring
// Modification Reason: Integrated network rate tracking with RegistrationManager
// Main Functionality: 
// - Collect CPU, memory, disk, network metrics for heartbeats
// - Calculate actual network usage based on rate over time
// - Provide INFO level logging for all metrics
// - Track network statistics persistently between measurements
// Dependencies: Used by RegistrationManager for periodic heartbeat messages
//
// Main Logical Flow:
// 1. Collect system metrics (CPU, memory, disk, network)
// 2. Calculate network rate using stored previous stats
// 3. Update stored stats for next calculation
// 4. Log all metrics at INFO level for visibility
// 5. Return accurate usage percentages for heartbeat
//
// ⚠️ Important Note for Next Developer:
// - Network usage now uses actual rate calculation via last_network_stats
// - ALL metrics use info! logging for production visibility
// - The get_network_usage() method now returns accurate percentages
// - Network stats are automatically updated on each measurement
//
// Last Modified: v1.3.0 - Complete network rate tracking
// ============================================

use super::RegistrationManager;
use crate::utils;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, warn, info, error};

/// Network statistics for tracking bandwidth usage
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub timestamp: u64,  // Unix timestamp in seconds
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl RegistrationManager {
    /// Get current CPU usage percentage with INFO level logging
    pub async fn get_cpu_usage(&self) -> f64 {
        if let Ok(result) = tokio::task::spawn_blocking(|| utils::system::get_load_average()).await {
            if let Ok((one_min, five_min, fifteen_min)) = result {
                // Get CPU count for normalization
                let cpu_count = match tokio::task::spawn_blocking(|| {
                    sys_info::cpu_num().unwrap_or(1) as f64
                }).await {
                    Ok(count) => count,
                    Err(_) => 1.0,
                };
                
                // Calculate CPU usage as percentage
                let usage = (one_min / cpu_count * 100.0).min(100.0).max(0.0);
                
                // Use INFO level logging so it appears in production logs
                info!("CPU stats - Usage: {:.2}%, Load averages: {:.2}/{:.2}/{:.2}, Cores: {}", 
                      usage, one_min, five_min, fifteen_min, cpu_count);
                
                usage
            } else {
                warn!("Failed to get load average, returning 0% CPU usage");
                0.0
            }
        } else {
            error!("Failed to spawn blocking task for CPU usage");
            0.0
        }
    }

    /// Get current memory usage percentage with detailed logging
    pub async fn get_memory_usage(&self) -> f64 {
        match tokio::task::spawn_blocking(|| utils::system::get_system_memory()).await {
            Ok(Ok((total, available))) => {
                // Ensure we don't have invalid values
                if total == 0 {
                    error!("System reported 0 total memory, which is impossible");
                    return 0.0;
                }
                
                // Calculate used memory
                let used = total.saturating_sub(available);
                let percentage = (used as f64 / total as f64 * 100.0).min(100.0).max(0.0);
                
                // Log detailed memory statistics at INFO level
                info!(
                    "Memory stats - Total: {} MB, Available: {} MB, Used: {} MB, Usage: {:.2}%",
                    total / (1024 * 1024),
                    available / (1024 * 1024),
                    used / (1024 * 1024),
                    percentage
                );
                
                percentage
            }
            Ok(Err(e)) => {
                error!("Failed to get system memory: {}", e);
                
                // Try alternative method on Linux
                #[cfg(target_os = "linux")]
                {
                    if let Ok(mem_pct) = self.get_memory_usage_alternative().await {
                        info!("Memory usage (alternative method): {:.2}%", mem_pct);
                        return mem_pct;
                    }
                }
                
                0.0
            }
            Err(e) => {
                error!("Spawn blocking task failed: {}", e);
                0.0
            }
        }
    }
    
    /// Alternative memory usage calculation method for Linux
    #[cfg(target_os = "linux")]
    async fn get_memory_usage_alternative(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string("/proc/meminfo").await?;
        
        let mut mem_total = None;
        let mut mem_available = None;
        let mut mem_free = None;
        let mut buffers = None;
        let mut cached = None;
        
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                mem_total = line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok());
            } else if line.starts_with("MemAvailable:") {
                mem_available = line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok());
            } else if line.starts_with("MemFree:") {
                mem_free = line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok());
            } else if line.starts_with("Buffers:") {
                buffers = line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok());
            } else if line.starts_with("Cached:") {
                cached = line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok());
            }
        }
        
        if let Some(total) = mem_total {
            if total > 0 {
                // Try to use MemAvailable first (more accurate)
                if let Some(available) = mem_available {
                    let used = total.saturating_sub(available);
                    let percentage = (used as f64 / total as f64 * 100.0).min(100.0);
                    return Ok(percentage);
                }
                
                // Fallback to calculating available from free + buffers + cached
                if let (Some(free), Some(buf), Some(cache)) = (mem_free, buffers, cached) {
                    let available = free + buf + cache;
                    let used = total.saturating_sub(available);
                    let percentage = (used as f64 / total as f64 * 100.0).min(100.0);
                    return Ok(percentage);
                }
            }
        }
        
        Err("Could not parse memory info".into())
    }

    /// Get current disk usage percentage with INFO level logging
    pub async fn get_disk_usage(&self) -> f64 {
        match tokio::task::spawn_blocking(|| utils::system::get_disk_usage()).await {
            Ok(Ok(usage)) => {
                // Use INFO level logging so it appears in production logs
                info!("Disk usage: {:.2}%", usage);
                usage as f64
            }
            Ok(Err(e)) => {
                warn!("Failed to get disk usage: {}", e);
                0.0
            }
            Err(e) => {
                error!("Failed to spawn blocking task for disk usage: {}", e);
                0.0
            }
        }
    }

    /// Get current network usage percentage using actual rate calculation
    /// This now uses the stored last_network_stats for accurate rate calculation
    pub async fn get_network_usage(&self) -> f64 {
        // Use the new method that tracks rates properly
        let usage = self.calculate_network_usage_rate().await;
        info!("Network usage: {:.2}%", usage);
        usage
    }
    
    /// Read network statistics from /proc/net/dev
    #[cfg(target_os = "linux")]
    pub async fn read_network_stats(&self) -> Result<NetworkStats, Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string("/proc/net/dev").await?;
        
        let mut total_rx_bytes = 0u64;
        let mut total_tx_bytes = 0u64;
        
        for line in content.lines().skip(2) {  // Skip header lines
            let parts: Vec<&str> = line.split_whitespace().collect();
            
            // Skip loopback interface
            if parts.is_empty() || parts[0].starts_with("lo:") {
                continue;
            }
            
            // Parse interface statistics
            // Format: interface: rx_bytes rx_packets ... tx_bytes tx_packets ...
            if parts.len() >= 10 {
                // Parse receive and transmit bytes
                let rx_bytes = if parts[0].contains(':') {
                    // Interface name has colon, stats start at index 1
                    parts[1].parse::<u64>().unwrap_or(0)
                } else {
                    // Interface name is separate, stats start at index 1
                    parts[1].parse::<u64>().unwrap_or(0)
                };
                
                let tx_bytes = if parts[0].contains(':') {
                    parts[9].parse::<u64>().unwrap_or(0)
                } else {
                    parts[9].parse::<u64>().unwrap_or(0)
                };
                
                total_rx_bytes += rx_bytes;
                total_tx_bytes += tx_bytes;
                
                debug!("Interface {}: RX={} bytes, TX={} bytes", 
                    parts[0].trim_end_matches(':'), rx_bytes, tx_bytes);
            }
        }
        
        Ok(NetworkStats {
            bytes_received: total_rx_bytes,
            bytes_sent: total_tx_bytes,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }
    
    #[cfg(not(target_os = "linux"))]
    pub async fn read_network_stats(&self) -> Result<NetworkStats, Box<dyn std::error::Error>> {
        Ok(NetworkStats::default())
    }
    
    /// Try to detect the actual network link speed
    #[cfg(target_os = "linux")]
    pub async fn detect_link_speed(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Try to read speed from common network interfaces
        let interfaces = ["eth0", "enp3s0", "ens3", "eno1", "enp0s3", "enp0s25", "em1"];
        
        for iface in &interfaces {
            let speed_path = format!("/sys/class/net/{}/speed", iface);
            if let Ok(speed_str) = tokio::fs::read_to_string(&speed_path).await {
                if let Ok(speed_mbps) = speed_str.trim().parse::<u64>() {
                    // Some interfaces report -1 when disconnected
                    if speed_mbps > 0 && speed_mbps < 100000 {  // Sanity check
                        debug!("Detected link speed for {}: {} Mbps", iface, speed_mbps);
                        return Ok(speed_mbps);
                    }
                }
            }
        }
        
        // Default to 1 Gbps if we can't detect
        Ok(1000)
    }
    
    #[cfg(not(target_os = "linux"))]
    pub async fn detect_link_speed(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Default to 1 Gbps for non-Linux systems
        Ok(1000)
    }

    /// Get CPU temperature if available
    pub async fn get_cpu_temperature(&self) -> Option<f64> {
        #[cfg(target_os = "linux")]
        {
            // Try different thermal zone paths
            let thermal_zones = [
                "/sys/class/thermal/thermal_zone0/temp",
                "/sys/class/thermal/thermal_zone1/temp",
                "/sys/class/hwmon/hwmon0/temp1_input",
                "/sys/class/hwmon/hwmon1/temp1_input",
                "/sys/class/hwmon/hwmon2/temp1_input",
                "/sys/class/hwmon/hwmon3/temp1_input",
                "/sys/class/hwmon/hwmon4/temp1_input",
            ];
            
            for zone in &thermal_zones {
                if let Ok(temp_str) = tokio::fs::read_to_string(zone).await {
                    if let Ok(temp_millidegrees) = temp_str.trim().parse::<f64>() {
                        let temp_celsius = temp_millidegrees / 1000.0;
                        info!("CPU temperature: {:.1}°C (from {})", temp_celsius, zone);
                        return Some(temp_celsius);
                    }
                }
            }
            
            debug!("CPU temperature not available");
        }
        
        None
    }

    /// Get current process count
    pub async fn get_process_count(&self) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            match fs::read_dir("/proc").await {
                Ok(mut entries) => {
                    let mut count = 0;
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        if entry.file_name()
                            .to_str()
                            .map(|name| name.chars().all(|c| c.is_ascii_digit()))
                            .unwrap_or(false) {
                            count += 1;
                        }
                    }
                    
                    info!("Process count: {}", count);
                    Some(count)
                }
                Err(e) => {
                    warn!("Failed to read /proc directory: {}", e);
                    None
                }
            }
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
    
    /// Collect all system metrics into a summary structure
    pub async fn collect_all_metrics(&self) -> SystemMetrics {
        // Collect all metrics with proper logging
        info!("Collecting all system metrics...");
        
        let metrics = SystemMetrics {
            cpu_usage: self.get_cpu_usage().await,
            memory_usage: self.get_memory_usage().await,
            disk_usage: self.get_disk_usage().await,
            network_usage: self.get_network_usage().await,  // Now uses actual rate calculation
            cpu_temperature: self.get_cpu_temperature().await,
            process_count: self.get_process_count().await,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        
        info!("Metrics collection complete: CPU={:.1}%, Mem={:.1}%, Disk={:.1}%, Net={:.1}%",
              metrics.cpu_usage, metrics.memory_usage, metrics.disk_usage, metrics.network_usage);
        
        metrics
    }
}

/// Complete system metrics snapshot
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_usage: f64,
    pub cpu_temperature: Option<f64>,
    pub process_count: Option<u32>,
    pub timestamp: u64,
}

impl SystemMetrics {
    /// Format metrics for display
    pub fn format_summary(&self) -> String {
        format!(
            "System Metrics:\n\
             ├─ CPU Usage: {:.1}%\n\
             ├─ Memory Usage: {:.1}%\n\
             ├─ Disk Usage: {:.1}%\n\
             ├─ Network Usage: {:.1}%\n\
             ├─ CPU Temperature: {}\n\
             └─ Process Count: {}",
            self.cpu_usage,
            self.memory_usage,
            self.disk_usage,
            self.network_usage,
            self.cpu_temperature
                .map(|t| format!("{:.1}°C", t))
                .unwrap_or_else(|| "N/A".to_string()),
            self.process_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "N/A".to_string())
        )
    }
}

// ============================================
// Module Tests
// ============================================
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_cpu_usage() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let cpu_usage = manager.get_cpu_usage().await;
        
        println!("CPU usage: {:.2}%", cpu_usage);
        assert!(cpu_usage >= 0.0);
        assert!(cpu_usage <= 100.0);
    }
    
    #[tokio::test]
    async fn test_memory_usage() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let mem_usage = manager.get_memory_usage().await;
        
        println!("Memory usage: {:.2}%", mem_usage);
        assert!(mem_usage >= 0.0);
        assert!(mem_usage <= 100.0);
    }
    
    #[tokio::test]
    async fn test_disk_usage() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let disk_usage = manager.get_disk_usage().await;
        
        println!("Disk usage: {:.2}%", disk_usage);
        assert!(disk_usage >= 0.0);
        assert!(disk_usage <= 100.0);
    }
    
    #[tokio::test]
    async fn test_network_usage_with_tracking() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        
        // First call initializes the stats
        let usage1 = manager.get_network_usage().await;
        println!("Initial network usage: {:.2}%", usage1);
        assert!(usage1 >= 0.0);
        assert!(usage1 <= 100.0);
        
        // Wait a moment to allow some network activity
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Second call should calculate actual rate
        let usage2 = manager.get_network_usage().await;
        println!("Network usage after 2 seconds: {:.2}%", usage2);
        assert!(usage2 >= 0.0);
        assert!(usage2 <= 100.0);
    }
    
    #[tokio::test]
    async fn test_cpu_temperature() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let cpu_temp = manager.get_cpu_temperature().await;
        
        if let Some(temp) = cpu_temp {
            println!("CPU temperature: {:.1}°C", temp);
            assert!(temp > -50.0);  // Reasonable lower bound
            assert!(temp < 150.0);  // Reasonable upper bound
        } else {
            println!("CPU temperature not available");
        }
    }
    
    #[tokio::test]
    async fn test_process_count() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let proc_count = manager.get_process_count().await;
        
        #[cfg(target_os = "linux")]
        {
            assert!(proc_count.is_some());
            if let Some(count) = proc_count {
                println!("Process count: {}", count);
                assert!(count > 0);
            }
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            assert!(proc_count.is_none());
        }
    }
    
    #[tokio::test]
    async fn test_collect_all_metrics() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let metrics = manager.collect_all_metrics().await;
        
        println!("{}", metrics.format_summary());
        
        assert!(metrics.cpu_usage >= 0.0 && metrics.cpu_usage <= 100.0);
        assert!(metrics.memory_usage >= 0.0 && metrics.memory_usage <= 100.0);
        assert!(metrics.disk_usage >= 0.0 && metrics.disk_usage <= 100.0);
        assert!(metrics.network_usage >= 0.0 && metrics.network_usage <= 100.0);
    }
    
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_network_stats_reading() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        
        if let Ok(stats) = manager.read_network_stats().await {
            println!("Network stats:");
            println!("  Bytes received: {}", stats.bytes_received);
            println!("  Bytes sent: {}", stats.bytes_sent);
            println!("  Timestamp: {}", stats.timestamp);
            
            assert!(stats.timestamp > 0);
        }
    }
    
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_link_speed_detection() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        
        if let Ok(speed) = manager.detect_link_speed().await {
            println!("Detected link speed: {} Mbps", speed);
            assert!(speed > 0);
            assert!(speed <= 100000);  // Reasonable upper bound
        }
    }
    
    #[tokio::test]
    async fn test_network_rate_calculation() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        
        // Initialize with first reading
        if let Ok(initial_stats) = manager.read_network_stats().await {
            manager.update_network_stats(initial_stats).await;
        }
        
        // Wait for some network activity
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Calculate rate
        let usage = manager.calculate_network_usage_rate().await;
        println!("Calculated network usage rate: {:.2}%", usage);
        
        assert!(usage >= 0.0);
        assert!(usage <= 100.0);
    }
}
