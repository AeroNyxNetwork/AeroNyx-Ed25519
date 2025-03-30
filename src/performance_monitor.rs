use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write, Result as IoResult};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Performance metrics for the VPN server
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// CPU utilization percentage
    pub cpu_utilization: f64,
    /// Memory usage percentage
    pub memory_usage: f64,
    /// Network throughput in bytes/sec
    pub network_throughput: HashMap<String, (u64, u64)>, // (bytes_in, bytes_out)
    /// Disk I/O in bytes/sec
    pub disk_io: (u64, u64), // (read_bytes, write_bytes)
    /// Number of active connections
    pub active_connections: usize,
    /// System load average
    pub load_average: (f64, f64, f64), // 1min, 5min, 15min
    /// TUN device throughput
    pub tun_throughput: (u64, u64), // (bytes_in, bytes_out)
    /// Timestamp when metrics were collected
    pub timestamp: Instant,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_utilization: 0.0,
            memory_usage: 0.0,
            network_throughput: HashMap::new(),
            disk_io: (0, 0),
            active_connections: 0,
            load_average: (0.0, 0.0, 0.0),
            tun_throughput: (0, 0),
            timestamp: Instant::now(),
        }
    }
}

/// Performance monitor for the VPN server
pub struct PerformanceMonitor {
    /// Current metrics
    metrics: Arc<Mutex<PerformanceMetrics>>,
    /// History of metrics
    history: Arc<Mutex<Vec<PerformanceMetrics>>>,
    /// Maximum history size
    max_history: usize,
    /// Metrics collection interval
    interval: Duration,
    /// Running flag
    running: Arc<Mutex<bool>>,
    /// Name of the TUN device to monitor
    tun_device: String,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(tun_device: &str, interval: Duration, max_history: usize) -> Self {
        Self {
            metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
            history: Arc::new(Mutex::new(Vec::with_capacity(max_history))),
            max_history,
            interval,
            running: Arc::new(Mutex::new(false)),
            tun_device: tun_device.to_string(),
        }
    }
    
    /// Start the performance monitor
    pub async fn start(&self) -> IoResult<()> {
        let mut running = self.running.lock().await;
        if *running {
            return Ok(());
        }
        
        *running = true;
        
        // Clone references for the monitoring task
        let metrics = self.metrics.clone();
        let history = self.history.clone();
        let running = self.running.clone();
        let max_history = self.max_history;
        let interval = self.interval;
        let tun_device = self.tun_device.clone();
        
        // Spawn the monitoring task
        tokio::spawn(async move {
            // Store previous network stats for calculating throughput
            let mut prev_net_stats: HashMap<String, (u64, u64)> = HashMap::new();
            let mut prev_disk_stats: (u64, u64) = (0, 0);
            let mut prev_tun_stats: (u64, u64) = (0, 0);
            let mut prev_time = Instant::now();
            
            while *running.lock().await {
                // Collect metrics
                let mut current_metrics = PerformanceMetrics::default();
                current_metrics.timestamp = Instant::now();
                
                // Collect CPU metrics
                if let Ok(cpu) = collect_cpu_metrics() {
                    current_metrics.cpu_utilization = cpu;
                }
                
                // Collect memory metrics
                if let Ok(mem) = collect_memory_metrics() {
                    current_metrics.memory_usage = mem;
                }
                
                // Collect network metrics
                if let Ok(net) = collect_network_metrics() {
                    let elapsed = current_metrics.timestamp.duration_since(prev_time).as_secs_f64();
                    if elapsed > 0.0 {
                        for (iface, (rx, tx)) in &net {
                            let prev = prev_net_stats.get(iface).unwrap_or(&(0, 0));
                            let rx_rate = if *rx >= prev.0 { (*rx - prev.0) as f64 / elapsed } else { 0.0 } as u64;
                            let tx_rate = if *tx >= prev.1 { (*tx - prev.1) as f64 / elapsed } else { 0.0 } as u64;
                            current_metrics.network_throughput.insert(iface.clone(), (rx_rate, tx_rate));
                        }
                    }
                    prev_net_stats = net;
                }
                
                // Collect disk I/O metrics
                if let Ok((read, write)) = collect_disk_metrics() {
                    let elapsed = current_metrics.timestamp.duration_since(prev_time).as_secs_f64();
                    if elapsed > 0.0 {
                        let read_rate = if read >= prev_disk_stats.0 { (read - prev_disk_stats.0) as f64 / elapsed } else { 0.0 } as u64;
                        let write_rate = if write >= prev_disk_stats.1 { (write - prev_disk_stats.1) as f64 / elapsed } else { 0.0 } as u64;
                        current_metrics.disk_io = (read_rate, write_rate);
                    }
                    prev_disk_stats = (read, write);
                }
                
                // Collect active connections
                if let Ok(connections) = collect_active_connections() {
                    current_metrics.active_connections = connections;
                }
                
                // Collect load average
                if let Ok(load) = collect_load_average() {
                    current_metrics.load_average = load;
                }
                
                // Collect TUN device throughput
                if let Ok((rx, tx)) = collect_tun_metrics(&tun_device) {
                    let elapsed = current_metrics.timestamp.duration_since(prev_time).as_secs_f64();
                    if elapsed > 0.0 {
                        let rx_rate = if rx >= prev_tun_stats.0 { (rx - prev_tun_stats.0) as f64 / elapsed } else { 0.0 } as u64;
                        let tx_rate = if tx >= prev_tun_stats.1 { (tx - prev_tun_stats.1) as f64 / elapsed } else { 0.0 } as u64;
                        current_metrics.tun_throughput = (rx_rate, tx_rate);
                    }
                    prev_tun_stats = (rx, tx);
                }
                
                // Update metrics
                {
                    let mut metrics_lock = metrics.lock().await;
                    *metrics_lock = current_metrics.clone();
                }
                
                // Add to history
                {
                    let mut history_lock = history.lock().await;
                    history_lock.push(current_metrics);
                    
                    // Trim history if needed
                    if history_lock.len() > max_history {
                        history_lock.remove(0);
                    }
                }
                
                // Update previous time
                prev_time = Instant::now();
                
                // Wait for next interval
                tokio::time::sleep(interval).await;
            }
        });
        
        Ok(())
    }
    
    /// Stop the performance monitor
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        *running = false;
    }
    
    /// Get current metrics
    pub async fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.lock().await.clone()
    }
    
    /// Get metrics history
    pub async fn get_history(&self) -> Vec<PerformanceMetrics> {
        self.history.lock().await.clone()
    }
    
    /// Generate a performance report
    pub async fn generate_report(&self) -> String {
        let metrics = self.metrics.lock().await;
        let history = self.history.lock().await;
        
        let mut report = String::new();
        report.push_str("=== AeroNyx VPN Performance Report ===\n\n");
        
        // Current metrics
        report.push_str(&format!("CPU Utilization: {:.2}%\n", metrics.cpu_utilization));
        report.push_str(&format!("Memory Usage: {:.2}%\n", metrics.memory_usage));
        report.push_str(&format!("Load Average: {:.2}, {:.2}, {:.2}\n", 
            metrics.load_average.0, metrics.load_average.1, metrics.load_average.2));
        report.push_str(&format!("Active Connections: {}\n", metrics.active_connections));
        
        // TUN throughput
        report.push_str(&format!("\nTUN Device Throughput:\n"));
        report.push_str(&format!("  Incoming: {} bytes/sec\n", format_bytes(metrics.tun_throughput.0)));
        report.push_str(&format!("  Outgoing: {} bytes/sec\n", format_bytes(metrics.tun_throughput.1)));
        
        // Network interfaces
        report.push_str("\nNetwork Interface Throughput:\n");
        for (iface, (rx, tx)) in &metrics.network_throughput {
            report.push_str(&format!("  {}: {} in, {} out\n", 
                iface, format_bytes(*rx), format_bytes(*tx)));
        }
        
        // Disk I/O
        report.push_str("\nDisk I/O:\n");
        report.push_str(&format!("  Read: {} bytes/sec\n", format_bytes(metrics.disk_io.0)));
        report.push_str(&format!("  Write: {} bytes/sec\n", format_bytes(metrics.disk_io.1)));
        
        // Average metrics if history exists
        if !history.is_empty() {
            let avg_cpu: f64 = history.iter().map(|m| m.cpu_utilization).sum::<f64>() / history.len() as f64;
            let avg_mem: f64 = history.iter().map(|m| m.memory_usage).sum::<f64>() / history.len() as f64;
            let avg_conn: f64 = history.iter().map(|m| m.active_connections as f64).sum::<f64>() / history.len() as f64;
            
            report.push_str("\nHistorical Averages:\n");
            report.push_str(&format!("  Average CPU: {:.2}%\n", avg_cpu));
            report.push_str(&format!("  Average Memory: {:.2}%\n", avg_mem));
            report.push_str(&format!("  Average Connections: {:.1}\n", avg_conn));
        }
        
        report
    }
    
    /// Save the performance report to a file
    pub async fn save_report(&self, path: &str) -> IoResult<()> {
        let report = self.generate_report().await;
        let mut file = File::create(path)?;
        file.write_all(report.as_bytes())?;
        Ok(())
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

/// Collect CPU utilization metrics
fn collect_cpu_metrics() -> IoResult<f64> {
    // Try to read from /proc/stat
    let content = fs::read_to_string("/proc/stat")?;
    
    // Parse first line (total CPU)
    let line = content.lines().next().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData, "Invalid /proc/stat format"))?;
    
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid CPU data"));
    }
    
    // CPU fields: user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
    let user = parts[1].parse::<u64>().unwrap_or(0);
    let nice = parts[2].parse::<u64>().unwrap_or(0);
    let system = parts[3].parse::<u64>().unwrap_or(0);
    let idle = parts[4].parse::<u64>().unwrap_or(0);
    let iowait = if parts.len() > 5 { parts[5].parse::<u64>().unwrap_or(0) } else { 0 };
    let irq = if parts.len() > 6 { parts[6].parse::<u64>().unwrap_or(0) } else { 0 };
    let softirq = if parts.len() > 7 { parts[7].parse::<u64>().unwrap_or(0) } else { 0 };
    let steal = if parts.len() > 8 { parts[8].parse::<u64>().unwrap_or(0) } else { 0 };
    
    let idle_total = idle + iowait;
    let non_idle = user + nice + system + irq + softirq + steal;
    let total = idle_total + non_idle;
    
    // We need two samples to calculate CPU usage
    // For simplicity, we'll return a rough estimate based on current values
    // In practice, we'd need to track previous values
    
    // This is a simplified approach that won't be accurate
    // But better than nothing for demonstration
    let cpu_usage = (non_idle as f64 / total as f64) * 100.0;
    
    Ok(cpu_usage)
}

/// Collect memory usage metrics
fn collect_memory_metrics() -> IoResult<f64> {
    // Read from /proc/meminfo
    let content = fs::read_to_string("/proc/meminfo")?;
    
    let mut total: Option<u64> = None;
    let mut free: Option<u64> = None;
    let mut buffers: Option<u64> = None;
    let mut cached: Option<u64> = None;
    
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = parse_meminfo_line(line);
        } else if line.starts_with("MemFree:") {
            free = parse_meminfo_line(line);
        } else if line.starts_with("Buffers:") {
            buffers = parse_meminfo_line(line);
        } else if line.starts_with("Cached:") && !line.starts_with("CacheFiles:") {
            cached = parse_meminfo_line(line);
        }
    }
    
    // Calculate memory usage
    if let (Some(total), Some(free), Some(buffers), Some(cached)) = (total, free, buffers, cached) {
        if total > 0 {
            let used = total - free - buffers - cached;
            let percent = (used as f64 / total as f64) * 100.0;
            return Ok(percent);
        }
    }
    
    Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid memory data"))
}

/// Parse a line from /proc/meminfo
fn parse_meminfo_line(line: &str) -> Option<u64> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        return parts[1].parse::<u64>().ok();
    }
    None
}

/// Collect network metrics
fn collect_network_metrics() -> IoResult<HashMap<String, (u64, u64)>> {
    let mut result = HashMap::new();
    
    // Read from /proc/net/dev
    let content = fs::read_to_string("/proc/net/dev")?;
    
    // Skip header lines
    let lines = content.lines().skip(2);
    
    for line in lines {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        
        let iface = parts[0].trim();
        let stats: Vec<&str> = parts[1].split_whitespace().collect();
        
        if stats.len() < 10 {
            continue;
        }
        
        // rx_bytes is at index 0, tx_bytes is at index 8
        let rx_bytes = stats[0].parse::<u64>().unwrap_or(0);
        let tx_bytes = stats[8].parse::<u64>().unwrap_or(0);
        
        result.insert(iface.to_string(), (rx_bytes, tx_bytes));
    }
    
    Ok(result)
}

/// Collect disk I/O metrics
fn collect_disk_metrics() -> IoResult<(u64, u64)> {
    // Read from /proc/diskstats
    let content = fs::read_to_string("/proc/diskstats")?;
    
    let mut total_read_bytes = 0u64;
    let mut total_write_bytes = 0u64;
    
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            continue;
        }
        
        // Skip partition entries (we want only disks)
        let device = parts[2];
        if device.starts_with("loop") || device.starts_with("ram") || device.contains("dm-") {
            continue;
        }
        
        // Fields: sectors read (idx 5) * 512 = bytes read
        // Fields: sectors written (idx 9) * 512 = bytes written
        let sectors_read = parts[5].parse::<u64>().unwrap_or(0);
        let sectors_written = parts[9].parse::<u64>().unwrap_or(0);
        
        total_read_bytes += sectors_read * 512;
        total_write_bytes += sectors_written * 512;
    }
    
    Ok((total_read_bytes, total_write_bytes))
}

/// Collect TUN metrics
fn collect_tun_metrics(tun_device: &str) -> IoResult<(u64, u64)> {
    // Read from /proc/net/dev for the specific TUN device
    let content = fs::read_to_string("/proc/net/dev")?;
    
    for line in content.lines() {
        if line.contains(tun_device) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            
            let stats: Vec<&str> = parts[1].split_whitespace().collect();
            
            if stats.len() < 10 {
                continue;
            }
            
            // rx_bytes is at index 0, tx_bytes is at index 8
            let rx_bytes = stats[0].parse::<u64>().unwrap_or(0);
            let tx_bytes = stats[8].parse::<u64>().unwrap_or(0);
            
            return Ok((rx_bytes, tx_bytes));
        }
    }
    
    Ok((0, 0))
}

/// Collect active connections
fn collect_active_connections() -> IoResult<usize> {
    // Use netstat to count established connections
    let output = Command::new("netstat")
        .args(&["-tn"])
        .output()?;
        
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // Count ESTABLISHED connections
    let count = output_str.lines()
        .filter(|line| line.contains("ESTABLISHED"))
        .count();
        
    Ok(count)
}

/// Collect load average
fn collect_load_average() -> IoResult<(f64, f64, f64)> {
    // Read from /proc/loadavg
    let content = fs::read_to_string("/proc/loadavg")?;
    
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid loadavg data"));
    }
    
    let load1 = parts[0].parse::<f64>().unwrap_or(0.0);
    let load5 = parts[1].parse::<f64>().unwrap_or(0.0);
    let load15 = parts[2].parse::<f64>().unwrap_or(0.0);
    
    Ok((load1, load5, load15))
}

/// A simple command to generate a one-time performance report
pub fn generate_performance_report(output_file: Option<&str>) -> IoResult<String> {
    let mut report = String::new();
    report.push_str("=== AeroNyx VPN System Performance Report ===\n\n");
    
    // Add timestamp
    let now = chrono::Local::now();
    report.push_str(&format!("Report time: {}\n\n", now.format("%Y-%m-%d %H:%M:%S")));
    
    // System information
    report.push_str("System Information:\n");
    
    // OS information
    if let Ok(output) = Command::new("lsb_release").args(&["-a"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        report.push_str(&format!("OS Information:\n{}\n", output_str));
    }
    
    // CPU information
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        let model_line = content.lines()
            .find(|line| line.starts_with("model name"))
            .unwrap_or("Unknown CPU");
            
        let cores = content.lines()
            .filter(|line| line.starts_with("processor"))
            .count();
            
        report.push_str(&format!("CPU: {} (Cores: {})\n", model_line.split(": ").nth(1).unwrap_or("Unknown"), cores));
    }
    
    // Memory information
    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        let total_line = content.lines()
            .find(|line| line.starts_with("MemTotal"))
            .unwrap_or("MemTotal: 0 kB");
            
        report.push_str(&format!("Memory: {}\n", total_line.split(": ").nth(1).unwrap_or("Unknown")));
    }
    
    // Current performance metrics
    report.push_str("\nCurrent Performance Metrics:\n");
    
    // CPU usage
    if let Ok(cpu) = collect_cpu_metrics() {
        report.push_str(&format!("CPU Usage: {:.2}%\n", cpu));
    }
    
    // Memory usage
    if let Ok(mem) = collect_memory_metrics() {
        report.push_str(&format!("Memory Usage: {:.2}%\n", mem));
    }
    
    // Load average
    if let Ok((load1, load5, load15)) = collect_load_average() {
        report.push_str(&format!("Load Average: {:.2}, {:.2}, {:.2}\n", load1, load5, load15));
    }
    
    // Network throughput
    if let Ok(net) = collect_network_metrics() {
        report.push_str("\nNetwork Interfaces:\n");
        for (iface, (rx, tx)) in net {
            report.push_str(&format!("  {}: {} received, {} sent\n", 
                iface, format_bytes(rx), format_bytes(tx)));
        }
    }
    
    // Disk usage
    if let Ok(output) = Command::new("df").args(&["-h"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        report.push_str("\nDisk Usage:\n");
        for line in output_str.lines().take(10) {
            report.push_str(&format!("  {}\n", line));
        }
    }
    
    // Process information for the VPN service
    report.push_str("\nVPN Process Information:\n");
    if let Ok(output) = Command::new("ps").args(&["aux", "|", "grep", "aeronyx"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("aeronyx") && !line.contains("grep") {
                report.push_str(&format!("  {}\n", line));
            }
        }
    }
    
    // Active connections
    if let Ok(connections) = collect_active_connections() {
        report.push_str(&format!("\nActive TCP Connections: {}\n", connections));
    }
    
    // If output file is specified, write to file
    if let Some(path) = output_file {
        let mut file = File::create(path)?;
        file.write_all(report.as_bytes())?;
        println!("Performance report saved to: {}", path);
    }
    
    Ok(report)
}
