// src/registration/metrics.rs
// AeroNyx Privacy Network - System Metrics Collection Module
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module handles system metrics collection for heartbeat messages
// and monitoring purposes.

use super::RegistrationManager;
use crate::utils;
use tokio::fs;
use tracing::{debug, warn};

impl RegistrationManager {
    /// Get current CPU usage percentage
    pub async fn get_cpu_usage(&self) -> f64 {
        if let Ok(result) = tokio::task::spawn_blocking(|| utils::system::get_load_average()).await {
            if let Ok((one_min, _, _)) = result {
                let cpu_count = sys_info::cpu_num().unwrap_or(1) as f64;
                (one_min / cpu_count * 100.0).min(100.0)
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    /// Get current memory usage percentage
    pub async fn get_memory_usage(&self) -> f64 {
        if let Ok(Ok((total, available))) = tokio::task::spawn_blocking(|| utils::system::get_system_memory()).await {
            let used = total.saturating_sub(available);
            used as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    }

    /// Get current disk usage percentage
    pub async fn get_disk_usage(&self) -> f64 {
        if let Ok(Ok(usage)) = tokio::task::spawn_blocking(|| utils::system::get_disk_usage()).await {
            usage as f64
        } else {
            0.0
        }
    }

    /// Get current network usage (placeholder implementation)
    pub async fn get_network_usage(&self) -> f64 {
        // TODO: Implement actual network usage calculation
        // This would track bytes sent/received over time
        10.0
    }

    /// Get CPU temperature if available
    pub async fn get_cpu_temperature(&self) -> Option<f64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            // Try different thermal zone paths
            let thermal_zones = [
                "/sys/class/thermal/thermal_zone0/temp",
                "/sys/class/thermal/thermal_zone1/temp",
                "/sys/class/hwmon/hwmon0/temp1_input",
            ];
            
            for zone in &thermal_zones {
                if let Ok(temp_str) = fs::read_to_string(zone) {
                    if let Ok(temp_millidegrees) = temp_str.trim().parse::<f64>() {
                        return Some(temp_millidegrees / 1000.0);
                    }
                }
            }
        }
        
        None
    }

    /// Get current process count
    pub async fn get_process_count(&self) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(mut entries) = fs::read_dir("/proc").await {
                let mut count = 0;
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if entry.file_name()
                        .to_str()
                        .map(|name| name.chars().all(|c| c.is_digit(10)))
                        .unwrap_or(false) {
                        count += 1;
                    }
                }
                
                return Some(count);
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_cpu_usage() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let cpu_usage = manager.get_cpu_usage().await;
        
        // CPU usage should be between 0 and 100
        assert!(cpu_usage >= 0.0);
        assert!(cpu_usage <= 100.0);
    }
    
    #[tokio::test]
    async fn test_memory_usage() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let mem_usage = manager.get_memory_usage().await;
        
        // Memory usage should be between 0 and 100
        assert!(mem_usage >= 0.0);
        assert!(mem_usage <= 100.0);
    }
    
    #[tokio::test]
    async fn test_disk_usage() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let disk_usage = manager.get_disk_usage().await;
        
        // Disk usage should be between 0 and 100
        assert!(disk_usage >= 0.0);
        assert!(disk_usage <= 100.0);
    }
    
    #[tokio::test]
    async fn test_network_usage() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let net_usage = manager.get_network_usage().await;
        
        // For now, this is just a placeholder
        assert_eq!(net_usage, 10.0);
    }
    
    #[tokio::test]
    async fn test_process_count() {
        let manager = RegistrationManager::new("https://api.aeronyx.com");
        let proc_count = manager.get_process_count().await;
        
        #[cfg(target_os = "linux")]
        {
            // On Linux, we should get some processes
            assert!(proc_count.is_some());
            if let Some(count) = proc_count {
                assert!(count > 0);
            }
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            // On other platforms, it returns None
            assert!(proc_count.is_none());
        }
    }
}
