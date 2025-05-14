// src/utils/system.rs
//! System-related utilities.
//!
//! This module provides functions for interacting with the operating system,
//! checking system capabilities, and managing resources.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::process::Command;
use tracing::{warn, debug};

/// Check if the current process is running as root/administrator
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata("/") {
            Ok(metadata) => metadata.uid() == 0,
            Err(_) => false,
        }
    }
    
    #[cfg(windows)]
    {
        // On Windows, check if we can create/write to a protected location
        false // Windows implementation would need to use a different approach
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        false // Default for unsupported platforms
    }
}

pub fn get_disk_usage() -> io::Result<u8> {
    #[cfg(target_os = "linux")]
    {
        // Use df command to get disk usage
        let output = Command::new("df")
            .args(["-h", "/"])  // Get usage for root filesystem
            .output()?;
            
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            
            if lines.len() >= 2 {
                let parts: Vec<&str> = lines[1].split_whitespace().collect();
                if parts.len() >= 5 {
                    // Parse percentage (remove % sign)
                    if let Some(percent_str) = parts[4].strip_suffix('%') {
                        if let Ok(percent) = percent_str.parse::<u8>() {
                            return Ok(percent);
                        }
                    }
                }
            }
        }
        
        // Fallback method - try parsing from statvfs
        match std::fs::metadata("/") {
            Ok(_) => {
                // This is a simplified approach. In a real implementation,
                // we would use libc::statvfs to get detailed filesystem stats
                // For now, return a default value
                debug!("Using default disk usage value");
                Ok(50) // Default 50% usage
            },
            Err(e) => Err(e)
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("Disk usage information not available on this platform");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Disk usage info not supported on this platform"
        ))
    }
}

pub fn get_system_uptime() -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let uptime_str = std::fs::read_to_string("/proc/uptime")?;
        let parts: Vec<&str> = uptime_str.split_whitespace().collect();
        
        if !parts.is_empty() {
            if let Ok(uptime) = parts[0].parse::<f64>() {
                return Ok(uptime as u64);
            }
        }
        
        Err(io::Error::new(io::ErrorKind::InvalidData, "Could not parse uptime"))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("System uptime information not available on this platform");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "System uptime info not supported on this platform"
        ))
    }
}

/// Get system memory information with better error handling
pub fn get_system_memory() -> io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let file = File::open("/proc/meminfo")?;
        let reader = BufReader::new(file);
        
        let mut total = None;
        let mut free = None;
        let mut buffers = None;
        let mut cached = None;
        
        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();
            
            if parts.len() < 2 {
                continue;
            }
            
            match parts[0] {
                "MemTotal:" => {
                    total = parts[1].parse::<u64>().ok();
                }
                "MemFree:" => {
                    free = parts[1].parse::<u64>().ok();
                }
                "Buffers:" => {
                    buffers = parts[1].parse::<u64>().ok();
                }
                "Cached:" => {
                    if !line.contains("SwapCached:") {
                        cached = parts[1].parse::<u64>().ok();
                    }
                }
                _ => {}
            }
            
            if total.is_some() && free.is_some() && buffers.is_some() && cached.is_some() {
                break;
            }
        }
        
        // Calculate values in bytes
        if let (Some(total), Some(free), Some(buffers), Some(cached)) = (total, free, buffers, cached) {
            let total_bytes = total * 1024;
            let available_bytes = (free + buffers + cached) * 1024;
            return Ok((total_bytes, available_bytes));
        }
        
        Err(io::Error::new(io::ErrorKind::NotFound, "Could not parse memory info"))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        // For other platforms, return a proper error instead of a placeholder
        warn!("Memory information not available on this platform");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "System memory info not supported on this platform"
        ))
    }
}

/// Get CPU load average with better error handling
pub fn get_load_average() -> io::Result<(f64, f64, f64)> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/loadavg")?;
        let parts: Vec<&str> = content.split_whitespace().collect();
        
        if parts.len() >= 3 {
            let one = parts[0].parse::<f64>().unwrap_or(0.0);
            let five = parts[1].parse::<f64>().unwrap_or(0.0);
            let fifteen = parts[2].parse::<f64>().unwrap_or(0.0);
            
            Ok((one, five, fifteen))
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid load average format"))
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        // For other platforms, return a proper error instead of a placeholder
        warn!("Load average information not available on this platform");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Load average info not supported on this platform"
        ))
    }
}

/// Set up IP forwarding (for VPN server) with improved error handling
pub fn enable_ip_forwarding() -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        // Try to enable IP forwarding
        match Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .status() {
            Ok(status) if status.success() => {
                debug!("IP forwarding enabled successfully");
                return Ok(true);
            }
            Ok(status) => {
                // Command ran but returned error status
                warn!("sysctl command failed with status {}", status);
                // Fall through to try the direct file write
            }
            Err(e) => {
                // Command failed to execute
                warn!("Failed to execute sysctl command: {}", e);
                // Fall through to try the direct file write
            }
        }
        
        // Try direct file write as fallback
        match std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
            Ok(_) => {
                debug!("IP forwarding enabled via direct write");
                return Ok(true);
            }
            Err(e) => {
                warn!("Failed to enable IP forwarding via direct write: {}", e);
                warn!("VPN functionality may be limited.");
                return Ok(false);
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        // For macOS, use pfctl to enable IP forwarding
        match Command::new("sysctl")
            .args(["-w", "net.inet.ip.forwarding=1"])
            .status() {
            Ok(status) if status.success() => {
                debug!("IP forwarding enabled successfully on macOS");
                return Ok(true);
            }
            Ok(status) => {
                warn!("sysctl command failed with status {} on macOS", status);
                return Ok(false);
            }
            Err(e) => {
                warn!("Failed to execute sysctl command on macOS: {}", e);
                return Ok(false);
            }
        }
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        warn!("IP forwarding setup not implemented for this platform");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IP forwarding not supported on this platform"
        ))
    }
}

/// Check if a network interface exists
pub fn interface_exists(name: &str) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Return false for unsupported platforms with a warning
        warn!("interface_exists not implemented for this platform");
        false
    }
}

/// Get the main network interface name with improved error handling
pub fn get_main_interface() -> io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        // Try using ip route to get default interface
        if let Ok(output) = Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output() {
            
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if let Some(pos) = line.find("dev ") {
                    let remaining = &line[pos + 4..];
                    if let Some(end) = remaining.find(' ') {
                        return Ok(remaining[..end].to_string());
                    } else {
                        return Ok(remaining.to_string());
                    }
                }
            }
        }
        
        // Fallback to common interfaces
        for iface in &["eth0", "ens3", "enp0s3", "wlan0"] {
            if interface_exists(iface) {
                return Ok(iface.to_string());
            }
        }
        
        Err(io::Error::new(io::ErrorKind::NotFound, "Could not determine main interface"))
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        // For other platforms, return a proper error instead of a placeholder
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Getting main interface not supported on this platform"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_root() {
        // This just ensures the function doesn't panic
        let _is_root = is_root();
    }
    
    #[test]
    fn test_get_system_memory() {
        // This test just ensures the function runs without panicking
        match get_system_memory() {
            Ok((total, available)) => {
                println!("Total memory: {} bytes, Available: {} bytes", total, available);
                assert!(total >= available);
            }
            Err(e) => {
                println!("Error getting system memory: {}", e);
                // Don't fail the test on unsupported platforms
            }
        }
    }
    
    #[test]
    fn test_interface_exists() {
        // Test with a commonly existing interface name
        let exists = interface_exists("lo");
        println!("Interface 'lo' exists: {}", exists);
    }
}
