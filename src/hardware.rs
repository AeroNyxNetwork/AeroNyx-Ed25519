use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub hostname: String,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disk: DiskInfo,
    pub network: NetworkInfo,
    pub os: OsInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub cores: u32,
    pub model: String,
    pub frequency: u64,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub total: u64,
    pub available: u64,
    pub filesystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetworkInterface>,
    pub public_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: String,
    pub mac_address: String,
    pub interface_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    #[serde(rename = "type")]
    pub os_type: String,
    pub version: String,
    pub distribution: String,
    pub kernel: String,
}

impl HardwareInfo {
    pub async fn collect() -> Result<Self, String> {
        debug!("Collecting hardware information...");
        
        Ok(HardwareInfo {
            hostname: gethostname::gethostname().to_string_lossy().to_string(),
            cpu: Self::collect_cpu_info()?,
            memory: Self::collect_memory_info()?,
            disk: Self::collect_disk_info()?,
            network: Self::collect_network_info().await?,
            os: Self::collect_os_info()?,
        })
    }
    
    fn collect_cpu_info() -> Result<CpuInfo, String> {
        let cores = sys_info::cpu_num()
            .map_err(|e| format!("Failed to get CPU count: {}", e))?;
        
        // Get CPU speed if available
        let frequency = sys_info::cpu_speed()
            .unwrap_or(0) as u64 * 1_000_000; // Convert MHz to Hz
        
        Ok(CpuInfo {
            cores,
            model: Self::get_cpu_model().unwrap_or_else(|| "Unknown CPU".to_string()),
            frequency,
            architecture: std::env::consts::ARCH.to_string(),
        })
    }
    
    fn get_cpu_model() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                for line in cpuinfo.lines() {
                    if line.starts_with("model name") {
                        return line.split(':').nth(1).map(|s| s.trim().to_string());
                    }
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl")
                .arg("-n")
                .arg("machdep.cpu.brand_string")
                .output()
            {
                if let Ok(model) = String::from_utf8(output.stdout) {
                    return Some(model.trim().to_string());
                }
            }
        }
        
        None
    }
    
    fn collect_memory_info() -> Result<MemoryInfo, String> {
        let mem_info = sys_info::mem_info()
            .map_err(|e| format!("Failed to get memory info: {}", e))?;
        
        Ok(MemoryInfo {
            total: mem_info.total * 1024, // Convert KB to bytes
            available: mem_info.avail * 1024,
        })
    }
    
    fn collect_disk_info() -> Result<DiskInfo, String> {
        let disk_info = sys_info::disk_info()
            .map_err(|e| format!("Failed to get disk info: {}", e))?;
        
        Ok(DiskInfo {
            total: disk_info.total * 1024, // Convert KB to bytes
            available: disk_info.free * 1024,
            filesystem: Self::get_filesystem_type().unwrap_or_else(|| "Unknown".to_string()),
        })
    }
    
    fn get_filesystem_type() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
                for line in mounts.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 && parts[1] == "/" {
                        return Some(parts[2].to_string());
                    }
                }
            }
        }
        
        None
    }
    
    async fn collect_network_info() -> Result<NetworkInfo, String> {
        let interfaces = Self::get_network_interfaces()?;
        let public_ip = Self::get_public_ip().await?;
        
        Ok(NetworkInfo {
            interfaces,
            public_ip,
        })
    }
    
    fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
        let mut interfaces = Vec::new();
        
        use pnet::datalink;
        
        for interface in datalink::interfaces() {
            // Skip loopback and virtual interfaces
            if interface.is_loopback() || interface.name.starts_with("veth") {
                continue;
            }
            
            // Get MAC address
            let mac_address = interface.mac
                .map(|mac| format!("{}", mac))
                .unwrap_or_else(|| "00:00:00:00:00:00".to_string());
            
            // Get IP addresses
            for ip_network in &interface.ips {
                if let Some(ip) = ip_network.ip().to_string().split('/').next() {
                    interfaces.push(NetworkInterface {
                        name: interface.name.clone(),
                        ip_address: ip.to_string(),
                        mac_address: mac_address.clone(),
                        interface_type: if interface.name.starts_with("eth") {
                            "ethernet".to_string()
                        } else if interface.name.starts_with("wl") {
                            "wifi".to_string()
                        } else {
                            "other".to_string()
                        },
                    });
                }
            }
        }
        
        if interfaces.is_empty() {
            warn!("No network interfaces found, using fallback");
            interfaces.push(NetworkInterface {
                name: "unknown".to_string(),
                ip_address: "0.0.0.0".to_string(),
                mac_address: "00:00:00:00:00:00".to_string(),
                interface_type: "unknown".to_string(),
            });
        }
        
        Ok(interfaces)
    }
    
    async fn get_public_ip() -> Result<String, String> {
        let response = reqwest::get("https://api.ipify.org")
            .await
            .map_err(|e| format!("Failed to get public IP: {}", e))?;
        
        response.text()
            .await
            .map_err(|e| format!("Failed to read IP response: {}", e))
    }
    
    fn collect_os_info() -> Result<OsInfo, String> {
        let os_type = std::env::consts::OS.to_string();
        let kernel = sys_info::os_release()
            .unwrap_or_else(|_| "Unknown".to_string());
        
        let (version, distribution) = Self::get_os_details();
        
        Ok(OsInfo {
            os_type,
            version,
            distribution,
            kernel,
        })
    }
    
    fn get_os_details() -> (String, String) {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
                let mut version = "Unknown".to_string();
                let mut distribution = "Unknown".to_string();
                
                for line in os_release.lines() {
                    if line.starts_with("VERSION=") {
                        version = line.split('=').nth(1)
                            .unwrap_or("Unknown")
                            .trim_matches('"')
                            .to_string();
                    } else if line.starts_with("NAME=") {
                        distribution = line.split('=').nth(1)
                            .unwrap_or("Unknown")
                            .trim_matches('"')
                            .to_string();
                    }
                }
                
                return (version, distribution);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    return (version.trim().to_string(), "macOS".to_string());
                }
            }
        }
        
        ("Unknown".to_string(), "Unknown".to_string())
    }
    
    /// Generate a hardware fingerprint for duplicate registration prevention
    pub fn generate_fingerprint(&self) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        
        // Include stable hardware identifiers
        hasher.update(&self.hostname);
        hasher.update(&self.cpu.model);
        hasher.update(&self.cpu.cores.to_string());
        hasher.update(&self.cpu.architecture);
        
        // Include MAC addresses (primary identifier for hardware)
        for interface in &self.network.interfaces {
            if interface.mac_address != "00:00:00:00:00:00" {
                hasher.update(&interface.mac_address);
            }
        }
        
        // Include OS information for additional entropy
        hasher.update(&self.os.os_type);
        hasher.update(&self.os.kernel);
        
        let result = hasher.finalize();
        hex::encode(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_hardware_info_collection() {
        let hw_info = HardwareInfo::collect().await;
        assert!(hw_info.is_ok());
        
        let info = hw_info.unwrap();
        assert!(!info.hostname.is_empty());
        assert!(info.cpu.cores > 0);
        assert!(info.memory.total > 0);
        assert!(!info.os.os_type.is_empty());
    }
    
    #[test]
    fn test_fingerprint_generation() {
        let hw_info = HardwareInfo {
            hostname: "test-host".to_string(),
            cpu: CpuInfo {
                cores: 8,
                model: "Intel Core i7".to_string(),
                frequency: 3600000000,
                architecture: "x86_64".to_string(),
            },
            memory: MemoryInfo {
                total: 16000000000,
                available: 8000000000,
            },
            disk: DiskInfo {
                total: 1000000000000,
                available: 500000000000,
                filesystem: "ext4".to_string(),
            },
            network: NetworkInfo {
                interfaces: vec![
                    NetworkInterface {
                        name: "eth0".to_string(),
                        ip_address: "192.168.1.100".to_string(),
                        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                        interface_type: "ethernet".to_string(),
                    }
                ],
                public_ip: "1.2.3.4".to_string(),
            },
            os: OsInfo {
                os_type: "linux".to_string(),
                version: "22.04".to_string(),
                distribution: "Ubuntu".to_string(),
                kernel: "5.15.0".to_string(),
            },
        };
        
        let fingerprint = hw_info.generate_fingerprint();
        assert_eq!(fingerprint.len(), 64); // SHA256 hex string length
    }
}
