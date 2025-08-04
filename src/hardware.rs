// src/hardware.rs
// AeroNyx Privacy Network - Hardware Information Collection Module
// Version: 1.0.0
// 
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module is responsible for collecting hardware information from the host system
// and generating stable hardware fingerprints for node identification and security.
// The fingerprint algorithm focuses on stable hardware characteristics that rarely
// change in cloud environments, avoiding volatile attributes like disk size or memory.
//
// MOBILE SUPPORT: This module now supports mobile devices (iOS/Android) through
// conditional compilation and platform-specific implementations.

use serde::{Deserialize, Serialize};
use tracing::{debug, warn, info};
use sha2::{Sha256, Digest};
use std::collections::BTreeSet;

// Mobile platform detection
#[cfg(any(target_os = "ios", target_os = "android"))]
const IS_MOBILE: bool = true;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const IS_MOBILE: bool = false;

/// Represents comprehensive hardware information collected from the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    /// System hostname
    pub hostname: String,
    /// CPU information including model and architecture
    pub cpu: CpuInfo,
    /// Memory information (total and available)
    pub memory: MemoryInfo,
    /// Disk information (used for metrics, not fingerprinting)
    pub disk: DiskInfo,
    /// Network interfaces and connectivity information
    pub network: NetworkInfo,
    /// Operating system details
    pub os: OsInfo,
    /// DMI system UUID (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_uuid: Option<String>,
    /// System machine ID (Linux-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    /// BIOS/UEFI information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bios_info: Option<BiosInfo>,
    /// Mobile device information (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_info: Option<MobileInfo>,
}

/// Mobile device specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileInfo {
    /// Device unique identifier (IDFV on iOS, Android ID on Android)
    pub device_id: String,
    /// Device model (e.g., "iPhone 13 Pro", "Pixel 6")
    pub device_model: String,
    /// Device manufacturer (e.g., "Apple", "Samsung")
    pub manufacturer: String,
    /// Whether the device is physical or emulator/simulator
    pub is_physical: bool,
    /// Optional advertising ID (if permissions granted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertising_id: Option<String>,
}

/// CPU information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    /// Number of CPU cores
    pub cores: u32,
    /// CPU model name
    pub model: String,
    /// CPU frequency in Hz
    pub frequency: u64,
    /// CPU architecture (x86_64, aarch64, etc.)
    pub architecture: String,
    /// CPU vendor ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<String>,
}

/// Memory information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    /// Total memory in bytes
    pub total: u64,
    /// Available memory in bytes
    pub available: u64,
}

/// Disk information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    /// Total disk space in bytes
    pub total: u64,
    /// Available disk space in bytes
    pub available: u64,
    /// Filesystem type
    pub filesystem: String,
}

/// Network information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// List of network interfaces
    pub interfaces: Vec<NetworkInterface>,
    /// Public IP address
    pub public_ip: String,
}

/// Individual network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface name (eth0, wlan0, etc.)
    pub name: String,
    /// IP address assigned to the interface
    pub ip_address: String,
    /// MAC address of the interface
    pub mac_address: String,
    /// Interface type (ethernet, wifi, etc.)
    pub interface_type: String,
    /// Whether this is a physical interface
    #[serde(default)]
    pub is_physical: bool,
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    /// OS type (linux, macos, windows, ios, android)
    #[serde(rename = "type")]
    pub os_type: String,
    /// OS version
    pub version: String,
    /// Distribution name (for Linux)
    pub distribution: String,
    /// Kernel version
    pub kernel: String,
}

/// BIOS/UEFI information for additional hardware identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiosInfo {
    /// BIOS vendor
    pub vendor: String,
    /// BIOS version
    pub version: String,
    /// System manufacturer
    pub system_manufacturer: String,
    /// System product name
    pub system_product: String,
}

impl HardwareInfo {
    /// Generate a stable hardware fingerprint for node identification
    /// This fingerprint uses only stable hardware characteristics that rarely change
    pub fn generate_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        
        // For mobile devices, use mobile-specific identifiers
        if let Some(mobile_info) = &self.mobile_info {
            hasher.update(mobile_info.device_id.as_bytes());
            hasher.update(b"|");
            hasher.update(mobile_info.device_model.as_bytes());
            hasher.update(b"|");
            hasher.update(mobile_info.manufacturer.as_bytes());
            hasher.update(b"|");
        } else {
            // Original server fingerprint logic
            // 1. Primary identifier: MAC addresses (very stable)
            let mac_addresses: BTreeSet<String> = self.network.interfaces
                .iter()
                .filter(|iface| {
                    iface.is_physical && 
                    !iface.mac_address.is_empty() && 
                    iface.mac_address != "00:00:00:00:00:00"
                })
                .map(|iface| iface.mac_address.to_lowercase())
                .collect();
            
            // Include all physical MAC addresses in sorted order
            for mac in &mac_addresses {
                hasher.update(mac.as_bytes());
                hasher.update(b"|");
            }
            
            // 2. System UUID (extremely stable on VMs and cloud instances)
            if let Some(uuid) = &self.system_uuid {
                hasher.update(uuid.as_bytes());
                hasher.update(b"|");
            }
            
            // 3. Machine ID (very stable on Linux systems)
            if let Some(machine_id) = &self.machine_id {
                hasher.update(machine_id.as_bytes());
                hasher.update(b"|");
            }
        }
        
        // Common identifiers for both mobile and server
        // 4. CPU model and architecture (stable on cloud VMs and devices)
        hasher.update(self.cpu.model.as_bytes());
        hasher.update(b"|");
        hasher.update(self.cpu.architecture.as_bytes());
        hasher.update(b"|");
        
        // 5. BIOS information (if available - very stable)
        if let Some(bios) = &self.bios_info {
            hasher.update(bios.system_manufacturer.as_bytes());
            hasher.update(b"|");
            hasher.update(bios.system_product.as_bytes());
            hasher.update(b"|");
        }
        
        // 6. OS type (stable, but not version)
        hasher.update(self.os.os_type.as_bytes());
        hasher.update(b"|");
        
        // 7. Hostname (lower priority, can change)
        hasher.update(self.hostname.to_lowercase().as_bytes());
        
        let result = hasher.finalize();
        hex::encode(result)
    }
    
    /// Generate a zero-knowledge commitment for this hardware
    pub fn generate_zkp_commitment(&self) -> Vec<u8> {
        use crate::zkp_halo2::commitment::PoseidonCommitment;
        
        // For mobile devices, use device ID as the second parameter
        if let Some(mobile_info) = &self.mobile_info {
            let commitment = PoseidonCommitment::commit_combined(
                &self.cpu.model,
                &mobile_info.device_id
            );
            return commitment.to_vec();
        }
        
        // Original server logic
        let default_mac = "00:00:00:00:00:00".to_string();
        let mac = self.network.interfaces
            .iter()
            .find(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
            .map(|iface| &iface.mac_address)
            .unwrap_or(&default_mac);
        
        let commitment = PoseidonCommitment::commit_combined(
            &self.cpu.model,
            mac
        );
        
        commitment.to_vec()
    }
    
    /// Create a deterministic serialization for ZKP circuit input
    pub fn to_zkp_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(self.generate_zkp_commitment())
    }
    
    /// Verify that this hardware matches a given commitment
    pub fn verify_commitment(&self, commitment: &[u8]) -> bool {
        let computed = self.generate_zkp_commitment();
        computed == commitment
    }
    
    /// Generate a human-readable summary of the fingerprint components
    pub fn generate_fingerprint_summary(&self) -> String {
        if let Some(mobile_info) = &self.mobile_info {
            return format!(
                "Device: {} {}, ID: {}, CPU: {}, Physical: {}",
                mobile_info.manufacturer,
                mobile_info.device_model,
                if mobile_info.device_id.len() > 8 {
                    format!("{}...", &mobile_info.device_id[..8])
                } else {
                    mobile_info.device_id.clone()
                },
                if self.cpu.model.len() > 20 {
                    format!("{}...", &self.cpu.model[..20])
                } else {
                    self.cpu.model.clone()
                },
                mobile_info.is_physical
            );
        }
        
        // Original server summary
        let physical_macs = self.network.interfaces
            .iter()
            .filter(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
            .count();
        
        format!(
            "Physical MACs: {}, CPU: {}, System UUID: {}, Machine ID: {}, BIOS: {}",
            physical_macs,
            if self.cpu.model.len() > 30 { 
                format!("{}...", &self.cpu.model[..30]) 
            } else { 
                self.cpu.model.clone() 
            },
            if self.system_uuid.is_some() { "Present" } else { "Absent" },
            if self.machine_id.is_some() { "Present" } else { "Absent" },
            if self.bios_info.is_some() { "Present" } else { "Absent" }
        )
    }

    /// Collect all hardware information from the system
    pub async fn collect() -> Result<Self, String> {
        info!("Starting hardware information collection");
        
        let mut hw_info = HardwareInfo {
            hostname: Self::get_hostname(),
            cpu: Self::collect_cpu_info()?,
            memory: Self::collect_memory_info()?,
            disk: Self::collect_disk_info()?,
            network: Self::collect_network_info().await?,
            os: Self::collect_os_info()?,
            system_uuid: None,
            machine_id: None,
            bios_info: None,
            mobile_info: None,
        };
        
        // Platform-specific collection
        if IS_MOBILE {
            hw_info.mobile_info = Self::collect_mobile_info();
        } else {
            hw_info.system_uuid = Self::get_system_uuid();
            hw_info.machine_id = Self::get_machine_id();
            hw_info.bios_info = Self::collect_bios_info();
        }
        
        debug!("Hardware information collection completed");
        Ok(hw_info)
    }
    
    /// Get hostname with mobile device support
    fn get_hostname() -> String {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            // On mobile, use a generic hostname or device name
            "mobile-device".to_string()
        }
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            gethostname::gethostname().to_string_lossy().to_string()
        }
    }
    
    /// Collect mobile device information
    #[cfg(any(target_os = "ios", target_os = "android"))]
    fn collect_mobile_info() -> Option<MobileInfo> {
        // This is a placeholder - actual implementation would use
        // platform-specific APIs through FFI or platform channels
        Some(MobileInfo {
            device_id: Self::get_mobile_device_id(),
            device_model: Self::get_mobile_device_model(),
            manufacturer: Self::get_mobile_manufacturer(),
            is_physical: Self::is_physical_device(),
            advertising_id: Self::get_advertising_id(),
        })
    }
    
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    fn collect_mobile_info() -> Option<MobileInfo> {
        None
    }
    
    // Mobile-specific helper functions (placeholders for actual implementation)
    #[cfg(any(target_os = "ios", target_os = "android"))]
    fn get_mobile_device_id() -> String {
        // In actual implementation:
        // iOS: Use identifierForVendor
        // Android: Use Settings.Secure.ANDROID_ID
        "placeholder-device-id".to_string()
    }
    
    #[cfg(any(target_os = "ios", target_os = "android"))]
    fn get_mobile_device_model() -> String {
        // In actual implementation:
        // iOS: Use UIDevice.current.model
        // Android: Use Build.MODEL
        "placeholder-model".to_string()
    }
    
    #[cfg(any(target_os = "ios", target_os = "android"))]
    fn get_mobile_manufacturer() -> String {
        #[cfg(target_os = "ios")]
        return "Apple".to_string();
        #[cfg(target_os = "android")]
        return "placeholder-manufacturer".to_string(); // Use Build.MANUFACTURER
    }
    
    #[cfg(any(target_os = "ios", target_os = "android"))]
    fn is_physical_device() -> bool {
        // Detect if running on simulator/emulator
        true // Placeholder
    }
    
    #[cfg(any(target_os = "ios", target_os = "android"))]
    fn get_advertising_id() -> Option<String> {
        // Requires user permission
        None
    }
    
    /// Collect CPU information from the system
    fn collect_cpu_info() -> Result<CpuInfo, String> {
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            // Mobile-specific CPU info collection
            Ok(CpuInfo {
                cores: num_cpus::get() as u32,
                model: "Mobile Processor".to_string(), // Would need platform API
                frequency: 0, // Not easily accessible on mobile
                architecture: std::env::consts::ARCH.to_string(),
                vendor_id: None,
            })
        }
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            // Original server implementation
            let cores = sys_info::cpu_num()
                .map_err(|e| format!("Failed to get CPU count: {}", e))?;
            
            let frequency = sys_info::cpu_speed()
                .unwrap_or(0) as u64 * 1_000_000;
            
            let model = Self::get_cpu_model().unwrap_or_else(|| "Unknown CPU".to_string());
            let vendor_id = Self::get_cpu_vendor_id();
            
            Ok(CpuInfo {
                cores,
                model,
                frequency,
                architecture: std::env::consts::ARCH.to_string(),
                vendor_id,
            })
        }
    }
    
    /// Get CPU model name from system
    fn get_cpu_model() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                for line in cpuinfo.lines() {
                    if line.starts_with("model name") {
                        return line.split(':')
                            .nth(1)
                            .map(|s| s.trim().to_string());
                    }
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl")
                .args(&["-n", "machdep.cpu.brand_string"])
                .output()
            {
                if let Ok(model) = String::from_utf8(output.stdout) {
                    return Some(model.trim().to_string());
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("wmic")
                .args(&["cpu", "get", "name", "/value"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    for line in output_str.lines() {
                        if line.starts_with("Name=") {
                            return Some(line[5..].trim().to_string());
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Get CPU vendor ID
    fn get_cpu_vendor_id() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                for line in cpuinfo.lines() {
                    if line.starts_with("vendor_id") {
                        return line.split(':')
                            .nth(1)
                            .map(|s| s.trim().to_string());
                    }
                }
            }
        }
        
        None
    }
    
    /// Collect memory information
    fn collect_memory_info() -> Result<MemoryInfo, String> {
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let mem_info = sys_info::mem_info()
                .map_err(|e| format!("Failed to get memory info: {}", e))?;
            
            Ok(MemoryInfo {
                total: mem_info.total * 1024,
                available: mem_info.avail * 1024,
            })
        }
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            // Mobile platforms - would need platform-specific APIs
            Ok(MemoryInfo {
                total: 4 * 1024 * 1024 * 1024, // 4GB placeholder
                available: 2 * 1024 * 1024 * 1024, // 2GB placeholder
            })
        }
    }
    
    /// Collect disk information
    fn collect_disk_info() -> Result<DiskInfo, String> {
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            let disk_info = sys_info::disk_info()
                .map_err(|e| format!("Failed to get disk info: {}", e))?;
            
            Ok(DiskInfo {
                total: disk_info.total * 1024,
                available: disk_info.free * 1024,
                filesystem: Self::get_filesystem_type().unwrap_or_else(|| "Unknown".to_string()),
            })
        }
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            // Mobile platforms - would need platform-specific APIs
            Ok(DiskInfo {
                total: 64 * 1024 * 1024 * 1024, // 64GB placeholder
                available: 32 * 1024 * 1024 * 1024, // 32GB placeholder
                filesystem: "mobile".to_string(),
            })
        }
    }
    
    /// Get filesystem type for root partition
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
        
        #[cfg(target_os = "macos")]
        {
            return Some("apfs".to_string());
        }
        
        #[cfg(target_os = "windows")]
        {
            return Some("ntfs".to_string());
        }
        
        None
    }
    
    /// Collect network interface information
    async fn collect_network_info() -> Result<NetworkInfo, String> {
        let interfaces = Self::get_network_interfaces()?;
        let public_ip = Self::get_public_ip().await?;
        
        Ok(NetworkInfo {
            interfaces,
            public_ip,
        })
    }
    
    /// Get all network interfaces with filtering for physical interfaces
    fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
        let mut interfaces = Vec::new();
        
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            use pnet::datalink;
            
            for interface in datalink::interfaces() {
                if interface.is_loopback() {
                    continue;
                }
                
                let is_physical = !interface.name.starts_with("veth") &&
                                !interface.name.starts_with("docker") &&
                                !interface.name.starts_with("br-") &&
                                !interface.name.starts_with("virbr") &&
                                !interface.name.starts_with("lo") &&
                                !interface.name.contains("tun");
                
                let mac_address = interface.mac
                    .map(|mac| mac.to_string())
                    .unwrap_or_else(|| "00:00:00:00:00:00".to_string());
                
                for ip_network in &interface.ips {
                    if let Some(ip) = ip_network.ip().to_string().split('/').next() {
                        interfaces.push(NetworkInterface {
                            name: interface.name.clone(),
                            ip_address: ip.to_string(),
                            mac_address: mac_address.clone(),
                            interface_type: Self::determine_interface_type(&interface.name),
                            is_physical,
                        });
                    }
                }
            }
        }
        
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            // Mobile platforms typically have WiFi and cellular interfaces
            interfaces.push(NetworkInterface {
                name: "wifi0".to_string(),
                ip_address: "192.168.1.100".to_string(),
                mac_address: "00:00:00:00:00:00".to_string(),
                interface_type: "wifi".to_string(),
                is_physical: true,
            });
        }
        
        if interfaces.is_empty() {
            warn!("No network interfaces found, using fallback");
            interfaces.push(NetworkInterface {
                name: "unknown".to_string(),
                ip_address: "0.0.0.0".to_string(),
                mac_address: "00:00:00:00:00:00".to_string(),
                interface_type: "unknown".to_string(),
                is_physical: false,
            });
        }
        
        Ok(interfaces)
    }
    
    /// Determine interface type based on name patterns
    fn determine_interface_type(name: &str) -> String {
        if name.starts_with("eth") || name.starts_with("enp") || name.starts_with("ens") {
            "ethernet".to_string()
        } else if name.starts_with("wl") || name.starts_with("wifi") {
            "wifi".to_string()
        } else if name.starts_with("tun") || name.starts_with("tap") {
            "tunnel".to_string()
        } else if name.starts_with("docker") || name.starts_with("br-") {
            "bridge".to_string()
        } else {
            "other".to_string()
        }
    }
    
    /// Get public IP address
    async fn get_public_ip() -> Result<String, String> {
        let services = [
            "https://api.ipify.org",
            "https://ipinfo.io/ip",
            "https://checkip.amazonaws.com",
        ];
        
        for service in &services {
            match reqwest::get(*service).await {
                Ok(response) => {
                    if let Ok(ip) = response.text().await {
                        let ip = ip.trim().to_string();
                        if Self::is_valid_ip(&ip) {
                            return Ok(ip);
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to get IP from {}: {}", service, e);
                }
            }
        }
        
        Err("Failed to determine public IP from all services".to_string())
    }
    
    /// Validate IP address format
    fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }
    
    /// Collect operating system information
    fn collect_os_info() -> Result<OsInfo, String> {
        let mut os_type = std::env::consts::OS.to_string();
        
        // Detect mobile OS types
        #[cfg(target_os = "ios")]
        {
            os_type = "ios".to_string();
        }
        #[cfg(target_os = "android")]
        {
            os_type = "android".to_string();
        }
        
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        let kernel = sys_info::os_release()
            .unwrap_or_else(|_| "Unknown".to_string());
        #[cfg(any(target_os = "ios", target_os = "android"))]
        let kernel = "mobile".to_string();
        
        let (version, distribution) = Self::get_os_details();
        
        Ok(OsInfo {
            os_type,
            version,
            distribution,
            kernel,
        })
    }
    
    /// Get detailed OS version and distribution information
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
            
            if let Ok(lsb) = fs::read_to_string("/etc/lsb-release") {
                let mut version = "Unknown".to_string();
                let mut distribution = "Unknown".to_string();
                
                for line in lsb.lines() {
                    if line.starts_with("DISTRIB_RELEASE=") {
                        version = line.split('=').nth(1).unwrap_or("Unknown").to_string();
                    } else if line.starts_with("DISTRIB_ID=") {
                        distribution = line.split('=').nth(1).unwrap_or("Unknown").to_string();
                    }
                }
                
                return (version, distribution);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            let version = Command::new("sw_vers")
                .arg("-productVersion")
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            
            return (version, "macOS".to_string());
        }
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            let version = Command::new("ver")
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            
            return (version, "Windows".to_string());
        }
        
        #[cfg(target_os = "ios")]
        {
            return ("Unknown".to_string(), "iOS".to_string());
        }
        
        #[cfg(target_os = "android")]
        {
            return ("Unknown".to_string(), "Android".to_string());
        }
        
        ("Unknown".to_string(), "Unknown".to_string())
    }
    
    /// Get system UUID from DMI (very stable on VMs)
    fn get_system_uuid() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            let uuid_paths = [
                "/sys/class/dmi/id/product_uuid",
                "/sys/devices/virtual/dmi/id/product_uuid",
            ];
            
            for path in &uuid_paths {
                if let Ok(uuid) = fs::read_to_string(path) {
                    let uuid = uuid.trim().to_string();
                    if !uuid.is_empty() && uuid != "00000000-0000-0000-0000-000000000000" {
                        return Some(uuid);
                    }
                }
            }
            
            if let Ok(serial) = fs::read_to_string("/sys/class/dmi/id/product_serial") {
                let serial = serial.trim();
                if !serial.is_empty() && serial != "0" && serial != "System Serial Number" {
                    return Some(format!("SERIAL:{}", serial));
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            if let Ok(output) = Command::new("ioreg")
                .args(&["-d2", "-c", "IOPlatformExpertDevice"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    for line in output_str.lines() {
                        if line.contains("IOPlatformUUID") {
                            if let Some(uuid) = line.split('"').nth(3) {
                                return Some(uuid.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Get machine ID (very stable on Linux)
    fn get_machine_id() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            if let Ok(id) = fs::read_to_string("/etc/machine-id") {
                let id = id.trim().to_string();
                if !id.is_empty() {
                    return Some(id);
                }
            }
            
            if let Ok(id) = fs::read_to_string("/var/lib/dbus/machine-id") {
                let id = id.trim().to_string();
                if !id.is_empty() {
                    return Some(id);
                }
            }
        }
        
        None
    }
    
    /// Collect BIOS/UEFI information
    fn collect_bios_info() -> Option<BiosInfo> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            let vendor = fs::read_to_string("/sys/class/dmi/id/bios_vendor")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            
            let version = fs::read_to_string("/sys/class/dmi/id/bios_version")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            
            let system_manufacturer = fs::read_to_string("/sys/class/dmi/id/sys_vendor")
                .or_else(|_| fs::read_to_string("/sys/class/dmi/id/board_vendor"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            
            let system_product = fs::read_to_string("/sys/class/dmi/id/product_name")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            
            if vendor != "Unknown" || system_manufacturer != "Unknown" {
                return Some(BiosInfo {
                    vendor,
                    version,
                    system_manufacturer,
                    system_product,
                });
            }
        }
        
        None
    }
    
    /// Detect cloud provider based on system characteristics
    pub fn detect_cloud_provider(&self) -> Option<String> {
        // Mobile devices are not cloud providers
        if self.mobile_info.is_some() {
            return None;
        }
        
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            if let Ok(uuid) = fs::read_to_string("/sys/hypervisor/uuid") {
                if uuid.to_lowercase().starts_with("ec2") {
                    return Some("AWS".to_string());
                }
            }
            
            if let Some(bios) = &self.bios_info {
                let manufacturer = bios.system_manufacturer.to_lowercase();
                let product = bios.system_product.to_lowercase();
                
                if manufacturer.contains("amazon") || product.contains("amazon") {
                    return Some("AWS".to_string());
                } else if manufacturer.contains("microsoft") || product.contains("virtual machine") {
                    return Some("Azure".to_string());
                } else if manufacturer.contains("google") || product.contains("google") {
                    return Some("GCP".to_string());
                } else if manufacturer.contains("digitalocean") {
                    return Some("DigitalOcean".to_string());
                } else if product.contains("kvm") || product.contains("qemu") {
                    return Some("KVM/Generic".to_string());
                }
            }
            
            if fs::metadata("/var/lib/cloud").is_ok() {
                return Some("Cloud/Generic".to_string());
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_hardware_info_collection() {
        let hw_info = HardwareInfo::collect().await;
        assert!(hw_info.is_ok(), "Failed to collect hardware info: {:?}", hw_info.err());
        
        let info = hw_info.unwrap();
        assert!(!info.hostname.is_empty());
        assert!(info.cpu.cores > 0);
        assert!(info.memory.total > 0);
        assert!(!info.os.os_type.is_empty());
        
        // Test fingerprint generation
        let fingerprint = info.generate_fingerprint();
        assert_eq!(fingerprint.len(), 64);
        
        // Test ZKP commitment generation
        let commitment = info.generate_zkp_commitment();
        assert_eq!(commitment.len(), 32);
        
        // Test commitment verification
        assert!(info.verify_commitment(&commitment));
        
        // Test fingerprint summary
        let summary = info.generate_fingerprint_summary();
        assert!(!summary.is_empty());
        println!("Fingerprint summary: {}", summary);
        
        // Test mobile info on mobile platforms
        if IS_MOBILE {
            assert!(info.mobile_info.is_some());
        } else {
            assert!(info.mobile_info.is_none());
        }
    }
    
    #[test]
    fn test_fingerprint_stability() {
        // Test with mobile device
        let mobile_hw_info = HardwareInfo {
            hostname: "mobile-device".to_string(),
            cpu: CpuInfo {
                cores: 8,
                model: "Apple A15 Bionic".to_string(),
                frequency: 0,
                architecture: "aarch64".to_string(),
                vendor_id: None,
            },
            memory: MemoryInfo {
                total: 6000000000,
                available: 3000000000,
            },
            disk: DiskInfo {
                total: 128000000000,
                available: 64000000000,
                filesystem: "apfs".to_string(),
            },
            network: NetworkInfo {
                interfaces: vec![],
                public_ip: "1.2.3.4".to_string(),
            },
            os: OsInfo {
                os_type: "ios".to_string(),
                version: "16.0".to_string(),
                distribution: "iOS".to_string(),
                kernel: "mobile".to_string(),
            },
            system_uuid: None,
            machine_id: None,
            bios_info: None,
            mobile_info: Some(MobileInfo {
                device_id: "1234-5678-9ABC-DEF0".to_string(),
                device_model: "iPhone 14 Pro".to_string(),
                manufacturer: "Apple".to_string(),
                is_physical: true,
                advertising_id: None,
            }),
        };
        
        let fingerprint1 = mobile_hw_info.generate_fingerprint();
        let mut mobile_hw_info2 = mobile_hw_info.clone();
        
        // Change volatile attributes
        mobile_hw_info2.memory.available = 2000000000;
        mobile_hw_info2.network.public_ip = "5.6.7.8".to_string();
        
        let fingerprint2 = mobile_hw_info2.generate_fingerprint();
        assert_eq!(fingerprint1, fingerprint2, "Mobile fingerprint changed with volatile data");
        
        // Change stable attribute (device ID)
        mobile_hw_info2.mobile_info.as_mut().unwrap().device_id = "FFFF-FFFF-FFFF-FFFF".to_string();
        let fingerprint3 = mobile_hw_info2.generate_fingerprint();
        assert_ne!(fingerprint1, fingerprint3, "Mobile fingerprint didn't change when device ID changed");
        
        // Test server hardware (original test)
        let hw_info1 = HardwareInfo {
            hostname: "test-host".to_string(),
            cpu: CpuInfo {
                cores: 8,
                model: "Intel Core i7".to_string(),
                frequency: 3600000000,
                architecture: "x86_64".to_string(),
                vendor_id: Some("GenuineIntel".to_string()),
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
                        is_physical: true,
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
            system_uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            machine_id: Some("abcdef1234567890".to_string()),
            bios_info: None,
            mobile_info: None,
        };
        
        let mut hw_info2 = hw_info1.clone();
        
        // Change volatile attributes
        hw_info2.memory.available = 7000000000;
        hw_info2.disk.total = 2000000000000;
        hw_info2.disk.available = 1500000000000;
        hw_info2.network.public_ip = "5.6.7.8".to_string();
        hw_info2.os.kernel = "5.19.0".to_string();
        
        let server_fingerprint1 = hw_info1.generate_fingerprint();
        let server_fingerprint2 = hw_info2.generate_fingerprint();
        
        assert_eq!(server_fingerprint1, server_fingerprint2, 
                   "Server fingerprint changed despite only volatile attributes changing");
        
        // Test ZKP commitments
        let commitment1 = hw_info1.generate_zkp_commitment();
        let commitment2 = hw_info2.generate_zkp_commitment();
        assert_eq!(commitment1, commitment2,
                   "ZKP commitment changed despite only volatile attributes changing");
        
        // Change stable attribute
        hw_info2.network.interfaces[0].mac_address = "11:22:33:44:55:66".to_string();
        let server_fingerprint3 = hw_info2.generate_fingerprint();
        let commitment3 = hw_info2.generate_zkp_commitment();
        
        assert_ne!(server_fingerprint1, server_fingerprint3, 
                   "Server fingerprint didn't change when MAC address changed");
        assert_ne!(commitment1, commitment3,
                   "ZKP commitment didn't change when MAC address changed");
    }
    
    #[test]
    fn test_valid_ip() {
        assert!(HardwareInfo::is_valid_ip("192.168.1.1"));
        assert!(HardwareInfo::is_valid_ip("10.0.0.1"));
        assert!(HardwareInfo::is_valid_ip("2001:db8::1"));
        assert!(!HardwareInfo::is_valid_ip("not.an.ip"));
        assert!(!HardwareInfo::is_valid_ip("256.256.256.256"));
        assert!(!HardwareInfo::is_valid_ip(""));
    }
    
    #[test]
    fn test_interface_type_detection() {
        assert_eq!(HardwareInfo::determine_interface_type("eth0"), "ethernet");
        assert_eq!(HardwareInfo::determine_interface_type("enp3s0"), "ethernet");
        assert_eq!(HardwareInfo::determine_interface_type("wlan0"), "wifi");
        assert_eq!(HardwareInfo::determine_interface_type("docker0"), "bridge");
        assert_eq!(HardwareInfo::determine_interface_type("tun0"), "tunnel");
        assert_eq!(HardwareInfo::determine_interface_type("weird0"), "other");
    }
    
    #[test]
    fn test_zkp_serialization() {
        // Test mobile hardware
        let mobile_hw = HardwareInfo {
            hostname: "mobile".to_string(),
            cpu: CpuInfo {
                cores: 6,
                model: "Snapdragon 888".to_string(),
                frequency: 0,
                architecture: "aarch64".to_string(),
                vendor_id: None,
            },
            memory: MemoryInfo {
                total: 8000000000,
                available: 4000000000,
            },
            disk: DiskInfo {
                total: 256000000000,
                available: 128000000000,
                filesystem: "f2fs".to_string(),
            },
            network: NetworkInfo {
                interfaces: vec![],
                public_ip: "1.2.3.4".to_string(),
            },
            os: OsInfo {
                os_type: "android".to_string(),
                version: "13".to_string(),
                distribution: "Android".to_string(),
                kernel: "mobile".to_string(),
            },
            system_uuid: None,
            machine_id: None,
            bios_info: None,
            mobile_info: Some(MobileInfo {
                device_id: "android-id-12345".to_string(),
                device_model: "Pixel 7".to_string(),
                manufacturer: "Google".to_string(),
                is_physical: true,
                advertising_id: None,
            }),
        };
        
        let mobile_zkp_bytes = mobile_hw.to_zkp_bytes();
        assert!(mobile_zkp_bytes.is_ok());
        assert!(!mobile_zkp_bytes.unwrap().is_empty());
        
        // Test server hardware
        let server_hw = HardwareInfo {
            hostname: "test".to_string(),
            cpu: CpuInfo {
                cores: 4,
                model: "Test CPU".to_string(),
                frequency: 2400000000,
                architecture: "x86_64".to_string(),
                vendor_id: None,
            },
            memory: MemoryInfo {
                total: 8000000000,
                available: 4000000000,
            },
            disk: DiskInfo {
                total: 500000000000,
                available: 250000000000,
                filesystem: "ext4".to_string(),
            },
            network: NetworkInfo {
                interfaces: vec![],
                public_ip: "1.2.3.4".to_string(),
            },
            os: OsInfo {
                os_type: "linux".to_string(),
                version: "22.04".to_string(),
                distribution: "Ubuntu".to_string(),
                kernel: "5.15.0".to_string(),
            },
            system_uuid: None,
            machine_id: None,
            bios_info: None,
            mobile_info: None,
        };
        
        let server_zkp_bytes = server_hw.to_zkp_bytes();
        assert!(server_zkp_bytes.is_ok());
        assert!(!server_zkp_bytes.unwrap().is_empty());
    }
}
