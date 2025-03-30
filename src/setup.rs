// src/setup.rs
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::{self, BufRead, BufReader};
use std::thread;
use std::time::Duration;
use crate::types::{Result, VpnError};
use crate::utils;
use rand::{Rng, thread_rng};

pub struct ServerSetup {
    pub installation_dir: PathBuf,
    pub config_dir: PathBuf,
    pub cert_dir: PathBuf,
    pub server_ip: String,
    pub port: u16,
    pub subnet: String,
    pub enable_obfuscation: bool,
    pub obfuscation_method: String,
    pub max_connections: usize,
    pub enable_security_hardening: bool,
    pub tls_cipher_suites: Vec<String>,
    pub key_rotation_interval: u64,
    pub session_timeout: u64,
}

impl Default for ServerSetup {
    fn default() -> Self {
        Self {
            installation_dir: PathBuf::from("/opt/aeronyx"),
            config_dir: PathBuf::from("/opt/aeronyx/config"),
            cert_dir: PathBuf::from("/opt/aeronyx/certs"),
            server_ip: String::new(),
            port: 8080,
            subnet: "10.7.0.0/24".to_string(),
            enable_obfuscation: true,
            obfuscation_method: "xor".to_string(),
            max_connections: 100,
            enable_security_hardening: true,
            tls_cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            key_rotation_interval: 3600,  // 1 hour in seconds
            session_timeout: 86400,       // 24 hours in seconds
        }
    }
}

impl ServerSetup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn interactive_setup(&mut self) -> Result<()> {
        println!("=== AeroNyx Privacy Network Server Setup ===");
        
        // Check for root privileges
        if !self.check_root() {
            return Err(VpnError::Network("This setup must be run with root privileges".into()));
        }
        
        // Detect server IP
        self.detect_server_ip()?;
        
        // Ask for installation directory
        println!("\nEnter installation directory [default: /opt/aeronyx]:");
        let input = self.read_line()?;
        if !input.trim().is_empty() {
            self.installation_dir = PathBuf::from(input.trim());
        }
        
        self.config_dir = self.installation_dir.join("config");
        self.cert_dir = self.installation_dir.join("certs");
        
        // Ask for server port
        println!("\nEnter server port [default: 8080]:");
        let input = self.read_line()?;
        if !input.trim().is_empty() {
            if let Ok(port) = input.trim().parse() {
                if port > 0 && port < 65536 {
                    self.port = port;
                } else {
                    println!("Invalid port (must be 1-65535), using default: 8080");
                }
            } else {
                println!("Invalid port, using default: 8080");
            }
        }
        
        // Ask for subnet
        println!("\nEnter VPN subnet [default: 10.7.0.0/24]:");
        let input = self.read_line()?;
        if !input.trim().is_empty() {
            // Basic validation for CIDR format
            if input.trim().contains("/") {
                self.subnet = input.trim().to_string();
            } else {
                println!("Invalid subnet format, using default: 10.7.0.0/24");
            }
        }
        
        // Configure obfuscation
        println!("\nEnable traffic obfuscation? [Y/n]:");
        let input = self.read_line()?;
        if input.trim().to_lowercase() == "n" {
            self.enable_obfuscation = false;
        } else {
            // Ask for obfuscation method
            println!("\nSelect obfuscation method:");
            println!("1. XOR (Basic obfuscation, fastest)");
            println!("2. ScrambleSuit (Advanced obfuscation, balanced)");
            println!("3. Obfs4 (Maximum obfuscation, slower)");
            println!("Enter your choice [default: 1]:");
            
            let input = self.read_line()?;
            match input.trim() {
                "2" => self.obfuscation_method = "scramblesuit".to_string(),
                "3" => self.obfuscation_method = "obfs4".to_string(),
                _ => self.obfuscation_method = "xor".to_string(),
            }
        }
        
        // Ask for max connections
        println!("\nMaximum concurrent connections [default: 100]:");
        let input = self.read_line()?;
        if !input.trim().is_empty() {
            if let Ok(conn) = input.trim().parse() {
                if conn > 0 {
                    self.max_connections = conn;
                } else {
                    println!("Invalid number, using default: 100");
                }
            } else {
                println!("Invalid input, using default: 100");
            }
        }
        
        // Ask for security hardening
        println!("\nEnable additional security hardening? [Y/n]:");
        let input = self.read_line()?;
        if input.trim().to_lowercase() == "n" {
            self.enable_security_hardening = false;
        }
        
        // Ask for key rotation interval
        println!("\nKey rotation interval in seconds [default: 3600 (1 hour)]:");
        let input = self.read_line()?;
        if !input.trim().is_empty() {
            if let Ok(interval) = input.trim().parse() {
                if interval >= 300 { // Minimum 5 minutes
                    self.key_rotation_interval = interval;
                } else {
                    println!("Interval too short, using default: 3600");
                }
            } else {
                println!("Invalid input, using default: 3600");
            }
        }

        // Confirm setup
        println!("\n=== Setup Summary ===");
        println!("Installation Directory: {}", self.installation_dir.display());
        println!("Server IP: {}", self.server_ip);
        println!("Server Port: {}", self.port);
        println!("VPN Subnet: {}", self.subnet);
        println!("Traffic Obfuscation: {}", if self.enable_obfuscation { "Enabled" } else { "Disabled" });
        if self.enable_obfuscation {
            println!("Obfuscation Method: {}", self.obfuscation_method);
        }
        println!("Maximum Connections: {}", self.max_connections);
        println!("Security Hardening: {}", if self.enable_security_hardening { "Enabled" } else { "Disabled" });
        println!("Key Rotation Interval: {} seconds", self.key_rotation_interval);
        
        println!("\nProceed with installation? [Y/n]:");
        let input = self.read_line()?;
        if input.trim().to_lowercase() == "n" {
            return Err(VpnError::Network("Setup cancelled by user".into()));
        }
        
        // Start installation
        self.perform_installation()?;
        
        Ok(())
    }
    
    fn perform_installation(&self) -> Result<()> {
        println!("\n=== Installing AeroNyx Privacy Network ===");
        
        // Create directories
        println!("Creating directories...");
        fs::create_dir_all(&self.installation_dir)?;
        fs::create_dir_all(&self.config_dir)?;
        fs::create_dir_all(&self.cert_dir)?;
        fs::create_dir_all(self.installation_dir.join("logs"))?;
        
        // Generate certificates
        println!("Generating TLS certificates...");
        self.generate_certificates()?;
        
        // Create ACL file
        println!("Creating access control list...");
        self.create_acl_file()?;
        
        // Configure networking
        println!("Configuring networking...");
        self.configure_networking()?;
        
        // Apply system optimizations
        println!("Applying system optimizations...");
        self.apply_system_optimizations()?;
        
        // Create systemd service
        println!("Creating systemd service...");
        self.create_systemd_service()?;
        
        // Create client registration script
        println!("Creating client registration script...");
        self.create_registration_script()?;
        
        // Configure firewall
        println!("Configuring firewall...");
        self.configure_firewall()?;
        
        // Set up log rotation
        println!("Setting up log rotation...");
        self.setup_log_rotation()?;
        
        // Start service
        println!("Starting AeroNyx service...");
        self.start_service()?;
        
        println!("\n=== Installation Complete ===");
        println!("AeroNyx Privacy Network is now running on {}:{}", self.server_ip, self.port);
        println!("To add clients, use: {}/add_client.sh <client_public_key>", self.installation_dir.display());
        println!("To view logs: journalctl -u aeronyx-vpn -f");
        println!("Or check log files at: {}/logs/", self.installation_dir.display());
        
        Ok(())
    }
    
    fn generate_certificates(&self) -> Result<()> {
        let cert_path = self.cert_dir.join("server.crt");
        let key_path = self.cert_dir.join("server.key");
        
        // Check if certificates already exist
        if cert_path.exists() && key_path.exists() {
            println!("Certificates already exist, skipping generation");
            return Ok(());
        }
        
        // Generate a strong ECDSA certificate
        let status = Command::new("openssl")
            .args(&[
                "req", "-x509", 
                "-newkey", "rsa:4096", 
                "-keyout", &key_path.to_string_lossy(),
                "-out", &cert_path.to_string_lossy(),
                "-days", "3650", // 10 years
                "-nodes",  // No passphrase
                "-sha256", // Use SHA-256
                "-subj", &format!("/CN={}", self.server_ip),
                // Add Subject Alternative Name for the IP
                "-addext", &format!("subjectAltName=IP:{}", self.server_ip)
            ])
            .status()?;
            
        if !status.success() {
            return Err(VpnError::Crypto("Failed to generate certificates".into()));
        }
        
        // Set proper permissions
        Command::new("chmod")
            .args(&["600", &key_path.to_string_lossy()])
            .status()?;
            
        println!("Generated TLS certificates with 4096-bit RSA key and SHA-256");
        Ok(())
    }
    
    fn create_acl_file(&self) -> Result<()> {
        let acl_path = self.config_dir.join("access_control.json");
        
        // Skip if file already exists
        if acl_path.exists() {
            println!("Access control file already exists, skipping creation");
            return Ok(());
        }
        
        let timestamp = utils::current_timestamp_millis();
            
        let acl_content = format!(
            r#"{{
  "default_policy": "deny",
  "entries": [],
  "updated_at": {}
}}"#, timestamp);
        
        let mut file = File::create(acl_path)?;
        file.write_all(acl_content.as_bytes())?;
        
        Ok(())
    }
    
    fn configure_networking(&self) -> Result<()> {
        // Enable IP forwarding
        let mut file = File::create("/proc/sys/net/ipv4/ip_forward")?;
        file.write_all(b"1")?;
        
        // Make IP forwarding persistent
        let mut sysctl_found = false;
        if let Ok(file) = File::open("/etc/sysctl.conf") {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if line.contains("net.ipv4.ip_forward") {
                        sysctl_found = true;
                        break;
                    }
                }
            }
        }
        
        if !sysctl_found {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open("/etc/sysctl.conf")?;
            file.write_all(b"net.ipv4.ip_forward = 1\n")?;
        }
        
        // Apply sysctl settings
        Command::new("sysctl")
            .args(&["-p"])
            .status()?;
            
        // Get main interface
        let interface = self.get_main_interface()?;
        
        // Configure NAT - Drop old rules first to avoid duplication
        Command::new("iptables")
            .args(&[
                "-t", "nat", "-D", "POSTROUTING",
                "-s", &self.subnet,
                "-o", &interface,
                "-j", "MASQUERADE"
            ])
            .status()
            .ok(); // Ignore error if rule doesn't exist
            
        // Add NAT rule
        Command::new("iptables")
            .args(&[
                "-t", "nat", "-A", "POSTROUTING",
                "-s", &self.subnet,
                "-o", &interface,
                "-j", "MASQUERADE"
            ])
            .status()?;
            
        // Add forward rules
        Command::new("iptables")
            .args(&[
                "-A", "FORWARD",
                "-s", &self.subnet,
                "-i", "tun0",
                "-o", &interface,
                "-m", "state",
                "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
            ])
            .status()?;
            
        Command::new("iptables")
            .args(&[
                "-A", "FORWARD",
                "-d", &self.subnet,
                "-i", &interface,
                "-o", "tun0",
                "-m", "state",
                "--state", "RELATED,ESTABLISHED",
                "-j", "ACCEPT"
            ])
            .status()?;
            
        // Install iptables-persistent if available
        if Command::new("which")
            .arg("apt")
            .status()?
            .success() {
            
            Command::new("apt")
                .args(&["install", "-y", "iptables-persistent"])
                .status()
                .ok(); // Ignore errors
                
            // Save iptables rules
            if Path::new("/usr/sbin/netfilter-persistent").exists() {
                Command::new("netfilter-persistent")
                    .args(&["save"])
                    .status()?;
            }
        }
            
        Ok(())
    }
    
    fn apply_system_optimizations(&self) -> Result<()> {
        // Create optimized sysctl configuration
        let sysctl_content = r#"# AeroNyx Performance Optimizations

# Network performance
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192

# Connection handling
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# VPN specific
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1

# File handles
fs.file-max = 2097152
fs.nr_open = 2097152

# Process limits
kernel.pid_max = 65536
"#;

        // Write to a separate config file to avoid conflicts
        let sysctl_path = "/etc/sysctl.d/99-aeronyx-performance.conf";
        let mut file = File::create(sysctl_path)?;
        file.write_all(sysctl_content.as_bytes())?;
        
        // Apply optimizations
        Command::new("sysctl")
            .args(&["-p", sysctl_path])
            .status()?;
            
        // Increase file descriptor limits
        let limits_dir = "/etc/security/limits.d";
        if !Path::new(limits_dir).exists() {
            fs::create_dir_all(limits_dir)?;
        }
        
        let limits_content = r#"*               soft    nofile          524288
*               hard    nofile          524288
root            soft    nofile          524288
root            hard    nofile          524288
"#;
        let mut file = File::create("/etc/security/limits.d/aeronyx.conf")?;
        file.write_all(limits_content.as_bytes())?;
        
        // Set systemd limits if systemd is used
        if Path::new("/etc/systemd").exists() {
            fs::create_dir_all("/etc/systemd/system.conf.d")?;
            let systemd_limits = r#"[Manager]
DefaultLimitNOFILE=524288
"#;
            let mut file = File::create("/etc/systemd/system.conf.d/limits.conf")?;
            file.write_all(systemd_limits.as_bytes())?;
        }
        
        Ok(())
    }
    
    fn create_systemd_service(&self) -> Result<()> {
        let binary_path = self.installation_dir.join("aeronyx-private-ed25519");
        
        // Generate a secure service definition with performance and security enhancements
        let mut security_options = String::new();
        if self.enable_security_hardening {
            security_options = r#"
# Security hardening
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW"#.to_string();
        }
        
        let service_content = format!(
            r#"[Unit]
Description=AeroNyx Privacy Network
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart={} \
  --listen 0.0.0.0:{} \
  --tun-name tun0 \
  --subnet {} \
  --cert-file {}/server.crt \
  --key-file {}/server.key \
  --acl-file {}/access_control.json \
  --enable-obfuscation {} \
  --obfuscation-method {} \
  --key-rotation-interval {} \
  --max-connections-per-ip {} \
  --log-level info
WorkingDirectory={}
Restart=on-failure
RestartSec=5
LimitNOFILE=524288
StandardOutput=append:{}/logs/aeronyx.log
StandardError=append:{}/logs/aeronyx.error.log{}

[Install]
WantedBy=multi-user.target
"#,
            binary_path.display(),
            self.port,
            self.subnet,
            self.cert_dir.display(),
            self.cert_dir.display(),
            self.config_dir.display(),
            if self.enable_obfuscation { "" } else { "false" },
            self.obfuscation_method,
            self.key_rotation_interval,
            self.max_connections,
            self.installation_dir.display(),
            self.installation_dir.display(),
            self.installation_dir.display(),
            security_options
        );
        
        let mut file = File::create("/etc/systemd/system/aeronyx-vpn.service")?;
        file.write_all(service_content.as_bytes())?;
        
        Ok(())
    }
    
    fn create_registration_script(&self) -> Result<()> {
        let script_path = self.installation_dir.join("add_client.sh");
        let acl_path = self.config_dir.join("access_control.json");
        
        // Enhanced registration script with security validation
        let script_content = format!(
            r#"#!/bin/bash
if [ $# -ne 1 ]; then
  echo "Usage: $0 <client_public_key>"
  exit 1
fi

CLIENT_KEY="$1"
ACL_FILE="{}"

# Verify the key format (basic check for Solana public key)
if [[ ! "$CLIENT_KEY" =~ ^[1-9A-HJ-NP-Za-km-z]{{32,44}}$ ]]; then
  echo "Error: Invalid public key format"
  exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
  echo "Error: jq is required but not installed"
  echo "Install with: apt install jq"
  exit 1
fi

# Check if client already exists
EXISTING_CLIENT=$(jq -r --arg key "$CLIENT_KEY" '.entries[] | select(.public_key == $key) | .public_key' "$ACL_FILE")
if [ ! -z "$EXISTING_CLIENT" ]; then
  echo "Client $CLIENT_KEY already exists in ACL"
  exit 0
fi

# Create a backup
cp "$ACL_FILE" "${{ACL_FILE}}.bak"

# Create a temporary file with updated JSON
jq --arg key "$CLIENT_KEY" --arg now "$(date)" '.entries += [{{"public_key": $key, "access_level": 100, "is_allowed": true, "bandwidth_limit": 0, "max_session_duration": 86400, "static_ip": null, "notes": "Added on " + $now}}]' "$ACL_FILE" > "${{ACL_FILE}}.tmp"

# Update the timestamp
jq ".updated_at = $(date +%s000)" "${{ACL_FILE}}.tmp" > "$ACL_FILE"

# Clean up
rm "${{ACL_FILE}}.tmp"

echo "Added client $CLIENT_KEY to ACL"
echo "Reloading AeroNyx service..."
systemctl reload aeronyx-vpn 2>/dev/null || systemctl restart aeronyx-vpn

"#,
            acl_path.display()
        );
        
        let mut file = File::create(script_path)?;
        file.write_all(script_content.as_bytes())?;
        
        // Make executable
        Command::new("chmod")
            .args(&["+x", &script_path.to_string_lossy()])
            .status()?;
            
        // Install jq if needed
        if Command::new("which")
            .arg("apt")
            .status()?
            .success() {
            
            Command::new("apt")
                .args(&["install", "-y", "jq"])
                .status()
                .ok(); // Ignore errors
        }
            
        Ok(())
    }
    
    fn configure_firewall(&self) -> Result<()> {
        // Check if UFW is installed
        if Command::new("which")
            .arg("ufw")
            .status()?
            .success() {
                
            // Allow SSH
            Command::new("ufw")
                .args(&["allow", "ssh"])
                .status()?;
                
            // Allow VPN port
            Command::new("ufw")
                .args(&["allow", &format!("{}/tcp", self.port)])
                .status()?;
                
            // Set default policies
            Command::new("ufw")
                .args(&["default", "deny", "incoming"])
                .status()?;
                
            Command::new("ufw")
                .args(&["default", "allow", "outgoing"])
                .status()?;
                
            // Enable firewall
            Command::new("ufw")
                .args(&["--force", "enable"])
                .status()?;
                
            println!("UFW firewall configured");
        } else {
            // Try iptables directly if UFW is not available
            // Allow SSH
            Command::new("iptables")
                .args(&["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])
                .status()
                .ok();
                
            // Allow VPN port
            Command::new("iptables")
                .args(&["-A", "INPUT", "-p", "tcp", "--dport", &self.port.to_string(), "-j", "ACCEPT"])
                .status()
                .ok();
                
            println!("Configured firewall rules with iptables");
        }
        
        Ok(())
    }
    
    fn setup_log_rotation(&self) -> Result<()> {
        // Configure logrotate if available
        if Path::new("/etc/logrotate.d").exists() {
            let logrotate_content = format!(
                r#"{}/logs/*.log {{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl reload aeronyx-vpn >/dev/null 2>&1 || true
    endscript
}}
"#,
                self.installation_dir.display()
            );
            
            let mut file = File::create("/etc/logrotate.d/aeronyx")?;
            file.write_all(logrotate_content.as_bytes())?;
            
            println!("Configured log rotation");
        }
        
        Ok(())
    }
    
    fn start_service(&self) -> Result<()> {
        // Reload systemd
        Command::new("systemctl")
            .args(&["daemon-reload"])
            .status()?;
            
        // Enable service
        Command::new("systemctl")
            .args(&["enable", "aeronyx-vpn"])
            .status()?;
            
        // Check if binary exists before starting
        let binary_path = self.installation_dir.join("aeronyx-private-ed25519");
        if binary_path.exists() {
            // Start service
            Command::new("systemctl")
                .args(&["start", "aeronyx-vpn"])
                .status()?;
                
            // Wait briefly to check status
            thread::sleep(Duration::from_secs(2));
            
            // Check service status
            let status = Command::new("systemctl")
                .args(&["is-active", "aeronyx-vpn"])
                .output()?;
                
            if status.status.success() {
                println!("Service started successfully!");
            } else {
                println!("Service may have failed to start. Check status with: systemctl status aeronyx-vpn");
            }
        } else {
            println!("Binary not found at: {}. Service configured but not started.", binary_path.display());
            println!("Please build and copy the binary, then start the service with: systemctl start aeronyx-vpn");
        }
        
        Ok(())
    }
    
    fn detect_server_ip(&mut self) -> Result<()> {
        // Try multiple methods to determine the server's public IP
        
        // Method 1: Using curl with ipinfo.io
        if let Ok(output) = Command::new("curl")
            .args(&["-s", "https://ipinfo.io/ip"])
            .output() {
            
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() && self.validate_ip(&ip) {
                    println!("Detected public IP: {}", ip);
                    self.server_ip = ip;
                    return Ok(());
                }
            }
        }
        
        // Method 2: Using curl with api.ipify.org as a backup
        if let Ok(output) = Command::new("curl")
            .args(&["-s", "https://api.ipify.org"])
            .output() {
            
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() && self.validate_ip(&ip) {
                    println!("Detected public IP: {}", ip);
                    self.server_ip = ip;
                    return Ok(());
                }
            }
        }
        
        // Method 3: Using dig with OpenDNS
        if let Ok(output) = Command::new("dig")
            .args(&["+short", "myip.opendns.com", "@resolver1.opendns.com"])
            .output() {
            
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() && self.validate_ip(&ip) {
                    println!("Detected public IP: {}", ip);
                    self.server_ip = ip;
                    return Ok(());
                }
            }
        }
        
        println!("Could not detect public IP automatically.");
        println!("Please enter your server's public IP address:");
        let input = self.read_line()?;
        if input.trim().is_empty() || !self.validate_ip(input.trim()) {
            return Err(VpnError::Network("Invalid IP address provided".into()));
        }
        
        self.server_ip = input.trim().to_string();
        Ok(())
    }
    
    // Validate IPv4 address format
    fn validate_ip(&self, ip: &str) -> bool {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        
        for part in parts {
            if let Ok(num) = part.parse::<u8>() {
                // Valid octet
            } else {
                return false;
            }
        }
        
        true
    }
    
    fn get_main_interface(&self) -> Result<String> {
        // Try to determine the main interface using different methods
        
        // Method 1: Using ip route
        if let Ok(output) = Command::new("ip")
            .args(&["route", "get", "1.1.1.1"])
            .output() {
            
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for part in output_str.split_whitespace() {
                    if part == "dev" {
                        if let Some(interface) = output_str.split_whitespace().skip_while(|&x| x != "dev").nth(1) {
                            return Ok(interface.to_string());
                        }
                    }
                }
            }
        }
        
        // Method 2: Using route command
        if let Ok(output) = Command::new("route")
            .args(&["-n"])
            .output() {
            
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // Look for default route
                    if parts.len() >= 8 && parts[0] == "0.0.0.0" {
                        return Ok(parts[7].to_string());
                    }
                }
            }
        }
        
        // Method 3: Using netstat
        if let Ok(output) = Command::new("netstat")
            .args(&["-rn"])
            .output() {
            
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // Look for default route
                    if parts.len() >= 8 && (parts[0] == "0.0.0.0" || parts[0] == "default") {
                        return Ok(parts[7].to_string());
                    }
                }
            }
        }
        
        // Fallback to common interfaces, checking if they exist
        for iface in &["eth0", "ens3", "enp0s3", "wlan0"] {
            if Path::new(&format!("/sys/class/net/{}", iface)).exists() {
                return Ok(iface.to_string());
            }
        }
        
        // Default to eth0 if we couldn't detect
        println!("Could not detect main network interface, using eth0");
        Ok("eth0".to_string())
    }
    
    fn check_root(&self) -> bool {
        // On Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            fs::metadata("/").map(|m| m.uid() == 0).unwrap_or(false)
        }
        
        // On other systems
        #[cfg(not(unix))]
        {
            false
        }
    }
    
    fn read_line(&self) -> Result<String> {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        Ok(buffer)
    }
    
    // Generate a secure random string
    pub fn generate_secure_token(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789-_!@#$%^&*()";
        let mut rng = thread_rng();
        
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}
