// src/setup.rs
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::{self, BufRead, BufReader};
use crate::types::{Result, VpnError};

pub struct ServerSetup {
    pub installation_dir: PathBuf,
    pub config_dir: PathBuf,
    pub cert_dir: PathBuf,
    pub server_ip: String,
    pub port: u16,
    pub subnet: String,
    pub enable_obfuscation: bool,
    pub obfuscation_method: String,
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
                self.port = port;
            } else {
                println!("Invalid port, using default: 8080");
            }
        }
        
        // Ask for subnet
        println!("\nEnter VPN subnet [default: 10.7.0.0/24]:");
        let input = self.read_line()?;
        if !input.trim().is_empty() {
            self.subnet = input.trim().to_string();
        }
        
        // Configure obfuscation
        println!("\nEnable traffic obfuscation? [Y/n]:");
        let input = self.read_line()?;
        if input.trim().to_lowercase() == "n" {
            self.enable_obfuscation = false;
        } else {
            // Ask for obfuscation method
            println!("\nSelect obfuscation method:");
            println!("1. XOR (Basic obfuscation)");
            println!("2. ScrambleSuit (Advanced obfuscation)");
            println!("3. Obfs4 (Maximum obfuscation)");
            println!("Enter your choice [default: 1]:");
            
            let input = self.read_line()?;
            match input.trim() {
                "2" => self.obfuscation_method = "scramblesuit".to_string(),
                "3" => self.obfuscation_method = "obfs4".to_string(),
                _ => self.obfuscation_method = "xor".to_string(),
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
        
        // Generate certificates
        println!("Generating TLS certificates...");
        self.generate_certificates()?;
        
        // Create ACL file
        println!("Creating access control list...");
        self.create_acl_file()?;
        
        // Configure networking
        println!("Configuring networking...");
        self.configure_networking()?;
        
        // Create systemd service
        println!("Creating systemd service...");
        self.create_systemd_service()?;
        
        // Create client registration script
        println!("Creating client registration script...");
        self.create_registration_script()?;
        
        // Configure firewall
        println!("Configuring firewall...");
        self.configure_firewall()?;
        
        // Start service
        println!("Starting AeroNyx service...");
        self.start_service()?;
        
        println!("\n=== Installation Complete ===");
        println!("AeroNyx Privacy Network is now running on {}:{}", self.server_ip, self.port);
        println!("To add clients, use: {}/add_client.sh <client_public_key>", self.installation_dir.display());
        println!("To view logs: journalctl -u aeronyx-vpn -f");
        
        Ok(())
    }
    
    fn generate_certificates(&self) -> Result<()> {
        let cert_path = self.cert_dir.join("server.crt");
        let key_path = self.cert_dir.join("server.key");
        
        let status = Command::new("openssl")
            .args(&[
                "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", &key_path.to_string_lossy(),
                "-out", &cert_path.to_string_lossy(),
                "-days", "365", "-nodes",
                "-subj", &format!("/CN={}", self.server_ip)
            ])
            .status()?;
            
        if !status.success() {
            return Err(VpnError::Crypto("Failed to generate certificates".into()));
        }
        
        // Set permissions
        Command::new("chmod")
            .args(&["600", &key_path.to_string_lossy()])
            .status()?;
            
        Ok(())
    }
    
    fn create_acl_file(&self) -> Result<()> {
        let acl_path = self.config_dir.join("access_control.json");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
            
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
        
        // Configure NAT
        Command::new("iptables")
            .args(&[
                "-t", "nat", "-A", "POSTROUTING",
                "-s", &self.subnet,
                "-o", &interface,
                "-j", "MASQUERADE"
            ])
            .status()?;
            
        // Install iptables-persistent
        Command::new("apt")
            .args(&["install", "-y", "iptables-persistent"])
            .status()?;
            
        // Save iptables rules
        Command::new("netfilter-persistent")
            .args(&["save"])
            .status()?;
            
        Ok(())
    }
    
    fn create_systemd_service(&self) -> Result<()> {
        let binary_path = self.get_binary_path()?;
        let service_content = format!(
            r#"[Unit]
Description=AeroNyx Privacy Network
After=network.target

[Service]
ExecStart={} \
  --listen 0.0.0.0:{} \
  --tun-name tun0 \
  --subnet {} \
  --cert-file {}/server.crt \
  --key-file {}/server.key \
  --acl-file {}/access_control.json \
  --enable-obfuscation \
  --obfuscation-method {} \
  --log-level info
Restart=on-failure
RestartSec=5
Type=simple
User=root
WorkingDirectory={}

[Install]
WantedBy=multi-user.target
"#,
            binary_path.display(),
            self.port,
            self.subnet,
            self.cert_dir.display(),
            self.cert_dir.display(),
            self.config_dir.display(),
            self.obfuscation_method,
            self.installation_dir.display()
        );
        
        let mut file = File::create("/etc/systemd/system/aeronyx-vpn.service")?;
        file.write_all(service_content.as_bytes())?;
        
        Ok(())
    }
    
    fn create_registration_script(&self) -> Result<()> {
        let script_path = self.installation_dir.join("add_client.sh");
        let acl_path = self.config_dir.join("access_control.json");
        
        let script_content = format!(
            r#"#!/bin/bash
if [ $# -ne 1 ]; then
  echo "Usage: $0 <client_public_key>"
  exit 1
fi

CLIENT_KEY="$1"
ACL_FILE="{}"

# Create a temporary file with updated JSON
jq --arg key "$CLIENT_KEY" '.entries += [{{"public_key": $key, "access_level": 100, "is_allowed": true, "bandwidth_limit": 0, "max_session_duration": 86400, "static_ip": null, "notes": "Added via script"}}]' $ACL_FILE > ${{ACL_FILE}}.tmp

# Update the timestamp
jq ".updated_at = $(date +%s000)" ${{ACL_FILE}}.tmp > ${{ACL_FILE}}

# Clean up
rm ${{ACL_FILE}}.tmp

echo "Added client $CLIENT_KEY to ACL"
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
        Command::new("apt")
            .args(&["install", "-y", "jq"])
            .status()?;
            
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
                
            // Enable firewall
            Command::new("ufw")
                .args(&["--force", "enable"])
                .status()?;
        } else {
            println!("UFW not installed. Skipping firewall configuration.");
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
            
        // Start service
        Command::new("systemctl")
            .args(&["start", "aeronyx-vpn"])
            .status()?;
            
        Ok(())
    }
    
    fn detect_server_ip(&mut self) -> Result<()> {
        let output = Command::new("curl")
            .args(&["-s", "https://api.ipify.org"])
            .output()?;
            
        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip.is_empty() {
                println!("Detected public IP: {}", ip);
                self.server_ip = ip;
                return Ok(());
            }
        }
        
        println!("Could not detect public IP automatically.");
        println!("Please enter your server's public IP address:");
        let input = self.read_line()?;
        if input.trim().is_empty() {
            return Err(VpnError::Network("No IP address provided".into()));
        }
        
        self.server_ip = input.trim().to_string();
        Ok(())
    }
    
    fn get_main_interface(&self) -> Result<String> {
        let output = Command::new("ip")
            .args(&["route", "get", "1.1.1.1"])
            .output()?;
            
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
        
        // Default to eth0 if we couldn't detect
        println!("Could not detect main network interface, using eth0");
        Ok("eth0".to_string())
    }
    
    fn get_binary_path(&self) -> Result<PathBuf> {
        // Try to get the current executable path
        if let Ok(current_exe) = std::env::current_exe() {
            return Ok(current_exe);
        }
        
        // If we can't, assume it will be in the installation directory
        Ok(self.installation_dir.join("aeronyx-private-ed25519"))
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
}
