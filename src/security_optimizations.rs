use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write, Result as IoResult};
use std::path::Path;
use std::process::Command;

/// Apply security hardening measures for the VPN server
pub fn apply_security_hardening() -> IoResult<()> {
    // List of security optimizations to apply
    harden_ssh()?;
    configure_firewall()?;
    disable_unused_services()?;
    secure_kernel_parameters()?;
    enable_auditd()?;
    secure_file_permissions()?;
    
    Ok(())
}

/// Harden SSH configuration
fn harden_ssh() -> IoResult<()> {
    const SSH_CONFIG: &str = "/etc/ssh/sshd_config";
    
    if !Path::new(SSH_CONFIG).exists() {
        return Ok(());
    }
    
    // Read the current config
    let mut content = String::new();
    File::open(SSH_CONFIG)?.read_to_string(&mut content)?;
    
    // Create a backup
    fs::copy(SSH_CONFIG, format!("{}.bak", SSH_CONFIG))?;
    
    // Prepare hardened settings
    let hardened_settings = [
        ("PermitRootLogin", "no"),
        ("PasswordAuthentication", "no"),
        ("PubkeyAuthentication", "yes"),
        ("PermitEmptyPasswords", "no"),
        ("ChallengeResponseAuthentication", "no"),
        ("UsePAM", "yes"),
        ("X11Forwarding", "no"),
        ("AllowTcpForwarding", "yes"),    // We need this for VPN
        ("Compression", "no"),
        ("ClientAliveInterval", "300"),
        ("ClientAliveCountMax", "2"),
        ("LogLevel", "VERBOSE"),
        ("MaxAuthTries", "3"),
        ("MaxSessions", "2"),
        ("TCPKeepAlive", "yes"),
        ("AllowAgentForwarding", "no"),
    ];
    
    // Process each setting
    for (key, value) in hardened_settings.iter() {
        // Check if the setting already exists
        let pattern = format!("^{} ", key);
        let re = regex::Regex::new(&pattern).unwrap();
        
        if re.is_match(&content) {
            // Replace existing setting
            let line_re = regex::Regex::new(&format!(r"^{}\s+.*$", key)).unwrap();
            content = line_re.replace_all(&content, format!("{} {}", key, value)).to_string();
        } else {
            // Add new setting
            content.push_str(&format!("\n{} {}", key, value));
        }
    }
    
    // Write updated config
    let mut file = File::create(SSH_CONFIG)?;
    file.write_all(content.as_bytes())?;
    
    // Restart SSH service
    let _ = Command::new("systemctl")
        .args(&["restart", "sshd"])
        .status();
    
    println!("SSH hardening applied");
    Ok(())
}

/// Configure firewall rules
fn configure_firewall() -> IoResult<()> {
    // Check if UFW is installed
    if Command::new("which")
        .arg("ufw")
        .status()?
        .success() {
        
        // Reset UFW to defaults
        let _ = Command::new("ufw")
            .args(&["--force", "reset"])
            .status();
        
        // Set default policies
        let _ = Command::new("ufw")
            .args(&["default", "deny", "incoming"])
            .status();
            
        let _ = Command::new("ufw")
            .args(&["default", "allow", "outgoing"])
            .status();
        
        // Allow SSH
        let _ = Command::new("ufw")
            .args(&["allow", "ssh"])
            .status();
        
        // Enable UFW
        let _ = Command::new("ufw")
            .args(&["--force", "enable"])
            .status();
            
        println!("UFW firewall configured");
    } else {
        // Use iptables directly if UFW is not available
        // Flush existing rules
        let _ = Command::new("iptables")
            .args(&["-F"])
            .status();
            
        // Set default policies
        let _ = Command::new("iptables")
            .args(&["-P", "INPUT", "DROP"])
            .status();
            
        let _ = Command::new("iptables")
            .args(&["-P", "FORWARD", "DROP"])
            .status();
            
        let _ = Command::new("iptables")
            .args(&["-P", "OUTPUT", "ACCEPT"])
            .status();
        
        // Allow established connections
        let _ = Command::new("iptables")
            .args(&["-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .status();
        
        // Allow SSH
        let _ = Command::new("iptables")
            .args(&["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])
            .status();
        
        // Allow loopback
        let _ = Command::new("iptables")
            .args(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            .status();
            
        println!("Iptables firewall configured");
    }
    
    Ok(())
}

/// Disable unused services
fn disable_unused_services() -> IoResult<()> {
    let unused_services = [
        "avahi-daemon",
        "cups",
        "rpcbind",
        "bluetooth",
        "telnet",
        "ftp",
        "nfs-server",
        "named",
        "vsftpd",
        "lpd",
        "xinetd",
        "portmap",
    ];
    
    for service in &unused_services {
        let _ = Command::new("systemctl")
            .args(&["disable", "--now", service])
            .status();
    }
    
    println!("Disabled unused services");
    Ok(())
}

/// Apply secure kernel parameters
fn secure_kernel_parameters() -> IoResult<()> {
    let security_params = r#"# Network security parameters
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1

# Kernel hardening
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.perf_event_paranoid=3
kernel.sysrq=0
kernel.yama.ptrace_scope=2
kernel.unprivileged_userns_clone=0
kernel.unprivileged_bpf_disabled=1
"#;

    // Write to security file
    let mut file = File::create("/etc/sysctl.d/99-security.conf")?;
    file.write_all(security_params.as_bytes())?;
    
    // Apply settings
    let _ = Command::new("sysctl")
        .args(&["-p", "/etc/sysctl.d/99-security.conf"])
        .status();
        
    println!("Kernel security parameters applied");
    Ok(())
}

/// Enable and configure auditd for security monitoring
fn enable_auditd() -> IoResult<()> {
    // Check if auditd is installed
    if !Path::new("/etc/audit/auditd.conf").exists() {
        // Try to install it
        let status = Command::new("apt-get")
            .args(&["install", "-y", "auditd", "audispd-plugins"])
            .status();
            
        if !status.map(|s| s.success()).unwrap_or(false) {
            println!("Could not install auditd");
            return Ok(());
        }
    }
    
    // Configure basic audit rules
    let audit_rules = r#"# Audit rules for AeroNyx VPN Security
# Monitor changes to authentication configuration
-w /etc/pam.d/ -p wa -k auth_changes
-w /etc/nsswitch.conf -p wa -k auth_changes
-w /etc/ssh/sshd_config -p wa -k auth_changes

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k privileged

# Monitor network configuration changes
-w /etc/network/ -p wa -k network_changes
-w /etc/sysconfig/network -p wa -k network_changes
-w /etc/hosts -p wa -k network_changes

# Monitor system user changes
-w /etc/passwd -p wa -k user_changes
-w /etc/shadow -p wa -k user_changes
-w /etc/group -p wa -k user_changes
-w /etc/gshadow -p wa -k user_changes
-w /etc/security/opasswd -p wa -k user_changes

# Monitor VPN configuration
-w /opt/aeronyx/config/ -p wa -k vpn_config_changes
-w /opt/aeronyx/certs/ -p wa -k vpn_cert_changes

# Log all commands run by root
-a always,exit -F arch=b64 -F euid=0 -S execve -k rootcmd
-a always,exit -F arch=b32 -F euid=0 -S execve -k rootcmd

# Log unsuccessful unauthorized file access attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
"#;

    // Write audit rules
    let mut file = File::create("/etc/audit/rules.d/50-aeronyx.rules")?;
    file.write_all(audit_rules.as_bytes())?;
    
    // Enable and start auditd
    let _ = Command::new("systemctl")
        .args(&["enable", "auditd"])
        .status();
        
    let _ = Command::new("systemctl")
        .args(&["restart", "auditd"])
        .status();
    
    println!("Audit rules configured and auditd enabled");
    Ok(())
}

/// Secure file permissions for critical files
fn secure_file_permissions() -> IoResult<()> {
    // Secure SSH keys
    let _ = Command::new("chmod")
        .args(&["700", "/etc/ssh"])
        .status();
        
    let _ = Command::new("chmod")
        .args(&["600", "/etc/ssh/ssh_host_*_key"])
        .status();
        
    let _ = Command::new("chmod")
        .args(&["644", "/etc/ssh/ssh_host_*_key.pub"])
        .status();
    
    // Secure password files
    let _ = Command::new("chmod")
        .args(&["644", "/etc/passwd"])
        .status();
        
    let _ = Command::new("chmod")
        .args(&["400", "/etc/shadow"])
        .status();
        
    let _ = Command::new("chmod")
        .args(&["644", "/etc/group"])
        .status();
        
    let _ = Command::new("chmod")
        .args(&["400", "/etc/gshadow"])
        .status();
    
    // Secure VPN certificates
    if Path::new("/opt/aeronyx/certs").exists() {
        let _ = Command::new("chmod")
            .args(&["700", "/opt/aeronyx/certs"])
            .status();
            
        let _ = Command::new("chmod")
            .args(&["600", "/opt/aeronyx/certs/server.key"])
            .status();
            
        let _ = Command::new("chmod")
            .args(&["644", "/opt/aeronyx/certs/server.crt"])
            .status();
    }
    
    println!("File permissions secured");
    Ok(())
}

/// Check server security status
pub fn check_security_status() -> String {
    let mut status = String::new();
    
    // Check SSH root login
    if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
        if content.contains("PermitRootLogin no") {
            status.push_str("✅ SSH root login: Disabled\n");
        } else {
            status.push_str("❌ SSH root login: Not explicitly disabled\n");
        }
        
        if content.contains("PasswordAuthentication no") {
            status.push_str("✅ SSH password authentication: Disabled\n");
        } else {
            status.push_str("❌ SSH password authentication: Enabled\n");
        }
    }
    
    // Check firewall status
    if Command::new("which")
        .arg("ufw")
        .status()
        .map(|s| s.success())
        .unwrap_or(false) {
        
        if let Ok(output) = Command::new("ufw").arg("status").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("Status: active") {
                status.push_str("✅ Firewall: Active (UFW)\n");
            } else {
                status.push_str("❌ Firewall: Inactive (UFW)\n");
            }
        }
    } else if let Ok(output) = Command::new("iptables").args(&["-L"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if !output_str.contains("Chain INPUT (policy ACCEPT)") {
            status.push_str("✅ Firewall: Active (iptables)\n");
        } else {
            status.push_str("❌ Firewall: Default ACCEPT policy\n");
        }
    }
    
    // Check auditd status
    if let Ok(output) = Command::new("systemctl").args(&["is-active", "auditd"]).output() {
        let status_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if status_str == "active" {
            status.push_str("✅ Audit daemon: Running\n");
        } else {
            status.push_str("❌ Audit daemon: Not running\n");
        }
    }
    
    // Check kernel hardening
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/kptr_restrict") {
        let value = content.trim().parse::<i32>().unwrap_or(0);
        if value >= 1 {
            status.push_str("✅ Kernel pointer restriction: Enabled\n");
        } else {
            status.push_str("❌ Kernel pointer restriction: Disabled\n");
        }
    }
    
    // Check for updates
    if let Ok(output) = Command::new("apt-get").args(&["upgrade", "--dry-run"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("0 upgraded, 0 newly installed, 0 to remove") {
            status.push_str("✅ System updates: Up to date\n");
        } else {
            status.push_str("❌ System updates: Updates available\n");
        }
    }
    
    status
}

/// Apply full server security optimization
pub fn optimize_server_security() -> IoResult<()> {
    println!("Applying security optimizations...");
    
    // Apply all security hardening measures
    apply_security_hardening()?;
    
    // Check and report security status
    let status = check_security_status();
    println!("Security optimization status:\n{}", status);
    
    Ok(())
}

/// Configure automatic security updates
pub fn configure_automatic_updates() -> IoResult<()> {
    // Check if unattended-upgrades is installed
    if !Path::new("/etc/apt/apt.conf.d/50unattended-upgrades").exists() {
        let _ = Command::new("apt-get")
            .args(&["install", "-y", "unattended-upgrades", "apt-listchanges"])
            .status();
    }
    
    // Configure unattended-upgrades
    let config = r#"// Automatically upgrade packages from these (origin:archive) pairs
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};

// List of packages to not upgrade
Unattended-Upgrade::Package-Blacklist {
    // None by default
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
"#;

    let mut file = File::create("/etc/apt/apt.conf.d/50unattended-upgrades")?;
    file.write_all(config.as_bytes())?;
    
    // Enable unattended-upgrades
    let enable_config = r#"APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
"#;

    let mut file = File::create("/etc/apt/apt.conf.d/20auto-upgrades")?;
    file.write_all(enable_config.as_bytes())?;
    
    // Restart unattended-upgrades service
    let _ = Command::new("systemctl")
        .args(&["restart", "unattended-upgrades"])
        .status();
        
    println!("Automatic security updates configured");
    Ok(())
}
