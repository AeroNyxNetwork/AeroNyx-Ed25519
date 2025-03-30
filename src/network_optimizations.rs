use std::io::Result as IoResult;
use std::process::Command;

/// Apply optimized network settings for a VPN server
pub fn apply_network_optimizations() -> IoResult<()> {
    // Create the sysctl configuration content
    let sysctl_config = r#"# AeroNyx VPN Network Optimizations
# Increase TCP buffer sizes
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216

# Increase the number of connections and backlog
net.core.somaxconn=65535
net.core.netdev_max_backlog=5000
net.ipv4.tcp_max_syn_backlog=8192

# Reuse sockets in TIME_WAIT state
net.ipv4.tcp_tw_reuse=1

# TCP keepalive optimizations
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=15

# TCP connection optimizations
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_fastopen=3

# Congestion control - use BBR for better performance
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq

# IP forwarding for VPN
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv6.conf.all.forwarding=1

# File handle limits
fs.file-max=2097152
fs.nr_open=2097152

# Process limits
kernel.pid_max=65536

# Disable netfilter on bridges for better performance
net.bridge.bridge-nf-call-ip6tables=0
net.bridge.bridge-nf-call-iptables=0
net.bridge.bridge-nf-call-arptables=0

# Optimize network memory
net.ipv4.tcp_mem=786432 1048576 26777216
net.ipv4.udp_mem=65536 131072 262144
"#;

    // Write the configuration to a file
    std::fs::write("/etc/sysctl.d/99-aeronyx-network.conf", sysctl_config)?;
    
    // Apply the settings
    Command::new("sysctl")
        .args(&["-p", "/etc/sysctl.d/99-aeronyx-network.conf"])
        .status()?;
    
    // Configure TCP congestion algorithm if BBR is available
    if std::path::Path::new("/proc/sys/net/ipv4/tcp_available_congestion_control").exists() {
        let available = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")?;
        if available.contains("bbr") {
            std::fs::write("/proc/sys/net/ipv4/tcp_congestion_control", "bbr")?;
            std::fs::write("/proc/sys/net/core/default_qdisc", "fq")?;
        }
    }
    
    // Set up optimal IRQ affinity if on a server with multiple cores
    optimize_irq_affinity()?;
    
    // Disable certain power-saving features that can impact network performance on servers
    disable_power_saving()?;
    
    Ok(())
}

/// Function to optimize IRQ affinity for network interfaces
fn optimize_irq_affinity() -> IoResult<()> {
    // Get the number of available CPUs
    let output = Command::new("nproc").output()?;
    let num_cpus = String::from_utf8_lossy(&output.stdout).trim().parse::<usize>().unwrap_or(1);
    
    if num_cpus <= 1 {
        // No need for IRQ affinity optimization on single-core systems
        return Ok(());
    }
    
    // Find network interfaces
    let interfaces_dir = std::path::Path::new("/sys/class/net");
    if !interfaces_dir.exists() {
        return Ok(());
    }
    
    for entry in std::fs::read_dir(interfaces_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy();
        
        // Skip loopback and virtual interfaces
        if name == "lo" || name.starts_with("tun") || name.starts_with("tap") || name.starts_with("veth") {
            continue;
        }
        
        // Get IRQs for this interface
        if let Ok(output) = Command::new("grep")
            .args(&[&format!("{}-", name), "/proc/interrupts"])
            .output() {
            
            let irqs_output = String::from_utf8_lossy(&output.stdout);
            let irqs: Vec<String> = irqs_output.lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 1 {
                        Some(parts[0].trim().to_string())
                    } else {
                        None
                    }
                })
                .collect();
            
            // Distribute IRQs across CPUs
            for (i, irq) in irqs.iter().enumerate() {
                let cpu = i % num_cpus;
                let mask = 1u64 << cpu;
                let hex_mask = format!("{:x}", mask);
                
                // Set IRQ affinity
                let _ = Command::new("sh")
                    .args(&["-c", &format!("echo {} > /proc/irq/{}/smp_affinity", hex_mask, irq)])
                    .status();
            }
        }
    }
    
    Ok(())
}

/// Disable power saving features that can impact network performance
fn disable_power_saving() -> IoResult<()> {
    // Find network interfaces
    let interfaces_dir = std::path::Path::new("/sys/class/net");
    if !interfaces_dir.exists() {
        return Ok(());
    }
    
    for entry in std::fs::read_dir(interfaces_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy();
        
        // Skip loopback and virtual interfaces
        if name == "lo" || name.starts_with("tun") || name.starts_with("tap") || name.starts_with("veth") {
            continue;
        }
        
        // Disable generic segmentation offload (can cause issues with VPN traffic)
        let _ = Command::new("ethtool")
            .args(&["-K", &name, "gso", "off", "tso", "off", "gro", "off"])
            .status();
        
        // Disable power saving mode if supported
        let power_path = format!("/sys/class/net/{}/power/control", name);
        if std::path::Path::new(&power_path).exists() {
            let _ = std::fs::write(power_path, "on");
        }
    }
    
    Ok(())
}

/// Set up optimal TUN device parameters
pub fn optimize_tun_device(tun_name: &str) -> IoResult<()> {
    // Set MTU to optimal value for VPN
    let _ = Command::new("ip")
        .args(&["link", "set", "dev", tun_name, "mtu", "1500"])
        .status();
    
    // Set TUN device to no checksum offloading to avoid potential issues
    let _ = Command::new("ethtool")
        .args(&["-K", tun_name, "tx", "off", "rx", "off", "sg", "off", "tso", "off", "ufo", "off", "gso", "off", "gro", "off"])
        .status();
    
    // Increase TUN device queue length if supported
    let txqlen_path = format!("/sys/class/net/{}/tx_queue_len", tun_name);
    if std::path::Path::new(&txqlen_path).exists() {
        let _ = std::fs::write(txqlen_path, "10000");
    }
    
    // Disable TCP segmentation offload which can cause issues with VPN
    let _ = Command::new("ethtool")
        .args(&["-K", tun_name, "tso", "off"])
        .status();
    
    Ok(())
}

/// Function to check for network optimization status
pub fn check_optimization_status() -> String {
    let mut status = String::new();
    
    // Check if IP forwarding is enabled
    if let Ok(ip_forward) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        if ip_forward.trim() == "1" {
            status.push_str("✅ IP forwarding: Enabled\n");
        } else {
            status.push_str("❌ IP forwarding: Disabled\n");
        }
    }
    
    // Check TCP congestion control algorithm
    if let Ok(cc_algo) = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control") {
        if cc_algo.trim() == "bbr" {
            status.push_str("✅ TCP congestion control: BBR (optimal)\n");
        } else {
            status.push_str(&format!("ℹ️ TCP congestion control: {} (consider using BBR)\n", cc_algo.trim()));
        }
    }
    
    // Check bufferbloat mitigation (fq_codel or similar)
    if let Ok(output) = Command::new("tc").args(&["qdisc", "show"]).output() {
        let qdisc_output = String::from_utf8_lossy(&output.stdout);
        if qdisc_output.contains("fq_codel") || qdisc_output.contains("cake") {
            status.push_str("✅ Bufferbloat mitigation: Enabled\n");
        } else {
            status.push_str("ℹ️ Bufferbloat mitigation: Not detected\n");
        }
    }
    
    // Check max connections settings
    if let Ok(somaxconn) = std::fs::read_to_string("/proc/sys/net/core/somaxconn") {
        let value = somaxconn.trim().parse::<i32>().unwrap_or(0);
        if value >= 1024 {
            status.push_str(&format!("✅ Max connections (somaxconn): {}\n", value));
        } else {
            status.push_str(&format!("❌ Max connections (somaxconn): {} (should be >= 1024)\n", value));
        }
    }
    
    // Check TCP mem settings
    if let Ok(tcp_mem) = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_mem") {
        status.push_str(&format!("ℹ️ TCP memory: {}\n", tcp_mem.trim()));
    }
    
    // Check file descriptor limits
    if let Ok(output) = Command::new("ulimit").args(&["-n"]).output() {
        let fdlimit = String::from_utf8_lossy(&output.stdout).trim().parse::<i32>().unwrap_or(0);
        if fdlimit >= 65536 {
            status.push_str(&format!("✅ File descriptor limit: {}\n", fdlimit));
        } else {
            status.push_str(&format!("ℹ️ File descriptor limit: {} (consider increasing to 65536+)\n", fdlimit));
        }
    }
    
    status
}

/// Set up optimal iptables rules for VPN traffic
pub fn setup_optimal_iptables(subnet: &str) -> IoResult<()> {
    // Get main interface
    let output = Command::new("ip")
        .args(&["route", "get", "1.1.1.1"])
        .output()?;
        
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut main_iface = "eth0"; // Default fallback
    
    for line in output_str.lines() {
        if let Some(idx) = line.find("dev ") {
            let parts: Vec<&str> = line[idx+4..].split_whitespace().collect();
            if !parts.is_empty() {
                main_iface = parts[0];
                break;
            }
        }
    }
    
    // Flush existing NAT rules for clean setup
    let _ = Command::new("iptables")
        .args(&["-t", "nat", "-F", "POSTROUTING"])
        .status();
        
    // Add MASQUERADE rule
    Command::new("iptables")
        .args(&[
            "-t", "nat", "-A", "POSTROUTING", 
            "-s", subnet, 
            "-o", main_iface, 
            "-j", "MASQUERADE"
        ])
        .status()?;
        
    // Forward rules for VPN traffic
    Command::new("iptables")
        .args(&[
            "-A", "FORWARD",
            "-i", "tun0", "-o", main_iface,
            "-s", subnet,
            "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED",
            "-j", "ACCEPT"
        ])
        .status()?;
        
    Command::new("iptables")
        .args(&[
            "-A", "FORWARD",
            "-i", main_iface, "-o", "tun0",
            "-d", subnet,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT"
        ])
        .status()?;
        
    // Save iptables rules if iptables-persistent is installed
    if std::path::Path::new("/usr/sbin/netfilter-persistent").exists() {
        Command::new("netfilter-persistent")
            .args(&["save"])
            .status()?;
    }
    
    Ok(())
}

/// Setup TCP BBR congestion control for better throughput
pub fn setup_tcp_bbr() -> IoResult<()> {
    // Check if BBR is available
    let available = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")?;
    
    if !available.contains("bbr") {
        // Try to load BBR module if not available
        let _ = Command::new("modprobe")
            .arg("tcp_bbr")
            .status();
            
        // Check again after loading
        let available = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")?;
        if !available.contains("bbr") {
            return Ok(());
        }
    }
    
    // Set BBR as default congestion control
    std::fs::write("/proc/sys/net/ipv4/tcp_congestion_control", "bbr")?;
    
    // Set FQ packet scheduler for BBR
    std::fs::write("/proc/sys/net/core/default_qdisc", "fq")?;
    
    Ok(())
}

/// Set up optimal TCP Keep-Alive settings for VPN
pub fn setup_tcp_keepalive() -> IoResult<()> {
    // Set TCP keepalive time (300 seconds = 5 minutes)
    std::fs::write("/proc/sys/net/ipv4/tcp_keepalive_time", "300")?;
    
    // Number of probes
    std::fs::write("/proc/sys/net/ipv4/tcp_keepalive_probes", "5")?;
    
    // Interval between probes
    std::fs::write("/proc/sys/net/ipv4/tcp_keepalive_intvl", "15")?;
    
    Ok(())
}

/// Apply all network optimizations for an Ubuntu 22.04 server
pub fn optimize_server(subnet: &str) -> IoResult<()> {
    // Apply sysctl optimizations
    apply_network_optimizations()?;
    
    // Set up optimal iptables rules
    setup_optimal_iptables(subnet)?;
    
    // Setup TCP BBR
    setup_tcp_bbr()?;
    
    // Setup TCP keep-alive
    setup_tcp_keepalive()?;
    
    // Check and report optimization status
    let status = check_optimization_status();
    println!("Network optimization status:\n{}", status);
    
    Ok(())
}
