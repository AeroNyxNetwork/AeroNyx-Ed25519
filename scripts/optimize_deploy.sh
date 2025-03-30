#!/bin/bash
# AeroNyx VPN Performance and Security Optimization Script
# Path: /scripts/optimize_deploy.sh

set -e

SERVER_IP="180.99.22.30"
SERVER_PORT=8080
VPN_SUBNET="10.7.0.0/24"
INSTALL_DIR="/opt/aeronyx"
CONFIG_DIR="${INSTALL_DIR}/config"
CERTS_DIR="${INSTALL_DIR}/certs"

# Make script directory
mkdir -p $(dirname "$0")

echo "=== AeroNyx VPN Performance and Security Optimization ==="
echo "Server IP: ${SERVER_IP}"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

# System dependencies
echo "=== Installing dependencies ==="
apt update
apt install -y build-essential pkg-config libssl-dev ufw jq curl \
    iptables-persistent net-tools htop iftop openssl

# Apply system performance optimizations
echo "=== Applying system optimizations ==="
cat > /etc/sysctl.d/99-aeronyx-performance.conf << EOF
# AeroNyx VPN Performance Optimizations

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
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-aeronyx-performance.conf

# Increase file limits in systemd
echo "=== Setting up file descriptor limits ==="
mkdir -p /etc/systemd/system.conf.d/
cat > /etc/systemd/system.conf.d/limits.conf << EOF
[Manager]
DefaultLimitNOFILE=524288
EOF

# Set up file limits for user sessions
cat > /etc/security/limits.d/aeronyx.conf << EOF
*               soft    nofile          524288
*               hard    nofile          524288
root            soft    nofile          524288
root            hard    nofile          524288
EOF

# Create installation directory structure
echo "=== Creating directory structure ==="
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${CERTS_DIR}"
mkdir -p "${INSTALL_DIR}/logs"

# Generate TLS certificates with stronger parameters
echo "=== Generating secure TLS certificates ==="
if [ ! -f "${CERTS_DIR}/server.key" ] || [ ! -f "${CERTS_DIR}/server.crt" ]; then
  openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 \
    -keyout "${CERTS_DIR}/server.key" -out "${CERTS_DIR}/server.crt" \
    -subj "/CN=${SERVER_IP}" \
    -addext "subjectAltName=IP:${SERVER_IP}"
  
  # Set proper permissions
  chmod 600 "${CERTS_DIR}/server.key"
fi

# Configure firewall
echo "=== Configuring firewall ==="
ufw allow ssh
ufw allow "${SERVER_PORT}/tcp"
ufw default deny incoming
ufw default allow outgoing
ufw --force enable

# Set up NAT for VPN traffic
echo "=== Setting up NAT for VPN traffic ==="
# Get main interface
MAIN_IFACE=$(ip route get 8.8.8.8 | grep -oP "dev \K\S+")
echo "Main interface: ${MAIN_IFACE}"

# Set up NAT rules
iptables -t nat -A POSTROUTING -s "${VPN_SUBNET}" -o "${MAIN_IFACE}" -j MASQUERADE
iptables -A FORWARD -s "${VPN_SUBNET}" -i tun0 -o "${MAIN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d "${VPN_SUBNET}" -i "${MAIN_IFACE}" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables
netfilter-persistent save

# Create systemd service with optimized settings
echo "=== Creating systemd service ==="
cat > /etc/systemd/system/aeronyx-vpn.service << EOF
[Unit]
Description=AeroNyx Privacy Network VPN
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${INSTALL_DIR}/aeronyx-private-ed25519 \\
  --listen 0.0.0.0:${SERVER_PORT} \\
  --tun-name tun0 \\
  --subnet ${VPN_SUBNET} \\
  --cert-file ${CERTS_DIR}/server.crt \\
  --key-file ${CERTS_DIR}/server.key \\
  --acl-file ${CONFIG_DIR}/access_control.json \\
  --enable-obfuscation \\
  --obfuscation-method xor \\
  --log-level info
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=5
LimitNOFILE=524288
StandardOutput=append:${INSTALL_DIR}/logs/aeronyx.log
StandardError=append:${INSTALL_DIR}/logs/aeronyx.error.log

# Security hardening
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# Create default empty ACL file if it doesn't exist
if [ ! -f "${CONFIG_DIR}/access_control.json" ]; then
  echo "=== Creating default ACL file ==="
  cat > "${CONFIG_DIR}/access_control.json" << EOF
{
  "default_policy": "deny",
  "entries": [],
  "updated_at": $(date +%s000)
}
EOF
fi

# Create a client registration script
echo "=== Creating client registration script ==="
cat > "${INSTALL_DIR}/add_client.sh" << EOF
#!/bin/bash
if [ \$# -ne 1 ]; then
  echo "Usage: \$0 <client_public_key>"
  exit 1
fi

CLIENT_KEY="\$1"
ACL_FILE="${CONFIG_DIR}/access_control.json"

# Verify the key format (check if it's a valid Solana public key)
if [[ ! "\$CLIENT_KEY" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]; then
  echo "Error: Invalid public key format"
  exit 1
fi

# Create a temporary file with updated JSON
jq --arg key "\$CLIENT_KEY" '.entries += [{"public_key": \$key, "access_level": 100, "is_allowed": true, "bandwidth_limit": 0, "max_session_duration": 86400, "static_ip": null, "notes": "Added on \$(date)"}]' \$ACL_FILE > \${ACL_FILE}.tmp

# Update the timestamp
jq ".updated_at = \$(date +%s000)" \${ACL_FILE}.tmp > \${ACL_FILE}

# Clean up
rm \${ACL_FILE}.tmp

echo "Added client \$CLIENT_KEY to ACL"
echo "Reloading AeroNyx service..."
systemctl reload aeronyx-vpn

EOF

# Make the script executable
chmod +x "${INSTALL_DIR}/add_client.sh"

# Set up log rotation
echo "=== Setting up log rotation ==="
cat > /etc/logrotate.d/aeronyx << EOF
${INSTALL_DIR}/logs/*.log {
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
}
EOF

# Check if we need to build from source or use an existing binary
if [ ! -f "${INSTALL_DIR}/aeronyx-private-ed25519" ]; then
    echo "=== No existing binary found. Please build the project and copy the binary to ${INSTALL_DIR}/aeronyx-private-ed25519 ==="
    echo "Build command: cargo build --release"
    echo "Copy command: cp target/release/aeronyx-private-ed25519 ${INSTALL_DIR}/"
else
    echo "=== Using existing binary at ${INSTALL_DIR}/aeronyx-private-ed25519 ==="
fi

# Enable and start service if binary exists
if [ -f "${INSTALL_DIR}/aeronyx-private-ed25519" ]; then
    echo "=== Enabling and starting service ==="
    systemctl daemon-reload
    systemctl enable aeronyx-vpn
    systemctl start aeronyx-vpn
    echo "Service started successfully!"
else
    echo "=== Service configuration complete, but not started (binary not found) ==="
fi

echo ""
echo "=== Optimization and deployment completed! ==="
echo "To check service status: systemctl status aeronyx-vpn"
echo "To add new clients: ${INSTALL_DIR}/add_client.sh <client_public_key>"
echo "Server IP: ${SERVER_IP}, Port: ${SERVER_PORT}"
echo ""
