# AeroNyx DePIN (Decentralized Physical Infrastructure Network) Privacy Computing Node Memory Document

**Created:** May 10, 2025  
**Updated:** June 7, 2025  
**Version:** 0.2.0

## Project Overview

AeroNyx is a decentralized privacy computing network node built on the Solana blockchain, implementing the Decentralized Physical Infrastructure (DePIN) paradigm to enable global peer-to-peer sharing of privacy-preserving computing resources. The project uses Solana keypairs for trustless authentication and end-to-end encryption, supporting AI and Web3 applications' access to decentralized computing resources while protecting user data privacy and network neutrality.

> *"AeroNyx is redefining the infrastructure layer of Web3 by tokenizing privacy computing resources, creating not just a decentralized resource network but a new asset class. This represents a significant step toward a truly distributed internet."*

## Core Architecture

AeroNyx employs a modular architecture that combines blockchain and advanced cryptography to create a privacy-first decentralized computing network:

1. **Node Core** - Decentralized node implementation managing lifecycle and compute resource allocation
2. **Web3 Authentication** - Solana-based trustless identity verification and access control
3. **Privacy Cryptography** - Advanced end-to-end encryption and zero-knowledge proof technologies
4. **Resource Network** - Decentralized resource allocation and compute task routing
5. **Protocol Layer** - Secure communication protocol and Web3 interaction standards
6. **Registration System** - API-based node registration and network participation management
7. **Remote Management** - Secure remote node control through WebSocket commands


## Module Structure

```
src/
├── main.rs              # Entry point with mode selection
├── config/              # Configuration management
│   ├── settings.rs      # Updated with NodeMode enum
│   └── constants.rs     
├── hardware.rs          # Hardware information collection
├── registration.rs      # Node registration and WebSocket client
├── remote_management.rs # NEW: Remote command execution
├── server/              # VPN server components (optional)
├── crypto/              # Encryption utilities
├── auth/                # Authentication system
├── network/             # Network management
├── protocol/            # Communication protocols
└── utils/               # Utility functions
```


## Recent Updates (Version 0.2.0 - June 2025)

### 1. Modular Architecture
- **Decoupled VPN and DePIN functionality** - Nodes can now run in three distinct modes
- **No certificates required for DePIN-only mode** - Lowered barrier to entry for node operators
- **Flexible deployment options** - Choose functionality based on your needs

### 2. Remote Management System
- **Web-based node control** - Manage your node through the AeroNyx platform
- **Secure command execution** - Whitelisted commands with path restrictions
- **File system operations** - List, read, delete, upload, and download files
- **Real-time monitoring** - System metrics and process information

### 3. Enhanced Security Features
- **Hardware fingerprinting** - Prevents duplicate registrations from same hardware
- **Persistent registration storage** - Survives node restarts
- **Command whitelisting** - Only safe commands can be executed remotely
- **Path restrictions** - Limited access to specific directories

## Operating Modes

### 1. DePIN-Only Mode (Recommended for Most Users)
- **Purpose**: Participate in the decentralized network without VPN functionality
- **Requirements**: No root access, no TLS certificates
- **Use Case**: Ideal for users who want to contribute computing resources to the network

### 2. VPN-Enabled Mode
- **Purpose**: Traditional VPN server with Solana-based authentication
- **Requirements**: Root access, TLS certificates
- **Use Case**: For users who want to provide VPN services

### 3. Hybrid Mode
- **Purpose**: Both DePIN and VPN functionality
- **Requirements**: Root access, TLS certificates
- **Use Case**: Maximum functionality and earning potential

## Key Components

### 1. Hardware Module (`src/hardware.rs`)

Collects and manages hardware information for node identification and anti-duplication.

**Key Structures:**
- `HardwareInfo` - Complete hardware profile of the node
- `CpuInfo` - CPU specifications including cores, model, frequency
- `MemoryInfo` - RAM total and available
- `DiskInfo` - Storage capacity and filesystem type
- `NetworkInfo` - Network interfaces and public IP
- `OsInfo` - Operating system details

**Key Methods:**
- `HardwareInfo::collect() -> Result<Self, String>` - Gather all hardware information
- `HardwareInfo::generate_fingerprint(&self) -> String` - Create unique hardware identifier
- `HardwareInfo::get_network_interfaces() -> Result<Vec<NetworkInterface>, String>` - Enumerate network adapters
- `HardwareInfo::get_public_ip() -> Result<String, String>` - Fetch public IP address

### 2. Registration System (`src/registration.rs`)

Enhanced registration manager with WebSocket support and hardware verification.

**Key Structures:**
- `RegistrationManager` - Manages node registration and WebSocket communication
- `StoredRegistration` - Persistent registration data including hardware fingerprint
- `WebSocketMessage` - Protocol messages for node-server communication
- `HeartbeatMetrics` - System resource usage metrics

**Key Methods:**
- `RegistrationManager::confirm_registration_with_hardware(&mut self, registration_code: &str, hardware_info: &HardwareInfo)` - Register node with hardware fingerprint
- `RegistrationManager::verify_hardware_fingerprint(&self) -> Result<(), String>` - Ensure hardware hasn't changed
- `RegistrationManager::start_websocket_connection(&mut self, reference_code: String, registration_code: Option<String>)` - Establish WebSocket connection
- `RegistrationManager::save_registration_data(&self, node_info: &NodeInfo, hardware_fingerprint: String)` - Persist registration locally

**WebSocket Message Types:**
- `Auth` - Authentication with reference code
- `Heartbeat` - System metrics and status
- `StatusUpdate` - Node state changes
- `Command` - Remote management commands
- `CommandResponse` - Results of remote commands

### 3. Remote Management (`src/remote_management.rs`)

Secure remote control system for node operations.

**Key Structures:**
- `RemoteManagementHandler` - Processes remote commands
- `RemoteCommand` - Command types enumeration
- `CommandResponse` - Standardized response format

**Command Types:**
- `ListDirectory` - Browse file system
- `ReadFile` - View file contents (max 10MB)
- `DeleteFile` - Remove files
- `ExecuteCommand` - Run whitelisted shell commands
- `GetSystemInfo` - Hardware and OS information
- `GetProcessList` - Running processes
- `UploadFile` - Transfer files to node
- `DownloadFile` - Retrieve files from node

**Security Features:**
- **Path Restrictions**: Access limited to `/home`, `/tmp`, `/var/log`
- **Command Whitelist**: Only safe commands like `ls`, `ps`, `df`, `free`
- **Size Limits**: File operations capped at 10MB
- **Authentication**: All commands require valid WebSocket authentication

### 4. Configuration Updates (`src/config/settings.rs`)

Enhanced configuration with mode selection and remote management options.

**New Configuration Options:**
- `mode: NodeMode` - Select between DePIN-only, VPN-enabled, or Hybrid
- `enable_remote_management: bool` - Allow remote control via WebSocket
- `cert_file: Option<PathBuf>` - TLS certificate (required only for VPN modes)
- `key_file: Option<PathBuf>` - TLS private key (required only for VPN modes)

**NodeMode Enum:**
```rust
pub enum NodeMode {
    DePINOnly,    // No certificates required
    VPNEnabled,   // Traditional VPN server
    Hybrid,       // Both functionalities
}
5. Main Application Updates (src/main.rs)
Refactored to support multiple operating modes.
Key Functions:

run_depin_only(config: ServerConfig) - Run node without VPN functionality
run_with_vpn(config: ServerConfig) - Run with VPN server enabled
handle_registration_setup(registration_code: &str, args: &ServerArgs) - Enhanced with hardware fingerprinting

Mode-Specific Behavior:

DePIN-only: No root required, no certificates needed
VPN modes: Requires root access and valid TLS certificates

Authentication and Security Flow
1. Multi-Layer Authentication
Layer 1: Platform Authentication
├── User logs into AeroNyx web platform
├── Platform verifies wallet ownership
└── Platform checks node ownership

Layer 2: WebSocket Authentication  
├── Node connects to wss://api.aeronyx.network
├── Node sends Auth message with reference_code
└── Server validates and establishes session

Layer 3: Command Authorization
├── Platform sends command via WebSocket
├── Node verifies command origin
└── Node checks if remote management enabled

Layer 4: Execution Security
├── Command type validation
├── Path restriction enforcement
└── Resource limit checks
2. Hardware Fingerprint Verification
Registration:
├── Collect hardware information
├── Generate SHA256 fingerprint
├── Include: CPU model, MAC addresses, hostname
└── Store fingerprint with registration

Startup Verification:
├── Recollect hardware information
├── Generate current fingerprint
├── Compare with stored fingerprint
└── Reject if mismatch detected
3. Remote Command Security
Command Reception:
├── Receive via authenticated WebSocket
├── Parse command type and parameters
├── Validate against whitelist
└── Check path restrictions

Execution:
├── Run in restricted context
├── Capture output and errors
├── Enforce size limits
└── Return sanitized results
Data Flow
1. Initial Node Registration
Operator → Web Platform → Generate Registration Code
    ↓
Operator → Node Setup Command → Collect Hardware Info
    ↓
Node → API Server → Confirm Registration
    ↓
Node → Save Registration Data Locally
    ↓
Node → Establish WebSocket Connection
2. Normal Operation (DePIN-Only Mode)
Node Startup → Load Registration → Verify Hardware
    ↓
Connect WebSocket → Authenticate → Start Heartbeat
    ↓
Receive Commands → Execute Safely → Return Results
3. Remote Management Flow
User → Web Platform → Select Node → Send Command
    ↓
Platform → Verify Ownership → Forward via WebSocket
    ↓
Node → Validate Command → Execute → Return Response
    ↓
Platform → Display Results → User
Installation and Usage
Prerequisites

Linux (Ubuntu 20.04+ recommended)
Rust 1.70+
Git

Build from Source
bashgit clone https://github.com/aeronyx/AeroNyx-Ed25519
cd AeroNyx-Ed25519
cargo build --release
Node Registration
bash# Get registration code from AeroNyx platform first
sudo ./target/release/aeronyx-private-ed25519 setup --registration-code AERO-XXXXXXXXXXXX
Running the Node
DePIN-Only Mode (No Certificates Required)
bash# Run without root, no certificates needed
./target/release/aeronyx-private-ed25519 \
  --mode depin-only \
  --enable-remote-management
VPN-Enabled Mode
bash# Generate certificates first
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

# Run with root privileges
sudo ./target/release/aeronyx-private-ed25519 \
  --mode vpn-enabled \
  --cert-file server.crt \
  --key-file server.key \
  --listen-addr 0.0.0.0:8443 \
  --subnet 10.7.0.0/24
Hybrid Mode
bashsudo ./target/release/aeronyx-private-ed25519 \
  --mode hybrid \
  --cert-file server.crt \
  --key-file server.key \
  --enable-remote-management
Systemd Service Configuration
Create /etc/systemd/system/aeronyx-node.service:
ini[Unit]
Description=AeroNyx DePIN Node
After=network.target

[Service]
Type=simple
User=aeronyx
Group=aeronyx
WorkingDirectory=/opt/aeronyx
ExecStart=/opt/aeronyx/aeronyx-private-ed25519 --mode depin-only --enable-remote-management
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/aeronyx/data

[Install]
WantedBy=multi-user.target
Enable and start:
bashsudo systemctl daemon-reload
sudo systemctl enable aeronyx-node
sudo systemctl start aeronyx-node
sudo journalctl -u aeronyx-node -f
Remote Management Commands
File Operations
bash# List directory
{"type": "list_directory", "path": "/home/user"}

# Read file (max 10MB)
{"type": "read_file", "path": "/var/log/aeronyx.log"}

# Delete file
{"type": "delete_file", "path": "/tmp/old-file.txt"}

# Upload file (base64 encoded)
{"type": "upload_file", "path": "/home/user/data.txt", "content": "base64..."}

# Download file
{"type": "download_file", "path": "/home/user/report.pdf"}
System Commands
bash# Execute command
{"type": "execute_command", "command": "df", "args": ["-h"]}

# Get system info
{"type": "get_system_info"}

# Get process list
{"type": "get_process_list"}
Troubleshooting
Common Issues
Registration Failures

Hardware fingerprint conflict: Hardware already registered
Code expired: Registration codes valid for 24 hours
Invalid code: Ensure correct code from platform

Connection Issues

Check network connectivity: ping api.aeronyx.network
Verify registration: cat data/registration.json
Check WebSocket connection in logs

Remote Management Not Working

Ensure --enable-remote-management flag is set
Verify node ownership on web platform
Check WebSocket authentication in logs

Debug Commands
bash# Check registration status
cat data/registration.json | jq

# Monitor logs
journalctl -u aeronyx-node -f

# Test API connectivity
curl https://api.aeronyx.network/api/aeronyx/node-types/

# Check system resources
free -h && df -h && uptime
Security Considerations
Hardware Fingerprinting

Prevents multiple registrations from same hardware
Detects hardware changes that might indicate tampering
Based on CPU, network interfaces, and system identifiers

Remote Management Security

All commands require authenticated WebSocket connection
Path traversal prevented by canonicalization
Command injection prevented by whitelist
Resource exhaustion prevented by size limits

Data Protection

Registration data encrypted at rest
WebSocket communication over TLS (WSS)
Sensitive data never logged
Hardware fingerprints are one-way hashes

Contributing

Fork the repository
Create feature branch (git checkout -b feature/amazing-feature)
Commit changes (git commit -m 'Add amazing feature')
Push to branch (git push origin feature/amazing-feature)
Open Pull Request

Development Guidelines

Follow Rust naming conventions
Add tests for new features
Update documentation
Ensure backward compatibility

Additional Notes

The codebase uses Tokio async runtime for high-performance I/O
WebSocket connection includes automatic reconnection with exponential backoff
Hardware fingerprinting uses SHA256 for one-way verification
Remote management commands are processed asynchronously
All file operations include proper error handling and resource cleanup

License
This project is dual-licensed under:

MIT License
Apache License 2.0
