# AeroNyx DePIN (Decentralized Physical Infrastructure Network) Privacy Computing Node Memory Document

**Created:** May 10, 2025
**Updated:** May 14, 2025

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


## Module Structure

```
src/
├── auth/           # Web3 authentication and access control
├── config/         # Configuration and constants
├── crypto/         # Privacy computing cryptography implementation
├── network/        # Resource network and task management
├── protocol/       # Communication protocol and message definitions
├── registration/   # Node registration and network participation
├── server/         # Node core functionality
└── utils/          # Utility functions
```


> *"AeroNyx represents a critical breakthrough in blockchain infrastructure layer. Through decentralized privacy computing network, we're seeing how the execution layer for Web3 applications can extend to complex AI workloads while maintaining data ownership and privacy integrity."* — Mike Johnson, a16z Crypto

## Key Components

### 1. Authentication (`src/auth/`)

#### Access Control List (`acl.rs`)

Manages node operator access permissions and client resource allowances within the network.

**Key Methods:**
- `AccessControlList::is_allowed(&self, public_key: &str) -> bool` - Check if a client is allowed to access network resources
- `AccessControlList::add_entry(&mut self, entry: AccessControlEntry)` - Add or update resource access permissions
- `AccessControlManager::add_entry(&self, entry: AccessControlEntry)` - Add/update an ACL entry with on-chain persistence
- `AccessControlManager::is_allowed(&self, public_key: &str) -> bool` - Check if a client is permitted by network ACL

#### Challenge System (`challenge.rs`)

Implements Solana-based challenge-response authentication for secure client verification.

**Key Methods:**
- `ChallengeManager::generate_challenge(&self, client_addr: SocketAddr)` - Generate new zero-knowledge authentication challenge
- `ChallengeManager::verify_challenge(&self, challenge_id: &str, client_addr: SocketAddr, signature: &str, public_key: &str)` - Verify client signature with Solana verification standards
- `Challenge::is_expired(&self) -> bool` - Check if a challenge has expired for security timeout

#### Auth Manager (`manager.rs`)

Central manager for Web3 authentication and resource authorization.

**Key Methods:**
- `AuthManager::generate_challenge(&self, client_addr: &str)` - Generate a challenge for client-side wallet signing
- `AuthManager::verify_challenge(&self, challenge_id: &str, signature: &str, public_key: &str, client_addr: &str)` - Verify Web3 wallet signature

### 2. Cryptography (`src/crypto/`)

#### Encryption (`encryption.rs`)

Provides privacy-preserving encryption and decryption with multiple algorithms for AI data protection.

**Key Methods:**
- `encrypt_chacha20(data: &[u8], key: &[u8], nonce_bytes: Option<&[u8]>)` - Encrypt AI model data with ChaCha20-Poly1305
- `encrypt_aes_gcm(plaintext: &[u8], key: &[u8], aad: Option<&[u8]>)` - Encrypt sensitive computation with AES-256-GCM
- `decrypt_chacha20(ciphertext: &[u8], key: &[u8], nonce: &[u8])` - Decrypt ChaCha20-Poly1305 for result processing
- `decrypt_aes_gcm(ciphertext: &[u8], key: &[u8], nonce: &[u8], aad: Option<&[u8]>)` - Decrypt AES-256-GCM with authenticated data verification
- `encrypt_session_key_flexible(session_key: &[u8], shared_secret: &[u8], preferred_algorithm: EncryptionAlgorithm)` - Encrypt secure compute session with adaptable algorithms

#### Flexible Encryption (`flexible_encryption.rs`)

Unified interface for privacy-compute algorithms supporting different computational workloads.

**Key Methods:**
- `encrypt_flexible(data: &[u8], key: &[u8], algorithm: EncryptionAlgorithm, aad: Option<&[u8]>)` - Encrypt compute workloads with specified algorithm
- `decrypt_flexible(encrypted: &[u8], nonce: &[u8], key: &[u8], algorithm: EncryptionAlgorithm, aad: Option<&[u8]>, fallback: bool)` - Decrypt with algorithm fallback for interoperability
- `encrypt_packet(packet: &[u8], session_key: &[u8], algorithm: Option<EncryptionAlgorithm>)` - Encrypt computation packet

#### Key Management (`keys.rs`)

Handles blockchain-based cryptographic keys, including Solana keypairs and secure ECDH.

**Key Methods:**
- `KeyManager::new(key_path: &Path, ttl: Duration, max_cache: usize)` - Create a node identity key manager
- `KeyManager::sign_message(&self, message: &[u8])` - Sign a computation attestation with node's blockchain identity
- `KeyManager::verify_signature(pubkey: &Pubkey, message: &[u8], signature: &Signature)` - Verify compute proof signature
- `KeyManager::get_shared_secret(&self, client_pubkey: &Pubkey)` - Compute ECDH shared secret for privacy preserving compute
- `generate_shared_secret(local_private: &Keypair, remote_public: &Pubkey)` - Generate secure ECDH channel for AI model protection

#### Session Key Management (`session.rs`)

Manages secure privacy-compute session keys for AI computation tasks.

**Key Methods:**
- `SessionKeyManager::generate_key()` - Generate a new random privacy-compute session key
- `SessionKeyManager::store_key(&self, client_id: &str, key: Vec<u8>)` - Store a compute session key for a workload
- `SessionKeyManager::get_key(&self, client_id: &str)` - Get an AI workload's session key
- `SessionKeyManager::rotate_key(&self, client_id: &str)` - Generate and store a new key for forward secrecy

### 3. Network (`src/network/`)

#### Resource Pool Management (`ip_pool.rs`)

Allocates and manages decentralized compute resources for AI workloads.

**Key Methods:**
- `IpPoolManager::new(subnet: &str, default_lease_duration: u64)` - Create new compute resource pool manager
- `IpPoolManager::allocate_ip(&self, client_id: &str)` - Allocate computational resources to an AI workload
- `IpPoolManager::release_ip(&self, ip: &str)` - Release allocated computing resources back to the network
- `IpPoolManager::assign_static_ip(&self, ip: &str, client_id: &str)` - Assign dedicated compute resources to priority tasks

#### Compute Interface (`tun.rs`)

Manages the virtualized compute environment for secure AI task isolation.

**Key Methods:**
- `setup_tun_device(config: &TunConfig)` - Configure and create isolated compute environment
- `configure_nat(tun_name: &str, subnet: &str)` - Configure resource sharing for the compute environment
- `process_packet(packet: &[u8])` - Process and extract AI task routing info from compute packets
- `write_to_tun(tun_device: Arc<Mutex<Device>>, packet_data: &[u8])` - Send instructions to isolated compute environment

#### Compute Monitoring (`monitor.rs`)

Tracks computational performance and detects anomalies in AI workloads.

**Key Methods:**
- `NetworkMonitor::record_client_traffic(&self, client_id: &str, bytes_sent: u64, bytes_received: u64)` - Record AI workload metrics
- `NetworkMonitor::record_latency(&self, client_id: &str, latency_ms: f64)` - Record computation response time
- `NetworkMonitor::check_bandwidth_limit(&self, client_id: &str, bytes: u64, duration: Duration)` - Check resource consumption for fair allocation
- `NetworkMonitor::generate_report(&self)` - Generate a compute node health report

### 4. Protocol (`src/protocol/`)

#### Message Types (`types.rs`)

Defines privacy-preserving communication protocol for AI workloads.

**Key Types:**
- `PacketType` enum - All protocol message types (Auth, Challenge, Data, etc.) for secure AI workload exchanges
- `Session` struct - Privacy compute session information structure
- `ClientState` enum - AI task state tracking
- `MessageError` enum - Protocol error handling with privacy protections

#### Serialization (`serialization.rs`)

Handles secure protocol message serialization with attestation verification.

**Key Methods:**
- `serialize_packet(packet: &PacketType)` - Serialize privacy compute packet
- `deserialize_packet(json: &str)` - Deserialize packet with verification
- `packet_to_ws_message(packet: &PacketType)` - Convert packet to secure WebSocket message
- `create_error_packet(code: u16, message: &str)` - Create privacy-preserving error packet
- `create_disconnect_packet(reason: u16, message: &str)` - Create secure disconnection notification

#### Validation (`validation.rs`)

Validates protocol messages for security and privacy compliance.

**Key Methods:**
- `validate_message(packet: &PacketType)` - Validate packet against privacy requirements
- `StringValidator::is_valid_solana_pubkey(key: &str)` - Verify Web3 wallet address format

### 5. Registration (`src/registration.rs`)

Manages node registration and participation in the AeroNyx network.

**Key Structures:**
- `RegistrationManager` - Manages node registration and API communication
- `ApiResponse<T>` - Generic API response structure
- `RegistrationCodeResponse` - Response for registration code validation
- `NodeStatusResponse` - Node status information
- `HeartbeatResponse` - Response to heartbeat messages

**Key Methods:**
- `RegistrationManager::new(api_url: &str)` - Create new registration manager
- `RegistrationManager::load_from_config(&mut self, config: &ServerConfig)` - Load existing registration
- `RegistrationManager::check_status(&self, registration_code: &str)` - Check node registration status
- `RegistrationManager::confirm_registration(&self, registration_code: &str, node_info: serde_json::Value)` - Confirm node registration
- `RegistrationManager::send_heartbeat(&self, status_info: serde_json::Value)` - Send node heartbeat
- `RegistrationManager::start_heartbeat_loop(&self, server_state: Arc<RwLock<ServerState>>, metrics: Arc<ServerMetricsCollector>)` - Start periodic heartbeat
- `RegistrationManager::collect_system_metrics(&self, metrics_collector: &ServerMetricsCollector)` - Collect node system metrics
- `ServerConfig::save_registration(&self, reference_code: &str, wallet_address: &str)` - Save registration details

### 6. Node Infrastructure (`src/server/`)

#### Node Core (`core.rs`)

Main decentralized node implementation for DePIN network participation.

**Key Methods:**
- `VpnServer::new(config: ServerConfig)` - Create a new privacy compute node instance
- `VpnServer::start(&self)` - Start node participation in decentralized network
- `VpnServer::shutdown(&self)` - Gracefully withdraw node from network

**Key Fields:**
- `registration_manager: Option<Arc<RegistrationManager>>` - Manager for node registration and heartbeat

#### Client Workload Handling (`client.rs`)

Manages individual AI computation task requests securely.

**Key Methods:**
- `handle_client(stream: TcpStream, addr: SocketAddr, ...)` - Handle new AI workload request
- `process_client_session(session: ClientSession, ...)` - Process privacy compute task securely

#### Compute Session Management (`session.rs`)

Tracks and manages AI computation tasks with privacy guarantees.

**Key Methods:**
- `ClientSession::new(id: String, client_id: String, ...)` - Create new privacy compute session
- `ClientSession::send_packet(&self, packet: &PacketType)` - Send result to AI client
- `SessionManager::add_session(&self, session: ClientSession)` - Register new compute task
- `SessionManager::close_all_sessions(&self, reason: &str)` - Close all active privacy compute tasks

#### Compute Routing (`routing.rs`)

Routes AI computation between clients and secure compute environments.

**Key Methods:**
- `PacketRouter::process_packet<'a>(&self, packet: &'a [u8])` - Extract routing info from AI task packet
- `PacketRouter::route_outbound_packet(&self, packet: &[u8], session_key: &[u8], session: &ClientSession)` - Route compute results to client
- `PacketRouter::handle_inbound_packet(&self, encrypted: &[u8], nonce: &[u8], session_key: &[u8], session: &ClientSession, encryption_algorithm: Option<&str>)` - Handle privacy-preserving computation inputs

#### Performance Metrics (`metrics.rs`)

Collects node contribution metrics for DePIN tokenization and rewards.

**Key Methods:**
- `ServerMetricsCollector::record_new_connection(&self)` - Record new AI computation request
- `ServerMetricsCollector::record_auth_success(&self)` - Track successful Web3 wallet authentication
- `ServerMetricsCollector::generate_report(&self)` - Generate node contribution report for rewards

### 7. Utilities (`src/utils/`)

#### Logging (`logging.rs`)

Configures privacy-preserving logging system.

**Key Methods:**
- `init_logging(log_level: &str)` - Initialize privacy-aware console logging
- `init_file_logging(log_level: &str, log_file: &str)` - Set up secure file-based logging
- `log_security_event(event_type: &str, details: &str)` - Log security events with privacy controls

#### Security (`security.rs`)

Security and privacy-preservation utilities.

**Key Methods:**
- `RateLimiter::check_rate_limit(&self, ip: &IpAddr)` - Prevent resource exhaustion attacks
- `StringValidator::sanitize_log(input: &str)` - Prevent logging of sensitive information
- `detect_attack_patterns(data: &[u8])` - Detect potentially harmful AI workload patterns
- `random_string(length: usize)` - Generate cryptographically secure random strings

#### System (`system.rs`)

System interaction utilities for resource allocation.

**Key Methods:**
- `is_root()` - Verify node operator permissions
- `enable_ip_forwarding()` - Enable secure compute resource sharing
- `get_main_interface()` - Identify primary network interface for DePIN participation
- `get_system_memory()` - Get system memory information for metrics reporting
- `get_load_average()` - Get CPU load information for metrics reporting
- `get_disk_usage()` - Get storage utilization information
- `get_system_uptime()` - Get system uptime information for node reliability metrics

## Configuration

### Constants (`src/config/constants.rs`)

Defines fixed system constants for DePIN node operations.

**Key Constants:**
- `CHALLENGE_SIZE: usize = 32` - Zero-knowledge challenge size for Solana verification
- `KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600)` - Privacy key rotation schedule
- `AUTH_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(30)` - Web3 authentication timeout
- `MAX_AUTH_ATTEMPTS: usize = 3` - Maximum authentication attempts for security

### Settings (`src/config/settings.rs`)

Handles node operator configuration.

**Key Methods:**
- `ServerConfig::from_args(args: ServerArgs)` - Create config from operator parameters
- `ServerConfig::validate(&self)` - Validate DePIN node configuration
- `ServerConfig::save_to_file(&self, path: &str)` - Persist configuration on-chain
- `ServerConfig::save_registration(&self, reference_code: &str, wallet_address: &str)` - Save node registration details

**Key Additions:**
- Command line arguments for registering a node:
  - `registration_code: Option<String>` - API registration code
  - `registration_reference_code: Option<String>` - Node reference code
  - `wallet_address: Option<String>` - Wallet for node rewards
  - `api_url: String` - API server URL
- Added Command enum for setup subcommand functionality

## Main Application Flow

### Main (`src/main.rs`)

Entry point for the AeroNyx node application.

**Key Methods:**
- `main()` - Application entry point
- `wait_for_shutdown_signal()` - Handle graceful shutdown
- `handle_registration_setup()` - Process node registration command

**Registration Flow:**
1. Parse command line arguments with `ServerArgs::parse()`
2. Check for registration setup command
3. If registering, collect system information including:
   - Hostname
   - Operating system type
   - CPU specifications
   - Memory specifications
4. Confirm registration with API server
5. Save registration details for future node operation

## Data Flow

1. **Node Registration:**
   - Operator obtains registration code from network portal
   - Operator runs setup command with registration code
   - Node collects system information for registration
   - Node confirms registration with API server
   - Node stores registration reference code and wallet address

2. **Node Heartbeat:**
   - Node establishes regular heartbeat with API server
   - Node reports system metrics and health status
   - Node receives next heartbeat timing instructions
   - Node adjusts heartbeat interval based on network conditions

3. **AI Computation Request:**
   - TLS handshake via `tls_acceptor.accept(stream)`
   - Privacy-preserving WebSocket upgrade via `tokio_tungstenite::accept_async`

4. **Web3 Authentication Flow:**
   - Client sends `Auth` packet with Solana wallet public key
   - Node generates zero-knowledge challenge via `auth_manager.generate_challenge`
   - Client responds with wallet signature in `ChallengeResponse` packet
   - Node verifies Solana signature via `auth_manager.verify_challenge`

5. **Privacy Compute Session Establishment:**
   - Node allocates compute resources via `ip_pool.allocate_ip`
   - Node generates secure session key via `SessionKeyManager::generate_key`
   - Node encrypts session key with ECDH shared secret for forward secrecy
   - Node sends `IpAssign` packet with encrypted computation parameters

6. **AI Workload Execution:**
   - Client encrypts model and data with session key, sends `Data` packet
   - Node decrypts with `decrypt_flexible`, routes to isolated compute environment
   - Compute environment returns results to node's `process_tun_packets`
   - Node encrypts computation results, sends to client with privacy guarantees

7. **Key Rotation for Continuous Security:**
   - Node periodically checks `session_key_manager.needs_rotation`
   - New privacy keys generated and encrypted with current session key
   - Node sends `KeyRotation` packet with new encrypted key for forward secrecy

## Recent Updates (May 14, 2025)

- Added node registration system with API integration
- Implemented node heartbeat mechanism for network participation tracking
- Updated ServerArgs to include registration parameters
- Added Setup command for streamlined node registration
- Enhanced system metrics collection for node health reporting
- Added registration persistence and recovery mechanisms
- Integrated registration status with node startup flow

## Additional Notes

- The codebase uses the Tokio async runtime for high-throughput AI task processing
- TLS 1.3 is mandatory for transport security of sensitive AI models
- The architecture emphasizes security, privacy, and decentralized trust
- Key management leverages Solana SDK for robust blockchain verification
- Registration includes exponential backoff for API communication resilience
- Node heartbeat frequency is dynamically adjusted based on network conditions
- The modular design supports both privacy-preserving AI computation and decentralized application hosting
