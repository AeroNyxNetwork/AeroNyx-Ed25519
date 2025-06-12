AeroNyx DePIN Node
Created: May 10, 2025

Updated: June 13, 2025 

Version: 0.1.0

1. Project Overview
AeroNyx is a decentralized privacy computing network node built on the Solana blockchain. It leverages the Decentralized Physical Infrastructure (DePIN) paradigm to enable a global, peer-to-peer network for sharing privacy-preserving computing resources. The project uses Solana keypairs as its root of trust, enabling password-less, cryptographic authentication and end-to-end encrypted communication. It is designed to support AI and Web3 applications by providing access to decentralized compute resources while guaranteeing user data privacy and network neutrality.

"AeroNyx is redefining the infrastructure layer of Web3 by tokenizing privacy computing resources, creating not just a decentralized resource network, but a new asset class. This represents a significant step toward a truly distributed internet."

2. Core Architecture & Module Deep Dive
AeroNyx employs a highly modular, asynchronous Rust architecture built on tokio. This design promotes a strong separation of concerns, making the system scalable and maintainable.

src/
├── main.rs              # Application entry point, handles startup arguments and mode selection
├── config/              # Configuration management (settings, constants, defaults)
├── hardware.rs          # Hardware information collection and fingerprinting
├── registration.rs      # Node registration and WebSocket communication with the central API
├── remote_management.rs # Remote command execution logic
├── server/              # VPN server core components (core, session, routing, client, etc.)
├── crypto/              # Cryptographic utilities (keys, encryption, session, flexible_encryption)
├── auth/                # Authentication system (acl, challenge, manager)
├── network/             # Network management (tun, ip_pool, monitor)
├── protocol/            # Custom application-layer protocol (types, serialization, validation)
└── utils/               # General-purpose utilities (system, security, logging)
2.1. Configuration Module (src/config/)
This module is responsible for the entire configuration lifecycle, from parsing command-line arguments to loading files and applying default values.

settings.rs:

ServerArgs struct: Defined using clap, this struct parses all command-line arguments, including the crucial --mode flag.
NodeMode Enum: This enum is fundamental to the project's flexibility, allowing the node to run in one of three modes:
DePINOnly: For contributing computing resources without VPN functionality. Does not require root privileges or TLS certificates.
VPNEnabled: Runs as a traditional VPN server, requiring root access and certificates.
Hybrid: Enables both DePIN and VPN functionalities concurrently.
ServerConfig struct: This is the unified runtime configuration struct. Its from_args method intelligently aggregates settings from command-line arguments and an optional JSON configuration file. The validate method ensures all settings are coherent and valid before the server starts (e.g., checking that key files exist in VPN mode).
constants.rs & defaults.rs:

These files externalize all magic numbers and default settings, improving maintainability.
constants.rs defines cryptographic and security parameters like SESSION_KEY_SIZE (32 bytes), NONCE_SIZE (12 bytes for ChaCha20-Poly1305), and AUTH_CHALLENGE_TIMEOUT (30 seconds).
defaults.rs provides default values for user-configurable settings, including a platform-aware default_data_dir() function that correctly sets the data path for Windows and Unix-like systems.
2.2. Authentication & Authorization Module (src/auth/)
This module is the security gatekeeper of the node, verifying every client's identity and enforcing access rules.

manager.rs:

The AuthManager struct orchestrates the entire authentication process. It integrates the ChallengeManager and AccessControlManager to provide a single, unified interface for authenticating a client.
It implements brute-force protection by tracking failed authentication attempts per IP address in a failed_attempts HashMap, locking out addresses that exceed MAX_AUTH_ATTEMPTS.
challenge.rs:

The ChallengeManager is responsible for the cryptographic challenge-response flow.
Workflow:
generate_challenge is called for a new client. It creates a Challenge struct containing CHALLENGE_SIZE (32) bytes of random data and sets a short expiry time based on timeout.
The client signs this random data with its Solana Ed25519 private key.
verify_challenge is called with the client's signature. It first checks for challenge expiry and IP address match, then uses KeyManager::verify_signature to perform the cryptographic verification. Upon success, the challenge is removed from memory.
acl.rs:

The AccessControlManager and AccessControlList structs implement a fine-grained, file-based access control system from a JSON file.
AccessControlEntry: This struct defines the rules for each client public key, allowing for control over is_allowed, bandwidth_limit, max_session_duration, and even the assignment of a static_ip.
The system supports a default_policy ("allow" or "deny"), which is applied to any client not explicitly listed in the entries.
2.3. Cryptography Module (src/crypto/)
This module is the heart of the node's privacy features, containing all core cryptographic implementations.

keys.rs:

KeyManager: Manages the node's master Ed25519 keypair, used for signing challenges and participating in key exchanges. It loads the key from the path specified in server_key_file or generates a new one on first startup.
ECDH Key Derivation: This module contains the critical logic for secure key exchange. The generate_shared_secret function implements the full ECDH flow using X25519. It correctly converts the Ed25519 keys to their Curve25519 counterparts (ed25519_private_to_x25519, ed25519_public_to_x25519) before performing the Diffie-Hellman exchange. The result is then passed through an HKDF using SHA-256 to produce the final, cryptographically strong shared secret.
SecretKeyCache: To optimize performance, a cache is implemented to store recently computed shared secrets. This avoids the expensive ECDH computation for every client reconnect, using a Time-To-Live (TTL) mechanism to expire old entries.
session.rs:

SessionKeyManager: Manages symmetric session keys for every active client connection. These keys are used for encrypting the actual data traffic.
Key Lifecycle: Each SessionKeyEntry tracks its created_at timestamp and usage_count. The should_rotate method checks if a key has exceeded its configured age (rotation_interval) or usage limit (max_key_usages), signaling the need for a key rotation event. The cleanup_old_sessions function periodically removes keys for inactive clients.
flexible_encryption.rs & encryption.rs:

EncryptionAlgorithm Enum: Defines the supported AEAD (Authenticated Encryption with Associated Data) algorithms: ChaCha20Poly1305 and Aes256Gcm. This allows the client and server to negotiate the strongest commonly-supported cipher.
Unified Interface: encrypt_flexible and decrypt_flexible provide a single point of entry for all symmetric encryption operations, dispatching the call to the correct underlying implementation (encrypt_chacha20, encrypt_aes_gcm, etc.).
Fallback Logic: The decryption function includes a fallback boolean parameter. If set to true, and decryption with the primary algorithm fails, it will attempt to use the other supported algorithm. This provides a robust mechanism for handling clients with different capabilities or configurations without dropping the connection.
2.4. Application Protocol Module (src/protocol/)
This module defines the "language" spoken between the client and the node.

types.rs:

PacketType Enum: This is the cornerstone of the protocol, defining every possible message exchanged between client and server. It uses Serde's tag = "type" feature, making the resulting JSON self-describing and easy to parse. Key packets include:
Auth: Client initiates authentication with its public key and capabilities.
Challenge: Server responds with data for the client to sign.
ChallengeResponse: Client returns the signature.
IpAssign: Upon success, the server assigns an IP and provides the encrypted session key.
Data: Carries the actual end-to-end encrypted traffic.
Ping/Pong: For connection keep-alive and latency measurement.
DataEnvelope Struct: This struct is a key innovation. It is nested inside a Data packet's encrypted payload, allowing the application to multiplex different types of data over the same secure channel. The payload_type field can be Ip (for VPN packets) or Json (for application-level messages like chat or remote commands), making the protocol highly extensible.
serialization.rs & validation.rs:

These modules provide the logic for converting PacketType objects to and from WebSocket messages.
Crucially, validate_message is called during both serialization and deserialization. This function enforces strict rules on all packet fields (e.g., checking public key format with StringValidator::is_valid_solana_pubkey, ensuring nonce length is correct), which hardens the server against malformed or malicious packets.
2.5. Server Core Module (src/server/)
This module contains the main operational logic of the node, managing connections, state, and data flow.

core.rs:

VpnServer Struct: The primary struct that orchestrates the entire server. Its new method is responsible for initializing and wiring together all manager components (AuthManager, SessionManager, KeyManager, etc.).
ServerState Enum: Manages the server's lifecycle (Created, Starting, Running, ShuttingDown, Stopped), ensuring operations are only performed in appropriate states.
Background Task Management: The start method launches several background tasks using tokio::spawn for periodic maintenance, such as cleaning up expired sessions, IP leases, and authentication challenges. The JoinHandles for these tasks are stored so they can be gracefully aborted during shutdown.
client.rs:

The handle_client function manages the entire lifecycle of a single client connection, from the initial TCP handshake through TLS negotiation, WebSocket upgrade, and finally the full authentication flow.
process_client_session contains the main message loop for an authenticated client, handling Data, Ping, Disconnect, and other in-session packets.
session.rs:

ClientSession Struct: Represents the state of a connected client. A key design choice is wrapping the WebSocket sender (ws_sender) and receiver (ws_receiver) in an Arc<Mutex<>>. This allows different tasks to safely interact with the same client connection—for example, a dedicated heartbeat task can send Ping messages while the main task is awaiting incoming data.
SessionManager: A thread-safe manager for all active ClientSessions, providing quick lookups by session ID or IP address.
routing.rs:

PacketRouter: The central traffic director.
Outbound Traffic: route_outbound_packet takes an IP packet from the tun device, uses the destination IP to look up the correct ClientSession, encrypts the packet with that session's key, and sends it.
Inbound Traffic: handle_inbound_packet showcases a robust, forward-compatible design. It first attempts to parse decrypted data as a DataEnvelope. If successful, it routes the payload based on its payload_type (to the TUN device for Ip, or to the chat handler for Json). If parsing fails, it gracefully falls back to assuming the entire payload is a legacy IP packet. This allows for protocol upgrades without breaking older clients.
globals.rs & packet.rs:

process_tun_packets runs as a dedicated task, forming the bridge between the OS's network stack and the application. It continuously reads raw IP packets from the TUN device and feeds them to the PacketRouter.
To facilitate clean architecture and avoid prop-drilling, the project uses once_cell to create global static references to shared components like the TUN_DEVICE and SESSION_MANAGER, allowing modules to access them safely where needed.
2.6. DePIN & Remote Management (src/registration.rs & src/remote_management.rs)
These modules handle the node's interaction with the broader DePIN ecosystem.

registration.rs:

RegistrationManager: Manages the node's identity and communication with the central AeroNyx API.
Hardware Fingerprinting: On setup, HardwareInfo::collect() gathers unique system identifiers, and generate_fingerprint() creates a stable hash to prevent a single physical machine from being registered as multiple nodes. This fingerprint is verified on every startup.
WebSocket Link: After registration, the manager establishes a persistent WebSocket connection to the API server. It handles authentication using the node's reference_code and sends periodic Heartbeat messages containing performance metrics. This link is also used to receive commands for remote management.
remote_management.rs:

RemoteManagementHandler: Processes commands received over the authenticated WebSocket channel.
Secure by Design: The handler is built with a security-first approach:
Command Whitelist: Only a predefined list of safe commands (ls, ps, df, etc.) can be executed via ExecuteCommand.
Path Restriction: All file system operations are sandboxed to specific directories (/home, /tmp, /var/log) via the is_path_allowed check.
Resource Limits: Operations like ReadFile have a built-in max file size to prevent DoS attacks.
2.7. Deployment & Operations
The repository is well-equipped for production deployments.

main.rs: The application entry point cleanly separates logic based on the --mode flag, routing to run_depin_only or run_with_vpn as appropriate.
setup.rs: Provides a comprehensive, interactive setup experience that guides the user through configuration, certificate generation, and system optimization.
Containerization: The Dockerfile, docker-compose.yml, and docker-entrypoint.sh provide a robust, production-ready container setup. The entrypoint script correctly handles creating the /dev/net/tun device and configuring IP forwarding inside the container.
Deployment Script: The scripts/optimize_deploy.sh script automates best practices for deploying on a bare-metal Linux server, including kernel parameter tuning (sysctl), setting file descriptor limits, configuring the UFW firewall, and creating a systemd service with security hardening options (PrivateTmp, ProtectSystem, NoNewPrivileges).

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
