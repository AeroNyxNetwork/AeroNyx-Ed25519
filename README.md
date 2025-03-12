# AeroNyx Privacy Network
## Client Implementation Guide

This guide provides essential information for developers implementing client applications for the AeroNyx Privacy Network. The AeroNyx network utilizes Solana ed25519 keypairs for authentication and secure communication between nodes.

## Protocol Overview

AeroNyx employs a hybrid cryptographic approach:
- **Authentication**: Solana ed25519 keypairs
- **Key Exchange**: Modified X25519 ECDH (Elliptic Curve Diffie-Hellman)
- **Data Encryption**: AES-256-CBC with HMAC-SHA256 authentication
- **Transport**: WebSocket over TLS

## Client Requirements

### Wallet Integration

1. **Solana Wallet Required**: Clients MUST have a valid Solana wallet with an ed25519 keypair
2. **Key Access**: Client applications need access to both:
   - The private key for encryption/decryption operations
   - The public key for authentication with the server

### Cryptographic Implementation

When implementing the cryptographic components, follow these guidelines:

1. **Ed25519 to X25519 Conversion**:
   - Properly convert Ed25519 keys to X25519 format for ECDH
   - Do not simply copy key bytes between formats
   - Implement the mathematical conversion between Edwards and Montgomery curves
   - Use established libraries when possible

2. **Shared Secret Derivation**:
   - Apply X25519 ECDH using the converted keys
   - Hash the raw ECDH output using SHA-256
   - Do not use the raw ECDH output directly as encryption key

3. **Message Encryption**:
   - Use AES-256-CBC for all data encryption
   - Generate a unique random IV (16 bytes) for each message
   - Apply PKCS#7 padding to handle messages of arbitrary length
   - Structure encrypted messages as: `[IV][Encrypted Data][HMAC]`

4. **Message Authentication**:
   - Calculate HMAC-SHA256 over `[IV][Encrypted Data]`
   - Use the same shared secret as the HMAC key
   - Verify HMAC before attempting decryption
   - Reject messages with invalid HMAC values

## Connection Protocol

### Authentication Flow

1. Establish WebSocket connection to the server
2. Send authentication message containing Solana public key
3. Receive IP address assignment from the server
4. Begin encrypted communication

### Packet Format

All packets must follow the `PacketType` enumeration:

```rust
pub enum PacketType {
    /// Client authentication with public key
    Auth { public_key: String },
    
    /// Server assigns IP address to client
    IpAssign { ip_address: String },
    
    /// Encrypted data packet
    Data { encrypted: Vec<u8> },
    
    /// Ping to keep connection alive
    Ping,
    
    /// Pong response to ping
    Pong,
}
```

### Heartbeat Mechanism

- Respond to `Ping` messages with `Pong` responses
- Client implementations should be prepared to handle disconnections and reconnect as needed

## Security Considerations

### Critical Warnings

1. **Key Protection**:
   - NEVER expose private keys in logs, debugging output, or client storage
   - Use secure storage mechanisms appropriate for the client platform
   - Consider hardware security when available

2. **Cryptographic Implementations**:
   - DO NOT create custom cryptographic primitives
   - Use well-established libraries and implementations
   - Update dependencies regularly to address security vulnerabilities

3. **Protocol Adherence**:
   - DO NOT modify the protocol without coordination with the server team
   - Maintain compatibility with server implementations
   - Document any custom extensions or modifications

### Additional Recommendations

1. **Transport Security**:
   - Use TLS for the WebSocket connection
   - Validate server certificates
   - Implement certificate pinning when possible

2. **Traffic Analysis Prevention**:
   - Consider implementing traffic padding
   - Maintain regular heartbeats even when idle
   - Add jitter to transmission timing when appropriate

## Recommended Libraries

### Rust Clients
- `solana-sdk`: For Solana keypair handling
- `ed25519-dalek` and `x25519-dalek`: For cryptographic operations
- `aes`, `cbc`, `hmac`: For encryption and authentication
- `tokio-tungstenite`: For WebSocket connectivity

### JavaScript/TypeScript Clients
- `@solana/web3.js`: For Solana wallet integration
- `tweetnacl-js`: For ed25519/x25519 operations
- `aes-js`: For AES encryption
- `hmac-sha256`: For message authentication
- `ws` or browser WebSocket API: For connectivity

### Mobile Clients
- Android: Use Bouncy Castle or Tink for cryptography
- iOS: Use CryptoKit or CommonCrypto

## Testing and Validation

1. **Interoperability Testing**:
   - Test client implementation against reference server
   - Verify successful connection and data exchange
   - Test reconnection and error recovery

2. **Security Testing**:
   - Verify HMAC validation rejects tampered messages
   - Confirm private keys are properly protected
   - Test behavior with malformed packets

3. **Performance Considerations**:
   - Minimize message processing latency
   - Implement efficient buffer management
   - Consider hardware acceleration for cryptographic operations when available

## Contact and Support

For implementation questions or technical support, contact the AeroNyx team:
- Email: hi@aeronyx.network
- GitHub: [AeroNyx Privacy Network](https://github.com/aeronyx)

---

*Copyright © 2025 AeroNyx. Licensed under MIT License.*
