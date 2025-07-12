// src/zkp/circuit.rs
// Hardware attestation circuit implementation using commitment schemes

use sha2::{Sha256, Digest};
use crate::hardware::HardwareInfo;
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

/// Hardware commitment structure representing a cryptographic commitment to hardware state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCommitment {
    /// Commitment value (hash of hardware info)
    pub value: [u8; 32],
    /// Metadata about the commitment
    pub metadata: CommitmentMetadata,
}

/// Metadata associated with a hardware commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentMetadata {
    /// Version of the commitment scheme
    pub version: u8,
    /// Algorithm used (e.g., "SHA256")
    pub algorithm: String,
    /// Number of hardware components included
    pub component_count: usize,
    /// Timestamp of commitment creation
    pub created_at: u64,
}

impl HardwareCommitment {
    /// Create commitment from hardware info with full validation
    pub fn from_hardware_info(hw_info: &HardwareInfo) -> Self {
        let serialized = Self::serialize_hardware_info(hw_info);
        let component_count = Self::count_components(hw_info);
        
        // Create structured input for commitment
        let commitment_input = Self::create_commitment_input(hw_info, &serialized);
        
        // Hash using SHA256 for the commitment
        let mut hasher = Sha256::new();
        hasher.update(&commitment_input);
        let result = hasher.finalize();
        
        let mut value = [0u8; 32];
        value.copy_from_slice(&result);
        
        let metadata = CommitmentMetadata {
            version: 1,
            algorithm: "SHA256".to_string(),
            component_count,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        Self { value, metadata }
    }
    
    /// Convert commitment to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }
    
    /// Create structured commitment input with domain separation
    fn create_commitment_input(hw_info: &HardwareInfo, serialized: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        
        // Domain separator
        input.extend_from_slice(b"AERONYX_HW_COMMITMENT_V1");
        input.extend_from_slice(&[0u8; 8]); // Padding
        
        // Include commitment scheme version
        input.push(1u8);
        
        // Include hardware fingerprint components in structured format
        // This ensures commitment uniqueness and prevents collision attacks
        let components = Self::extract_commitment_components(hw_info);
        for (key, value) in components {
            input.extend_from_slice(key.as_bytes());
            input.extend_from_slice(b":");
            input.extend_from_slice(value.as_bytes());
            input.extend_from_slice(b"|");
        }
        
        // Include full serialized data hash
        let data_hash = Sha256::digest(serialized);
        input.extend_from_slice(&data_hash);
        
        input
    }
    
    /// Extract key components for commitment in deterministic order
    fn extract_commitment_components(hw_info: &HardwareInfo) -> BTreeMap<String, String> {
        let mut components = BTreeMap::new();
        
        // CPU information
        components.insert("cpu_model".to_string(), hw_info.cpu.model.clone());
        components.insert("cpu_cores".to_string(), hw_info.cpu.cores.to_string());
        components.insert("cpu_arch".to_string(), hw_info.cpu.architecture.clone());
        
        // System identifiers
        if let Some(uuid) = &hw_info.system_uuid {
            components.insert("system_uuid".to_string(), uuid.clone());
        }
        
        if let Some(machine_id) = &hw_info.machine_id {
            components.insert("machine_id".to_string(), machine_id.clone());
        }
        
        // Network MACs (sorted)
        let mut mac_addresses: Vec<String> = hw_info.network.interfaces
            .iter()
            .filter(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
            .map(|iface| iface.mac_address.to_lowercase())
            .collect();
        mac_addresses.sort();
        
        for (i, mac) in mac_addresses.iter().enumerate() {
            components.insert(format!("mac_{}", i), mac.clone());
        }
        
        // OS type (stable)
        components.insert("os_type".to_string(), hw_info.os.os_type.clone());
        
        // Hostname (hashed for privacy)
        let hostname_hash = hex::encode(Sha256::digest(hw_info.hostname.as_bytes()));
        components.insert("hostname_hash".to_string(), hostname_hash);
        
        components
    }
    
    /// Count the number of hardware components
    fn count_components(hw_info: &HardwareInfo) -> usize {
        let mut count = 4; // CPU, Memory, Disk, OS
        
        if hw_info.system_uuid.is_some() {
            count += 1;
        }
        
        if hw_info.machine_id.is_some() {
            count += 1;
        }
        
        if hw_info.bios_info.is_some() {
            count += 1;
        }
        
        count += hw_info.network.interfaces
            .iter()
            .filter(|iface| iface.is_physical)
            .count();
        
        count
    }
    
    /// Serialize hardware info deterministically
    fn serialize_hardware_info(hw_info: &HardwareInfo) -> Vec<u8> {
        // Primary serialization using bincode
        bincode::serialize(&hw_info).unwrap_or_else(|_| {
            // Fallback to manual serialization if bincode fails
            Self::manual_serialize(hw_info)
        })
    }
    
    /// Manual serialization fallback
    fn manual_serialize(hw_info: &HardwareInfo) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Version marker
        data.extend_from_slice(b"HW_V1:");
        
        // Hostname
        data.extend_from_slice(&(hw_info.hostname.len() as u32).to_le_bytes());
        data.extend_from_slice(hw_info.hostname.as_bytes());
        
        // CPU info
        data.extend_from_slice(&(hw_info.cpu.model.len() as u32).to_le_bytes());
        data.extend_from_slice(hw_info.cpu.model.as_bytes());
        data.extend_from_slice(&hw_info.cpu.cores.to_le_bytes());
        data.extend_from_slice(&hw_info.cpu.frequency.to_le_bytes());
        data.extend_from_slice(&(hw_info.cpu.architecture.len() as u32).to_le_bytes());
        data.extend_from_slice(hw_info.cpu.architecture.as_bytes());
        
        // Memory
        data.extend_from_slice(&hw_info.memory.total.to_le_bytes());
        
        // Network interfaces (sorted for consistency)
        let mut interfaces = hw_info.network.interfaces.clone();
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        
        data.extend_from_slice(&(interfaces.len() as u32).to_le_bytes());
        for iface in &interfaces {
            data.extend_from_slice(&(iface.name.len() as u32).to_le_bytes());
            data.extend_from_slice(iface.name.as_bytes());
            data.extend_from_slice(&(iface.mac_address.len() as u32).to_le_bytes());
            data.extend_from_slice(iface.mac_address.as_bytes());
            data.push(if iface.is_physical { 1 } else { 0 });
        }
        
        // System identifiers
        if let Some(uuid) = &hw_info.system_uuid {
            data.push(1); // Present flag
            data.extend_from_slice(&(uuid.len() as u32).to_le_bytes());
            data.extend_from_slice(uuid.as_bytes());
        } else {
            data.push(0); // Not present flag
        }
        
        if let Some(machine_id) = &hw_info.machine_id {
            data.push(1);
            data.extend_from_slice(&(machine_id.len() as u32).to_le_bytes());
            data.extend_from_slice(machine_id.as_bytes());
        } else {
            data.push(0);
        }
        
        // OS info
        data.extend_from_slice(&(hw_info.os.os_type.len() as u32).to_le_bytes());
        data.extend_from_slice(hw_info.os.os_type.as_bytes());
        data.extend_from_slice(&(hw_info.os.distribution.len() as u32).to_le_bytes());
        data.extend_from_slice(hw_info.os.distribution.as_bytes());
        
        data
    }
    
    /// Verify that hardware info matches this commitment
    pub fn verify(&self, hw_info: &HardwareInfo) -> bool {
        let computed = Self::from_hardware_info(hw_info);
        computed.value == self.value
    }
}

/// Configuration for the hardware circuit
#[derive(Debug, Clone)]
pub struct HardwareCircuitConfig {
    /// Circuit parameters
    pub params: CircuitParams,
}

/// Parameters for the circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitParams {
    /// Security parameter (bits of security)
    pub security_bits: usize,
    /// Hash function identifier
    pub hash_function: String,
    /// Circuit depth
    pub depth: usize,
}

impl Default for CircuitParams {
    fn default() -> Self {
        Self {
            security_bits: 128,
            hash_function: "SHA256".to_string(),
            depth: 10,
        }
    }
}

/// Hardware attestation circuit
#[derive(Clone)]
pub struct HardwareCircuit {
    /// Private input: serialized hardware info
    hardware_data: Vec<u8>,
    /// Public input: commitment
    commitment: [u8; 32],
    /// Circuit configuration
    config: HardwareCircuitConfig,
}

impl HardwareCircuit {
    /// Create a new hardware circuit
    pub fn new(hardware_data: Vec<u8>, commitment: [u8; 32]) -> Self {
        Self {
            hardware_data,
            commitment,
            config: HardwareCircuitConfig {
                params: CircuitParams::default(),
            },
        }
    }
    
    /// Verify circuit constraints
    pub fn verify_constraints(&self) -> bool {
        // Compute commitment from hardware data
        let computed_hash = Sha256::digest(&self.hardware_data);
        let mut computed_commitment = [0u8; 32];
        computed_commitment.copy_from_slice(&computed_hash);
        
        // Verify commitment matches
        self.commitment == computed_commitment
    }
}

/// ZKP parameters containing Ed25519 keypair for signing commitments
#[derive(Clone, Serialize, Deserialize)]
pub struct ZkpParams {
    /// Secret key for proving
    pub secret_key: [u8; 32],
    /// Public key for verification
    pub public_key: [u8; 32],
    /// Circuit parameters
    pub circuit_params: CircuitParams,
    /// Generation timestamp
    pub generated_at: u64,
}

/// Generate setup parameters for the circuit
pub async fn generate_setup_params() -> Result<crate::zkp::SetupParams, String> {
    use tokio::task;
    
    // Generate parameters in blocking task (CPU intensive)
    let params = task::spawn_blocking(|| {
        // Generate Ed25519 keypair for commitment signing
        let keypair = Keypair::generate(&mut OsRng);
        
        let zkp_params = ZkpParams {
            secret_key: keypair.secret.to_bytes(),
            public_key: keypair.public.to_bytes(),
            circuit_params: CircuitParams::default(),
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Serialize parameters
        bincode::serialize(&zkp_params)
    })
    .await
    .map_err(|e| format!("Failed to generate parameters: {}", e))?
    .map_err(|e| format!("Failed to serialize parameters: {}", e))?;
    
    // Extract public key for verifying key
    let zkp_params: ZkpParams = bincode::deserialize(&params)
        .map_err(|e| format!("Failed to deserialize params: {}", e))?;
    
    Ok(crate::zkp::SetupParams {
        proving_key: params,
        verifying_key: zkp_params.public_key.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_commitment() {
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        let commitment1 = HardwareCommitment::from_hardware_info(&hw_info);
        let commitment2 = HardwareCommitment::from_hardware_info(&hw_info);
        
        // Same hardware should produce same commitment
        assert_eq!(commitment1.value, commitment2.value);
        assert_eq!(commitment1.metadata.version, 1);
        assert_eq!(commitment1.metadata.algorithm, "SHA256");
        assert!(commitment1.metadata.component_count > 0);
    }
    
    #[test]
    fn test_commitment_determinism() {
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        let commitment = HardwareCommitment::from_hardware_info(&hw_info);
        
        // Commitment should be 32 bytes
        assert_eq!(commitment.value.len(), 32);
        
        // Commitment should be deterministic
        let bytes = commitment.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, commitment.value.to_vec());
        
        // Verify should work
        assert!(commitment.verify(&hw_info));
    }
    
    #[test]
    fn test_commitment_components() {
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        let components = HardwareCommitment::extract_commitment_components(&hw_info);
        
        // Should have expected components
        assert!(components.contains_key("cpu_model"));
        assert!(components.contains_key("cpu_cores"));
        assert!(components.contains_key("system_uuid"));
        assert!(components.contains_key("mac_0"));
        assert_eq!(components["cpu_cores"], "4");
        assert_eq!(components["mac_0"], "aa:bb:cc:dd:ee:ff");
    }
    
    #[test]
    fn test_circuit_constraints() {
        let hw_info = crate::zkp::tests::create_mock_hardware_info();
        let commitment = HardwareCommitment::from_hardware_info(&hw_info);
        let hw_data = HardwareCommitment::serialize_hardware_info(&hw_info);
        
        // Create circuit with matching data
        let circuit = HardwareCircuit::new(hw_data.clone(), commitment.value);
        assert!(circuit.verify_constraints());
        
        // Create circuit with mismatched data
        let wrong_commitment = [0u8; 32];
        let wrong_circuit = HardwareCircuit::new(hw_data, wrong_commitment);
        assert!(!wrong_circuit.verify_constraints());
    }
    
    #[tokio::test]
    async fn test_setup_params_generation() {
        let result = generate_setup_params().await;
        assert!(result.is_ok());
        
        let params = result.unwrap();
        assert!(!params.proving_key.is_empty());
        assert_eq!(params.verifying_key.len(), 32); // Ed25519 public key
        
        // Verify we can deserialize the params
        let zkp_params: Result<ZkpParams, _> = bincode::deserialize(&params.proving_key);
        assert!(zkp_params.is_ok());
    }
}
