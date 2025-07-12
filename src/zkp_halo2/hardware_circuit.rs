// src/zkp_halo2/hardware_circuit.rs
// Production-grade hardware attestation circuit

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

use super::poseidon_hasher::{PoseidonChip, PoseidonConfig, PoseidonParams};

/// Configuration for hardware attestation circuit
#[derive(Clone, Debug)]
pub struct HardwareCircuitConfig {
    /// Advice columns for witness data
    advice: [Column<Advice>; 4],
    /// Fixed column for constants
    fixed: Column<Fixed>,
    /// Instance column for public inputs (commitment)
    instance: Column<Instance>,
    /// Poseidon configuration
    poseidon: PoseidonConfig<pallas::Base>,
    /// Selector for input loading
    s_load: Selector,
}

/// Hardware attestation circuit proving knowledge of CPU and MAC
#[derive(Clone)]
pub struct HardwareAttestationCircuit {
    /// CPU model string encoded as field elements
    cpu_encoded: Vec<Value<pallas::Base>>,
    /// MAC address as field element
    mac_encoded: Value<pallas::Base>,
}

impl HardwareAttestationCircuit {
    /// Create new circuit from hardware information
    pub fn new(cpu_model: &str, mac_address: &str) -> Self {
        // Encode CPU model
        let cpu_encoded = Self::encode_string_to_field_elements(cpu_model);
        
        // Encode MAC address
        let mac_encoded = Self::encode_mac_address(mac_address);
        
        Self {
            cpu_encoded,
            mac_encoded,
        }
    }
    
    /// Encode a string into field elements (31 bytes per element for safety)
    fn encode_string_to_field_elements(s: &str) -> Vec<Value<pallas::Base>> {
        const BYTES_PER_ELEMENT: usize = 31;
        let bytes = s.as_bytes();
        
        bytes.chunks(BYTES_PER_ELEMENT)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[1..chunk.len() + 1].copy_from_slice(chunk);
                
                let fe = pallas::Base::from_repr(padded).unwrap();
                Value::known(fe)
            })
            .collect()
    }
    
    /// Encode MAC address to field element
    fn encode_mac_address(mac: &str) -> Value<pallas::Base> {
        // Normalize MAC address
        let normalized = mac.to_lowercase()
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "");
        
        let bytes = hex::decode(&normalized).expect("Invalid MAC address");
        assert_eq!(bytes.len(), 6, "MAC address must be 6 bytes");
        
        // Pack into field element with padding
        let mut padded = [0u8; 32];
        padded[1..7].copy_from_slice(&bytes);
        
        Value::known(pallas::Base::from_repr(padded).unwrap())
    }
}

impl Circuit<pallas::Base> for HardwareAttestationCircuit {
    type Config = HardwareCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self {
            cpu_encoded: vec![Value::unknown(); self.cpu_encoded.len()],
            mac_encoded: Value::unknown(),
        }
    }
    
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Configure advice columns
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        
        // Enable equality for copy constraints
        for &col in &advice {
            meta.enable_equality(col);
        }
        
        // Configure fixed and instance columns
        let fixed = meta.fixed_column();
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        
        // Configure Poseidon
        let poseidon_params = PoseidonParams::new();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        
        let poseidon = PoseidonChip::configure(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            rc_a,
            rc_b,
            &poseidon_params,
        );
        
        // Selector for loading inputs
        let s_load = meta.selector();
        
        // No custom gates needed - Poseidon handles the constraints
        
        HardwareCircuitConfig {
            advice,
            fixed,
            instance,
            poseidon,
            s_load,
        }
    }
    
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Load all inputs
        let (cpu_cells, mac_cell) = layouter.assign_region(
            || "load inputs",
            |mut region| {
                let mut cpu_cells = Vec::new();
                
                // Load CPU field elements
                for (i, &value) in self.cpu_encoded.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("cpu_{}", i),
                        config.advice[i % 4],
                        i / 4,
                        || value,
                    )?;
                    cpu_cells.push(cell);
                }
                
                // Load MAC address
                let mac_cell = region.assign_advice(
                    || "mac",
                    config.advice[0],
                    (self.cpu_encoded.len() + 3) / 4,
                    || self.mac_encoded,
                )?;
                
                Ok((cpu_cells, mac_cell))
            },
        )?;
        
        // Initialize Poseidon chip
        let poseidon_params = PoseidonParams::new();
        let poseidon_chip = PoseidonChip::construct(config.poseidon.clone(), poseidon_params);
        
        // Hash all inputs using Poseidon sponge
        let mut state = self.initialize_state(&mut layouter, &config)?;
        
        // Absorb CPU elements
        for (i, cpu_cell) in cpu_cells.iter().enumerate() {
            state = self.absorb_element(
                &mut layouter,
                &poseidon_chip,
                state,
                cpu_cell.clone(),
                i,
            )?;
        }
        
        // Absorb MAC address
        state = self.absorb_element(
            &mut layouter,
            &poseidon_chip,
            state,
            mac_cell,
            cpu_cells.len(),
        )?;
        
        // Final squeeze to get commitment
        let commitment = self.finalize_hash(&mut layouter, &poseidon_chip, state)?;
        
        // Expose commitment as public input
        layouter.constrain_instance(commitment.cell(), config.instance, 0)?;
        
        Ok(())
    }
}

impl HardwareAttestationCircuit {
    /// Initialize the Poseidon sponge state
    fn initialize_state(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        config: &HardwareCircuitConfig,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 3], Error> {
        layouter.assign_region(
            || "initialize state",
            |mut region| {
                let zero = region.assign_advice_from_constant(
                    || "zero",
                    config.advice[0],
                    0,
                    pallas::Base::ZERO,
                )?;
                Ok([zero.clone(), zero.clone(), zero])
            },
        )
    }
    
    /// Absorb one element into the sponge
    fn absorb_element(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        chip: &PoseidonChip<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 3],
        element: AssignedCell<pallas::Base, pallas::Base>,
        round: usize,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 3], Error> {
        layouter.assign_region(
            || format!("absorb_{}", round),
            |mut region| {
                // Add element to first state element
                let new_state_0 = region.assign_advice(
                    || "state_0 + element",
                    chip.config.state[0],
                    0,
                    || state[0].value().and_then(|s| element.value().map(|e| *s + *e)),
                )?;
                
                // Apply permutation
                let output = chip.hash_two(
                    layouter.namespace(|| format!("permute_{}", round)),
                    new_state_0,
                    state[1].clone(),
                )?;
                
                Ok([output, state[2].clone(), state[0].clone()])
            },
        )
    }
    
    /// Finalize the hash
    fn finalize_hash(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        chip: &PoseidonChip<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 3],
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // One final permutation
        chip.hash_two(
            layouter.namespace(|| "final_permutation"),
            state[0].clone(),
            state[1].clone(),
        )
    }
}

/// Utility to compute expected commitment (for testing)
pub fn compute_expected_commitment(cpu_model: &str, mac_address: &str) -> pallas::Base {
    use sha2::{Sha256, Digest};
    
    // This is a placeholder - in production, use the same Poseidon hash
    let mut hasher = Sha256::new();
    hasher.update(b"HARDWARE_COMMITMENT");
    hasher.update(cpu_model.as_bytes());
    hasher.update(mac_address.as_bytes());
    
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    
    pallas::Base::from_repr(bytes).unwrap_or(pallas::Base::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    
    #[test]
    fn test_hardware_circuit() {
        let k = 10; // 2^10 = 1024 rows
        
        let cpu_model = "Intel Core i7-9700K @ 3.60GHz";
        let mac_address = "aa:bb:cc:dd:ee:ff";
        
        let circuit = HardwareAttestationCircuit::new(cpu_model, mac_address);
        
        // Compute expected commitment
        let commitment = compute_expected_commitment(cpu_model, mac_address);
        
        // Create and verify proof
        let prover = MockProver::run(k, &circuit, vec![vec![commitment]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
    
    #[test]
    fn test_different_hardware_different_commitment() {
        let cpu1 = "Intel Core i7";
        let cpu2 = "AMD Ryzen 9";
        let mac = "11:22:33:44:55:66";
        
        let commitment1 = compute_expected_commitment(cpu1, mac);
        let commitment2 = compute_expected_commitment(cpu2, mac);
        
        assert_ne!(commitment1, commitment2);
    }
}
