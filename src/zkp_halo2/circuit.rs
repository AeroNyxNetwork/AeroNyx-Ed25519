// src/zkp_halo2/circuit.rs
// AeroNyx Privacy Network - Secure Zero-Knowledge Proof Circuit
// Version: 7.0.0 - 使用正确的 halo2_gadgets v0.3 API

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2_gadgets::poseidon::{
    primitives::{self as poseidon_primitives, ConstantLength, P128Pow5T3},
    Pow5Chip, Pow5Config,
};
use pasta_curves::pallas;

/// Circuit configuration for hardware attestation
#[derive(Debug, Clone)]
pub struct HardwareCircuitConfig {
    /// Columns for private inputs (CPU model and MAC address)
    input_columns: [Column<Advice>; 2],
    /// Public input column for the commitment
    instance_column: Column<Instance>,
    /// Poseidon hash configuration with secure parameters
    poseidon_config: Pow5Config<pallas::Base, 3, 2>,
}

/// Hardware attestation circuit proving knowledge of CPU and MAC
#[derive(Clone, Default)]
pub struct HardwareCircuit {
    /// Private: CPU model encoded as field element
    pub cpu_model: Value<pallas::Base>,
    /// Private: MAC address encoded as field element
    pub mac_address: Value<pallas::Base>,
}

impl HardwareCircuit {
    /// Create new circuit with private witnesses
    pub fn new(cpu_model: &str, mac_address: &str) -> Self {
        use crate::zkp_halo2::commitment::{string_to_field, mac_to_field};
        
        Self {
            cpu_model: Value::known(string_to_field(cpu_model)),
            mac_address: Value::known(mac_to_field(mac_address)),
        }
    }
    
    /// Create circuit without witnesses (for key generation)
    pub fn without_witnesses() -> Self {
        Self::default()
    }
}

impl Circuit<pallas::Base> for HardwareCircuit {
    type Config = HardwareCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::without_witnesses()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Configure advice columns for inputs
        let input_columns = [
            meta.advice_column(),
            meta.advice_column(),
        ];
        
        // Configure instance column for public commitment
        let instance_column = meta.instance_column();
        
        // Enable equality constraints
        for &col in &input_columns {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance_column);
        
        // Configure Poseidon hash with width 3
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        
        // For halo2_gadgets v0.3, we need a partial round column
        let partial_sbox = meta.advice_column();
        meta.enable_equality(partial_sbox);
        
        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        
        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        
        // Configure Poseidon with secure parameters
        let poseidon_config = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            rc_a,
            rc_b,
        );
        
        HardwareCircuitConfig {
            input_columns,
            instance_column,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Instantiate Poseidon chip
        let poseidon_chip = Pow5Chip::construct(config.poseidon_config);
        
        // Step 1: Load private inputs
        let cpu_cell = layouter.assign_region(
            || "load cpu model",
            |mut region| {
                region.assign_advice(
                    || "cpu_model",
                    config.input_columns[0],
                    0,
                    || self.cpu_model,
                )
            },
        )?;
        
        let mac_cell = layouter.assign_region(
            || "load mac address",
            |mut region| {
                region.assign_advice(
                    || "mac_address",
                    config.input_columns[1],
                    0,
                    || self.mac_address,
                )
            },
        )?;
        
        // Step 2: Hash the inputs using secure Poseidon
        // For halo2_gadgets v0.3, use the generic hash method
        let message = [cpu_cell, mac_cell];
        let hasher = poseidon_chip.construct_hasher(layouter.namespace(|| "init hasher"))?;
        let commitment_cell = hasher.hash(
            layouter.namespace(|| "hash inputs"),
            message,
        )?;
        
        // Step 3: Constrain hash output to public input
        layouter.constrain_instance(
            commitment_cell.cell(),
            config.instance_column,
            0,
        )?;
        
        Ok(())
    }
}

/// Compute commitment outside circuit (for verification)
pub fn compute_commitment(cpu_model: &str, mac_address: &str) -> pallas::Base {
    use crate::zkp_halo2::commitment::{string_to_field, mac_to_field};
    
    let cpu_field = string_to_field(cpu_model);
    let mac_field = mac_to_field(mac_address);
    
    // Use the same Poseidon parameters as the circuit
    poseidon_primitives::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
        .hash([cpu_field, mac_field])
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    
    #[test]
    fn test_hardware_circuit() {
        let k = 7; // 2^7 = 128 rows
        
        let cpu = "Intel Core i7-9700K";
        let mac = "aa:bb:cc:dd:ee:ff";
        
        // Create circuit
        let circuit = HardwareCircuit::new(cpu, mac);
        
        // Compute expected public input
        let commitment = compute_commitment(cpu, mac);
        
        // Run mock prover
        let prover = MockProver::run(k, &circuit, vec![vec![commitment]]).unwrap();
        
        // Verify
        assert_eq!(prover.verify(), Ok(()));
    }
    
    #[test]
    fn test_commitment_determinism() {
        let cpu = "AMD Ryzen 9 5950X";
        let mac = "11:22:33:44:55:66";
        
        let c1 = compute_commitment(cpu, mac);
        let c2 = compute_commitment(cpu, mac);
        
        assert_eq!(c1, c2, "Commitment should be deterministic");
    }
}
