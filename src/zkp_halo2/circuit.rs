// src/zkp_halo2/circuit.rs
// AeroNyx Privacy Network - Production-Ready Zero-Knowledge Proof Circuit
// Version: 8.0.1 - Verified against halo2_proofs 0.3.0 API

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, P128Pow5T3},
    Hash as PoseidonHash,
    Pow5Chip, Pow5Config,
};
use pasta_curves::pallas;

/// Circuit configuration for hardware attestation
#[derive(Debug, Clone)]
pub struct HardwareCircuitConfig {
    /// Columns for private inputs (CPU model and MAC address)
    advice: [Column<Advice>; 2],
    /// Public input column for the commitment
    instance: Column<Instance>,
    /// Poseidon hash configuration
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
        // Configure advice columns
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
        ];
        
        // Enable equality
        for &col in &advice {
            meta.enable_equality(col);
        }
        
        // Configure instance column
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        
        // Configure Poseidon chip with proper parameters for halo2_gadgets 0.3
        let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        
        for &col in &state {
            meta.enable_equality(col);
        }
        meta.enable_equality(partial_sbox);
        
        // Fixed columns for round constants
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        
        let poseidon_config = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );
        
        HardwareCircuitConfig {
            advice,
            instance,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Load private inputs
        let (cpu_cell, mac_cell) = layouter.assign_region(
            || "load inputs",
            |mut region| {
                let cpu = region.assign_advice(
                    || "cpu_model",
                    config.advice[0],
                    0,
                    || self.cpu_model,
                )?;
                
                let mac = region.assign_advice(
                    || "mac_address",
                    config.advice[1],
                    0,
                    || self.mac_address,
                )?;
                
                Ok((cpu, mac))
            },
        )?;
        
        // Hash using Poseidon
        let chip = Pow5Chip::construct(config.poseidon_config);
        
        // Create hasher instance for constant length 2
        let hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "init hasher"),
        )?;
        
        // Hash the two inputs
        let message = [cpu_cell, mac_cell];
        let hash_output = hasher.hash(
            layouter.namespace(|| "hash inputs"),
            message,
        )?;
        
        // Expose as public input
        layouter.constrain_instance(hash_output.cell(), config.instance, 0)?;
        
        Ok(())
    }
}

/// Compute commitment outside circuit (for verification)
pub fn compute_commitment(cpu_model: &str, mac_address: &str) -> pallas::Base {
    use crate::zkp_halo2::commitment::{string_to_field, mac_to_field};
    
    let cpu_field = string_to_field(cpu_model);
    let mac_field = mac_to_field(mac_address);
    
    // Use Poseidon with the same parameters as the circuit
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
        .hash([cpu_field, mac_field])
}

/// Generate setup parameters - moved to a separate function to avoid circular dependency
pub async fn generate_setup_params(k: u32) -> Result<crate::zkp_halo2::types::SetupParams, String> {
    // This will be implemented in prover.rs to avoid circular imports
    crate::zkp_halo2::prover::generate_setup_params(k).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    
    #[test]
    fn test_hardware_circuit() {
        let k = 7;
        
        let cpu = "Intel Core i7-9700K";
        let mac = "aa:bb:cc:dd:ee:ff";
        
        let circuit = HardwareCircuit::new(cpu, mac);
        let commitment = compute_commitment(cpu, mac);
        
        let prover = MockProver::run(k, &circuit, vec![vec![commitment]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
