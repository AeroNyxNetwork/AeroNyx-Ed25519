// src/zkp_halo2/hardware_circuit.rs
// Fixed version for halo2_proofs 0.3.0

use ff::Field; // Added Field trait import
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
    },
};
use pasta_curves::pallas;

use super::poseidon_hasher::{PoseidonChip, PoseidonConfig, PoseidonParams};

/// Configuration for hardware attestation circuit
#[derive(Clone, Debug)]
pub struct HardwareCircuitConfig {
    advice: [Column<Advice>; 4],
    fixed: Column<Fixed>,
    instance: Column<Instance>,
    poseidon: PoseidonConfig<pallas::Base>,
    s_load: Selector,
}

/// Hardware attestation circuit proving knowledge of CPU and MAC
#[derive(Clone)]
pub struct HardwareAttestationCircuit {
    cpu_encoded: Vec<Value<pallas::Base>>,
    mac_encoded: Value<pallas::Base>,
}

impl HardwareAttestationCircuit {
    pub fn new(cpu_model: &str, mac_address: &str) -> Self {
        let cpu_encoded = Self::encode_string_to_field_elements(cpu_model);
        let mac_encoded = Self::encode_mac_address(mac_address);
        
        Self {
            cpu_encoded,
            mac_encoded,
        }
    }
    
    fn encode_string_to_field_elements(s: &str) -> Vec<Value<pallas::Base>> {
        const BYTES_PER_ELEMENT: usize = 31;
        let bytes = s.as_bytes();
        
        bytes.chunks(BYTES_PER_ELEMENT)
            .map(|chunk| {
                let mut padded = [0u8; 32];
                padded[1..chunk.len() + 1].copy_from_slice(chunk);
                
                // Use from_repr with proper type hint
                let fe = pallas::Base::from_repr(padded.into())
                    .expect("Invalid field element");
                Value::known(fe)
            })
            .collect()
    }
    
    fn encode_mac_address(mac: &str) -> Value<pallas::Base> {
        let normalized = mac.to_lowercase()
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "");
        
        let bytes = hex::decode(&normalized).expect("Invalid MAC address");
        assert_eq!(bytes.len(), 6, "MAC address must be 6 bytes");
        
        let mut padded = [0u8; 32];
        padded[1..7].copy_from_slice(&bytes);
        
        let fe = pallas::Base::from_repr(padded.into())
            .expect("Invalid MAC address encoding");
        Value::known(fe)
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
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        
        for &col in &advice {
            meta.enable_equality(col);
        }
        
        let fixed = meta.fixed_column();
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        
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
        
        let s_load = meta.selector();
        
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
        let (cpu_cells, mac_cell) = layouter.assign_region(
            || "load inputs",
            |mut region| {
                let mut cpu_cells = Vec::new();
                
                for (i, &value) in self.cpu_encoded.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("cpu_{}", i),
                        config.advice[i % 4],
                        i / 4,
                        || value,
                    )?;
                    cpu_cells.push(cell);
                }
                
                let mac_cell = region.assign_advice(
                    || "mac",
                    config.advice[0],
                    (self.cpu_encoded.len() + 3) / 4,
                    || self.mac_encoded,
                )?;
                
                Ok((cpu_cells, mac_cell))
            },
        )?;
        
        let poseidon_params = PoseidonParams::new();
        let poseidon_chip = PoseidonChip::construct(config.poseidon.clone(), poseidon_params);
        
        let mut state = self.initialize_state(&mut layouter, &config)?;
        
        for (i, cpu_cell) in cpu_cells.iter().enumerate() {
            state = self.absorb_element(
                &mut layouter,
                &poseidon_chip,
                state,
                cpu_cell.clone(),
                i,
            )?;
        }
        
        state = self.absorb_element(
            &mut layouter,
            &poseidon_chip,
            state,
            mac_cell,
            cpu_cells.len(),
        )?;
        
        let commitment = self.finalize_hash(&mut layouter, &poseidon_chip, state)?;
        
        layouter.constrain_instance(commitment.cell(), config.instance, 0)?;
        
        Ok(())
    }
}

impl HardwareAttestationCircuit {
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
                    pallas::Base::ZERO, // Using ZERO constant
                )?;
                Ok([zero.clone(), zero.clone(), zero])
            },
        )
    }
    
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
                let new_state_0 = region.assign_advice(
                    || "state_0 + element",
                    chip.config.state[0], // Now accessible since config is public
                    0,
                    || state[0].value().and_then(|s| element.value().map(|e| *s + *e)),
                )?;
                
                let output = chip.hash_two(
                    layouter.namespace(|| format!("permute_{}", round)),
                    new_state_0,
                    state[1].clone(),
                )?;
                
                Ok([output, state[2].clone(), state[0].clone()])
            },
        )
    }
    
    fn finalize_hash(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        chip: &PoseidonChip<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 3],
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
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
    
    let mut hasher = Sha256::new();
    hasher.update(b"HARDWARE_COMMITMENT");
    hasher.update(cpu_model.as_bytes());
    hasher.update(mac_address.as_bytes());
    
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    
    let fe = pallas::Base::from_repr(bytes.into())
        .unwrap_or(pallas::Base::ZERO);
    fe
}
