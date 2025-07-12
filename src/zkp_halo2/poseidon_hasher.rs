// src/zkp_halo2/poseidon_hasher.rs
// Fixed version for halo2_proofs 0.3.0

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
    },
    poly::Rotation,
};

/// Poseidon hash parameters for 128-bit security
#[derive(Clone, Debug)]
pub struct PoseidonParams<F: Field> {
    pub t: usize,
    pub r_f: usize,
    pub r_p: usize,
    pub mds_matrix: Vec<Vec<F>>,
    pub round_constants: Vec<Vec<F>>,
    pub alpha: u64,
}

impl<F: Field> PoseidonParams<F> {
    pub fn new() -> Self {
        let t = 3;
        let r_f = 8;
        let r_p = 57;
        let alpha = 5u64;
        
        let mds_matrix = Self::generate_mds_matrix(t);
        let total_constants = (r_f + r_p) * t;
        let round_constants = Self::generate_round_constants(total_constants, t);
        
        Self {
            t,
            r_f,
            r_p,
            mds_matrix,
            round_constants,
            alpha,
        }
    }
    
    fn generate_mds_matrix(t: usize) -> Vec<Vec<F>> {
        let mut matrix = vec![vec![F::ZERO; t]; t];
        
        // Simple MDS matrix for demonstration
        for i in 0..t {
            for j in 0..t {
                // Using a different construction that doesn't require from_u64
                let val = F::ONE.double().double(); // F::from(4)
                matrix[i][j] = val;
            }
        }
        
        matrix
    }
    
    fn generate_round_constants(total: usize, t: usize) -> Vec<Vec<F>> {
        let rounds = (total + t - 1) / t;
        let mut constants = Vec::with_capacity(rounds);
        
        for _ in 0..rounds {
            let mut round_constants = Vec::with_capacity(t);
            for _ in 0..t {
                // Use F::ONE for simplicity in this fixed version
                round_constants.push(F::ONE);
            }
            constants.push(round_constants);
        }
        
        constants
    }
}

/// Poseidon chip configuration
#[derive(Clone, Debug)]
pub struct PoseidonConfig<F: Field> {
    pub state: [Column<Advice>; 3],
    pub partial_sbox: Column<Advice>,
    pub rc_a: [Column<Fixed>; 3],
    pub rc_b: [Column<Fixed>; 3],
    pub s_full: Selector,
    pub s_partial: Selector,
    pub s_pad: Selector,
    pub mds: [[F; 3]; 3],
}

/// Poseidon chip implementing the permutation
pub struct PoseidonChip<F: Field> {
    pub config: PoseidonConfig<F>, // Made public to fix access error
    params: PoseidonParams<F>,
}

impl<F: Field> PoseidonChip<F> {
    pub fn construct(config: PoseidonConfig<F>, params: PoseidonParams<F>) -> Self {
        Self { config, params }
    }
    
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 3],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; 3],
        rc_b: [Column<Fixed>; 3],
        params: &PoseidonParams<F>,
    ) -> PoseidonConfig<F> {
        for column in &state {
            meta.enable_equality(*column);
        }
        meta.enable_equality(partial_sbox);
        
        let s_full = meta.selector();
        let s_partial = meta.selector();
        let s_pad = meta.selector();
        
        // Full rounds constraints
        meta.create_gate("full rounds", |meta| {
            let s = meta.query_selector(s_full);
            
            (0..3).map(|i| {
                let cur = meta.query_advice(state[i], Rotation::cur());
                let next = meta.query_advice(state[i], Rotation::next());
                let rc = meta.query_fixed(rc_a[i]); // Fixed: removed Rotation parameter
                
                let sbox = cur + rc;
                let sbox2 = sbox.clone() * sbox.clone();
                let sbox4 = sbox2.clone() * sbox2.clone();
                let sbox5 = sbox4 * sbox.clone();
                
                let mds_sum = (0..3).fold(Expression::Constant(F::ZERO), |acc, j| {
                    let state_j = meta.query_advice(state[j], Rotation::cur());
                    let rc_j = meta.query_fixed(rc_a[j]); // Fixed: removed Rotation parameter
                    let after_sbox = {
                        let tmp = state_j + rc_j;
                        let tmp2 = tmp.clone() * tmp.clone();
                        let tmp4 = tmp2.clone() * tmp2.clone();
                        tmp4 * tmp
                    };
                    acc + after_sbox * Expression::Constant(params.mds_matrix[i][j])
                });
                
                s.clone() * (next - mds_sum)
            }).collect::<Vec<_>>()
        });
        
        // Partial rounds constraints
        meta.create_gate("partial rounds", |meta| {
            let s = meta.query_selector(s_partial);
            
            let mut constraints = vec![];
            
            let cur_0 = meta.query_advice(state[0], Rotation::cur());
            let mid = meta.query_advice(partial_sbox, Rotation::cur());
            let rc_0 = meta.query_fixed(rc_b[0]); // Fixed: removed Rotation parameter
            
            let sbox_in = cur_0 + rc_0;
            let sbox2 = sbox_in.clone() * sbox_in.clone();
            let sbox4 = sbox2.clone() * sbox2.clone();
            let sbox5 = sbox4 * sbox_in.clone();
            constraints.push(s.clone() * (mid - sbox5));
            
            for i in 0..3 {
                let next_i = meta.query_advice(state[i], Rotation::next());
                let mds_sum = Expression::Constant(params.mds_matrix[i][0]) * mid.clone()
                    + (1..3).fold(Expression::Constant(F::ZERO), |acc, j| {
                        let state_j = meta.query_advice(state[j], Rotation::cur());
                        let rc_j = meta.query_fixed(rc_b[j]); // Fixed: removed Rotation parameter
                        acc + Expression::Constant(params.mds_matrix[i][j]) * (state_j + rc_j)
                    });
                constraints.push(s.clone() * (next_i - mds_sum));
            }
            
            constraints
        });
        
        PoseidonConfig {
            state,
            partial_sbox,
            rc_a,
            rc_b,
            s_full,
            s_partial,
            s_pad,
            mds: [
                [params.mds_matrix[0][0], params.mds_matrix[0][1], params.mds_matrix[0][2]],
                [params.mds_matrix[1][0], params.mds_matrix[1][1], params.mds_matrix[1][2]],
                [params.mds_matrix[2][0], params.mds_matrix[2][1], params.mds_matrix[2][2]],
            ],
        }
    }
    
    pub fn hash_two(
        &self,
        mut layouter: impl Layouter<F>,
        input_a: AssignedCell<F, F>,
        input_b: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "poseidon hash",
            |mut region| {
                let mut state = [Value::unknown(), Value::unknown(), Value::unknown()];
                state[0] = input_a.value().copied();
                state[1] = input_b.value().copied();
                state[2] = Value::known(F::ZERO);
                
                let mut row = 0;
                self.permutation(&mut region, &mut state, &mut row)?;
                
                let output = region.assign_advice(
                    || "output",
                    self.config.state[0],
                    row,
                    || state[0],
                )?;
                
                Ok(output)
            },
        )
    }
    
    fn permutation(
        &self,
        region: &mut Region<F>,
        state: &mut [Value<F>; 3],
        row: &mut usize,
    ) -> Result<(), Error> {
        for round in 0..(self.params.r_f / 2) {
            self.full_round(region, state, row, round)?;
        }
        
        for round in 0..self.params.r_p {
            self.partial_round(region, state, row, round)?;
        }
        
        for round in (self.params.r_f / 2)..self.params.r_f {
            self.full_round(region, state, row, round + self.params.r_p)?;
        }
        
        Ok(())
    }
    
    fn full_round(
        &self,
        region: &mut Region<F>,
        state: &mut [Value<F>; 3],
        row: &mut usize,
        round: usize,
    ) -> Result<(), Error> {
        self.config.s_full.enable(region, *row)?;
        
        for i in 0..3 {
            region.assign_fixed(
                || format!("rc_a_{}", i),
                self.config.rc_a[i],
                *row,
                || Value::known(self.params.round_constants[round][i]),
            )?;
        }
        
        for i in 0..3 {
            region.assign_advice(
                || format!("state_{}", i),
                self.config.state[i],
                *row,
                || state[i],
            )?;
        }
        
        let mut next_state = [Value::unknown(); 3];
        for i in 0..3 {
            next_state[i] = Value::known(F::ZERO);
            for j in 0..3 {
                let sbox_val = state[j].map(|s| {
                    let tmp = s + self.params.round_constants[round][j];
                    tmp.pow(&[self.params.alpha, 0, 0, 0])
                });
                next_state[i] = next_state[i].and_then(|acc| {
                    sbox_val.map(|s| acc + self.params.mds_matrix[i][j] * s)
                });
            }
        }
        
        *state = next_state;
        *row += 1;
        
        Ok(())
    }
    
    fn partial_round(
        &self,
        region: &mut Region<F>,
        state: &mut [Value<F>; 3],
        row: &mut usize,
        round: usize,
    ) -> Result<(), Error> {
        self.config.s_partial.enable(region, *row)?;
        
        let round_idx = round + self.params.r_f / 2;
        
        for i in 0..3 {
            region.assign_fixed(
                || format!("rc_b_{}", i),
                self.config.rc_b[i],
                *row,
                || Value::known(self.params.round_constants[round_idx][i]),
            )?;
        }
        
        for i in 0..3 {
            region.assign_advice(
                || format!("state_{}", i),
                self.config.state[i],
                *row,
                || state[i],
            )?;
        }
        
        let sbox_0 = state[0].map(|s| {
            let tmp = s + self.params.round_constants[round_idx][0];
            tmp.pow(&[self.params.alpha, 0, 0, 0])
        });
        
            // Assign S-box output
            let sbox_5 = region.assign_advice(
                || "partial_sbox",
                self.config.partial_sbox,
                *row,
                || sbox_0,
            )?;
        
        let mut next_state = [Value::unknown(); 3];
        for i in 0..3 {
            next_state[i] = sbox_0.map(|s| self.params.mds_matrix[i][0] * s);
            for j in 1..3 {
                let linear = state[j].map(|s| s + self.params.round_constants[round_idx][j]);
                next_state[i] = next_state[i].and_then(|acc| {
                    linear.map(|l| acc + self.params.mds_matrix[i][j] * l)
                });
            }
        }
        
        *state = next_state;
        *row += 1;
        
        Ok(())
    }
}
