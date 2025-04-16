use ark_bls12_381::Fr;
use ark_ff::{One, PrimeField, Zero};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use crate::utils::{modular_inverse, modular_exponentiation};

// DSA Verification Circuit for small parameters (p=7, q=3, g=3)
#[derive(Clone)]
pub struct DSAVerificationCircuit {
    pub y: Fr,      // Public key
    pub h_x: Fr,    // Message hash
    pub r: Fr,      // Signature part r
    pub s: Fr,      // Signature part s
    pub p: Fr,      // Prime p
    pub q: Fr,      // Prime q
    pub g: Fr,      // Generator g
}

impl ConstraintSynthesizer<Fr> for DSAVerificationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Compute intermediate values from public inputs
        let s_val = self.s.into_repr().as_ref()[0] as u64;
        let q_val = self.q.into_repr().as_ref()[0] as u64;
        let w_val = modular_inverse(s_val, q_val)?;
        let h_x_val = self.h_x.into_repr().as_ref()[0] as u64;
        let u1_val = (h_x_val * w_val) % q_val;
        let r_val = self.r.into_repr().as_ref()[0] as u64;
        let u2_val = (r_val * w_val) % q_val;
        let g_val = self.g.into_repr().as_ref()[0] as u64;
        let p_val = self.p.into_repr().as_ref()[0] as u64;
        let g_u1_val = modular_exponentiation(g_val, u1_val, p_val);
        let y_val = self.y.into_repr().as_ref()[0] as u64;
        let y_u2_val = modular_exponentiation(y_val, u2_val, p_val);
        let v_val = (g_u1_val * y_u2_val) % p_val;
        let v_mod_q_val = v_val % q_val;
        let r_mod_q_val = r_val % q_val;

        // Debug prints to verify values
        println!("w_val: {}, u1_val: {}, u2_val: {}", w_val, u1_val, u2_val);
        println!("g_u1_val: {}, y_u2_val: {}, v_val: {}", g_u1_val, y_u2_val, v_val);
        println!("v_mod_q_val: {}, r_mod_q_val: {}", v_mod_q_val, r_mod_q_val);

        // Allocate public inputs (prefixed to suppress warnings)
        let _y_var = cs.new_input_variable(|| Ok(self.y))?;
        let _h_x_var = cs.new_input_variable(|| Ok(self.h_x))?;
        let _r_var = cs.new_input_variable(|| Ok(self.r))?;
        let _s_var = cs.new_input_variable(|| Ok(self.s))?;
        let _p_var = cs.new_input_variable(|| Ok(self.p))?;
        let _q_var = cs.new_input_variable(|| Ok(self.q))?;
        let _g_var = cs.new_input_variable(|| Ok(self.g))?;

        // Allocate witnesses
        let w_var = cs.new_witness_variable(|| Ok(Fr::from(w_val)))?;
        let u1_var = cs.new_witness_variable(|| Ok(Fr::from(u1_val)))?;
        let u2_var = cs.new_witness_variable(|| Ok(Fr::from(u2_val)))?;
        let g_u1_var = cs.new_witness_variable(|| Ok(Fr::from(g_u1_val)))?;
        let y_u2_var = cs.new_witness_variable(|| Ok(Fr::from(y_u2_val)))?;
        let v_var = cs.new_witness_variable(|| Ok(Fr::from(v_val)))?;
        let v_mod_q_var = cs.new_witness_variable(|| Ok(Fr::from(v_mod_q_val)))?;
        let r_mod_q_var = cs.new_witness_variable(|| Ok(Fr::from(r_mod_q_val)))?;

        // Constants
        let one = Fr::one();
        let zero = Fr::zero();

        // Constraint: w * s = 1 mod q
        let ws_var = cs.new_witness_variable(|| Ok(Fr::from(w_val * s_val)))?;
        let ws_remainder_var = cs.new_witness_variable(|| Ok(Fr::from((w_val * s_val) % q_val)))?;
        let ws_quotient_var = cs.new_witness_variable(|| Ok(Fr::from((w_val * s_val) / q_val)))?;
        let q_times_ws_quotient_var = cs.new_witness_variable(|| Ok(Fr::from(q_val * ((w_val * s_val) / q_val))))?;
        cs.enforce_constraint(lc!() + w_var, lc!() + _s_var, lc!() + ws_var)?;
        cs.enforce_constraint(lc!() + _q_var, lc!() + ws_quotient_var, lc!() + q_times_ws_quotient_var)?;
        cs.enforce_constraint(
            lc!() + ws_var - q_times_ws_quotient_var,
            lc!() + (one, Variable::One),
            lc!() + ws_remainder_var,
        )?;
        cs.enforce_constraint(
            lc!() + ws_remainder_var - (one, Variable::One),
            lc!() + (one, Variable::One),
            lc!() + (zero, Variable::One),
        )?;

        // Constraint: u1 = h_x * w mod q
        let u1_product_var = cs.new_witness_variable(|| Ok(Fr::from(h_x_val * w_val)))?;
        let u1_remainder_var = cs.new_witness_variable(|| Ok(Fr::from((h_x_val * w_val) % q_val)))?;
        let u1_quotient_var = cs.new_witness_variable(|| Ok(Fr::from((h_x_val * w_val) / q_val)))?;
        let q_times_u1_quotient_var = cs.new_witness_variable(|| Ok(Fr::from(q_val * ((h_x_val * w_val) / q_val))))?;
        cs.enforce_constraint(lc!() + _h_x_var, lc!() + w_var, lc!() + u1_product_var)?;
        cs.enforce_constraint(lc!() + _q_var, lc!() + u1_quotient_var, lc!() + q_times_u1_quotient_var)?;
        cs.enforce_constraint(
            lc!() + u1_product_var - q_times_u1_quotient_var,
            lc!() + (one, Variable::One),
            lc!() + u1_remainder_var,
        )?;
        cs.enforce_constraint(
            lc!() + u1_remainder_var - u1_var,
            lc!() + (one, Variable::One),
            lc!() + (zero, Variable::One),
        )?;

        // Constraint: u2 = r * w mod q
        let u2_product_var = cs.new_witness_variable(|| Ok(Fr::from(r_val * w_val)))?;
        let u2_remainder_var = cs.new_witness_variable(|| Ok(Fr::from((r_val * w_val) % q_val)))?;
        let u2_quotient_var = cs.new_witness_variable(|| Ok(Fr::from((r_val * w_val) / q_val)))?;
        let q_times_u2_quotient_var = cs.new_witness_variable(|| Ok(Fr::from(q_val * ((r_val * w_val) / q_val))))?;
        cs.enforce_constraint(lc!() + _r_var, lc!() + w_var, lc!() + u2_product_var)?;
        cs.enforce_constraint(lc!() + _q_var, lc!() + u2_quotient_var, lc!() + q_times_u2_quotient_var)?;
        cs.enforce_constraint(
            lc!() + u2_product_var - q_times_u2_quotient_var,
            lc!() + (one, Variable::One),
            lc!() + u2_remainder_var,
        )?;
        cs.enforce_constraint(
            lc!() + u2_remainder_var - u2_var,
            lc!() + (one, Variable::One),
            lc!() + (zero, Variable::One),
        )?;

        // Constraint: v = g_u1 * y_u2 mod p
        let v_product_var = cs.new_witness_variable(|| Ok(Fr::from(g_u1_val * y_u2_val)))?;
        let v_remainder_var = cs.new_witness_variable(|| Ok(Fr::from((g_u1_val * y_u2_val) % p_val)))?;
        let v_quotient_var = cs.new_witness_variable(|| Ok(Fr::from((g_u1_val * y_u2_val) / p_val)))?;
        let p_times_v_quotient_var = cs.new_witness_variable(|| Ok(Fr::from(p_val * ((g_u1_val * y_u2_val) / p_val))))?;
        cs.enforce_constraint(lc!() + g_u1_var, lc!() + y_u2_var, lc!() + v_product_var)?;
        cs.enforce_constraint(lc!() + _p_var, lc!() + v_quotient_var, lc!() + p_times_v_quotient_var)?;
        cs.enforce_constraint(
            lc!() + v_product_var - p_times_v_quotient_var,
            lc!() + (one, Variable::One),
            lc!() + v_remainder_var,
        )?;
        cs.enforce_constraint(
            lc!() + v_remainder_var - v_var,
            lc!() + (one, Variable::One),
            lc!() + (zero, Variable::One),
        )?;

        // Constraint: v_mod_q == r_mod_q
        cs.enforce_constraint(
            lc!() + v_mod_q_var - r_mod_q_var,
            lc!() + (one, Variable::One),
            lc!() + (zero, Variable::One),
        )?;

        Ok(())
    }
}
