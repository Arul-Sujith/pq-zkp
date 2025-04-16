use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::{rand::rngs::StdRng, rand::SeedableRng};
use crate::circuit::DSAVerificationCircuit;

mod circuit;
mod utils;

fn main() {
    // Initialize random number generator
    let mut rng = StdRng::seed_from_u64(0u64);

    // Example inputs: p=7, q=3, g=3, y=3, h(x)=2, r=2, s=2
    let circuit = DSAVerificationCircuit {
        y: Fr::from(3u64),    // Public key
        h_x: Fr::from(2u64),  // Message hash
        r: Fr::from(2u64),    // Signature r
        s: Fr::from(2u64),    // Signature s
        p: Fr::from(7u64),    // Prime p
        q: Fr::from(3u64),    // Prime q
        g: Fr::from(3u64),    // Generator g
    };

    // Generate proving and verification keys
    let pk_vk = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).expect("Setup failed");
    let (pk, vk) = pk_vk;

    // Generate proof
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng).expect("Proving failed");

    // Verify proof
    let public_inputs = vec![
        circuit.y,
        circuit.h_x,
        circuit.r,
        circuit.s,
        circuit.p,
        circuit.q,
        circuit.g,
    ];
    let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof).expect("Verification failed");

    println!("Proof verification result: {}", is_valid);
}
