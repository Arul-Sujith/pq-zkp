use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::{rand::rngs::StdRng, rand::SeedableRng};
use crate::circuit::DSAVerificationCircuit;

#[test]
fn test_dsa_verification() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let circuit = DSAVerificationCircuit {
        y: Fr::from(3u64),
        h_x: Fr::from(2u64),
        r: Fr::from(2u64),
        s: Fr::from(2u64),
        p: Fr::from(7u64),
        q: Fr::from(3u64),
        g: Fr::from(3u64),
    };
    let pk_vk = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)
        .expect("Setup failed");
    let (pk, vk) = pk_vk;
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng)
        .expect("Proving failed");
    let public_inputs = vec![
        circuit.y,
        circuit.h_x,
        circuit.r,
        circuit.s,
        circuit.p,
        circuit.q,
        circuit.g,
    ];
    let is_valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)
        .expect("Verification failed");
    assert!(is_valid, "Proof verification should succeed");
}
