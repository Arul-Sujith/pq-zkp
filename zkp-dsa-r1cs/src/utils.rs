use ark_relations::r1cs::SynthesisError;

pub fn modular_inverse(a: u64, m: u64) -> Result<u64, SynthesisError> {
    let (g, x, _) = extended_gcd(a as i64, m as i64);
    if g != 1 {
        return Err(SynthesisError::AssignmentMissing);
    }
    Ok(((x % m as i64 + m as i64) % m as i64) as u64)
}

pub fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

pub fn modular_exponentiation(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    let mut base = base % modulus;
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp >>= 1;
    }
    result
}
