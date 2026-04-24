use crate::math::scalar_field::FourQScalarField;
use anyhow::Result;
use rand::Rng;
use rand::RngExt;

pub type FE = FourQScalarField;
// FE_LIMBS = FE length / 2 (for 32-byte FE represented as two 16-byte u128 limbs).
pub const FE_LIMBS: usize = 2;

pub fn random_fe_vec(cnt: usize) -> Result<Vec<FE>> {
    let mut rng = rand::rng();
    random_fe_vec_from_rng(&mut rng, cnt)
}

pub fn random_fe_vec_from_rng(rng: &mut impl Rng, cnt: usize) -> Result<Vec<FE>> {
    let mut out = Vec::with_capacity(cnt);
    for _ in 0..cnt {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        out.push(FE::from_bytes_le_mod_order(&bytes));
    }
    Ok(out)
}

pub fn powers(base: FE, n: usize) -> Vec<FE> {
    let mut out = Vec::with_capacity(n);
    if n == 0 {
        return out;
    }
    out.push(FE::one());
    for _ in 1..n {
        let next = *out.last().unwrap() * base;
        out.push(next);
    }
    out
}
