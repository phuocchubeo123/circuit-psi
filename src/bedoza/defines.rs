use crate::scalar_field::FourQScalarField;
use anyhow::Result;
use rand::Rng;
use rand::RngExt;

pub type FE = FourQScalarField;

pub fn random_fe_vec(cnt: usize) -> Result<Vec<FE>> {
    let mut rng = rand::rng();
    random_fe_vec_from_rng(&mut rng, cnt)
}

pub fn random_fe_vec_from_rng(rng: &mut impl Rng, cnt: usize) -> Result<Vec<FE>> {
    let mut out = Vec::with_capacity(cnt);
    for _ in 0..cnt {
        let fe = loop {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes);
            if let Ok(fe) = FE::from_bytes_le(&bytes) {
                break fe;
            }
        };
        out.push(fe);
    }
    Ok(out)
}
