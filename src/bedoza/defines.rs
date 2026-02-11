use lambdaworks_math::field::
use anyhow::{anyhow, Result};
use rand::RngExt;

pub type FE = F128b;

pub fn random_fe_vec(cnt: usize) -> Result<Vec<FE>> {
    let mut rng = rand::rng();
    let mut res: Vec<FE> = Vec::with_capacity(cnt);
    for _ in 0..cnt {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        let fe = FE::from_bytes(&bytes.into())
            .map_err(|e| anyhow!("Failed to deserialize random FE bytes: {}", e))?;
        res.push(fe);
    }
    Ok(res)
}
