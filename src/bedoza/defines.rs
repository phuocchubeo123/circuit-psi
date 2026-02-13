use crate::stark_scalar::{random_scalars, random_scalars_from_rng, StarkScalar};
use anyhow::{anyhow, Result};
use rand::Rng;

pub type FE = StarkScalar;

pub fn random_fe_vec(cnt: usize) -> Result<Vec<FE>> {
    random_scalars(cnt)
        .map_err(|e| anyhow!("Failed to deserialize random scalar bytes: {:?}", e))
}

pub fn random_fe_vec_from_rng(rng: &mut impl Rng, cnt: usize) -> Result<Vec<FE>> {
    random_scalars_from_rng(rng, cnt)
        .map_err(|e| anyhow!("Failed to deserialize random scalar bytes: {:?}", e))
}
