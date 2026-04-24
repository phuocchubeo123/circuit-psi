use anyhow::Result;
use circuit_psi::math::{defines::random_fe_vec, group::Group};
use std::hint::black_box;
use std::time::Instant;

fn main() -> Result<()> {
    let s = random_fe_vec(1)?
        .into_iter()
        .next()
        .expect("random_fe_vec(1) must return exactly one scalar");

    let points: Vec<Group> = random_fe_vec(10)?
        .into_iter()
        .map(|r| Group::base_point().scalar_mul(&r))
        .collect();

    let started = Instant::now();
    let products: Vec<Group> = points.iter().map(|p| p.scalar_mul(&s)).collect();
    let elapsed = started.elapsed();

    black_box(products);
    println!("computed {} multiplications in {:?}", points.len(), elapsed);

    Ok(())
}
