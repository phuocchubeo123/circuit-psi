use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use std::hint::black_box;
use std::time::Instant;

fn random_scalar() -> Scalar {
    Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>())
}

fn main() {
    let s = random_scalar();

    let points: Vec<EdwardsPoint> = (0..10)
        .map(|_| EdwardsPoint::mul_base(&random_scalar()))
        .collect();

    let started = Instant::now();
    let products: Vec<EdwardsPoint> = points.iter().map(|p| p * &s).collect();
    let elapsed = started.elapsed();

    black_box(products);
    println!("computed {} multiplications in {:?}", points.len(), elapsed);
}
