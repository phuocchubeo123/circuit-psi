use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use rayon::prelude::*;
use std::hint::black_box;
use std::time::Instant;

const DEFAULT_POINT_COUNT: usize = 1_000_000;

fn random_scalar() -> Scalar {
    Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>())
}

fn parse_point_count() -> usize {
    std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_POINT_COUNT)
}

fn print_rate(label: &str, count: usize, elapsed: std::time::Duration) {
    let per_op_us = elapsed.as_secs_f64() * 1e6 / count as f64;
    println!(
        "{label}: {} multiplications in {:?} ({:.3} us/op)",
        count, elapsed, per_op_us
    );
}

fn main() {
    let count = parse_point_count();
    println!("benchmarking dalek with {count} points and one shared scalar");

    let s = random_scalar();

    let setup_start = Instant::now();
    let points: Vec<EdwardsPoint> = (0..count)
        .map(|_| EdwardsPoint::mul_base(&random_scalar()))
        .collect();
    let setup_elapsed = setup_start.elapsed();
    println!("generated points in {:?}", setup_elapsed);

    let seq_start = Instant::now();
    let seq_out: Vec<EdwardsPoint> = points.iter().map(|p| p * &s).collect();
    let seq_elapsed = seq_start.elapsed();
    black_box(&seq_out);
    print_rate("sequential", count, seq_elapsed);

    let par_start = Instant::now();
    let par_out: Vec<EdwardsPoint> = points.par_iter().map(|p| p * &s).collect();
    let par_elapsed = par_start.elapsed();
    black_box(&par_out);
    print_rate("parallel", count, par_elapsed);

    let speedup = seq_elapsed.as_secs_f64() / par_elapsed.as_secs_f64();
    println!("parallel speedup: {:.2}x", speedup);
}
