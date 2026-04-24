use anyhow::Result;
use ark_ec::PrimeGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_pallas::{Fr, Projective};
use rand08::{SeedableRng, rngs::StdRng};
use std::env;
use std::hint::black_box;
use std::time::Instant;

const DEFAULT_EXPONENTIATIONS: usize = 1_000;
const DEFAULT_SEED: u64 = 42;

fn main() -> Result<()> {
    let (n, seed) = parse_args()?;

    println!("Preparing {} ark-pallas exponents with seed {}...", n, seed);
    let scalars = random_scalars(n, seed);
    let generator = Projective::generator();

    let started = Instant::now();
    let products: Vec<Projective> = scalars
        .iter()
        .map(|scalar| black_box(&generator).mul_bigint(black_box((*scalar).into_bigint())))
        .collect();
    let elapsed = started.elapsed();

    black_box(products);
    println!("computed {} ark-pallas exponentiations in {:?}", n, elapsed);
    println!(
        "throughput: {:.2} exponentiations/sec",
        n as f64 / elapsed.as_secs_f64()
    );
    println!(
        "average latency: {:.3} ms/exponentiation",
        elapsed.as_secs_f64() * 1_000.0 / n as f64
    );

    Ok(())
}

fn random_scalars(n: usize, seed: u64) -> Vec<Fr> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(|_| Fr::rand(&mut rng)).collect()
}

fn parse_args() -> Result<(usize, u64)> {
    let mut args = env::args();
    let _bin = args.next();

    let n = match args.next() {
        Some(raw) => {
            let parsed: usize = raw
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid exponentiation count '{}': {}", raw, e))?;
            if parsed == 0 {
                return Err(anyhow::anyhow!("Exponentiation count must be > 0"));
            }
            parsed
        }
        None => DEFAULT_EXPONENTIATIONS,
    };

    let seed = match args.next() {
        Some(raw) => raw
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid RNG seed '{}': {}", raw, e))?,
        None => DEFAULT_SEED,
    };

    if let Some(extra) = args.next() {
        return Err(anyhow::anyhow!(
            "Unexpected extra argument '{}'. Usage: bench_ark_pallas_exponentiations [count] [seed]",
            extra
        ));
    }

    Ok((n, seed))
}
