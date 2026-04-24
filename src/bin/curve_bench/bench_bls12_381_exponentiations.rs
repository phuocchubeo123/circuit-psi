use anyhow::Result;
use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::{
        short_weierstrass::curves::bls12_381::curve::BLS12381Curve, traits::IsEllipticCurve,
    },
    unsigned_integer::element::U256,
};
use rand08::{Rng, SeedableRng, rngs::StdRng};
use std::env;
use std::hint::black_box;
use std::time::Instant;

const DEFAULT_EXPONENTIATIONS: usize = 1_000;
const DEFAULT_SEED: u64 = 42;

fn main() -> Result<()> {
    let (n, seed) = parse_args()?;

    println!(
        "Preparing {} BLS12-381 G1 exponents with seed {}...",
        n, seed
    );
    let mut rng = StdRng::seed_from_u64(seed);
    let exponents: Vec<U256> = (0..n)
        .map(|_| U256::from_limbs(rng.r#gen::<[u64; 4]>()))
        .collect();
    let generator = BLS12381Curve::generator();

    let started = Instant::now();
    let products: Vec<_> = exponents
        .iter()
        .map(|exponent| black_box(&generator).operate_with_self(black_box(*exponent)))
        .collect();
    let elapsed = started.elapsed();

    black_box(products);
    println!(
        "computed {} BLS12-381 G1 exponentiations in {:?}",
        n, elapsed
    );
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
            "Unexpected extra argument '{}'. Usage: bench_bls12_381_exponentiations [count] [seed]",
            extra
        ));
    }

    Ok((n, seed))
}
