use anyhow::Result;
use blst::{blst_p1, blst_p1_generator, blst_p1_mult};
use rand08::{RngCore, SeedableRng, rngs::StdRng};
use std::env;
use std::hint::black_box;
use std::time::Instant;

const DEFAULT_EXPONENTIATIONS: usize = 1_000;
const DEFAULT_SEED: u64 = 42;
const SCALAR_BITS: usize = 255;

fn main() -> Result<()> {
    let (n, seed) = parse_args()?;

    println!(
        "Preparing {} blst BLS12-381 G1 exponents with seed {}...",
        n, seed
    );
    let exponents = random_exponents(n, seed);
    let generator = unsafe { blst_p1_generator() };

    let started = Instant::now();
    let products: Vec<blst_p1> = exponents
        .iter()
        .map(|exponent| {
            let mut out = blst_p1::default();
            unsafe {
                blst_p1_mult(
                    &mut out,
                    black_box(generator),
                    black_box(exponent.as_ptr()),
                    SCALAR_BITS,
                );
            }
            out
        })
        .collect();
    let elapsed = started.elapsed();

    black_box(products);
    println!(
        "computed {} blst BLS12-381 G1 exponentiations in {:?}",
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

fn random_exponents(n: usize, seed: u64) -> Vec<[u8; 32]> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut exponents = vec![[0u8; 32]; n];
    for exponent in &mut exponents {
        rng.fill_bytes(exponent);
        exponent[31] &= 0x7f;
    }
    exponents
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
            "Unexpected extra argument '{}'. Usage: bench_blst_bls12_381_exponentiations [count] [seed]",
            extra
        ));
    }

    Ok((n, seed))
}
