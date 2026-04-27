use anyhow::Result;
use circuit_psi::math::defines::FE;
use rand08::{RngCore, SeedableRng, rngs::StdRng};
use std::env;
use std::hint::black_box;
use std::time::Instant;

const DEFAULT_MULS: usize = 1_000_000;
const DEFAULT_SEED: u64 = 42;

fn main() -> Result<()> {
    let (n, seed) = parse_args()?;
    println!("benchmark=fourq_fe_mul n={} seed={}", n, seed);

    let mut rng = StdRng::seed_from_u64(seed);
    let lhs: Vec<FE> = (0..n).map(|_| sample_fe(&mut rng)).collect();
    let rhs: Vec<FE> = (0..n).map(|_| sample_fe(&mut rng)).collect();

    let started = Instant::now();
    let mut acc = FE::zero();
    for i in 0..n {
        let product = black_box(lhs[i]) * black_box(rhs[i]);
        acc = black_box(acc + product);
    }
    let elapsed = started.elapsed();

    black_box(acc);
    print_report(n, elapsed);
    Ok(())
}

fn sample_fe(rng: &mut StdRng) -> FE {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    FE::from_bytes_le_mod_order(&bytes)
}

fn print_report(n: usize, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    let muls_per_sec = n as f64 / secs;
    let ns_per_mul = secs * 1e9 / n as f64;

    println!("elapsed={:?}", elapsed);
    println!("throughput_mul_per_sec={:.2}", muls_per_sec);
    println!("latency_ns_per_mul={:.2}", ns_per_mul);
}

fn parse_args() -> Result<(usize, u64)> {
    let mut args = env::args();
    let _bin = args.next();

    let n = match args.next() {
        Some(raw) => parse_nonzero_usize(&raw, "n")?,
        None => DEFAULT_MULS,
    };
    let seed = match args.next() {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("Invalid seed '{}': {}", raw, e))?,
        None => DEFAULT_SEED,
    };

    if let Some(extra) = args.next() {
        return Err(anyhow::anyhow!(
            "Unexpected extra argument '{}'. Usage: bench_fourq_fe_mul [n] [seed]",
            extra
        ));
    }

    Ok((n, seed))
}

fn parse_nonzero_usize(raw: &str, name: &str) -> Result<usize> {
    let value: usize = raw
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid {} '{}': {}", name, raw, e))?;
    if value == 0 {
        return Err(anyhow::anyhow!("{} must be > 0", name));
    }
    Ok(value)
}
