use anyhow::Result;
use circuit_psi::math::defines::{FE, random_fe_vec_from_rng};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

const DEFAULT_N: usize = 1_000_000;
const DEFAULT_ROUNDS: usize = 5;
const DEFAULT_SEED: u64 = 42;

fn main() -> Result<()> {
    let (n, rounds, seed) = parse_args()?;
    println!(
        "benchmark=fe_sampling_strategies n={} rounds={} seed={}",
        n, rounds, seed
    );

    let pads = build_pads(n, seed ^ 0xA5A5_A5A5_A5A5_A5A5);

    let mut t_on_the_fly = Duration::ZERO;
    let mut t_vec_once = Duration::ZERO;
    let mut t_bulk_fill = Duration::ZERO;

    for round in 0..rounds {
        let round_seed = seed.wrapping_add((round as u64).wrapping_mul(0x9E37_79B9));

        let started = Instant::now();
        let acc1 = on_the_fly_sample_and_accumulate(&pads, round_seed);
        t_on_the_fly += started.elapsed();
        black_box(acc1);

        let started = Instant::now();
        let acc2 = vec_sample_then_accumulate(&pads, round_seed)?;
        t_vec_once += started.elapsed();
        black_box(acc2);

        let started = Instant::now();
        let acc3 = bulk_fill_then_accumulate(&pads, round_seed);
        t_bulk_fill += started.elapsed();
        black_box(acc3);
    }

    report("on_the_fly", n, rounds, t_on_the_fly);
    report("vec_sample", n, rounds, t_vec_once);
    report("bulk_fill", n, rounds, t_bulk_fill);

    Ok(())
}

fn build_pads(n: usize, seed: u64) -> Vec<FE> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let bytes: [u8; 32] = rng.random();
        out.push(FE::from_bytes_le_mod_order(&bytes));
    }
    out
}

fn on_the_fly_sample_and_accumulate(pads: &[FE], seed: u64) -> FE {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut acc = FE::zero();
    for pad in pads {
        let bytes: [u8; 32] = rng.random();
        let coeff = FE::from_bytes_le_mod_order(&bytes);
        acc += coeff * *pad;
    }
    acc
}

fn vec_sample_then_accumulate(pads: &[FE], seed: u64) -> Result<FE> {
    let mut rng = StdRng::seed_from_u64(seed);
    let coeffs = random_fe_vec_from_rng(&mut rng, pads.len())?;
    let mut acc = FE::zero();
    for (coeff, pad) in coeffs.iter().zip(pads.iter()) {
        acc += *coeff * *pad;
    }
    Ok(acc)
}

fn bulk_fill_then_accumulate(pads: &[FE], seed: u64) -> FE {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut buf = vec![0u8; pads.len() * 32];
    rng.fill(&mut buf);

    let mut acc = FE::zero();
    for (chunk, pad) in buf.chunks_exact(32).zip(pads.iter()) {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(chunk);
        let coeff = FE::from_bytes_le_mod_order(&bytes);
        acc += coeff * *pad;
    }
    acc
}

fn report(name: &str, n: usize, rounds: usize, total: Duration) {
    let total_ops = (n as u128) * (rounds as u128);
    let total_secs = total.as_secs_f64();
    let ns_per_op = total_secs * 1e9 / (total_ops as f64);
    let ops_per_sec = (total_ops as f64) / total_secs;

    println!(
        "method={} total={:?} avg_per_round={:?} ns_per_op={:.2} ops_per_sec={:.2}",
        name,
        total,
        total / (rounds as u32),
        ns_per_op,
        ops_per_sec
    );
}

fn parse_args() -> Result<(usize, usize, u64)> {
    let mut args = env::args();
    let _bin = args.next();

    let n = match args.next() {
        Some(raw) => parse_nonzero_usize(&raw, "n")?,
        None => DEFAULT_N,
    };

    let rounds = match args.next() {
        Some(raw) => parse_nonzero_usize(&raw, "rounds")?,
        None => DEFAULT_ROUNDS,
    };

    let seed = match args.next() {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("Invalid seed '{}': {}", raw, e))?,
        None => DEFAULT_SEED,
    };

    if let Some(extra) = args.next() {
        return Err(anyhow::anyhow!(
            "Unexpected extra argument '{}'. Usage: bench_fe_sampling_strategies [n] [rounds] [seed]",
            extra
        ));
    }

    Ok((n, rounds, seed))
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
