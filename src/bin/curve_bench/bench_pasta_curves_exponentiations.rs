use anyhow::Result;
use pasta_curves::group::{Group, ff::Field};
use pasta_curves::{pallas, vesta};
use rand08::{SeedableRng, rngs::StdRng};
use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

const DEFAULT_EXPONENTIATIONS: usize = 1_000;
const DEFAULT_SEED: u64 = 42;

fn main() -> Result<()> {
    let (n, seed) = parse_args()?;

    println!(
        "Preparing {} pasta_curves Pallas and Vesta exponents with seed {}...",
        n, seed
    );
    let pallas_scalars = random_pallas_scalars(n, seed);
    let vesta_scalars = random_vesta_scalars(n, seed);

    let pallas_elapsed = benchmark_pallas(&pallas_scalars);
    report("pasta_curves Pallas", n, pallas_elapsed);

    let vesta_elapsed = benchmark_vesta(&vesta_scalars);
    report("pasta_curves Vesta", n, vesta_elapsed);

    Ok(())
}

fn benchmark_pallas(scalars: &[pallas::Scalar]) -> Duration {
    let generator = pallas::Point::generator();

    let started = Instant::now();
    let products: Vec<pallas::Point> = scalars
        .iter()
        .map(|scalar| black_box(&generator) * black_box(scalar))
        .collect();
    let elapsed = started.elapsed();

    black_box(products);
    elapsed
}

fn benchmark_vesta(scalars: &[vesta::Scalar]) -> Duration {
    let generator = vesta::Point::generator();

    let started = Instant::now();
    let products: Vec<vesta::Point> = scalars
        .iter()
        .map(|scalar| black_box(&generator) * black_box(scalar))
        .collect();
    let elapsed = started.elapsed();

    black_box(products);
    elapsed
}

fn random_pallas_scalars(n: usize, seed: u64) -> Vec<pallas::Scalar> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(|_| pallas::Scalar::random(&mut rng)).collect()
}

fn random_vesta_scalars(n: usize, seed: u64) -> Vec<vesta::Scalar> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n).map(|_| vesta::Scalar::random(&mut rng)).collect()
}

fn report(name: &str, n: usize, elapsed: Duration) {
    println!("computed {} {} exponentiations in {:?}", n, name, elapsed);
    println!(
        "{} throughput: {:.2} exponentiations/sec",
        name,
        n as f64 / elapsed.as_secs_f64()
    );
    println!(
        "{} average latency: {:.3} ms/exponentiation",
        name,
        elapsed.as_secs_f64() * 1_000.0 / n as f64
    );
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
            "Unexpected extra argument '{}'. Usage: bench_pasta_curves_exponentiations [count] [seed]",
            extra
        ));
    }

    Ok((n, seed))
}
