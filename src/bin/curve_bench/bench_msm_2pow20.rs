use anyhow::Result;
use circuit_psi::math::{
    defines::{FE, random_fe_vec},
    group::{Group, msm_pippenger, msm_pippenger_with_window},
};
use std::env;
use std::hint::black_box;
use std::time::Instant;

const DEFAULT_N: usize = 1 << 20;

fn main() -> Result<()> {
    let (n, windows) = parse_args()?;

    println!("Preparing {} points and {} scalars...", n, n);
    let setup_start = Instant::now();

    let point_scalars = random_fe_vec(n)?;
    let msm_scalars = random_fe_vec(n)?;
    let base = Group::base_point();
    let points: Vec<Group> = point_scalars.iter().map(|s| base.scalar_mul(s)).collect();

    let setup_elapsed = setup_start.elapsed();
    println!(
        "Setup done in {:?} ({:.2} points/sec while building points)",
        setup_elapsed,
        n as f64 / setup_elapsed.as_secs_f64()
    );

    if windows.is_empty() {
        run_default_compare(n, &points, &msm_scalars)?;
    } else {
        run_window_sweep(n, &points, &msm_scalars, &windows)?;
    }

    Ok(())
}

fn run_default_compare(n: usize, points: &[Group], scalars: &[FE]) -> Result<()> {
    let pip_start = Instant::now();
    let pip_msm = msm_pippenger(points, scalars)?;
    let pip_elapsed = pip_start.elapsed();

    let naive_start = Instant::now();
    let naive_msm = msm_naive(points, scalars);
    let naive_elapsed = naive_start.elapsed();

    black_box((pip_msm.clone(), naive_msm.clone()));

    if pip_msm != naive_msm {
        return Err(anyhow::anyhow!(
            "Mismatch between msm_pippenger and naive MSM results"
        ));
    }

    println!("msm_pippenger over {} points took {:?}", n, pip_elapsed);
    println!(
        "Pippenger throughput: {:.2} points/sec",
        n as f64 / pip_elapsed.as_secs_f64()
    );
    println!("naive_msm over {} points took {:?}", n, naive_elapsed);
    println!(
        "Naive throughput: {:.2} points/sec",
        n as f64 / naive_elapsed.as_secs_f64()
    );
    println!(
        "Speedup (naive / pippenger): {:.3}x",
        naive_elapsed.as_secs_f64() / pip_elapsed.as_secs_f64()
    );

    Ok(())
}

fn run_window_sweep(n: usize, points: &[Group], scalars: &[FE], windows: &[usize]) -> Result<()> {
    println!("Window sweep mode over windows: {:?}", windows);

    let mut reference: Option<Group> = None;
    let mut best_window = 0usize;
    let mut best_time = std::time::Duration::MAX;

    for &window in windows {
        let start = Instant::now();
        let out = msm_pippenger_with_window(points, scalars, window)?;
        let elapsed = start.elapsed();

        if let Some(expected) = reference.as_ref() {
            if out != *expected {
                return Err(anyhow::anyhow!(
                    "MSM mismatch for window {} against reference result",
                    window
                ));
            }
        } else {
            reference = Some(out.clone());
        }

        black_box(out);
        println!(
            "window={:<2}  time={:?}  throughput={:.2} points/sec",
            window,
            elapsed,
            n as f64 / elapsed.as_secs_f64()
        );

        if elapsed < best_time {
            best_time = elapsed;
            best_window = window;
        }
    }

    println!(
        "Best window in this sweep: {} (time={:?}, throughput={:.2} points/sec)",
        best_window,
        best_time,
        n as f64 / best_time.as_secs_f64()
    );
    Ok(())
}

fn msm_naive(points: &[Group], scalars: &[FE]) -> Group {
    let mut acc = Group::base_point().scalar_mul(&FE::zero());
    for (point, scalar) in points.iter().zip(scalars.iter()) {
        acc += point.scalar_mul(scalar);
    }
    acc
}

fn parse_args() -> Result<(usize, Vec<usize>)> {
    let mut args = env::args();
    let _bin = args.next();
    let maybe_n = args.next();

    let n = if let Some(raw) = maybe_n {
        let parsed: usize = raw
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid point count '{}': {}", raw, e))?;
        if parsed == 0 {
            return Err(anyhow::anyhow!("Point count must be > 0"));
        }
        parsed
    } else {
        DEFAULT_N
    };

    let mut windows = Vec::new();
    for raw in args {
        let window: usize = raw
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid window size '{}': {}", raw, e))?;
        windows.push(window);
    }

    Ok((n, windows))
}
