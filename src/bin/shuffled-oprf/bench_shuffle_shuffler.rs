use anyhow::{Context, Result, ensure};
use circuit_psi::{
    math::scalar_field::fq,
    shuffled_oprf::shuffle_shuffler::Shuffler,
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use std::time::Instant;

const SWANKY_ADDR: &str = "127.0.0.1:23000";
const SHUFFLER_RNG_SEED: [u8; 32] = [42u8; 32];

fn random_permutation(n: usize, rng: &mut impl Rng) -> Vec<usize> {
    let mut p: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        p.swap(i, j);
    }
    p
}

fn main() -> Result<()> {
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    ensure!(n > 0, "set size n must be > 0");

    let delta_0 = fq(97);
    let delta_1 = fq(131);
    let shuffler_vole_key = fq(149);
    let _ = (delta_0, delta_1);

    let mut swanky =
        circuit_psi::tcp_channel::listen_to(SWANKY_ADDR).context("listen swanky channel")?;

    // Init order must match inputer counterpart exactly.
    let mut auth_vole_receiver = BufferedVoleReceiver::init(&mut swanky, -delta_1, LPN21)
        .map_err(|e| anyhow::anyhow!("init auth receiver VOLE failed: {}", e))?;
    let mut auth_vole_sender = BufferedVoleSender::init(&mut swanky, LPN21)
        .map_err(|e| anyhow::anyhow!("init auth sender VOLE failed: {}", e))?;

    let mut protocol_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);

    let mut k1_mul_vole_receiver =
        BufferedVoleReceiver::init(&mut swanky, shuffler_vole_key, LPN21)
            .map_err(|e| anyhow::anyhow!("init k1 mul receiver VOLE failed: {}", e))?;

    let mut perm_rng = rand::rng();
    let t_perm_start = Instant::now();
    let permutation = random_permutation(n, &mut perm_rng);
    let t_perm = t_perm_start.elapsed();

    let shuffler = Shuffler::new(delta_1, shuffler_vole_key);
    let t_proto_start = Instant::now();
    let shuffled = shuffler.run_full_shuffled_oprf(
        &permutation,
        &mut protocol_rng,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        &mut k1_mul_vole_receiver,
        &mut swanky,
    )?;
    let t_proto = t_proto_start.elapsed();

    println!("role=shuffler n={}", n);
    println!(
        "timing_ms permutation_generation={} protocol_total={}",
        t_perm.as_millis(),
        t_proto.as_millis()
    );
    println!(
        "bytes swanky_sent={} swanky_recv={}",
        swanky.bytes_sent(),
        swanky.bytes_received(),
    );
    println!("output_count={}", shuffled.len());

    Ok(())
}
