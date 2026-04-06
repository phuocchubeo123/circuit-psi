use anyhow::{Context, Result, ensure};
use circuit_psi::{
    bedoza::{
        defines::random_fe_vec_from_rng,
    },
    scalar_field::fq,
    shuffle_inputer::Inputer,
    vole_triple::LPN21,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

const SWANKY_ADDR: &str = "127.0.0.1:23000";
const SHUFFLER_RNG_SEED: [u8; 32] = [42u8; 32];

fn main() -> Result<()> {
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    ensure!(n > 0, "set size n must be > 0");

    let delta_0 = fq(97);
    let delta_1 = fq(131);
    let k1_prime = fq(193);

    let _ = (delta_1, k1_prime, StdRng::from_seed(SHUFFLER_RNG_SEED));

    let mut swanky = circuit_psi::tcp_channel::connect_with_retry(SWANKY_ADDR)
        .context("connect swanky channel")?;

    // Init order must match shuffler counterpart exactly.
    let mut auth_vole_sender =
        BufferedVoleSender::init(&mut swanky, LPN21)
            .map_err(|e| anyhow::anyhow!("init auth sender VOLE failed: {}", e))?;
    let mut auth_vole_receiver = BufferedVoleReceiver::init(
        &mut swanky,
        -delta_0,
        LPN21,
    )
    .map_err(|e| anyhow::anyhow!("init auth receiver VOLE failed: {}", e))?;
    let mut k1_mul_vole_sender =
        BufferedVoleSender::init(&mut swanky, LPN21)
            .map_err(|e| anyhow::anyhow!("init k1 mul sender VOLE failed: {}", e))?;
    let mut k1_prime_mul_vole_sender = BufferedVoleSender::init(
        &mut swanky,
        LPN21,
    )
    .map_err(|e| anyhow::anyhow!("init k1' mul sender VOLE failed: {}", e))?;

    let mut rng = rand::rng();
    let t_inputs_start = Instant::now();
    let x_values = random_fe_vec_from_rng(&mut rng, n)?;
    let t_inputs = t_inputs_start.elapsed();

    let inputer = Inputer::new(delta_0);
    let t_proto_start = Instant::now();
    let shuffled = inputer.run_full_shuffled_oprf(
        &x_values,
        &mut rng,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        &mut k1_mul_vole_sender,
        &mut k1_prime_mul_vole_sender,
        &mut swanky,
    )?;
    let t_proto = t_proto_start.elapsed();

    println!("role=inputer n={}", n);
    println!(
        "timing_ms input_generation={} protocol_total={}",
        t_inputs.as_millis(),
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
