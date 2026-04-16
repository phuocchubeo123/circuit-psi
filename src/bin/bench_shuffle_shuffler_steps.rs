use anyhow::{Context, Result, anyhow, ensure};
use circuit_psi::{
    scalar_field::fq,
    shuffle_shuffler::Shuffler,
    tcp_channel::listen_to,
    vole_triple::LPN21,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
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

fn timed<T, F>(label: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed().as_millis();
    println!("timing_ms {}={}", label, elapsed);
    out.with_context(|| format!("{} failed", label))
}

fn main() -> Result<()> {
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    ensure!(n > 0, "set size n must be > 0");

    println!("role=shuffler_steps n={}", n);
    let total_start = Instant::now();

    let delta_1 = fq(131);

    let mut channel = timed("listen_to", || {
        listen_to(SWANKY_ADDR).context("listen swanky channel")
    })?;

    let mut auth_vole_receiver = timed("init_auth_vole_receiver", || {
        BufferedVoleReceiver::init(&mut channel, delta_1, LPN21)
            .map_err(|e| anyhow!("init auth receiver VOLE failed: {}", e))
    })?;
    let mut auth_vole_sender = timed("init_auth_vole_sender", || {
        BufferedVoleSender::init(&mut channel, LPN21)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {}", e))
    })?;
    let shuffler = Shuffler::new(delta_1);
    let mut protocol_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);
    let mut perm_rng = rand::rng();

    let permutation = timed("generate_permutation", || {
        Ok(random_permutation(n, &mut perm_rng))
    })?;

    let (
        shuffler_key_share,
        k1,
        authenticated_inputs,
        authenticated_ri_receiver,
        authenticated_pi_sender,
    ) = timed("step0", || {
        shuffler.step0_authenticate_oprf_key_and_xi_and_ri_and_send_pi(
            &permutation,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let mut k1_mul_vole_receiver = timed("init_k1_mul_vole_receiver", || {
        BufferedVoleReceiver::init(&mut channel, k1, LPN21)
            .map_err(|e| anyhow!("init k1 mul receiver VOLE failed: {}", e))
    })?;

    let authenticated_r_x_plus_k0_receiver = timed("step1", || {
        shuffler.step1_inputer_authenticates_r_times_x_plus_k0_and_verifies(
            &authenticated_inputs,
            &authenticated_ri_receiver,
            &shuffler_key_share,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let (v_values, authenticated_u_receiver, authenticated_v_sender) = timed("step2", || {
        shuffler.step2_vole_share_x_times_k1_and_authenticate(
            &authenticated_inputs,
            shuffler_key_share.bedoza_sender(),
            k1,
            &mut auth_vole_receiver,
            &mut auth_vole_sender,
            &mut k1_mul_vole_receiver,
            &mut channel,
        )
    })?;

    let (inverse_values, authenticated_inverse_sender) = timed("step3", || {
        shuffler.step3_receive_ri_x_plus_k0_plus_ui_and_receive_reauthenticate_and_inverse(
            &authenticated_r_x_plus_k0_receiver,
            &authenticated_u_receiver,
            &v_values,
            &authenticated_v_sender,
            &mut auth_vole_sender,
            &mut protocol_rng,
            &mut channel,
        )
    })?;

    let g_ri = timed("step4", || {
        shuffler.step4_receive_g_ri_and_verify_pad_consistency_proof(
            &authenticated_ri_receiver,
            &mut channel,
        )
    })?;

    let (x, authenticated_x_powers_sender) = timed("step5", || {
        shuffler.step5_receive_challenge_and_authenticate_xpi_and_prove_running_product(
            &permutation,
            &authenticated_pi_sender,
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    let shuffled = timed("step6", || {
        shuffler.step6_send_shuffled_oprf_points_and_open_and_verify_products(
            &permutation,
            &g_ri,
            &inverse_values,
            &authenticated_inverse_sender,
            x,
            &authenticated_x_powers_sender,
            &mut channel,
        )
    })?;

    let total_ms = total_start.elapsed().as_millis();
    println!("timing_ms total={}", total_ms);
    println!(
        "bytes swanky_sent={} swanky_recv={}",
        channel.bytes_sent(),
        channel.bytes_received()
    );
    println!("output_count={}", shuffled.len());

    Ok(())
}
