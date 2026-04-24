use anyhow::{Context, Result, anyhow, ensure};
use circuit_psi::{
    math::{defines::random_fe_vec_from_rng, scalar_field::fq},
    shuffled_oprf::shuffle_inputer::Inputer,
    tcp_channel::connect_with_retry,
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use std::time::Instant;

const SWANKY_ADDR: &str = "127.0.0.1:23000";

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

    println!("role=inputer_steps n={}", n);
    let total_start = Instant::now();

    let delta_0 = fq(97);
    let inputer_vole_key = fq(173);

    let mut channel = timed("connect_swanky", || {
        connect_with_retry(SWANKY_ADDR).context("connect swanky channel")
    })?;

    let mut auth_vole_sender = timed("init_auth_vole_sender", || {
        BufferedVoleSender::init(&mut channel, LPN21)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {}", e))
    })?;
    let mut auth_vole_receiver = timed("init_auth_vole_receiver", || {
        BufferedVoleReceiver::init(&mut channel, -delta_0, LPN21)
            .map_err(|e| anyhow!("init auth receiver VOLE failed: {}", e))
    })?;
    let inputer = Inputer::new(delta_0, inputer_vole_key);
    let mut rng = rand::rng();

    let x_values = timed("generate_inputs", || {
        random_fe_vec_from_rng(&mut rng, n).context("generate input set")
    })?;

    let (key_shares, authenticated_xi, authenticated_ri, authenticated_pi) =
        timed("step0", || {
            inputer.step0_authenticate_oprf_key_and_xi_and_ri_and_receive_pi(
                &x_values,
                &mut auth_vole_sender,
                &mut auth_vole_receiver,
                &mut channel,
            )
        })?;

    let mut k1_mul_vole_sender = timed("init_k1_mul_vole_sender", || {
        BufferedVoleSender::init(&mut channel, LPN21)
            .map_err(|e| anyhow!("init k1 mul sender VOLE failed: {}", e))
    })?;

    let authenticated_r_x_plus_k0 = timed("step1", || {
        inputer.step1_inputer_authenticates_r_times_x_plus_k0_and_proves(
            &authenticated_xi,
            &authenticated_ri,
            key_shares.bedoza_sender(),
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    let (_u_values, authenticated_u, authenticated_v) = timed("step2", || {
        inputer.step2_vole_share_x_times_k1_and_authenticate(
            &authenticated_xi,
            key_shares.bedoza_receiver(),
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut k1_mul_vole_sender,
            &mut channel,
        )
    })?;

    let authenticated_r_x_k_inverse = timed("step3", || {
        inputer.step3_open_ri_x_plus_k0_plus_ui_and_receive_reauthenticate(
            &authenticated_r_x_plus_k0,
            &authenticated_u,
            &authenticated_v,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let g_ri = timed("step4", || {
        inputer.step4_send_g_ri_and_pad_consistency_proof(&authenticated_ri, &mut channel)
    })?;

    let (_x, authenticated_permuted_x_powers, authenticated_xi_times_inverse) =
        timed("step5", || {
            inputer.step5_send_challenge_and_receive_authenticated_xpi_and_xi_times_inverse(
                &authenticated_pi,
                &authenticated_r_x_k_inverse,
                &mut rng,
                &mut auth_vole_receiver,
                &mut channel,
            )
        })?;

    let shuffled = timed("step6", || {
        inputer.step6_receive_shuffled_oprf_points_and_verify(
            &g_ri,
            &authenticated_permuted_x_powers,
            &authenticated_xi_times_inverse,
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
