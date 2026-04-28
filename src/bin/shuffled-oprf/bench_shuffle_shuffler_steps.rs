use anyhow::{Context, Result, anyhow, ensure};
use circuit_psi::{
    math::scalar_field::fq,
    shuffled_oprf::shuffle_shuffler::Shuffler,
    tcp_channel::listen_to,
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use clap::{Args, Parser};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use std::time::Instant;

const DEFAULT_N: usize = 1000;
const DEFAULT_SENDER_ADDR: &str = "127.0.0.1";
const DEFAULT_SENDER_PORT: u16 = 23000;
const SHUFFLER_RNG_SEED: [u8; 32] = [42u8; 32];

#[derive(Debug, Clone, Args)]
struct NetworkArgs {
    #[arg(long, default_value = DEFAULT_SENDER_ADDR)]
    sender_addr: String,
    #[arg(long, default_value_t = DEFAULT_SENDER_PORT)]
    sender_port: u16,
}

impl NetworkArgs {
    fn socket_addr(&self) -> String {
        format!("{}:{}", self.sender_addr, self.sender_port)
    }
}

#[derive(Debug, Clone, Parser)]
#[command(name = "bench_shuffle_shuffler_steps")]
struct Cli {
    #[command(flatten)]
    network: NetworkArgs,
    #[arg(long, default_value_t = DEFAULT_N)]
    n: usize,
}

fn random_permutation(n: usize, rng: &mut impl Rng) -> Vec<usize> {
    let mut p: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        p.swap(i, j);
    }
    p
}

fn timed<T, F>(
    label: &str,
    f: F,
) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed().as_millis();
    println!(
        "step_stats {} time_ms={} bytes_sent_delta={} bytes_received_delta={}",
        label, elapsed, 0, 0
    );
    out.with_context(|| format!("{} failed", label))
}

fn timed_channel<T, F>(
    label: &str,
    channel: &mut circuit_psi::tcp_channel::SwankyChannel,
    f: F,
) -> Result<T>
where
    F: FnOnce(&mut circuit_psi::tcp_channel::SwankyChannel) -> Result<T>,
{
    let before_sent = channel.bytes_sent();
    let before_recv = channel.bytes_received();
    let start = Instant::now();
    let out = f(channel);
    let elapsed = start.elapsed().as_millis();
    let delta_sent = channel.bytes_sent().saturating_sub(before_sent);
    let delta_recv = channel.bytes_received().saturating_sub(before_recv);
    println!(
        "step_stats {} time_ms={} bytes_sent_delta={} bytes_received_delta={}",
        label, elapsed, delta_sent, delta_recv
    );
    out.with_context(|| format!("{} failed", label))
}

fn main() -> Result<()> {
    let args = Cli::parse();
    ensure!(args.n > 0, "set size n must be > 0");

    let sender_socket = args.network.socket_addr();
    println!("role=shuffler_steps n={} sender={}", args.n, sender_socket);
    let total_start = Instant::now();

    let delta_1 = fq(131);
    let shuffler_vole_key = fq(149);

    let mut channel = timed("listen_to", || {
        listen_to(&sender_socket).context("listen swanky channel")
    })?;

    let mut auth_vole_receiver = timed_channel("init_auth_vole_receiver", &mut channel, |channel| {
        BufferedVoleReceiver::init(channel, delta_1, LPN21)
            .map_err(|e| anyhow!("init auth receiver VOLE failed: {}", e))
    })?;
    let mut auth_vole_sender = timed_channel("init_auth_vole_sender", &mut channel, |channel| {
        BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {}", e))
    })?;
    let shuffler = Shuffler::new(delta_1, shuffler_vole_key);
    let mut protocol_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);
    let mut perm_rng = rand::rng();

    let permutation = timed("generate_permutation", || {
        Ok(random_permutation(args.n, &mut perm_rng))
    })?;

    let mut shuffler_key_share = None;
    let mut authenticated_inputs = Vec::with_capacity(permutation.len());
    let mut authenticated_ri_receiver = Vec::with_capacity(permutation.len());
    let mut authenticated_pi_sender = Vec::with_capacity(permutation.len());
    timed_channel("step0", &mut channel, |channel| {
        shuffler.step0_authenticate_oprf_key_and_xi_and_ri_and_send_pi(
            &permutation,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            channel,
            &mut shuffler_key_share,
            &mut authenticated_inputs,
            &mut authenticated_ri_receiver,
            &mut authenticated_pi_sender,
        )
    })?;
    let shuffler_key_share =
        shuffler_key_share.ok_or_else(|| anyhow!("step0 did not produce key share"))?;

    let mut k1_mul_vole_receiver =
        timed_channel("init_k1_mul_vole_receiver", &mut channel, |channel| {
        BufferedVoleReceiver::init(channel, shuffler_vole_key, LPN21)
            .map_err(|e| anyhow!("init k1 mul receiver VOLE failed: {}", e))
    })?;

    let mut authenticated_r_x_plus_k0_receiver = Vec::with_capacity(permutation.len());
    timed_channel("step1", &mut channel, |channel| {
        shuffler.step1_inputer_authenticates_r_times_x_plus_k0_and_verifies(
            &authenticated_inputs,
            &authenticated_ri_receiver,
            &shuffler_key_share,
            &mut auth_vole_receiver,
            channel,
            &mut authenticated_r_x_plus_k0_receiver,
        )
    })?;

    let mut v_values = Vec::with_capacity(permutation.len());
    let mut authenticated_u_receiver = Vec::with_capacity(permutation.len());
    let mut authenticated_v_sender = Vec::with_capacity(permutation.len());
    timed_channel("step2", &mut channel, |channel| {
        shuffler.step2_vole_share_r_times_k1_and_authenticate(
            &authenticated_ri_receiver,
            shuffler_key_share.bedoza_sender(),
            &mut auth_vole_receiver,
            &mut auth_vole_sender,
            &mut k1_mul_vole_receiver,
            channel,
            &mut v_values,
            &mut authenticated_u_receiver,
            &mut authenticated_v_sender,
        )
    })?;

    let (_r_x_k_values, inverse_values, authenticated_inverse_sender) =
        timed_channel("step3", &mut channel, |channel| {
        shuffler.step3_receive_ri_x_plus_k0_plus_ui_and_receive_reauthenticate_and_inverse(
            &authenticated_r_x_plus_k0_receiver,
            &authenticated_u_receiver,
            &v_values,
            &authenticated_v_sender,
            &mut auth_vole_sender,
            &mut protocol_rng,
            channel,
        )
    })?;

    let g_ri = timed_channel("step4", &mut channel, |channel| {
        shuffler.step4_receive_g_ri_and_verify_pad_consistency_proof(
            &authenticated_ri_receiver,
            channel,
        )
    })?;

    let (x, authenticated_x_powers_sender) = timed_channel("step5", &mut channel, |channel| {
        shuffler.step5_receive_challenge_and_authenticate_xpi_and_prove_running_product(
            &permutation,
            &authenticated_pi_sender,
            &mut auth_vole_sender,
            channel,
        )
    })?;

    let shuffled = timed_channel("step6", &mut channel, |channel| {
        shuffler.step6_send_shuffled_oprf_points_and_open_and_verify_products(
            &permutation,
            &g_ri,
            &inverse_values,
            &authenticated_inverse_sender,
            x,
            &authenticated_x_powers_sender,
            channel,
        )
    })?;

    let total_ms = total_start.elapsed().as_millis();
    println!("timing_ms total={}", total_ms);
    println!(
        "bytes swanky_sent={} swanky_recv={}",
        channel.bytes_sent(),
        channel.bytes_received()
    );
    println!("output_count={}", shuffled.0.len());

    Ok(())
}
