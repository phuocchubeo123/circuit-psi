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
use clap::{Args, Parser};
use std::time::Instant;

const DEFAULT_N: usize = 1000;
const DEFAULT_SENDER_ADDR: &str = "127.0.0.1";
const DEFAULT_SENDER_PORT: u16 = 23000;

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
#[command(name = "bench_shuffle_inputer_steps")]
struct Cli {
    #[command(flatten)]
    network: NetworkArgs,
    #[arg(long, default_value_t = DEFAULT_N)]
    n: usize,
}

fn timed_local<T, F>(label: &str, f: F) -> Result<T>
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
    println!("role=inputer_steps n={} sender={}", args.n, sender_socket);
    let delta_0 = fq(97);
    let inputer_vole_key = fq(173);

    let mut channel = timed_local("connect_swanky", || {
        connect_with_retry(&sender_socket).context("connect swanky channel")
    })?;

    let total_start = Instant::now();


    let mut auth_vole_sender = timed_channel("init_auth_vole_sender", &mut channel, |channel| {
        BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {}", e))
    })?;
    let mut auth_vole_receiver =
        timed_channel("init_auth_vole_receiver", &mut channel, |channel| {
        BufferedVoleReceiver::init(channel, -delta_0, LPN21)
            .map_err(|e| anyhow!("init auth receiver VOLE failed: {}", e))
        })?;
    let inputer = Inputer::new(delta_0, inputer_vole_key);
    let mut rng = rand::rng();

    let x_values = timed_local("generate_inputs", || {
        random_fe_vec_from_rng(&mut rng, args.n).context("generate input set")
    })?;

    let mut key_shares = None;
    let mut authenticated_xi = Vec::with_capacity(x_values.len());
    let mut authenticated_ri = Vec::with_capacity(x_values.len());
    let mut authenticated_pi = Vec::with_capacity(x_values.len());
    timed_channel("step0", &mut channel, |channel| {
        inputer.step0_authenticate_oprf_key_and_xi_and_ri_and_receive_pi(
            &x_values,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            channel,
            &mut key_shares,
            &mut authenticated_xi,
            &mut authenticated_ri,
            &mut authenticated_pi,
        )
    })?;
    let key_shares = key_shares.ok_or_else(|| anyhow!("step0 did not produce key shares"))?;

    let mut k1_mul_vole_sender = timed_channel("init_k1_mul_vole_sender", &mut channel, |channel| {
        BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init k1 mul sender VOLE failed: {}", e))
    })?;

    let mut authenticated_r_x_plus_k0 = Vec::with_capacity(x_values.len());
    timed_channel("step1", &mut channel, |channel| {
        inputer.step1_inputer_authenticates_r_times_x_plus_k0_and_proves(
            &authenticated_xi,
            &authenticated_ri,
            key_shares.bedoza_sender(),
            &mut auth_vole_sender,
            channel,
            &mut authenticated_r_x_plus_k0,
        )
    })?;

    let mut u_values = Vec::with_capacity(x_values.len());
    let mut authenticated_u = Vec::with_capacity(x_values.len());
    let mut authenticated_v = Vec::with_capacity(x_values.len());
    timed_channel("step2", &mut channel, |channel| {
        inputer.step2_vole_share_r_times_k1_and_authenticate(
            &authenticated_ri,
            key_shares.bedoza_receiver(),
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut k1_mul_vole_sender,
            channel,
            &mut u_values,
            &mut authenticated_u,
            &mut authenticated_v,
        )
    })?;

    let authenticated_r_x_k_inverse = timed_channel("step3", &mut channel, |channel| {
        inputer.step3_open_ri_x_plus_k0_plus_ui_and_receive_reauthenticate(
            &authenticated_r_x_plus_k0,
            &authenticated_u,
            &authenticated_v,
            &mut auth_vole_receiver,
            channel,
        )
    })?;

    let g_ri = timed_channel("step4", &mut channel, |channel| {
        inputer.step4_send_g_ri_and_pad_consistency_proof(&authenticated_ri, channel)
    })?;

    let (_x, authenticated_permuted_x_powers, authenticated_xi_times_inverse) =
        timed_channel("step5", &mut channel, |channel| {
            inputer.step5_send_challenge_and_receive_authenticated_xpi_and_xi_times_inverse(
                &authenticated_pi,
                &authenticated_r_x_k_inverse,
                &mut rng,
                &mut auth_vole_receiver,
                channel,
            )
        })?;

    let shuffled = timed_channel("step6", &mut channel, |channel| {
        inputer.step6_receive_shuffled_oprf_points_and_verify(
            &g_ri,
            &authenticated_permuted_x_powers,
            &authenticated_xi_times_inverse,
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
    println!("output_count={}", shuffled.len());

    Ok(())
}
