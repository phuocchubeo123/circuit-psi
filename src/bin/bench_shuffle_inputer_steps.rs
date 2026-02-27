use anyhow::{Context, Result, anyhow, ensure};
use circuit_psi::{
    bedoza::{
        defines::{FE, random_fe_vec_from_rng},
        vole_auth::FourQVoleMac,
    },
    scalar_field::fq,
    shuffle_inputer::Inputer,
    tcp_channel::{connect_swanky_with_retry, connect_with_retry},
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use mac_n_cheese_vole::{mac::Mac, vole::VoleSizes};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;
use swanky_aes_rng::AesRng;
use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier};

type SenderMac = Mac<Prover, FourQVoleMac>;
type ReceiverMac = Mac<Verifier, FourQVoleMac>;

const SWANKY_ADDR: &str = "127.0.0.1:23000";
const TCP_ADDR: &str = "127.0.0.1:23001";
const SHUFFLER_RNG_SEED: [u8; 32] = [42u8; 32];

fn make_base_voles(key: FE, count: usize, offset: u64) -> (Vec<SenderMac>, Vec<ReceiverMac>) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let idx = offset + i as u64;
        let x = fq(idx + 1);
        let beta = fq(3 * idx + 7);
        sender.push(Mac::prover_new(IS_PROVER, x, beta));
        receiver.push(Mac::verifier_new(IS_VERIFIER, x * key + beta));
    }
    (sender, receiver)
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

    println!("role=inputer_steps n={}", n);
    let total_start = Instant::now();

    let delta_0 = fq(97);
    let delta_1 = fq(131);
    let k1_prime = fq(193);

    let mut preview_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);
    let k1_preview = random_fe_vec_from_rng(&mut preview_rng, 1)?[0];

    let sizes = VoleSizes::of::<FE, FE>();
    let (auth_sender_base, _) = make_base_voles(delta_1, sizes.base_voles_needed, 10_000);
    let (_, auth_receiver_base) = make_base_voles(delta_0, sizes.base_voles_needed, 1_000_000);
    let (k1_mul_sender_base, _) = make_base_voles(k1_preview, sizes.base_voles_needed, 2_000_000);
    let (k1_prime_mul_sender_base, _) =
        make_base_voles(k1_prime, sizes.base_voles_needed, 3_000_000);

    let mut swanky = timed("connect_swanky", || {
        connect_swanky_with_retry(SWANKY_ADDR).context("connect swanky channel")
    })?;
    let mut tcp = timed("connect_tcp", || {
        connect_with_retry(TCP_ADDR).context("connect tcp channel")
    })?;

    let mut vole_rng = AesRng::new();
    let mut auth_vole_sender = timed("init_auth_vole_sender", || {
        BufferedVoleSender::<FourQVoleMac>::init(&mut swanky, &mut vole_rng, auth_sender_base)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {}", e))
    })?;
    let mut auth_vole_receiver = timed("init_auth_vole_receiver", || {
        BufferedVoleReceiver::<FourQVoleMac>::init(
            &mut swanky,
            &mut vole_rng,
            -delta_0,
            auth_receiver_base,
        )
        .map_err(|e| anyhow!("init auth receiver VOLE failed: {}", e))
    })?;

    let inputer = Inputer::new(delta_0);
    let mut rng = rand::rng();

    let (_k0, inputer_key_share) = timed("step0", || {
        inputer.step0_sample_and_authenticate_oprf_key_share(
            &mut rng,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;

    let mut k1_mul_vole_sender = timed("init_k1_mul_vole_sender", || {
        BufferedVoleSender::<FourQVoleMac>::init(&mut swanky, &mut vole_rng, k1_mul_sender_base)
            .map_err(|e| anyhow!("init k1 mul sender VOLE failed: {}", e))
    })?;
    let mut k1_prime_mul_vole_sender =
        timed("init_k1_prime_mul_vole_sender", || {
            BufferedVoleSender::<FourQVoleMac>::init(
                &mut swanky,
                &mut vole_rng,
                k1_prime_mul_sender_base,
            )
            .map_err(|e| anyhow!("init k1' mul sender VOLE failed: {}", e))
        })?;

    let x_values = timed("generate_inputs", || {
        random_fe_vec_from_rng(&mut rng, n).context("generate input set")
    })?;

    let authenticated_inputs = timed("step1", || {
        inputer.step1_inputer_commits_inputs(&x_values, &mut auth_vole_sender, &mut swanky)
    })?;
    let (random_values, authenticated_ri_sender) = timed("step2", || {
        inputer.step2_inputer_commits_random_values(n, &mut rng, &mut auth_vole_sender, &mut swanky)
    })?;
    let authenticated_r_x_plus_k0_sender = timed("step3", || {
        inputer.step3_inputer_authenticates_r_times_x_plus_k0_and_proves(
            &authenticated_inputs,
            &random_values,
            &authenticated_ri_sender,
            &inputer_key_share,
            &mut auth_vole_sender,
            &mut swanky,
        )
    })?;
    let (_u_values, authenticated_u_sender, authenticated_v_receiver) =
        timed("step4", || {
            inputer.step4_vole_share_x_times_k1_and_authenticate(
                &x_values,
                &mut auth_vole_sender,
                &mut auth_vole_receiver,
                &mut k1_mul_vole_sender,
                &mut swanky,
            )
        })?;
    timed("step5", || {
        inputer.step5_open_random_linear_combination_for_uv_consistency(
            &authenticated_inputs,
            &authenticated_u_sender,
            &mut swanky,
        )
    })?;
    timed("step6", || {
        inputer.step6_verify_authenticated_v_linear_combination_consistency(
            &authenticated_inputs,
            &authenticated_u_sender,
            &authenticated_v_receiver,
            inputer_key_share.bedoza_receiver(),
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut k1_prime_mul_vole_sender,
            &mut rng,
            &mut swanky,
        )
    })?;
    let opened_r_x_plus_k0_plus_u_sender = timed("step7", || {
        inputer.step7_open_ri_x_plus_k0_plus_ui(
            &authenticated_r_x_plus_k0_sender,
            &authenticated_u_sender,
            &mut swanky,
        )
    })?;
    let authenticated_r_x_k_receiver = timed("step8", || {
        inputer.step8_receive_reauthenticated_ri_x_plus_k_and_verify_consistency(
            &opened_r_x_plus_k0_plus_u_sender,
            &authenticated_v_receiver,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    let authenticated_inverse_receiver = timed("step9", || {
        inputer.step9_receive_authenticated_inverses_and_verify(
            &authenticated_r_x_k_receiver,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    let g_ri = timed("step10", || {
        inputer.step10_send_g_ri_and_pad_consistency_proof(&authenticated_ri_sender, &mut tcp)
    })?;
    timed("step11", || {
        inputer.step11_receive_authenticated_permutation_values(
            n,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    let (x_challenge, authenticated_x_powers_receiver) = timed("step12", || {
        inputer.step12_send_challenge_and_receive_authenticated_x_powers(
            n,
            &mut rng,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    timed("step13", || {
        inputer.step13_receive_authenticated_xpi_times_inverse_and_verify(
            &authenticated_x_powers_receiver,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    timed("step14", || {
        inputer.step14_sample_challenges_and_verify_shuffle_product_identity(
            n,
            &mut rng,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    let shuffled = timed("step15", || {
        inputer.step15_receive_shuffled_oprf_points(n, &mut tcp)
    })?;
    let opened_left_product = timed("step16", || {
        inputer.step16_receive_and_verify_left_oprf_product(
            &g_ri,
            &authenticated_inverse_receiver,
            x_challenge,
            &mut tcp,
        )
    })?;
    let opened_right_product = timed("step17", || {
        inputer.step17_receive_and_verify_right_oprf_product(
            &shuffled,
            &authenticated_x_powers_receiver,
            &mut tcp,
        )
    })?;
    timed("step18", || {
        inputer
            .step18_verify_opened_oprf_products_match(&opened_left_product, &opened_right_product)
    })?;

    let total_ms = total_start.elapsed().as_millis();

    println!("timing_ms total={}", total_ms);
    println!(
        "bytes swanky_sent={} swanky_recv={} tcp_sent={} tcp_recv={}",
        swanky.bytes_sent(),
        swanky.bytes_received(),
        tcp.bytes_sent(),
        tcp.bytes_received()
    );
    println!("output_count={}", shuffled.len());

    Ok(())
}
