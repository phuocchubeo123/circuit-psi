use anyhow::{Context, Result, anyhow, ensure};
use circuit_psi::{
    bedoza::{
        defines::{FE, random_fe_vec_from_rng},
        vole_auth::FourQVoleMac,
    },
    scalar_field::fq,
    shuffle_shuffler::Shuffler,
    tcp_channel::{listen_swanky, listen_to},
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use mac_n_cheese_vole::{mac::Mac, vole::VoleSizes};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
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

    let delta_0 = fq(97);
    let delta_1 = fq(131);
    let k1_prime = fq(193);

    let mut preview_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);
    let k1_preview = random_fe_vec_from_rng(&mut preview_rng, 1)?[0];

    let sizes = VoleSizes::of::<FE, FE>();
    let (_, auth_receiver_base) = make_base_voles(delta_1, sizes.base_voles_needed, 10_000);
    let (auth_sender_base, _) = make_base_voles(delta_0, sizes.base_voles_needed, 1_000_000);
    let (_, k1_mul_receiver_base) = make_base_voles(k1_preview, sizes.base_voles_needed, 2_000_000);
    let (_, k1_prime_mul_receiver_base) =
        make_base_voles(k1_prime, sizes.base_voles_needed, 3_000_000);

    let mut swanky = timed("listen_swanky", || {
        listen_swanky(SWANKY_ADDR).context("listen swanky channel")
    })?;
    let mut tcp = timed("listen_tcp", || {
        listen_to(TCP_ADDR).context("listen tcp channel")
    })?;

    let mut vole_rng = AesRng::new();
    let mut auth_vole_receiver = timed("init_auth_vole_receiver", || {
        BufferedVoleReceiver::<FourQVoleMac>::init(
            &mut swanky,
            &mut vole_rng,
            -delta_1,
            auth_receiver_base,
        )
        .map_err(|e| anyhow!("init auth receiver VOLE failed: {}", e))
    })?;
    let mut auth_vole_sender = timed("init_auth_vole_sender", || {
        BufferedVoleSender::<FourQVoleMac>::init(&mut swanky, &mut vole_rng, auth_sender_base)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {}", e))
    })?;

    let mut protocol_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);
    let shuffler = Shuffler::new(delta_1);

    let (k1, shuffler_key_share) = timed("step0", || {
        shuffler.step0_sample_and_authenticate_oprf_key_share(
            &mut protocol_rng,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    ensure!(
        k1 == k1_preview,
        "deterministic seed mismatch for k1 preview"
    );

    let mut k1_mul_vole_receiver = timed("init_k1_mul_vole_receiver", || {
        BufferedVoleReceiver::<FourQVoleMac>::init(
            &mut swanky,
            &mut vole_rng,
            -k1,
            k1_mul_receiver_base,
        )
        .map_err(|e| anyhow!("init k1 mul receiver VOLE failed: {}", e))
    })?;
    let mut k1_prime_mul_vole_receiver =
        timed("init_k1_prime_mul_vole_receiver", || {
            BufferedVoleReceiver::<FourQVoleMac>::init(
                &mut swanky,
                &mut vole_rng,
                -k1_prime,
                k1_prime_mul_receiver_base,
            )
            .map_err(|e| anyhow!("init k1' mul receiver VOLE failed: {}", e))
        })?;

    let mut perm_rng = rand::rng();
    let permutation = timed("generate_permutation", || {
        Ok(random_permutation(n, &mut perm_rng))
    })?;

    let authenticated_inputs = timed("step1", || {
        shuffler.step1_inputer_commits_inputs(n, &mut auth_vole_receiver, &mut swanky)
    })?;
    let authenticated_ri_receiver = timed("step2", || {
        shuffler.step2_inputer_commits_random_values(n, &mut auth_vole_receiver, &mut swanky)
    })?;
    let authenticated_r_x_plus_k0_receiver = timed("step3", || {
        shuffler.step3_inputer_authenticates_r_times_x_plus_k0_and_proves(
            &authenticated_inputs,
            &authenticated_ri_receiver,
            &shuffler_key_share,
            &mut auth_vole_receiver,
            &mut swanky,
        )
    })?;
    let (v_values, authenticated_u_receiver, authenticated_v_sender) =
        timed("step4", || {
            shuffler.step4_vole_share_x_times_k1_and_authenticate(
                n,
                &mut auth_vole_receiver,
                &mut auth_vole_sender,
                &mut k1_mul_vole_receiver,
                &mut swanky,
            )
        })?;
    timed("step5", || {
        shuffler.step5_verify_random_linear_combination_for_uv_consistency(
            &authenticated_inputs,
            &authenticated_u_receiver,
            &v_values,
            k1,
            &mut swanky,
        )
    })?;
    timed("step6", || {
        shuffler.step6_prove_authenticated_v_linear_combination_consistency(
            &authenticated_inputs,
            &authenticated_u_receiver,
            &authenticated_v_sender,
            shuffler_key_share.bedoza_sender(),
            k1_prime,
            &mut auth_vole_receiver,
            &mut auth_vole_sender,
            &mut k1_prime_mul_vole_receiver,
            &mut swanky,
        )
    })?;
    let r_x_k_values = timed("step7", || {
        shuffler.step7_receive_ri_x_plus_k0_plus_ui_and_reconstruct_ri_x_plus_k(
            &authenticated_r_x_plus_k0_receiver,
            &authenticated_u_receiver,
            &v_values,
            &mut swanky,
        )
    })?;
    let authenticated_r_x_k_sender = timed("step8", || {
        shuffler.step8_reauthenticate_ri_x_plus_k_and_prove_consistency(
            &r_x_k_values,
            &authenticated_v_sender,
            &mut auth_vole_sender,
            &mut protocol_rng,
            &mut swanky,
        )
    })?;
    let (inverse_values, authenticated_inverse_sender) = timed("step9", || {
        shuffler.step9_authenticate_inverses_and_prove(
            &authenticated_r_x_k_sender,
            &mut auth_vole_sender,
            &mut swanky,
        )
    })?;
    let g_ri = timed("step10", || {
        shuffler
            .step10_receive_g_ri_and_verify_pad_consistency(&authenticated_ri_receiver, &mut tcp)
    })?;
    let authenticated_pi_sender = timed("step11", || {
        shuffler.step11_authenticate_permutation_values(
            &permutation,
            &mut auth_vole_sender,
            &mut swanky,
        )
    })?;
    let (x_challenge, _permuted_x_powers, authenticated_x_powers_sender) =
        timed("step12", || {
            shuffler.step12_receive_challenge_and_authenticate_x_powers(
                &permutation,
                &mut auth_vole_sender,
                &mut swanky,
            )
        })?;
    let (
        _permuted_inverse_values,
        _product_values,
        _authenticated_permuted_inverse_sender,
        authenticated_products_sender,
    ) = timed("step13", || {
        shuffler.step13_authenticate_xpi_times_inverse_and_prove(
            &permutation,
            &authenticated_x_powers_sender,
            &authenticated_inverse_sender,
            &mut auth_vole_sender,
            &mut swanky,
        )
    })?;
    timed("step14", || {
        shuffler.step14_prove_shuffle_product_identity(
            x_challenge,
            &authenticated_pi_sender,
            &authenticated_products_sender,
            &authenticated_inverse_sender,
            &authenticated_x_powers_sender,
            &mut auth_vole_sender,
            &mut swanky,
        )
    })?;
    let shuffled = timed("step15", || {
        shuffler.step15_send_shuffled_oprf_points(&permutation, &g_ri, &inverse_values, &mut tcp)
    })?;
    let opened_left_product = timed("step16", || {
        shuffler.step16_open_left_oprf_product_and_pad_proof(
            &g_ri,
            &authenticated_inverse_sender,
            x_challenge,
            &mut tcp,
        )
    })?;
    let opened_right_product = timed("step17", || {
        shuffler.step17_open_right_oprf_product_and_pad_proof(
            &shuffled,
            &authenticated_x_powers_sender,
            &mut tcp,
        )
    })?;
    timed("step18", || {
        shuffler
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
