use anyhow::{Context, Result, anyhow, ensure};
use circuit_psi::{
    bedoza::{
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        defines::{FE, random_fe_vec_from_rng},
    },
    group::Group,
    scalar_field::fq,
    shuffle_inputer::Inputer,
    shuffle_shuffler::Shuffler,
    tcp_channel::{connect_with_retry, listen_to},
    vole_triple::LPN21,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use circuit_psi::mac_n_cheese_vole::vole::VoleSizes;
use rand::{SeedableRng, rngs::StdRng};
use std::{
    net::TcpListener,
    thread,
};
use swanky_channel_legacy::AesRng;
type SenderMac = BeDOZaSender;
type ReceiverMac = BeDOZaReceiver;

fn make_base_voles(key: FE, count: usize, offset: u64) -> (Vec<SenderMac>, Vec<ReceiverMac>) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let idx = offset + i as u64;
        let x = fq(idx + 1);
        let beta = fq(3 * idx + 7);
        sender.push(BeDOZaSender::new(x, beta, false));
        receiver.push(BeDOZaReceiver::new(x * key + beta, key, false));
    }
    (sender, receiver)
}

fn run_step<T, F>(role: &str, step: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let out = f();
    match &out {
        Ok(_) => println!("[{}] {} passed", role, step),
        Err(e) => eprintln!("[{}] {} FAILED: {:#}", role, step, e),
    }
    out.with_context(|| format!("{} {}", role, step))
}

fn run_inputer(
    swanky_addr: String,
    tcp_addr: String,
    delta_0: FE,
    x_values: Vec<FE>,
    auth_sender_base: Vec<SenderMac>,
    auth_receiver_base: Vec<ReceiverMac>,
    k1_mul_sender_base: Vec<SenderMac>,
    k1_prime_mul_sender_base: Vec<SenderMac>,
) -> Result<Vec<Group>> {
    let mut channel =
        listen_to(&swanky_addr).with_context(|| format!("inputer listen swanky at {}", swanky_addr))?;
    let mut tcp_channel =
        listen_to(&tcp_addr).with_context(|| format!("inputer listen tcp at {}", tcp_addr))?;

    let mut vole_rng = AesRng::new();
    let mut auth_vole_sender = run_step("Inputer", "init_auth_vole_sender", || {
        BufferedVoleSender::init(&mut channel, LPN21)
            .map_err(|e| anyhow!("init sender VOLE failed: {}", e))
    })?;
    let mut auth_vole_receiver = run_step("Inputer", "init_auth_vole_receiver", || {
        BufferedVoleReceiver::init(
            &mut channel,
            -delta_0,
            LPN21,
        )
        .map_err(|e| anyhow!("init receiver VOLE failed: {}", e))
    })?;

    let inputer = Inputer::new(delta_0);
    let mut rng = rand::rng();
    let n = x_values.len();

    let (_k0, inputer_key_share) = run_step("Inputer", "step0", || {
        inputer.step0_sample_and_authenticate_oprf_key_share(
            &mut rng,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let mut k1_mul_vole_sender = run_step("Inputer", "init_k1_mul_vole_sender", || {
        BufferedVoleSender::init(&mut channel, LPN21)
            .map_err(|e| anyhow!("init k1-mul sender VOLE failed: {}", e))
    })?;
    let mut k1_prime_mul_vole_sender =
        run_step("Inputer", "init_k1_prime_mul_vole_sender", || {
            BufferedVoleSender::init(
                &mut channel,
                LPN21,
            )
            .map_err(|e| anyhow!("init k1'-mul sender VOLE failed: {}", e))
        })?;

    let authenticated_inputs = run_step("Inputer", "step1", || {
        inputer.step1_inputer_commits_inputs(&x_values, &mut auth_vole_sender, &mut channel)
    })?;

    let (random_values, authenticated_ri_sender) = run_step("Inputer", "step2", || {
        inputer.step2_inputer_commits_random_values(
            n,
            &mut rng,
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    let authenticated_r_x_plus_k0_sender = run_step("Inputer", "step3", || {
        inputer.step3_inputer_authenticates_r_times_x_plus_k0_and_proves(
            &authenticated_inputs,
            &random_values,
            &authenticated_ri_sender,
            &inputer_key_share,
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    let (_u_values, authenticated_u_sender, authenticated_v_receiver) =
        run_step("Inputer", "step4", || {
            inputer.step4_vole_share_x_times_k1_and_authenticate(
                &x_values,
                &mut auth_vole_sender,
                &mut auth_vole_receiver,
                &mut k1_mul_vole_sender,
                &mut channel,
            )
        })?;

    run_step("Inputer", "step5", || {
        inputer.step5_open_random_linear_combination_for_uv_consistency(
            &authenticated_inputs,
            &authenticated_u_sender,
            &mut channel,
        )
    })?;

    run_step("Inputer", "step6", || {
        inputer.step6_verify_authenticated_v_linear_combination_consistency(
            &authenticated_inputs,
            &authenticated_u_sender,
            &authenticated_v_receiver,
            inputer_key_share.bedoza_receiver(),
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut k1_prime_mul_vole_sender,
            &mut rng,
            &mut channel,
        )
    })?;

    let opened_r_x_plus_k0_plus_u_sender = run_step("Inputer", "step7", || {
        inputer.step7_open_ri_x_plus_k0_plus_ui(
            &authenticated_r_x_plus_k0_sender,
            &authenticated_u_sender,
            &mut channel,
        )
    })?;

    let authenticated_r_x_k_receiver = run_step("Inputer", "step8", || {
        inputer.step8_receive_reauthenticated_ri_x_plus_k_and_verify_consistency(
            &opened_r_x_plus_k0_plus_u_sender,
            &authenticated_v_receiver,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let authenticated_inverse_receiver = run_step("Inputer", "step9", || {
        inputer.step9_receive_authenticated_inverses_and_verify(
            &authenticated_r_x_k_receiver,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let g_ri = run_step("Inputer", "step10", || {
        inputer
            .step10_send_g_ri_and_pad_consistency_proof(&authenticated_ri_sender, &mut tcp_channel)
    })?;

    let _authenticated_pi_receiver = run_step("Inputer", "step11", || {
        inputer.step11_receive_authenticated_permutation_values(
            n,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let (x_challenge, authenticated_x_powers_receiver) = run_step("Inputer", "step12", || {
        inputer.step12_send_challenge_and_receive_authenticated_x_powers(
            n,
            &mut rng,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let (_authenticated_permuted_inverse_receiver, _authenticated_products_receiver) =
        run_step("Inputer", "step13", || {
            inputer.step13_receive_authenticated_xpi_times_inverse_and_verify(
                &authenticated_x_powers_receiver,
                &mut auth_vole_receiver,
                &mut channel,
            )
        })?;

    run_step("Inputer", "step14", || {
        inputer.step14_sample_challenges_and_verify_shuffle_product_identity(
            n,
            &mut rng,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let shuffled_oprf = run_step("Inputer", "step15", || {
        inputer.step15_receive_shuffled_oprf_points(n, &mut tcp_channel)
    })?;

    let opened_left_product = run_step("Inputer", "step16", || {
        inputer.step16_receive_and_verify_left_oprf_product(
            &g_ri,
            &authenticated_inverse_receiver,
            x_challenge,
            &mut tcp_channel,
        )
    })?;

    let opened_right_product = run_step("Inputer", "step17", || {
        inputer.step17_receive_and_verify_right_oprf_product(
            &shuffled_oprf,
            &authenticated_x_powers_receiver,
            &mut tcp_channel,
        )
    })?;

    run_step("Inputer", "step18", || {
        inputer
            .step18_verify_opened_oprf_products_match(&opened_left_product, &opened_right_product)
    })?;

    Ok(shuffled_oprf)
}

fn run_shuffler(
    swanky_addr: String,
    tcp_addr: String,
    delta_1: FE,
    permutation: Vec<usize>,
    k1_prime: FE,
    auth_sender_base: Vec<SenderMac>,
    auth_receiver_base: Vec<ReceiverMac>,
    k1_mul_receiver_base: Vec<ReceiverMac>,
    k1_prime_mul_receiver_base: Vec<ReceiverMac>,
    shuffler_rng_seed: [u8; 32],
) -> Result<Vec<Group>> {
    let mut channel =
        connect_with_retry(&swanky_addr).with_context(|| format!("shuffler connect swanky {}", swanky_addr))?;
    let mut tcp_channel =
        connect_with_retry(&tcp_addr).with_context(|| format!("shuffler connect tcp {}", tcp_addr))?;

    let mut vole_rng = AesRng::new();
    let mut auth_vole_receiver = run_step("Shuffler", "init_auth_vole_receiver", || {
        BufferedVoleReceiver::init(
            &mut channel,
            -delta_1,
            LPN21,
        )
        .map_err(|e| anyhow!("init receiver VOLE failed: {}", e))
    })?;
    let mut auth_vole_sender = run_step("Shuffler", "init_auth_vole_sender", || {
        BufferedVoleSender::init(&mut channel, LPN21)
            .map_err(|e| anyhow!("init sender VOLE failed: {}", e))
    })?;

    let shuffler = Shuffler::new(delta_1);
    let mut rng = StdRng::from_seed(shuffler_rng_seed);
    let n = permutation.len();

    let (k1, shuffler_key_share) = run_step("Shuffler", "step0", || {
        shuffler.step0_sample_and_authenticate_oprf_key_share(
            &mut rng,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let mut k1_mul_vole_receiver = run_step("Shuffler", "init_k1_mul_vole_receiver", || {
        BufferedVoleReceiver::init(
            &mut channel,
            -k1,
            LPN21,
        )
        .map_err(|e| anyhow!("init k1-mul receiver VOLE failed: {}", e))
    })?;
    let mut k1_prime_mul_vole_receiver =
        run_step("Shuffler", "init_k1_prime_mul_vole_receiver", || {
            BufferedVoleReceiver::init(
                &mut channel,
                -k1_prime,
                LPN21,
            )
            .map_err(|e| anyhow!("init k1'-mul receiver VOLE failed: {}", e))
        })?;

    let authenticated_inputs = run_step("Shuffler", "step1", || {
        shuffler.step1_inputer_commits_inputs(n, &mut auth_vole_receiver, &mut channel)
    })?;

    let authenticated_ri_receiver = run_step("Shuffler", "step2", || {
        shuffler.step2_inputer_commits_random_values(n, &mut auth_vole_receiver, &mut channel)
    })?;

    let authenticated_r_x_plus_k0_receiver = run_step("Shuffler", "step3", || {
        shuffler.step3_inputer_authenticates_r_times_x_plus_k0_and_proves(
            &authenticated_inputs,
            &authenticated_ri_receiver,
            &shuffler_key_share,
            &mut auth_vole_receiver,
            &mut channel,
        )
    })?;

    let (v_values, authenticated_u_receiver, authenticated_v_sender) =
        run_step("Shuffler", "step4", || {
            shuffler.step4_vole_share_x_times_k1_and_authenticate(
                n,
                &mut auth_vole_receiver,
                &mut auth_vole_sender,
                &mut k1_mul_vole_receiver,
                &mut channel,
            )
        })?;

    run_step("Shuffler", "step5", || {
        shuffler.step5_verify_random_linear_combination_for_uv_consistency(
            &authenticated_inputs,
            &authenticated_u_receiver,
            &v_values,
            k1,
            &mut channel,
        )
    })?;

    run_step("Shuffler", "step6", || {
        shuffler.step6_prove_authenticated_v_linear_combination_consistency(
            &authenticated_inputs,
            &authenticated_u_receiver,
            &authenticated_v_sender,
            shuffler_key_share.bedoza_sender(),
            k1_prime,
            &mut auth_vole_receiver,
            &mut auth_vole_sender,
            &mut k1_prime_mul_vole_receiver,
            &mut channel,
        )
    })?;

    let r_x_k_values = run_step("Shuffler", "step7", || {
        shuffler.step7_receive_ri_x_plus_k0_plus_ui_and_reconstruct_ri_x_plus_k(
            &authenticated_r_x_plus_k0_receiver,
            &authenticated_u_receiver,
            &v_values,
            &mut channel,
        )
    })?;

    let authenticated_r_x_k_sender = run_step("Shuffler", "step8", || {
        shuffler.step8_reauthenticate_ri_x_plus_k_and_prove_consistency(
            &r_x_k_values,
            &authenticated_v_sender,
            &mut auth_vole_sender,
            &mut rng,
            &mut channel,
        )
    })?;

    let (inverse_values, authenticated_inverse_sender) = run_step("Shuffler", "step9", || {
        shuffler.step9_authenticate_inverses_and_prove(
            &authenticated_r_x_k_sender,
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    let g_ri = run_step("Shuffler", "step10", || {
        shuffler.step10_receive_g_ri_and_verify_pad_consistency(
            &authenticated_ri_receiver,
            &mut tcp_channel,
        )
    })?;

    let authenticated_pi_sender = run_step("Shuffler", "step11", || {
        shuffler.step11_authenticate_permutation_values(
            &permutation,
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    let (x_challenge, _permuted_x_powers, authenticated_x_powers_sender) =
        run_step("Shuffler", "step12", || {
            shuffler.step12_receive_challenge_and_authenticate_x_powers(
                &permutation,
                &mut auth_vole_sender,
                &mut channel,
            )
        })?;

    let (
        _permuted_inverse_values,
        _product_values,
        _authenticated_permuted_inverse_sender,
        authenticated_products_sender,
    ) = run_step("Shuffler", "step13", || {
        shuffler.step13_authenticate_xpi_times_inverse_and_prove(
            &permutation,
            &authenticated_x_powers_sender,
            &authenticated_inverse_sender,
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    run_step("Shuffler", "step14", || {
        shuffler.step14_prove_shuffle_product_identity(
            x_challenge,
            &authenticated_pi_sender,
            &authenticated_products_sender,
            &authenticated_inverse_sender,
            &authenticated_x_powers_sender,
            &mut auth_vole_sender,
            &mut channel,
        )
    })?;

    let shuffled_oprf = run_step("Shuffler", "step15", || {
        shuffler.step15_send_shuffled_oprf_points(
            &permutation,
            &g_ri,
            &inverse_values,
            &mut tcp_channel,
        )
    })?;

    let opened_left_product = run_step("Shuffler", "step16", || {
        shuffler.step16_open_left_oprf_product_and_pad_proof(
            &g_ri,
            &authenticated_inverse_sender,
            x_challenge,
            &mut tcp_channel,
        )
    })?;

    let opened_right_product = run_step("Shuffler", "step17", || {
        shuffler.step17_open_right_oprf_product_and_pad_proof(
            &shuffled_oprf,
            &authenticated_x_powers_sender,
            &mut tcp_channel,
        )
    })?;

    run_step("Shuffler", "step18", || {
        shuffler
            .step18_verify_opened_oprf_products_match(&opened_left_product, &opened_right_product)
    })?;

    Ok(shuffled_oprf)
}

fn main() -> Result<()> {
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    ensure!(n > 0, "set size n must be > 0");

    let delta_0 = fq(97);
    let delta_1 = fq(131);
    let k1_prime = fq(193);
    let shuffler_rng_seed = [42u8; 32];
    let mut k1_preview_rng = StdRng::from_seed(shuffler_rng_seed);
    let k1_preview = random_fe_vec_from_rng(&mut k1_preview_rng, 1)?[0];

    let x_values: Vec<FE> = (0..n).map(|i| fq((i as u64) + 11)).collect();
    let permutation: Vec<usize> = (0..n).rev().collect();

    let sizes = VoleSizes::of::<FE, FE>();
    let (inputer_auth_sender_base, shuffler_auth_receiver_base) =
        make_base_voles(delta_1, sizes.base_voles_needed, 10_000);
    let (shuffler_auth_sender_base, inputer_auth_receiver_base) =
        make_base_voles(delta_0, sizes.base_voles_needed, 1_000_000);
    let (inputer_k1_mul_sender_base, shuffler_k1_mul_receiver_base) =
        make_base_voles(k1_preview, sizes.base_voles_needed, 2_000_000);
    let (inputer_k1_prime_mul_sender_base, shuffler_k1_prime_mul_receiver_base) =
        make_base_voles(k1_prime, sizes.base_voles_needed, 3_000_000);

    let swanky_listener = TcpListener::bind("127.0.0.1:0").context("bind swanky listener")?;
    let swanky_addr = swanky_listener
        .local_addr()
        .context("read swanky listener address")?
        .to_string();
    drop(swanky_listener);
    let tcp_listener = TcpListener::bind("127.0.0.1:0").context("bind tcp listener")?;
    let tcp_addr = tcp_listener
        .local_addr()
        .context("read tcp listener address")?
        .to_string();
    drop(tcp_listener);

    let inputer_swanky_addr = swanky_addr.clone();
    let inputer_tcp_addr = tcp_addr.clone();
    let inputer_handle = thread::spawn(move || {
        run_inputer(
            inputer_swanky_addr,
            inputer_tcp_addr,
            delta_0,
            x_values,
            inputer_auth_sender_base,
            inputer_auth_receiver_base,
            inputer_k1_mul_sender_base,
            inputer_k1_prime_mul_sender_base,
        )
    });

    let shuffler_handle = thread::spawn(move || {
        run_shuffler(
            swanky_addr,
            tcp_addr,
            delta_1,
            permutation,
            k1_prime,
            shuffler_auth_sender_base,
            shuffler_auth_receiver_base,
            shuffler_k1_mul_receiver_base,
            shuffler_k1_prime_mul_receiver_base,
            shuffler_rng_seed,
        )
    });

    let inputer_output = inputer_handle
        .join()
        .map_err(|_| anyhow!("inputer thread panicked"))??;
    let shuffler_output = shuffler_handle
        .join()
        .map_err(|_| anyhow!("shuffler thread panicked"))??;

    ensure!(
        inputer_output.len() == shuffler_output.len(),
        "output length mismatch: inputer={} shuffler={}",
        inputer_output.len(),
        shuffler_output.len()
    );
    for (i, (lhs, rhs)) in inputer_output
        .iter()
        .zip(shuffler_output.iter())
        .enumerate()
    {
        ensure!(lhs == rhs, "output mismatch at index {}", i);
    }

    println!(
        "all steps passed for n={} and outputs match on both parties",
        n
    );
    Ok(())
}
