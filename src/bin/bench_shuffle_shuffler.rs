use anyhow::{Context, Result, ensure};
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

fn main() -> Result<()> {
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    ensure!(n > 0, "set size n must be > 0");

    let delta_0 = fq(97);
    let delta_1 = fq(131);
    let k1_prime = fq(193);

    // Must match the first sampled value from protocol RNG in step0.
    let mut preview_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);
    let k1_preview = random_fe_vec_from_rng(&mut preview_rng, 1)?[0];

    let sizes = VoleSizes::of::<FE, FE>();
    let (_, auth_receiver_base) = make_base_voles(delta_1, sizes.base_voles_needed, 10_000);
    let (auth_sender_base, _) = make_base_voles(delta_0, sizes.base_voles_needed, 1_000_000);
    let (_, k1_mul_receiver_base) = make_base_voles(k1_preview, sizes.base_voles_needed, 2_000_000);
    let (_, k1_prime_mul_receiver_base) =
        make_base_voles(k1_prime, sizes.base_voles_needed, 3_000_000);

    let mut swanky = listen_swanky(SWANKY_ADDR).context("listen swanky channel")?;
    let mut tcp = listen_to(TCP_ADDR).context("listen tcp channel")?;

    // Init order must match inputer counterpart exactly.
    let mut vole_rng = AesRng::new();
    let mut auth_vole_receiver = BufferedVoleReceiver::<FourQVoleMac>::init(
        &mut swanky,
        &mut vole_rng,
        -delta_1,
        auth_receiver_base,
    )
    .map_err(|e| anyhow::anyhow!("init auth receiver VOLE failed: {}", e))?;
    let mut auth_vole_sender =
        BufferedVoleSender::<FourQVoleMac>::init(&mut swanky, &mut vole_rng, auth_sender_base)
            .map_err(|e| anyhow::anyhow!("init auth sender VOLE failed: {}", e))?;

    // k1 is sampled inside step0 using this deterministic RNG.
    let mut protocol_rng = StdRng::from_seed(SHUFFLER_RNG_SEED);

    let mut k1_mul_vole_receiver = BufferedVoleReceiver::<FourQVoleMac>::init(
        &mut swanky,
        &mut vole_rng,
        -k1_preview,
        k1_mul_receiver_base,
    )
    .map_err(|e| anyhow::anyhow!("init k1 mul receiver VOLE failed: {}", e))?;
    let mut k1_prime_mul_vole_receiver = BufferedVoleReceiver::<FourQVoleMac>::init(
        &mut swanky,
        &mut vole_rng,
        -k1_prime,
        k1_prime_mul_receiver_base,
    )
    .map_err(|e| anyhow::anyhow!("init k1' mul receiver VOLE failed: {}", e))?;

    let mut perm_rng = rand::rng();
    let t_perm_start = Instant::now();
    let permutation = random_permutation(n, &mut perm_rng);
    let t_perm = t_perm_start.elapsed();

    let shuffler = Shuffler::new(delta_1);
    let t_proto_start = Instant::now();
    let shuffled = shuffler.run_full_shuffled_oprf(
        &permutation,
        k1_prime,
        &mut protocol_rng,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        &mut k1_mul_vole_receiver,
        &mut k1_prime_mul_vole_receiver,
        &mut swanky,
        &mut tcp,
    )?;
    let t_proto = t_proto_start.elapsed();

    println!("role=shuffler n={}", n);
    println!(
        "timing_ms permutation_generation={} protocol_total={}",
        t_perm.as_millis(),
        t_proto.as_millis()
    );
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
