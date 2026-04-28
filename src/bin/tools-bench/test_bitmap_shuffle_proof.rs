use circuit_psi::{
    circuit_psi::mq_rpmt::{prove_bitmap_shuffle, verify_bitmap_shuffle},
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use clap::{Parser, ValueEnum};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use std::time::Instant;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Side {
    Prover,
    Verifier,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "test_bitmap_shuffle_proof")]
struct Args {
    #[arg(long, value_enum)]
    side: Side,
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
    #[arg(long, default_value_t = 23010)]
    port: u16,
    #[arg(long, default_value_t = 512)]
    len: usize,
}

fn socket_addr(args: &Args) -> String {
    format!("{}:{}", args.addr, args.port)
}

fn random_permutation<R: Rng>(n: usize, rng: &mut R) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        perm.swap(i, j);
    }
    perm
}

fn sample_shuffle_instance(seed: [u8; 32], len: usize) -> (Vec<FE>, Vec<usize>, Vec<FE>) {
    let mut rng = StdRng::from_seed(seed);
    let original_bitmap: Vec<FE> = (0..len)
        .map(|_| {
            if rng.random::<bool>() {
                FE::one()
            } else {
                FE::zero()
            }
        })
        .collect();
    let permutation = random_permutation(len, &mut rng);
    let shuffled_bitmap: Vec<FE> = permutation
        .iter()
        .map(|&idx| original_bitmap[idx])
        .collect();
    (original_bitmap, permutation, shuffled_bitmap)
}

fn prover_party(addr: &str, len: usize) -> eyre::Result<()> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{e}"))?;
    let start = Instant::now();

    let mut bootstrap_rng = rand::rng();
    let mut shared_seed = [0u8; 32];
    bootstrap_rng.fill(&mut shared_seed);
    channel
        .send(&shared_seed)
        .map_err(|e| eyre::eyre!("prover failed to send shared seed: {e}"))?;

    let (original_bitmap, permutation, shuffled_bitmap) = sample_shuffle_instance(shared_seed, len);
    let permutation_fe: Vec<FE> = permutation
        .iter()
        .map(|&idx| FE::from(idx as u64))
        .collect();

    let mut auth_sender = BufferedVoleSender::init(&mut channel, LPN21)
        .map_err(|e| eyre::eyre!("prover failed to init auth VOLE sender: {e}"))?;

    let authenticated_original_bitmap = auth_sender
        .commit_auth(&mut channel, &original_bitmap)
        .map_err(|e| eyre::eyre!("prover failed to commit-auth original bitmap: {e}"))?;
    let authenticated_permutation = auth_sender
        .commit_auth(&mut channel, &permutation_fe)
        .map_err(|e| eyre::eyre!("prover failed to commit-auth permutation: {e}"))?;

    prove_bitmap_shuffle(
        &authenticated_original_bitmap,
        &authenticated_permutation,
        &shuffled_bitmap,
        &mut auth_sender,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("prove_bitmap_shuffle failed: {e}"))?;

    println!(
        "bitmap_shuffle_proof_ok side=prover len={} timing_ms={} bytes_sent={} bytes_received={}",
        len,
        start.elapsed().as_millis(),
        channel.bytes_sent(),
        channel.bytes_received()
    );
    Ok(())
}

fn verifier_party(addr: &str, len: usize) -> eyre::Result<()> {
    let mut channel = connect_with_retry(addr).map_err(|e| eyre::eyre!("{e}"))?;
    let start = Instant::now();

    let shared_seed_bytes = channel
        .receive()
        .map_err(|e| eyre::eyre!("verifier failed to receive shared seed: {e}"))?;
    eyre::ensure!(
        shared_seed_bytes.len() == 32,
        "expected 32-byte shared seed, got {} bytes",
        shared_seed_bytes.len()
    );
    let mut shared_seed = [0u8; 32];
    shared_seed.copy_from_slice(&shared_seed_bytes);

    let (_original_bitmap, _permutation, shuffled_bitmap) =
        sample_shuffle_instance(shared_seed, len);

    let mut auth_receiver = BufferedVoleReceiver::init(&mut channel, fq(97), LPN21)
        .map_err(|e| eyre::eyre!("verifier failed to init auth VOLE receiver: {e}"))?;

    let authenticated_original_bitmap = auth_receiver
        .commit_auth(&mut channel, len)
        .map_err(|e| eyre::eyre!("verifier failed to receive original bitmap auth shares: {e}"))?;
    let authenticated_permutation = auth_receiver
        .commit_auth(&mut channel, len)
        .map_err(|e| eyre::eyre!("verifier failed to receive permutation auth shares: {e}"))?;

    let mut challenge_rng = StdRng::from_seed(shared_seed);
    verify_bitmap_shuffle(
        &authenticated_original_bitmap,
        &authenticated_permutation,
        &shuffled_bitmap,
        &mut challenge_rng,
        &mut auth_receiver,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("verify_bitmap_shuffle failed: {e}"))?;

    println!(
        "bitmap_shuffle_proof_ok side=verifier len={} timing_ms={} bytes_sent={} bytes_received={}",
        len,
        start.elapsed().as_millis(),
        channel.bytes_sent(),
        channel.bytes_received()
    );
    Ok(())
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    eyre::ensure!(args.len > 1, "len must be > 1");

    let addr = socket_addr(&args);
    match args.side {
        Side::Prover => prover_party(&addr, args.len)?,
        Side::Verifier => verifier_party(&addr, args.len)?,
    }

    Ok(())
}
