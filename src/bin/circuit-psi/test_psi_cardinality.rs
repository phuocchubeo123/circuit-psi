use circuit_psi::{
    circuit_psi::psi_cardinality::{PsiCardinalityReceiver, PsiCardinalitySender},
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
};
use clap::{Parser, ValueEnum};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, time::Instant};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Side {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "test_psi_cardinality")]
struct Args {
    #[arg(long, value_enum)]
    side: Side,
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
    #[arg(long, default_value_t = 23000)]
    port: u16,
    #[arg(long, default_value_t = 256)]
    set_size: usize,
    #[arg(long, default_value_t = 64)]
    intersection_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct PartyRun {
    side: Side,
    cardinality: usize,
    bytes_sent: u64,
    bytes_received: u64,
    elapsed_ms: u128,
}

fn socket_addr(args: &Args) -> String {
    format!("{}:{}", args.addr, args.port)
}

fn derive_seed(shared_seed: [u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_seed);
    hasher.update(label);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sample_unique_values(rng: &mut StdRng, count: usize, seen: &mut HashSet<[u8; 32]>) -> Vec<FE> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        if !seen.insert(bytes) {
            continue;
        }
        out.push(FE::from_bytes_le_mod_order(&bytes));
    }
    out
}

fn shuffle_values(rng: &mut StdRng, values: &mut [FE]) {
    for i in (1..values.len()).rev() {
        let j = rng.random_range(0..=i);
        values.swap(i, j);
    }
}

fn sample_correlated_sets(
    shared_seed: [u8; 32],
    set_size: usize,
    intersection_size: usize,
) -> eyre::Result<(Vec<FE>, Vec<FE>)> {
    eyre::ensure!(set_size > 0, "set size must be > 0");
    eyre::ensure!(
        intersection_size <= set_size,
        "intersection size {} exceeds set size {}",
        intersection_size,
        set_size
    );

    let mut seen = HashSet::with_capacity(2 * set_size - intersection_size);

    let mut common_rng = StdRng::from_seed(derive_seed(shared_seed, b"common-set"));
    let common = sample_unique_values(&mut common_rng, intersection_size, &mut seen);

    let mut sender_only_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-only-set"));
    let sender_only = sample_unique_values(
        &mut sender_only_rng,
        set_size - intersection_size,
        &mut seen,
    );

    let mut receiver_only_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-only-set"));
    let receiver_only = sample_unique_values(
        &mut receiver_only_rng,
        set_size - intersection_size,
        &mut seen,
    );

    let mut sender_set = common.clone();
    sender_set.extend(sender_only);
    let mut receiver_set = common;
    receiver_set.extend(receiver_only);

    let mut sender_shuffle_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-shuffle"));
    shuffle_values(&mut sender_shuffle_rng, &mut sender_set);

    let mut receiver_shuffle_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-shuffle"));
    shuffle_values(&mut receiver_shuffle_rng, &mut receiver_set);

    Ok((sender_set, receiver_set))
}

fn cardinality(values_a: &[FE], values_b: &[FE]) -> usize {
    let set_a: HashSet<[u8; 32]> = values_a.iter().map(FE::to_bytes_le).collect();
    let set_b: HashSet<[u8; 32]> = values_b.iter().map(FE::to_bytes_le).collect();
    set_a.intersection(&set_b).count()
}

fn sender_party(addr: &str, args: Args) -> eyre::Result<PartyRun> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{e}"))?;
    let start = Instant::now();

    let mut seed_rng = rand::rng();
    let mut shared_seed = [0u8; 32];
    seed_rng.fill(&mut shared_seed);
    channel
        .send(&shared_seed)
        .map_err(|e| eyre::eyre!("sender failed to send shared seed: {e}"))?;

    let (sender_set, receiver_set) =
        sample_correlated_sets(shared_seed, args.set_size, args.intersection_size)?;
    let expected = cardinality(&sender_set, &receiver_set);
    eyre::ensure!(
        expected == args.intersection_size,
        "generated sender/receiver sets intersect at {}, expected {}",
        expected,
        args.intersection_size
    );

    let mut psi = PsiCardinalitySender::new(fq(97), fq(173), &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize PSI cardinality: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-protocol-rng"));
    let got = psi
        .run(&sender_set, &mut protocol_rng, &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to run PSI cardinality: {e}"))?;
    eyre::ensure!(
        got == expected,
        "sender observed cardinality {}, expected {}",
        got,
        expected
    );

    Ok(PartyRun {
        side: Side::Sender,
        cardinality: got,
        bytes_sent: channel.bytes_sent(),
        bytes_received: channel.bytes_received(),
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn receiver_party(addr: &str, args: Args) -> eyre::Result<PartyRun> {
    let mut channel = connect_with_retry(addr).map_err(|e| eyre::eyre!("{e}"))?;
    let start = Instant::now();

    let shared_seed_bytes = channel
        .receive()
        .map_err(|e| eyre::eyre!("receiver failed to receive shared seed: {e}"))?;
    eyre::ensure!(
        shared_seed_bytes.len() == 32,
        "expected 32-byte shared seed, got {} bytes",
        shared_seed_bytes.len()
    );
    let mut shared_seed = [0u8; 32];
    shared_seed.copy_from_slice(&shared_seed_bytes);

    let (sender_set, receiver_set) =
        sample_correlated_sets(shared_seed, args.set_size, args.intersection_size)?;
    let expected = cardinality(&sender_set, &receiver_set);
    eyre::ensure!(
        expected == args.intersection_size,
        "generated sender/receiver sets intersect at {}, expected {}",
        expected,
        args.intersection_size
    );

    let mut psi = PsiCardinalityReceiver::new(fq(131), fq(149), &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize PSI cardinality: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-protocol-rng"));
    let got = psi
        .run(&receiver_set, &mut protocol_rng, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to run PSI cardinality: {e}"))?;
    eyre::ensure!(
        got == expected,
        "receiver observed cardinality {}, expected {}",
        got,
        expected
    );

    Ok(PartyRun {
        side: Side::Receiver,
        cardinality: got,
        bytes_sent: channel.bytes_sent(),
        bytes_received: channel.bytes_received(),
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    eyre::ensure!(args.set_size > 0, "set size must be > 0");
    eyre::ensure!(
        args.intersection_size <= args.set_size,
        "intersection size {} exceeds set size {}",
        args.intersection_size,
        args.set_size
    );

    let addr = socket_addr(&args);
    let run = match args.side {
        Side::Sender => sender_party(&addr, args.clone())?,
        Side::Receiver => receiver_party(&addr, args.clone())?,
    };

    eyre::ensure!(
        run.cardinality == args.intersection_size,
        "{:?} output {} does not match expected {}",
        run.side,
        run.cardinality,
        args.intersection_size
    );

    println!(
        "psi_cardinality_ok side={:?} addr={} set_size={} intersection_size={} cardinality={}",
        run.side, addr, args.set_size, args.intersection_size, run.cardinality
    );
    println!(
        "timing_ms={} bytes_sent={} bytes_received={}",
        run.elapsed_ms, run.bytes_sent, run.bytes_received
    );

    Ok(())
}
