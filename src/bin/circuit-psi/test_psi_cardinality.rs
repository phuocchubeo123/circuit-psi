use circuit_psi::{
    circuit_psi::psi_cardinality::{PsiCardinalityReceiver, PsiCardinalitySender},
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
    utils::sets::sample_correlated_sets,
};
use clap::{Parser, ValueEnum};
use rand::{RngExt, SeedableRng, rngs::StdRng};
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

fn sample_local_protocol_rng(rng: &mut impl rand::Rng) -> StdRng {
    let mut protocol_seed = [0u8; 32];
    rng.fill(&mut protocol_seed);
    StdRng::from_seed(protocol_seed)
}

fn cardinality(values_a: &[FE], values_b: &[FE]) -> usize {
    let set_a: HashSet<[u8; 32]> = values_a.iter().map(FE::to_bytes_le).collect();
    let set_b: HashSet<[u8; 32]> = values_b.iter().map(FE::to_bytes_le).collect();
    set_a.intersection(&set_b).count()
}

fn sender_party(addr: &str, args: Args) -> eyre::Result<PartyRun> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{e}"))?;

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

    // Count only PSI-cardinality protocol work (init/run), excluding setup.
    let start = Instant::now();
    let bytes_sent_before = channel.bytes_sent();
    let bytes_received_before = channel.bytes_received();

    let mut psi = PsiCardinalitySender::new(fq(97), fq(173), &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize PSI cardinality: {e}"))?;
    let mut protocol_rng = sample_local_protocol_rng(&mut seed_rng);
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
        bytes_sent: channel.bytes_sent().saturating_sub(bytes_sent_before),
        bytes_received: channel.bytes_received().saturating_sub(bytes_received_before),
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn receiver_party(addr: &str, args: Args) -> eyre::Result<PartyRun> {
    let mut channel = connect_with_retry(addr).map_err(|e| eyre::eyre!("{e}"))?;
    let mut local_rng = rand::rng();

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

    // Count only PSI-cardinality protocol work (init/run), excluding setup.
    let start = Instant::now();
    let bytes_sent_before = channel.bytes_sent();
    let bytes_received_before = channel.bytes_received();

    let mut psi = PsiCardinalityReceiver::new(fq(131), fq(149), &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize PSI cardinality: {e}"))?;
    let mut protocol_rng = sample_local_protocol_rng(&mut local_rng);
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
        bytes_sent: channel.bytes_sent().saturating_sub(bytes_sent_before),
        bytes_received: channel.bytes_received().saturating_sub(bytes_received_before),
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
