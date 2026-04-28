use circuit_psi::{
    bedoza::BeDOZaTriple,
    circuit_psi::one_side_psu::{OneSidePsuReceiver, OneSidePsuSender},
    math::defines::FE,
    tcp_channel::{connect_with_retry, listen_to},
    utils::{
        bedoza_csv::{read_fe_txt, read_triples_csv},
        sets::sample_correlated_sets,
    },
};
use clap::{Parser, ValueEnum};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::{collections::HashSet, path::PathBuf, time::Instant};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Side {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "test_one_side_psu")]
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
    #[arg(long)]
    triples_csv: PathBuf,
    #[arg(long)]
    delta_txt: PathBuf,
}

#[derive(Debug, Clone)]
struct PartyRun {
    side: Side,
    sender_difference_size: usize,
    union_size: usize,
    bytes_sent: u64,
    bytes_received: u64,
    elapsed_ms: u128,
}

fn socket_addr(args: &Args) -> String {
    format!("{}:{}", args.addr, args.port)
}

fn sample_local_key(rng: &mut impl rand::Rng) -> FE {
    let mut key_seed = [0u8; 32];
    rng.fill(&mut key_seed);
    FE::from_bytes_le_mod_order(&key_seed)
}

fn sample_local_protocol_rng(rng: &mut impl rand::Rng) -> StdRng {
    let mut protocol_seed = [0u8; 32];
    rng.fill(&mut protocol_seed);
    StdRng::from_seed(protocol_seed)
}

fn expected_sender_difference(sender_set: &[FE], receiver_set: &[FE]) -> Vec<FE> {
    let receiver_membership: HashSet<[u8; 32]> = receiver_set.iter().map(FE::to_bytes_le).collect();
    sender_set
        .iter()
        .copied()
        .filter(|value| !receiver_membership.contains(&value.to_bytes_le()))
        .collect()
}

fn expected_union(sender_set: &[FE], receiver_set: &[FE]) -> HashSet<[u8; 32]> {
    sender_set
        .iter()
        .chain(receiver_set.iter())
        .map(FE::to_bytes_le)
        .collect()
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
    let expected_difference = expected_sender_difference(&sender_set, &receiver_set);
    let expected_union = expected_union(&sender_set, &receiver_set);

    let delta = read_fe_txt(&args.delta_txt, "delta")?;
    let k0 = sample_local_key(&mut seed_rng);
    let sender_triples_all = read_triples_csv(&args.triples_csv)?;
    eyre::ensure!(
        sender_triples_all.len() >= sender_set.len(),
        "sender set size {} exceeds prepared triple count {}",
        sender_set.len(),
        sender_triples_all.len()
    );
    let sender_triples: &[BeDOZaTriple] = &sender_triples_all[..sender_set.len()];

    let start = Instant::now();
    let bytes_sent_before = channel.bytes_sent();
    let bytes_received_before = channel.bytes_received();
    let mut one_side_psu = OneSidePsuSender::new(delta, k0, &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize one_side_psu: {e}"))?;
    let mut protocol_rng = sample_local_protocol_rng(&mut seed_rng);
    one_side_psu
        .run_and_open(
            &sender_set,
            sender_triples,
            &mut protocol_rng,
            &mut channel,
        )
        .map_err(|e| eyre::eyre!("sender failed to run one_side_psu: {e}"))?;

    Ok(PartyRun {
        side: Side::Sender,
        sender_difference_size: expected_difference.len(),
        union_size: expected_union.len(),
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
    let expected_difference = expected_sender_difference(&sender_set, &receiver_set);
    let expected_union = expected_union(&sender_set, &receiver_set);

    let delta = read_fe_txt(&args.delta_txt, "delta")?;
    let k1 = sample_local_key(&mut local_rng);
    let receiver_triples_all = read_triples_csv(&args.triples_csv)?;
    eyre::ensure!(
        receiver_triples_all.len() >= sender_set.len(),
        "receiver set size {} exceeds prepared triple count {}",
        sender_set.len(),
        receiver_triples_all.len()
    );
    let receiver_triples: &[BeDOZaTriple] = &receiver_triples_all[..sender_set.len()];

    let start = Instant::now();
    let bytes_sent_before = channel.bytes_sent();
    let bytes_received_before = channel.bytes_received();
    let mut one_side_psu = OneSidePsuReceiver::new(delta, k1, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize one_side_psu: {e}"))?;
    let mut protocol_rng = sample_local_protocol_rng(&mut local_rng);
    let sender_difference = one_side_psu
        .run_and_open(
            &receiver_set,
            receiver_triples,
            &mut protocol_rng,
            &mut channel,
        )
        .map_err(|e| eyre::eyre!("receiver failed to run one_side_psu: {e}"))?;
    eyre::ensure!(
        sender_difference == expected_difference,
        "receiver observed sender difference mismatch: got {} values, expected {}",
        sender_difference.len(),
        expected_difference.len()
    );

    let union: HashSet<[u8; 32]> = receiver_set
        .iter()
        .chain(sender_difference.iter())
        .map(FE::to_bytes_le)
        .collect();
    eyre::ensure!(
        union == expected_union,
        "receiver-side reconstructed union size {} does not match expected {}",
        union.len(),
        expected_union.len()
    );

    Ok(PartyRun {
        side: Side::Receiver,
        sender_difference_size: sender_difference.len(),
        union_size: union.len(),
        bytes_sent: channel.bytes_sent().saturating_sub(bytes_sent_before),
        bytes_received: channel.bytes_received().saturating_sub(bytes_received_before),
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    eyre::ensure!(args.set_size > 1, "set size must be > 1");
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

    println!(
        "one_side_psu_ok side={:?} addr={} set_size={} intersection_size={} sender_difference_size={} union_size={}",
        run.side,
        addr,
        args.set_size,
        args.intersection_size,
        run.sender_difference_size,
        run.union_size
    );
    println!(
        "timing_ms={} bytes_sent={} bytes_received={}",
        run.elapsed_ms, run.bytes_sent, run.bytes_received
    );

    Ok(())
}
