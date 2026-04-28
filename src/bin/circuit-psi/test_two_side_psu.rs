use circuit_psi::{
    bedoza::BeDOZaTriple,
    circuit_psi::two_side_psu::{TwoSidePsuReceiver, TwoSidePsuSender},
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
#[command(name = "test_two_side_psu")]
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
    receiver_difference_size: usize,
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

fn expected_receiver_difference(sender_set: &[FE], receiver_set: &[FE]) -> Vec<FE> {
    let sender_membership: HashSet<[u8; 32]> = sender_set.iter().map(FE::to_bytes_le).collect();
    receiver_set
        .iter()
        .copied()
        .filter(|value| !sender_membership.contains(&value.to_bytes_le()))
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
    let expected_sender_difference = expected_sender_difference(&sender_set, &receiver_set);
    let expected_receiver_difference = expected_receiver_difference(&sender_set, &receiver_set);
    let expected_union = expected_union(&sender_set, &receiver_set);

    let delta = read_fe_txt(&args.delta_txt, "delta")?;
    let k0 = sample_local_key(&mut seed_rng);
    let sender_triples_all = read_triples_csv(&args.triples_csv)?;
    let required_triples = sender_set.len() * 2;
    eyre::ensure!(
        sender_triples_all.len() >= required_triples,
        "sender requires {} triples (2 * set_size), but csv only has {}",
        required_triples,
        sender_triples_all.len()
    );
    let sender_sender_only_triples: &[BeDOZaTriple] = &sender_triples_all[..sender_set.len()];
    let sender_receiver_only_triples: &[BeDOZaTriple] =
        &sender_triples_all[sender_set.len()..required_triples];

    let start = Instant::now();
    let bytes_sent_before = channel.bytes_sent();
    let bytes_received_before = channel.bytes_received();
    let mut two_side_psu = TwoSidePsuSender::new(delta, k0, &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize two_side_psu: {e}"))?;
    let mut protocol_rng = sample_local_protocol_rng(&mut seed_rng);
    let receiver_difference = two_side_psu
        .run_and_open(
            &sender_set,
            sender_sender_only_triples,
            sender_receiver_only_triples,
            &mut protocol_rng,
            &mut channel,
        )
        .map_err(|e| eyre::eyre!("sender failed to run two_side_psu: {e}"))?;
    eyre::ensure!(
        receiver_difference == expected_receiver_difference,
        "sender observed receiver difference mismatch: got {} values, expected {}",
        receiver_difference.len(),
        expected_receiver_difference.len()
    );

    let union: HashSet<[u8; 32]> = sender_set
        .iter()
        .chain(receiver_difference.iter())
        .map(FE::to_bytes_le)
        .collect();
    eyre::ensure!(
        union == expected_union,
        "sender-side reconstructed union size {} does not match expected {}",
        union.len(),
        expected_union.len()
    );

    Ok(PartyRun {
        side: Side::Sender,
        sender_difference_size: expected_sender_difference.len(),
        receiver_difference_size: receiver_difference.len(),
        union_size: union.len(),
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
    let expected_sender_difference = expected_sender_difference(&sender_set, &receiver_set);
    let expected_receiver_difference = expected_receiver_difference(&sender_set, &receiver_set);
    let expected_union = expected_union(&sender_set, &receiver_set);

    let delta = read_fe_txt(&args.delta_txt, "delta")?;
    let k1 = sample_local_key(&mut local_rng);
    let receiver_triples_all = read_triples_csv(&args.triples_csv)?;
    let required_triples = sender_set.len() * 2;
    eyre::ensure!(
        receiver_triples_all.len() >= required_triples,
        "receiver requires {} triples (2 * set_size), but csv only has {}",
        required_triples,
        receiver_triples_all.len()
    );
    let receiver_sender_only_triples: &[BeDOZaTriple] = &receiver_triples_all[..sender_set.len()];
    let receiver_receiver_only_triples: &[BeDOZaTriple] =
        &receiver_triples_all[sender_set.len()..required_triples];

    let start = Instant::now();
    let bytes_sent_before = channel.bytes_sent();
    let bytes_received_before = channel.bytes_received();
    let mut two_side_psu = TwoSidePsuReceiver::new(delta, k1, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize two_side_psu: {e}"))?;
    let mut protocol_rng = sample_local_protocol_rng(&mut local_rng);
    let sender_difference = two_side_psu
        .run_and_open(
            &receiver_set,
            receiver_sender_only_triples,
            receiver_receiver_only_triples,
            &mut protocol_rng,
            &mut channel,
        )
        .map_err(|e| eyre::eyre!("receiver failed to run two_side_psu: {e}"))?;
    eyre::ensure!(
        sender_difference == expected_sender_difference,
        "receiver observed sender difference mismatch: got {} values, expected {}",
        sender_difference.len(),
        expected_sender_difference.len()
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
        receiver_difference_size: expected_receiver_difference.len(),
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
        "two_side_psu_ok side={:?} addr={} set_size={} intersection_size={} sender_difference_size={} receiver_difference_size={} union_size={}",
        run.side,
        addr,
        args.set_size,
        args.intersection_size,
        run.sender_difference_size,
        run.receiver_difference_size,
        run.union_size
    );
    println!(
        "timing_ms={} bytes_sent={} bytes_received={}",
        run.elapsed_ms, run.bytes_sent, run.bytes_received
    );

    Ok(())
}
