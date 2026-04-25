use circuit_psi::{
    bedoza::{BeDOZa, BeDOZaTriple, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    circuit_psi::one_side_psu::{OneSidePsuReceiver, OneSidePsuSender},
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
    utils::sets::sample_correlated_sets,
};
use clap::{Parser, ValueEnum};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, time::Instant};

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

fn derive_seed(shared_seed: [u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_seed);
    hasher.update(label);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sample_fe<R: Rng>(rng: &mut R) -> FE {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    FE::from_bytes_le_mod_order(&bytes)
}

fn make_cross_party_share<R: Rng>(
    total_value: FE,
    delta0: FE,
    delta1: FE,
    rng: &mut R,
) -> (BeDOZa, BeDOZa) {
    let share0_value = sample_fe(rng);
    let share1_value = total_value - share0_value;
    let share0_pad = sample_fe(rng);
    let share1_pad = sample_fe(rng);

    let party0 = BeDOZa::new(
        BeDOZaSender::new(share0_value, share0_pad),
        BeDOZaReceiver::new(delta0 * share1_value - share1_pad, delta0),
        false,
    );
    let party1 = BeDOZa::new(
        BeDOZaSender::new(share1_value, share1_pad),
        BeDOZaReceiver::new(delta1 * share0_value - share0_pad, delta1),
        true,
    );

    (party0, party1)
}

fn generate_fake_triples<R: Rng>(
    n: usize,
    delta0: FE,
    delta1: FE,
    rng: &mut R,
) -> (Vec<BeDOZaTriple>, Vec<BeDOZaTriple>) {
    let mut side0 = Vec::with_capacity(n);
    let mut side1 = Vec::with_capacity(n);

    for _ in 0..n {
        let a = sample_fe(rng);
        let b = sample_fe(rng);
        let c = a * b;

        let (a0, a1) = make_cross_party_share(a, delta0, delta1, rng);
        let (b0, b1) = make_cross_party_share(b, delta0, delta1, rng);
        let (c0, c1) = make_cross_party_share(c, delta0, delta1, rng);

        side0.push((a0, b0, c0));
        side1.push((a1, b1, c1));
    }

    (side0, side1)
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
    let start = Instant::now();

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

    let mut triple_rng = StdRng::from_seed(derive_seed(shared_seed, b"fake-triples"));
    let (sender_triples, _) =
        generate_fake_triples(args.set_size, fq(97), fq(131), &mut triple_rng);

    let mut one_side_psu = OneSidePsuSender::new(fq(97), fq(173), &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize one_side_psu: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-protocol-rng"));
    one_side_psu
        .run(
            &sender_set,
            &sender_triples,
            &mut protocol_rng,
            &mut channel,
        )
        .map_err(|e| eyre::eyre!("sender failed to run one_side_psu: {e}"))?;

    Ok(PartyRun {
        side: Side::Sender,
        sender_difference_size: expected_difference.len(),
        union_size: expected_union.len(),
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
    let expected_difference = expected_sender_difference(&sender_set, &receiver_set);
    let expected_union = expected_union(&sender_set, &receiver_set);

    let mut triple_rng = StdRng::from_seed(derive_seed(shared_seed, b"fake-triples"));
    let (_, receiver_triples) =
        generate_fake_triples(args.set_size, fq(97), fq(131), &mut triple_rng);

    let mut one_side_psu = OneSidePsuReceiver::new(fq(131), fq(149), &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize one_side_psu: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-protocol-rng"));
    let opened_products = one_side_psu
        .run(
            &receiver_set,
            &receiver_triples,
            &mut protocol_rng,
            &mut channel,
        )
        .map_err(|e| eyre::eyre!("receiver failed to run one_side_psu: {e}"))?;
    // Zero products correspond to sender elements in the intersection, so filter them out.
    let sender_difference: Vec<FE> = opened_products
        .iter()
        .copied()
        .filter(|value| *value != FE::zero())
        .collect();
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
        bytes_sent: channel.bytes_sent(),
        bytes_received: channel.bytes_received(),
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
