use circuit_psi::{
    bedoza::{BeDOZa, BeDOZaTriple, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    circuit_psi::psi_sum::{PsiSumReceiver, PsiSumSender, open_psi_sum_receive, open_psi_sum_send},
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
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
#[command(name = "test_psi_sum")]
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
    opened_sum: FE,
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

fn fe_to_hex(value: FE) -> String {
    let bytes = value.to_bytes_le();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
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
    eyre::ensure!(set_size > 1, "set size must be > 1");
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
        BeDOZaSender::new(share0_value, share0_pad, false),
        BeDOZaReceiver::new(delta0 * share1_value - share1_pad, delta0, true),
    );
    let party1 = BeDOZa::new(
        BeDOZaSender::new(share1_value, share1_pad, true),
        BeDOZaReceiver::new(delta1 * share0_value - share0_pad, delta1, false),
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

fn expected_psi_sum(sender_set: &[FE], receiver_set: &[FE]) -> FE {
    let receiver_membership: HashSet<[u8; 32]> = receiver_set.iter().map(FE::to_bytes_le).collect();
    sender_set.iter().fold(FE::zero(), |acc, value| {
        if receiver_membership.contains(&value.to_bytes_le()) {
            acc + *value
        } else {
            acc
        }
    })
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
    let expected = expected_psi_sum(&sender_set, &receiver_set);

    let mut triple_rng = StdRng::from_seed(derive_seed(shared_seed, b"fake-triples"));
    let (sender_triples, _) = generate_fake_triples(args.set_size, fq(97), fq(131), &mut triple_rng);

    let mut psi_sum = PsiSumSender::new(fq(97), fq(173), &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize psi_sum: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-protocol-rng"));
    let sum_share = psi_sum
        .run(&sender_set, &sender_triples, &mut protocol_rng, &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to run psi_sum: {e}"))?;

    let opened_sum = open_psi_sum_receive(&sum_share, &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to receive opened psi_sum: {e}"))?;
    eyre::ensure!(
        opened_sum == expected,
        "sender observed psi_sum {}, expected {}",
        fe_to_hex(opened_sum),
        fe_to_hex(expected)
    );

    Ok(PartyRun {
        side: Side::Sender,
        opened_sum,
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
    let expected = expected_psi_sum(&sender_set, &receiver_set);

    let mut triple_rng = StdRng::from_seed(derive_seed(shared_seed, b"fake-triples"));
    let (_, receiver_triples) =
        generate_fake_triples(args.set_size, fq(97), fq(131), &mut triple_rng);

    let mut psi_sum = PsiSumReceiver::new(fq(131), fq(149), &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize psi_sum: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-protocol-rng"));
    let sum_share = psi_sum
        .run(&receiver_set, &receiver_triples, &mut protocol_rng, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to run psi_sum: {e}"))?;

    open_psi_sum_send(&sum_share, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to send opened psi_sum: {e}"))?;

    Ok(PartyRun {
        side: Side::Receiver,
        opened_sum: expected,
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
        "psi_sum_ok side={:?} addr={} set_size={} intersection_size={} opened_sum={}",
        run.side,
        addr,
        args.set_size,
        args.intersection_size,
        fe_to_hex(run.opened_sum)
    );
    println!(
        "timing_ms={} bytes_sent={} bytes_received={}",
        run.elapsed_ms, run.bytes_sent, run.bytes_received
    );

    Ok(())
}
