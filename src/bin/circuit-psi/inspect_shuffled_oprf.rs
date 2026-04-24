use circuit_psi::{
    math::{defines::FE, group::Group, scalar_field::fq},
    shuffled_oprf::{shuffle_inputer::Inputer, shuffle_shuffler::Shuffler},
    tcp_channel::{connect_with_retry, listen_to},
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use clap::{Parser, ValueEnum};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Side {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "inspect_shuffled_oprf")]
struct Args {
    #[arg(long, value_enum)]
    side: Side,
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
    #[arg(long, default_value_t = 23000)]
    port: u16,
    #[arg(long, default_value_t = 8)]
    set_size: usize,
    #[arg(long, default_value_t = 3)]
    intersection_size: usize,
    #[arg(long, default_value_t = 5)]
    dump_count: usize,
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
        let bytes: [u8; 32] = rng.random();
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

fn random_permutation(n: usize, rng: &mut StdRng) -> Vec<usize> {
    let mut permutation: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        permutation.swap(i, j);
    }
    permutation
}

fn hex_group(group: &Group) -> String {
    let bytes = group.to_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn hex_fe(value: FE) -> String {
    let bytes = value.to_bytes_le();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn dump_outputs(label: &str, outputs: &[Group], dump_count: usize) {
    println!("{} count={}", label, outputs.len());
    for (i, output) in outputs.iter().take(dump_count).enumerate() {
        println!("{}[{}]={}", label, i, hex_group(output));
    }
}

fn exchange_oprf_key_share(
    side: Side,
    local_key_share: FE,
    channel: &mut circuit_psi::tcp_channel::SwankyChannel,
) -> eyre::Result<FE> {
    match side {
        Side::Sender => {
            channel
                .send(&local_key_share.to_bytes_le())
                .map_err(|e| eyre::eyre!("sender failed to send OPRF key share: {e}"))?;
            let peer_bytes = channel
                .receive()
                .map_err(|e| eyre::eyre!("sender failed to receive OPRF key share: {e}"))?;
            eyre::ensure!(
                peer_bytes.len() == 32,
                "sender expected 32-byte peer OPRF key share, got {}",
                peer_bytes.len()
            );
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&peer_bytes);
            FE::from_bytes_le(&bytes)
                .map_err(|e| eyre::eyre!("sender failed to parse peer OPRF key share: {:?}", e))
        }
        Side::Receiver => {
            let peer_bytes = channel
                .receive()
                .map_err(|e| eyre::eyre!("receiver failed to receive OPRF key share: {e}"))?;
            eyre::ensure!(
                peer_bytes.len() == 32,
                "receiver expected 32-byte peer OPRF key share, got {}",
                peer_bytes.len()
            );
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&peer_bytes);
            let peer_key_share = FE::from_bytes_le(&bytes).map_err(|e| {
                eyre::eyre!("receiver failed to parse peer OPRF key share: {:?}", e)
            })?;
            channel
                .send(&local_key_share.to_bytes_le())
                .map_err(|e| eyre::eyre!("receiver failed to send OPRF key share: {e}"))?;
            Ok(peer_key_share)
        }
    }
}

fn plain_oprf_outputs(values: &[FE], total_key: FE) -> eyre::Result<Vec<Group>> {
    let mut out = Vec::with_capacity(values.len());
    for (i, &value) in values.iter().enumerate() {
        let denominator = value + total_key;
        let inverse = denominator.inv().map_err(|e| {
            eyre::eyre!(
                "failed to invert x + total_oprf_key at index {}: {:?}",
                i,
                e
            )
        })?;
        out.push(Group::base_point().scalar_mul(&inverse));
    }
    Ok(out)
}

fn compare_output_sets(label: &str, actual: &[Group], expected: &[Group]) {
    let actual_set: HashSet<[u8; 32]> = actual.iter().map(Group::to_bytes).collect();
    let expected_set: HashSet<[u8; 32]> = expected.iter().map(Group::to_bytes).collect();
    let missing = expected_set.difference(&actual_set).count();
    let extra = actual_set.difference(&expected_set).count();
    println!(
        "{} set_match={} missing={} extra={}",
        label,
        actual_set == expected_set,
        missing,
        extra
    );
}

fn sender_party(addr: &str, args: &Args) -> eyre::Result<()> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{e}"))?;

    let mut shared_seed = [0u8; 32];
    rand::rng().fill(&mut shared_seed);
    channel
        .send(&shared_seed)
        .map_err(|e| eyre::eyre!("sender failed to send shared seed: {e}"))?;

    let (sender_set, receiver_set) =
        sample_correlated_sets(shared_seed, args.set_size, args.intersection_size)?;
    let peer_key_share = exchange_oprf_key_share(Side::Sender, fq(173), &mut channel)?;
    let total_key = fq(173) + peer_key_share;

    let mut auth_vole_sender = BufferedVoleSender::init(&mut channel, LPN21)
        .map_err(|e| eyre::eyre!("init auth sender VOLE failed: {e}"))?;
    let mut auth_vole_receiver = BufferedVoleReceiver::init(&mut channel, fq(97), LPN21)
        .map_err(|e| eyre::eyre!("init auth receiver VOLE failed: {e}"))?;
    let mut product_vole_sender = BufferedVoleSender::init(&mut channel, LPN21)
        .map_err(|e| eyre::eyre!("init product sender VOLE failed: {e}"))?;
    let mut product_vole_receiver = BufferedVoleReceiver::init(&mut channel, fq(173), LPN21)
        .map_err(|e| eyre::eyre!("init product receiver VOLE failed: {e}"))?;

    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-protocol-rng"));
    let inputer = Inputer::new(fq(97), fq(173));
    let sender_run = inputer.run_full_shuffled_oprf(
        &sender_set,
        &mut protocol_rng,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        &mut product_vole_sender,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("sender inputer run failed: {e}"))?;

    let receiver_permutation =
        random_permutation(args.set_size, &mut StdRng::from_seed(derive_seed(shared_seed, b"receiver-permutation")));
    let shuffler = Shuffler::new(fq(97), fq(173));
    let receiver_run = shuffler.run_full_shuffled_oprf(
        &receiver_permutation,
        &mut protocol_rng,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        &mut product_vole_receiver,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("sender shuffler run failed: {e}"))?;

    dump_outputs("sender_inputer_shuffled", &sender_run.shuffled_oprf, args.dump_count);
    dump_outputs("receiver_shuffler_shuffled", &receiver_run.shuffled_oprf, args.dump_count);
    println!(
        "sender local_key_share={} peer_key_share={} total_key={}",
        hex_fe(fq(173)),
        hex_fe(peer_key_share),
        hex_fe(total_key)
    );
    let expected_sender_outputs = plain_oprf_outputs(&sender_set, total_key)?;
    compare_output_sets(
        "sender_inputer_vs_plain_sender_set",
        &sender_run.shuffled_oprf,
        &expected_sender_outputs,
    );
    let expected_receiver_outputs = plain_oprf_outputs(&receiver_set, total_key)?;
    compare_output_sets(
        "receiver_shuffler_vs_plain_receiver_set",
        &receiver_run.shuffled_oprf,
        &expected_receiver_outputs,
    );

    Ok(())
}

fn receiver_party(addr: &str, args: &Args) -> eyre::Result<()> {
    let mut channel = connect_with_retry(addr).map_err(|e| eyre::eyre!("{e}"))?;

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
    let peer_key_share = exchange_oprf_key_share(Side::Receiver, fq(149), &mut channel)?;
    let total_key = fq(149) + peer_key_share;

    let mut auth_vole_receiver = BufferedVoleReceiver::init(&mut channel, fq(131), LPN21)
        .map_err(|e| eyre::eyre!("init auth receiver VOLE failed: {e}"))?;
    let mut auth_vole_sender = BufferedVoleSender::init(&mut channel, LPN21)
        .map_err(|e| eyre::eyre!("init auth sender VOLE failed: {e}"))?;
    let mut product_vole_receiver = BufferedVoleReceiver::init(&mut channel, fq(149), LPN21)
        .map_err(|e| eyre::eyre!("init product receiver VOLE failed: {e}"))?;
    let mut product_vole_sender = BufferedVoleSender::init(&mut channel, LPN21)
        .map_err(|e| eyre::eyre!("init product sender VOLE failed: {e}"))?;

    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-protocol-rng"));
    let sender_permutation =
        random_permutation(args.set_size, &mut StdRng::from_seed(derive_seed(shared_seed, b"sender-permutation")));
    let shuffler = Shuffler::new(fq(131), fq(149));
    let sender_run = shuffler.run_full_shuffled_oprf(
        &sender_permutation,
        &mut protocol_rng,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        &mut product_vole_receiver,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("receiver shuffler run failed: {e}"))?;

    let inputer = Inputer::new(fq(131), fq(149));
    let receiver_run = inputer.run_full_shuffled_oprf(
        &receiver_set,
        &mut protocol_rng,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        &mut product_vole_sender,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("receiver inputer run failed: {e}"))?;

    dump_outputs("sender_shuffler_shuffled", &sender_run.shuffled_oprf, args.dump_count);
    dump_outputs("receiver_inputer_shuffled", &receiver_run.shuffled_oprf, args.dump_count);
    println!(
        "receiver local_key_share={} peer_key_share={} total_key={}",
        hex_fe(fq(149)),
        hex_fe(peer_key_share),
        hex_fe(total_key)
    );
    let expected_receiver_outputs = plain_oprf_outputs(&receiver_set, total_key)?;
    compare_output_sets(
        "receiver_inputer_vs_plain_receiver_set",
        &receiver_run.shuffled_oprf,
        &expected_receiver_outputs,
    );
    let expected_sender_outputs = plain_oprf_outputs(&sender_set, total_key)?;
    compare_output_sets(
        "sender_shuffler_vs_plain_sender_set",
        &sender_run.shuffled_oprf,
        &expected_sender_outputs,
    );

    Ok(())
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let addr = socket_addr(&args);
    match args.side {
        Side::Sender => sender_party(&addr, &args)?,
        Side::Receiver => receiver_party(&addr, &args)?,
    }
    Ok(())
}
