use circuit_psi::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender, BeDOZa, BeDOZaTriple},
    circuit_psi::psi_sum::{open_psi_sum_receive, open_psi_sum_send, PsiSumReceiver, PsiSumSender},
    math::defines::FE,
    tcp_channel::{connect_with_retry, listen_to},
    utils::sets::sample_correlated_sets,
};
use clap::{Parser, ValueEnum};
use rand::{rngs::StdRng, RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

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
    #[arg(long)]
    triples_csv: PathBuf,
    #[arg(long)]
    delta_txt: PathBuf,
    #[arg(long)]
    key_txt: PathBuf,
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

fn hex_to_fe(hex: &str) -> eyre::Result<FE> {
    let hex = hex.trim();
    eyre::ensure!(
        hex.len() == 64,
        "expected 64 hex chars for FE encoding, got {}",
        hex.len()
    );
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let part = std::str::from_utf8(chunk)
            .map_err(|e| eyre::eyre!("invalid utf8 in FE hex encoding: {e}"))?;
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|e| eyre::eyre!("invalid FE hex byte `{part}`: {e}"))?;
    }
    FE::from_bytes_le(&bytes).map_err(|e| eyre::eyre!("invalid FE canonical encoding: {:?}", e))
}

fn parse_u8_field(raw: &str, field_name: &str) -> eyre::Result<u8> {
    raw.parse::<u8>()
        .map_err(|e| eyre::eyre!("invalid {field_name} value `{raw}`: {e}"))
}

fn parse_share(fields: &[&str], offset: usize) -> eyre::Result<BeDOZa> {
    eyre::ensure!(
        fields.len() >= offset + 6,
        "expected at least {} fields, got {}",
        offset + 6,
        fields.len()
    );

    let sender_val = hex_to_fe(fields[offset])?;
    let sender_pad = hex_to_fe(fields[offset + 1])?;
    let sender_side = parse_u8_field(fields[offset + 2], "sender_side")?;
    eyre::ensure!(sender_side <= 1, "sender_side must be 0 or 1");

    let receiver_tag = hex_to_fe(fields[offset + 3])?;
    let receiver_key = hex_to_fe(fields[offset + 4])?;
    let receiver_side = parse_u8_field(fields[offset + 5], "receiver_side")?;
    eyre::ensure!(receiver_side <= 1, "receiver_side must be 0 or 1");
    eyre::ensure!(
        receiver_side != sender_side,
        "expected sender_side and receiver_side to differ"
    );

    Ok(BeDOZa::new(
        BeDOZaSender::new(sender_val, sender_pad),
        BeDOZaReceiver::new(receiver_tag, receiver_key),
        sender_side == 1,
    ))
}

fn read_fe_txt(path: &Path, label: &str) -> eyre::Result<FE> {
    let content = fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("failed to read {label} txt {}: {e}", path.display()))?;
    let first_line = content
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| eyre::eyre!("{label} txt {} is empty", path.display()))?;
    hex_to_fe(first_line)
}

fn read_triples_csv(path: &Path) -> eyre::Result<Vec<BeDOZaTriple>> {
    let content = fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("failed to read triples csv {}: {e}", path.display()))?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| eyre::eyre!("triples csv {} is empty", path.display()))?;
    eyre::ensure!(
        header.starts_with("triple_index,"),
        "unexpected triples csv header in {}",
        path.display()
    );

    let mut triples = Vec::new();
    for (line_no, line) in lines.enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split(',').collect();
        eyre::ensure!(
            fields.len() == 19,
            "expected 19 csv fields at data line {}, got {}",
            line_no + 2,
            fields.len()
        );

        let _triple_index = fields[0]
            .parse::<usize>()
            .map_err(|e| eyre::eyre!("invalid triple_index at line {}: {}", line_no + 2, e))?;
        let a_share = parse_share(&fields, 1)?;
        let b_share = parse_share(&fields, 7)?;
        let c_share = parse_share(&fields, 13)?;
        triples.push((a_share, b_share, c_share));
    }

    Ok(triples)
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

    let delta = read_fe_txt(&args.delta_txt, "delta")?;
    let key = read_fe_txt(&args.key_txt, "key")?;
    let sender_triples = read_triples_csv(&args.triples_csv)?;
    eyre::ensure!(
        sender_triples.len() == sender_set.len(),
        "sender triple count {} does not match set size {}",
        sender_triples.len(),
        sender_set.len()
    );

    let mut psi_sum = PsiSumSender::new(delta, key, &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize psi_sum: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-protocol-rng"));
    let sum_share = psi_sum
        .run(
            &sender_set,
            &sender_triples,
            &mut protocol_rng,
            &mut channel,
        )
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

    let delta = read_fe_txt(&args.delta_txt, "delta")?;
    let key = read_fe_txt(&args.key_txt, "key")?;
    let receiver_triples = read_triples_csv(&args.triples_csv)?;
    eyre::ensure!(
        receiver_triples.len() == sender_set.len(),
        "receiver triple count {} does not match set size {}",
        receiver_triples.len(),
        sender_set.len()
    );

    let mut psi_sum = PsiSumReceiver::new(delta, key, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize psi_sum: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-protocol-rng"));
    let sum_share = psi_sum
        .run(
            &receiver_set,
            &receiver_triples,
            &mut protocol_rng,
            &mut channel,
        )
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
