use anyhow::{Context, Result, ensure};
use circuit_psi::{
    bedoza::{BeDOZa, BeDOZaTriple, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::defines::FE,
    tcp_channel::{SwankyChannel, connect_with_retry, listen_to},
};
use clap::{Parser, ValueEnum};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Side {
    Sender,
    Receiver,
}

#[derive(Debug, Parser)]
#[command(name = "create_fake_triples_interactive")]
struct Args {
    #[arg(long, value_enum)]
    side: Side,
    #[arg(long)]
    n: usize,
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
    #[arg(long, default_value_t = 23000)]
    port: u16,
    #[arg(long)]
    triples_csv: Option<PathBuf>,
    #[arg(long)]
    delta_txt: Option<PathBuf>,
}

fn socket_addr(args: &Args) -> String {
    format!("{}:{}", args.addr, args.port)
}

fn default_triples_csv(side: Side) -> PathBuf {
    match side {
        Side::Sender => PathBuf::from("fake_triples_sender.csv"),
        Side::Receiver => PathBuf::from("fake_triples_receiver.csv"),
    }
}

fn default_delta_txt(side: Side) -> PathBuf {
    match side {
        Side::Sender => PathBuf::from("delta_sender.txt"),
        Side::Receiver => PathBuf::from("delta_receiver.txt"),
    }
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

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
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

fn write_share_columns(writer: &mut dyn Write, share: &BeDOZa) -> Result<()> {
    write!(
        writer,
        "{},{},{},{},{},{}",
        fe_to_hex(share.bedoza_sender().val()),
        fe_to_hex(share.bedoza_sender().pad()),
        share.side() as u8,
        fe_to_hex(share.bedoza_receiver().tag()),
        fe_to_hex(share.bedoza_receiver().key()),
        (!share.side()) as u8,
    )?;
    Ok(())
}

fn write_triples_csv(path: &Path, triples: &[BeDOZaTriple]) -> Result<()> {
    ensure_parent_dir(path)?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "triple_index,\
         a_sender_val,a_sender_pad,a_sender_side,a_receiver_tag,a_receiver_key,a_receiver_side,\
         b_sender_val,b_sender_pad,b_sender_side,b_receiver_tag,b_receiver_key,b_receiver_side,\
         c_sender_val,c_sender_pad,c_sender_side,c_receiver_tag,c_receiver_key,c_receiver_side"
    )?;

    for (i, (a_share, b_share, c_share)) in triples.iter().enumerate() {
        write!(writer, "{i},")?;
        write_share_columns(&mut writer, a_share)?;
        write!(writer, ",")?;
        write_share_columns(&mut writer, b_share)?;
        write!(writer, ",")?;
        write_share_columns(&mut writer, c_share)?;
        writeln!(writer)?;
    }

    writer.flush()?;
    Ok(())
}

fn write_delta_txt(path: &Path, delta: FE) -> Result<()> {
    ensure_parent_dir(path)?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{}", fe_to_hex(delta))?;
    writer.flush()?;
    Ok(())
}

fn exchange_handshake(
    side: Side,
    n: usize,
    channel: &mut SwankyChannel,
) -> Result<([u8; 32], [u8; 32])> {
    let mut local_seed = [0u8; 32];
    rand::rng().fill(&mut local_seed);

    let mut local_payload = Vec::with_capacity(40);
    local_payload.extend_from_slice(&(n as u64).to_le_bytes());
    local_payload.extend_from_slice(&local_seed);

    let peer_payload = match side {
        Side::Sender => {
            channel
                .send(&local_payload)
                .context("sender failed to send triple generation handshake")?;
            channel
                .receive()
                .context("sender failed to receive triple generation handshake")?
        }
        Side::Receiver => {
            let peer = channel
                .receive()
                .context("receiver failed to receive triple generation handshake")?;
            channel
                .send(&local_payload)
                .context("receiver failed to send triple generation handshake")?;
            peer
        }
    };

    ensure!(
        peer_payload.len() == 40,
        "expected 40-byte handshake payload, got {} bytes",
        peer_payload.len()
    );

    let mut peer_n_bytes = [0u8; 8];
    peer_n_bytes.copy_from_slice(&peer_payload[..8]);
    let peer_n = u64::from_le_bytes(peer_n_bytes) as usize;
    ensure!(
        peer_n == n,
        "handshake mismatch: local n={} peer n={}",
        n,
        peer_n
    );

    let mut peer_seed = [0u8; 32];
    peer_seed.copy_from_slice(&peer_payload[8..]);

    Ok(match side {
        Side::Sender => (local_seed, peer_seed),
        Side::Receiver => (peer_seed, local_seed),
    })
}

fn derive_shared_seed(sender_seed: [u8; 32], receiver_seed: [u8; 32], n: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"create_fake_triples_interactive/v1");
    hasher.update((n as u64).to_le_bytes());
    hasher.update(sender_seed);
    hasher.update(receiver_seed);
    let digest = hasher.finalize();
    let mut shared_seed = [0u8; 32];
    shared_seed.copy_from_slice(&digest);
    shared_seed
}

fn run(args: Args) -> Result<()> {
    ensure!(args.n > 0, "n must be > 0");

    let triples_csv = args
        .triples_csv
        .clone()
        .unwrap_or_else(|| default_triples_csv(args.side));
    let delta_txt = args
        .delta_txt
        .clone()
        .unwrap_or_else(|| default_delta_txt(args.side));
    ensure!(
        triples_csv != delta_txt,
        "triples_csv and delta_txt must be different files"
    );

    let addr = socket_addr(&args);
    let mut channel = match args.side {
        Side::Sender => listen_to(&addr).map_err(|e| anyhow::anyhow!("{e}"))?,
        Side::Receiver => connect_with_retry(&addr).map_err(|e| anyhow::anyhow!("{e}"))?,
    };

    let (sender_seed, receiver_seed) = exchange_handshake(args.side, args.n, &mut channel)?;
    let shared_seed = derive_shared_seed(sender_seed, receiver_seed, args.n);
    let mut rng = StdRng::from_seed(shared_seed);
    let delta0 = sample_fe(&mut rng);
    let delta1 = sample_fe(&mut rng);
    let (sender_triples, receiver_triples) =
        generate_fake_triples(args.n, delta0, delta1, &mut rng);

    let (triples, delta) = match args.side {
        Side::Sender => (sender_triples, delta0),
        Side::Receiver => (receiver_triples, delta1),
    };

    write_triples_csv(&triples_csv, &triples)?;
    write_delta_txt(&delta_txt, delta)?;

    println!(
        "generated_fake_triples_interactive side={:?} addr={} n={} triples_csv={} delta_txt={} shared_seed={} bytes_sent={} bytes_received={}",
        args.side,
        addr,
        args.n,
        triples_csv.display(),
        delta_txt.display(),
        hex_seed(shared_seed),
        channel.bytes_sent(),
        channel.bytes_received()
    );

    Ok(())
}

fn hex_seed(seed: [u8; 32]) -> String {
    let mut out = String::with_capacity(seed.len() * 2);
    for byte in seed {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn main() -> Result<()> {
    let args = Args::parse();
    run(args)
}
