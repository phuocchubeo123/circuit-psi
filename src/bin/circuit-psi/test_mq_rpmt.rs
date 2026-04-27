use circuit_psi::{
    circuit_psi::mq_rpmt::{
        MqRpmtReceiver, MqRpmtSender, open_authenticated_shuffled_bitmap_receive,
        open_authenticated_shuffled_bitmap_send,
    },
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
    utils::sets::sample_correlated_sets,
};
use clap::{Parser, ValueEnum};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Side {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "test_mq_rpmt")]
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
    public_shuffled_bitmap: Vec<FE>,
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

fn sender_party(addr: &str, args: Args) -> eyre::Result<PartyRun> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{e}"))?;
    let start = Instant::now();

    let mut seed_rng = rand::rng();
    let mut shared_seed = [0u8; 32];
    seed_rng.fill(&mut shared_seed);
    channel
        .send(&shared_seed)
        .map_err(|e| eyre::eyre!("sender failed to send shared seed: {e}"))?;

    let (sender_set, _receiver_set) =
        sample_correlated_sets(shared_seed, args.set_size, args.intersection_size)?;
    let mut mq_rpmt = MqRpmtSender::new(fq(97), fq(173), &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to initialize mq_rpmt: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-protocol-rng"));
    let output = mq_rpmt
        .run(&sender_set, &mut protocol_rng, &mut channel)
        .map_err(|e| eyre::eyre!("sender failed to run mq_rpmt: {e}"))?;

    let bytes_sent = channel.bytes_sent();
    let bytes_received = channel.bytes_received();
    let elapsed_ms = start.elapsed().as_millis();


    let opened_bitmap = open_authenticated_shuffled_bitmap_receive(
        &output.authenticated_shuffled_bitmap,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("sender failed to receive bitmap opening: {e}"))?;
    eyre::ensure!(
        opened_bitmap == output.shuffled_bitmap,
        "sender opened shuffled bitmap mismatch: got {:?}, expected {:?}",
        opened_bitmap,
        output.shuffled_bitmap
    );

    Ok(PartyRun {
        side: Side::Sender,
        public_shuffled_bitmap: output.shuffled_bitmap,
        bytes_sent,
        bytes_received,
        elapsed_ms,
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

    let (_sender_set, receiver_set) =
        sample_correlated_sets(shared_seed, args.set_size, args.intersection_size)?;
    let mut mq_rpmt = MqRpmtReceiver::new(fq(131), fq(149), &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to initialize mq_rpmt: {e}"))?;
    let mut protocol_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-protocol-rng"));
    let output = mq_rpmt
        .run(&receiver_set, &mut protocol_rng, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to run mq_rpmt: {e}"))?;

    let bytes_sent = channel.bytes_sent();
    let bytes_received = channel.bytes_received();
    let elapsed_ms = start.elapsed().as_millis();

    open_authenticated_shuffled_bitmap_send(&output.authenticated_shuffled_bitmap, &mut channel)
        .map_err(|e| eyre::eyre!("receiver failed to send bitmap opening: {e}"))?;
    eyre::ensure!(
        output.shuffled_bitmap.len() == args.set_size,
        "receiver shuffled bitmap length {} does not match set size {}",
        output.shuffled_bitmap.len(),
        args.set_size
    );
    eyre::ensure!(
        output.original_bitmap.len() == args.set_size,
        "receiver original bitmap length {} does not match set size {}",
        output.original_bitmap.len(),
        args.set_size
    );

    Ok(PartyRun {
        side: Side::Receiver,
        public_shuffled_bitmap: output.shuffled_bitmap,
        bytes_sent,
        bytes_received,
        elapsed_ms,
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
        "mq_rpmt_ok side={:?} addr={} set_size={} intersection_size={} bitmap_len={}",
        run.side,
        addr,
        args.set_size,
        args.intersection_size,
        run.public_shuffled_bitmap.len()
    );
    println!(
        "timing_ms={} bytes_sent={} bytes_received={}",
        run.elapsed_ms, run.bytes_sent, run.bytes_received
    );

    Ok(())
}
