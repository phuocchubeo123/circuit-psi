use anyhow::{Result, anyhow, ensure};
use circuit_psi::{
    bedoza::{
        BeDOZa, BeDOZaTriple,
        bedoza_multiply::batch_multiply,
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        comm_util::{receive_fe_vec, send_fe_vec},
        open_values_receive, open_values_send,
    },
    math::defines::FE,
    tcp_channel::{SwankyChannel, connect_with_retry, listen_to},
};
use clap::{Parser, ValueEnum};
use rand::{Rng, RngExt};
use std::{
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
#[command(name = "test_batch_multiply")]
struct Args {
    #[arg(long, value_enum)]
    side: Side,
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
    #[arg(long, default_value_t = 23000)]
    port: u16,
    #[arg(long)]
    triples_csv: PathBuf,
    #[arg(long)]
    delta_txt: PathBuf,
    #[arg(long)]
    n: usize,
}

fn socket_addr(args: &Args) -> String {
    format!("{}:{}", args.addr, args.port)
}

fn side_flag(side: Side) -> bool {
    match side {
        Side::Sender => false,
        Side::Receiver => true,
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

fn hex_to_fe(hex: &str) -> Result<FE> {
    let hex = hex.trim();
    ensure!(
        hex.len() == 64,
        "expected 64 hex chars for FE encoding, got {}",
        hex.len()
    );
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let part = std::str::from_utf8(chunk)
            .map_err(|e| anyhow!("invalid utf8 in FE hex encoding: {e}"))?;
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|e| anyhow!("invalid FE hex byte `{part}`: {e}"))?;
    }
    FE::from_bytes_le(&bytes).map_err(|e| anyhow!("invalid FE canonical encoding: {:?}", e))
}

fn parse_u8_field(raw: &str, field_name: &str) -> Result<u8> {
    raw.parse::<u8>()
        .map_err(|e| anyhow!("invalid {field_name} value `{raw}`: {e}"))
}

fn parse_share(fields: &[&str], offset: usize) -> Result<BeDOZa> {
    ensure!(
        fields.len() >= offset + 6,
        "expected at least {} fields, got {}",
        offset + 6,
        fields.len()
    );

    let sender_val = hex_to_fe(fields[offset])?;
    let sender_pad = hex_to_fe(fields[offset + 1])?;
    let sender_side = parse_u8_field(fields[offset + 2], "sender_side")?;
    ensure!(sender_side <= 1, "sender_side must be 0 or 1");

    let receiver_tag = hex_to_fe(fields[offset + 3])?;
    let receiver_key = hex_to_fe(fields[offset + 4])?;
    let receiver_side = parse_u8_field(fields[offset + 5], "receiver_side")?;
    ensure!(receiver_side <= 1, "receiver_side must be 0 or 1");
    ensure!(
        receiver_side != sender_side,
        "expected sender_side and receiver_side to differ"
    );

    Ok(BeDOZa::new(
        BeDOZaSender::new(sender_val, sender_pad),
        BeDOZaReceiver::new(receiver_tag, receiver_key),
        sender_side == 1,
    ))
}

fn read_delta_txt(path: &Path) -> Result<FE> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read delta txt {}: {e}", path.display()))?;
    let first_line = content
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| anyhow!("delta txt {} is empty", path.display()))?;
    hex_to_fe(first_line)
}

fn read_triples_csv(path: &Path) -> Result<Vec<BeDOZaTriple>> {
    let content = fs::read_to_string(path)
        .map_err(|e| anyhow!("failed to read triples csv {}: {e}", path.display()))?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| anyhow!("triples csv {} is empty", path.display()))?;
    ensure!(
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
        ensure!(
            fields.len() == 19,
            "expected 19 csv fields at data line {}, got {}",
            line_no + 2,
            fields.len()
        );

        let _triple_index = fields[0]
            .parse::<usize>()
            .map_err(|e| anyhow!("invalid triple_index at line {}: {}", line_no + 2, e))?;
        let a_share = parse_share(&fields, 1)?;
        let b_share = parse_share(&fields, 7)?;
        let c_share = parse_share(&fields, 13)?;
        triples.push((a_share, b_share, c_share));
    }

    Ok(triples)
}

fn sample_sender_shares<R: Rng>(n: usize, side: bool, rng: &mut R) -> Vec<BeDOZaSender> {
    let mut shares = Vec::with_capacity(n);
    for _ in 0..n {
        let mut value_bytes = [0u8; 32];
        let mut pad_bytes = [0u8; 32];
        rng.fill(&mut value_bytes);
        rng.fill(&mut pad_bytes);
        let _ = side;
        shares.push(BeDOZaSender::new(
            FE::from_bytes_le_mod_order(&value_bytes),
            FE::from_bytes_le_mod_order(&pad_bytes),
        ));
    }
    shares
}

fn receive_peer_sender_components(
    expected_count: usize,
    channel: &mut SwankyChannel,
) -> Result<(Vec<FE>, Vec<FE>)> {
    let values = receive_fe_vec(channel).map_err(|e| anyhow!("failed to receive values: {e}"))?;
    let pads = receive_fe_vec(channel).map_err(|e| anyhow!("failed to receive pads: {e}"))?;
    ensure!(
        values.len() == expected_count,
        "expected {} received values, got {}",
        expected_count,
        values.len()
    );
    ensure!(
        pads.len() == expected_count,
        "expected {} received pads, got {}",
        expected_count,
        pads.len()
    );

    Ok((values, pads))
}

fn exchange_sender_shares(
    local_shares: &[BeDOZaSender],
    side: bool,
    channel: &mut SwankyChannel,
) -> Result<(Vec<FE>, Vec<FE>)> {
    let local_values: Vec<FE> = local_shares.iter().map(|s| s.val()).collect();
    let local_pads: Vec<FE> = local_shares.iter().map(|s| s.pad()).collect();

    if !side {
        send_fe_vec(&local_values, channel)
            .map_err(|e| anyhow!("failed to send local sender values: {e}"))?;
        send_fe_vec(&local_pads, channel)
            .map_err(|e| anyhow!("failed to send local sender pads: {e}"))?;
        receive_peer_sender_components(local_shares.len(), channel)
    } else {
        let peer = receive_peer_sender_components(local_shares.len(), channel)?;
        send_fe_vec(&local_values, channel)
            .map_err(|e| anyhow!("failed to send local sender values: {e}"))?;
        send_fe_vec(&local_pads, channel)
            .map_err(|e| anyhow!("failed to send local sender pads: {e}"))?;
        Ok(peer)
    }
}

fn build_bedoza_inputs(
    local_senders: &[BeDOZaSender],
    peer_values: &[FE],
    peer_pads: &[FE],
    delta: FE,
    side: bool,
) -> Result<Vec<BeDOZa>> {
    ensure!(
        local_senders.len() == peer_values.len(),
        "input sender/value length mismatch: local={} peer_values={}",
        local_senders.len(),
        peer_values.len()
    );
    ensure!(
        peer_values.len() == peer_pads.len(),
        "peer value/pad length mismatch: values={} pads={}",
        peer_values.len(),
        peer_pads.len()
    );

    Ok(local_senders
        .iter()
        .zip(peer_values.iter().zip(peer_pads.iter()))
        .map(|(local, (&peer_value, &peer_pad))| {
            BeDOZa::new(
                *local,
                BeDOZaReceiver::new(delta * peer_value - peer_pad, delta),
                side,
            )
        })
        .collect())
}

fn verify_outputs(
    outputs: &[BeDOZa],
    expected: &[FE],
    side: bool,
    channel: &mut SwankyChannel,
) -> Result<()> {
    ensure!(
        outputs.len() == expected.len(),
        "output length mismatch: outputs={} expected={}",
        outputs.len(),
        expected.len()
    );

    let opened = if !side {
        open_values_send(outputs, channel)
            .map_err(|e| anyhow!("failed to send output openings: {e}"))?;
        open_values_receive(outputs, channel)
            .map_err(|e| anyhow!("failed to receive output openings: {e}"))?
    } else {
        let opened = open_values_receive(outputs, channel)
            .map_err(|e| anyhow!("failed to receive output openings: {e}"))?;
        open_values_send(outputs, channel)
            .map_err(|e| anyhow!("failed to send output openings: {e}"))?;
        opened
    };

    for (i, (&got, &want)) in opened.iter().zip(expected.iter()).enumerate() {
        ensure!(
            got == want,
            "opened product mismatch at index {}: got {}, expected {}",
            i,
            fe_to_hex(got),
            fe_to_hex(want)
        );
    }

    Ok(())
}

fn run_party(args: &Args) -> Result<()> {
    ensure!(args.n > 0, "n must be > 0");

    let delta = read_delta_txt(&args.delta_txt)?;
    let triples = read_triples_csv(&args.triples_csv)?;
    ensure!(
        args.n <= triples.len(),
        "requested n={} multiplications but csv only stores {} triples",
        args.n,
        triples.len()
    );
    let triples = &triples[..args.n];

    let addr = socket_addr(args);
    let mut channel = match args.side {
        Side::Sender => listen_to(&addr).map_err(|e| anyhow!("{e}"))?,
        Side::Receiver => connect_with_retry(&addr).map_err(|e| anyhow!("{e}"))?,
    };
    let side = side_flag(args.side);
    let mut rng = rand::rng();
    let local_x_senders = sample_sender_shares(args.n, side, &mut rng);
    let local_y_senders = sample_sender_shares(args.n, side, &mut rng);

    let (peer_x_values, peer_x_pads) =
        exchange_sender_shares(&local_x_senders, side, &mut channel)?;
    let (peer_y_values, peer_y_pads) =
        exchange_sender_shares(&local_y_senders, side, &mut channel)?;

    let x_shares =
        build_bedoza_inputs(&local_x_senders, &peer_x_values, &peer_x_pads, delta, side)?;
    let y_shares =
        build_bedoza_inputs(&local_y_senders, &peer_y_values, &peer_y_pads, delta, side)?;

    let expected_products: Vec<FE> = local_x_senders
        .iter()
        .zip(peer_x_values.iter())
        .zip(local_y_senders.iter().zip(peer_y_values.iter()))
        .map(|((x_local, &x_peer_value), (y_local, &y_peer_value))| {
            let x = x_local.val() + x_peer_value;
            let y = y_local.val() + y_peer_value;
            x * y
        })
        .collect();

    let start = Instant::now();
    let current_bytes_sent = channel.bytes_sent();
    let current_bytes_received = channel.bytes_received();

    let outputs = batch_multiply(&x_shares, &y_shares, triples, side, &mut channel)?;

    let multiply_time = start.elapsed().as_millis();
    let multiply_bytes_sent = channel.bytes_sent() - current_bytes_sent;
    let multiply_bytes_received = channel.bytes_received() - current_bytes_received;

    verify_outputs(&outputs, &expected_products, side, &mut channel)?;

    println!(
        "batch_multiply_ok side={:?} addr={} n={} timing_ms={} bytes_sent={} bytes_received={}",
        args.side, addr, args.n, multiply_time, multiply_bytes_sent, multiply_bytes_received,
    );

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    run_party(&args)
}
