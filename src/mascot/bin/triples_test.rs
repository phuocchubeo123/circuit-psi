use anyhow::{Context, Result, bail};
use circuit_psi::base_cot::BaseCot;
use circuit_psi::bedoza::{
    BeDOZaTriple, open_values_receive, open_values_send,
};
use circuit_psi::mascot::triple::{MascotTripleReceiver, MascotTripleSender};
use circuit_psi::network::tcp_channel::{SwankyChannel, connect_with_retry, listen_to};
use circuit_psi::scalar_field::fq;
use circuit_psi::vole::field_config::FE;
use circuit_psi::vole_triple::LPN21;
use circuit_psi::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender};
use std::time::Instant;

const DEFAULT_ADDR: &str = "127.0.0.1:19110";
const DELTA_SENDER: u64 = 97;
const DELTA_RECEIVER: u64 = 131;
const TRIPLE_CHUNK_SIZE: usize = 1000;

fn open_authenticated_triples(
    io: &mut SwankyChannel,
    triples: &[BeDOZaTriple],
    comm: &mut u64,
) -> Result<Vec<(FE, FE, FE)>> {
    let a_shares = triples.iter().map(|t| t.0).collect::<Vec<_>>();
    let b_shares = triples.iter().map(|t| t.1).collect::<Vec<_>>();
    let c_shares = triples.iter().map(|t| t.2).collect::<Vec<_>>();

    open_values_send(&a_shares, io).context("failed to send opened a shares")?;
    *comm += (a_shares.len() as u64) * 64;
    let opened_a = open_values_receive(&a_shares, io).context("failed to receive opened a shares")?;

    open_values_send(&b_shares, io).context("failed to send opened b shares")?;
    *comm += (b_shares.len() as u64) * 64;
    let opened_b = open_values_receive(&b_shares, io).context("failed to receive opened b shares")?;

    open_values_send(&c_shares, io).context("failed to send opened c shares")?;
    *comm += (c_shares.len() as u64) * 64;
    let opened_c = open_values_receive(&c_shares, io).context("failed to receive opened c shares")?;

    Ok((0..triples.len())
        .map(|i| (opened_a[i], opened_b[i], opened_c[i]))
        .collect())
}

fn run_sender(addr: &str, n: usize) -> Result<()> {
    let mut io = connect_with_retry(addr).with_context(|| format!("connect {addr}"))?;
    let mut comm = 0u64;
    let local_key = fq(DELTA_SENDER);

    let mut auth_vole_sender =
        BufferedVoleSender::init(&mut io, LPN21)
            .map_err(|e| anyhow::anyhow!("init auth VOLE sender failed: {e}"))?;
    let mut auth_vole_receiver = BufferedVoleReceiver::init(&mut io, -local_key, LPN21)
        .map_err(|e| anyhow::anyhow!("init auth VOLE receiver failed: {e}"))?;

    let start = Instant::now();
    let mut cot_when_sender = BaseCot::new(0, false);
    cot_when_sender.cot_gen_pre(&mut io, None, &mut comm);
    let mut cot_when_receiver = BaseCot::new(1, false);
    cot_when_receiver.cot_gen_pre(&mut io, None, &mut comm);
    let mut mascot = MascotTripleSender::new();
    let mut chunks = Vec::new();
    for chunk_start in (0..n).step_by(TRIPLE_CHUNK_SIZE) {
        let chunk_n = (n - chunk_start).min(TRIPLE_CHUNK_SIZE);
        let local = mascot.triples(
            &mut io,
            &mut cot_when_receiver,
            &mut cot_when_sender,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            chunk_n,
            &mut comm,
        );
        chunks.push(local);
    }
    let elapsed = start.elapsed();
    let mut ok = true;
    for chunk in &chunks {
        let opened = open_authenticated_triples(&mut io, chunk, &mut comm)?;
        ok &= opened.iter().all(|(a, b, c)| *c == *a * *b);
    }

    println!("role: sender");
    println!("triples n={}: {:?}", n, elapsed);
    println!(
        "all triple checks c = a*b: {}",
        if ok { "PASS" } else { "FAIL" }
    );
    println!("comm bytes (counted): {}", comm);
    println!("channel bytes sent: {}", io.bytes_sent());
    println!("channel bytes received: {}", io.bytes_received());
    Ok(())
}

fn run_receiver(addr: &str, n: usize) -> Result<()> {
    let mut io = listen_to(addr).with_context(|| format!("listen {addr}"))?;
    let mut comm = 0u64;
    let local_key = fq(DELTA_RECEIVER);

    let mut auth_vole_receiver = BufferedVoleReceiver::init(&mut io, -local_key, LPN21)
        .map_err(|e| anyhow::anyhow!("init auth VOLE receiver failed: {e}"))?;
    let mut auth_vole_sender =
        BufferedVoleSender::init(&mut io, LPN21)
            .map_err(|e| anyhow::anyhow!("init auth VOLE sender failed: {e}"))?;

    let start = Instant::now();

    let mut cot_when_receiver = BaseCot::new(1, false);
    cot_when_receiver.cot_gen_pre(&mut io, None, &mut comm);
    let mut cot_when_sender = BaseCot::new(0, false);
    cot_when_sender.cot_gen_pre(&mut io, None, &mut comm);
    let mut mascot = MascotTripleReceiver::new();
    let mut chunks = Vec::new();

    for chunk_start in (0..n).step_by(TRIPLE_CHUNK_SIZE) {
        let chunk_n = (n - chunk_start).min(TRIPLE_CHUNK_SIZE);
        let local = mascot.triples(
            &mut io,
            &mut cot_when_receiver,
            &mut cot_when_sender,
            &mut auth_vole_sender,
            &mut auth_vole_receiver,
            chunk_n,
            &mut comm,
        );
        chunks.push(local);
    }
    let elapsed = start.elapsed();
    let mut ok = true;
    for chunk in &chunks {
        let opened = open_authenticated_triples(&mut io, chunk, &mut comm)?;
        ok &= opened.iter().all(|(a, b, c)| *c == *a * *b);
    }

    println!("role: receiver");
    println!("triples n={}: {:?}", n, elapsed);
    println!(
        "all triple checks c = a*b: {}",
        if ok { "PASS" } else { "FAIL" }
    );
    println!("comm bytes (counted): {}", comm);
    println!("channel bytes sent: {}", io.bytes_sent());
    println!("channel bytes received: {}", io.bytes_received());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        bail!("usage: {} <sender|receiver> [n] [addr]", args[0]);
    }
    let role = args[1].as_str();
    let (n, addr) = match args.get(2) {
        None => (1usize, DEFAULT_ADDR),
        Some(arg2) => match arg2.parse::<usize>() {
            Ok(parsed_n) => (
                parsed_n,
                args.get(3).map(String::as_str).unwrap_or(DEFAULT_ADDR),
            ),
            Err(_) => (1usize, arg2.as_str()),
        },
    };

    match role {
        "sender" => run_sender(addr, n),
        "receiver" => run_receiver(addr, n),
        _ => bail!("invalid role '{}', expected sender|receiver", role),
    }
}
