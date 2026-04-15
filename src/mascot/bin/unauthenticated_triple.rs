use anyhow::{Context, Result, anyhow, bail};
use circuit_psi::base_cot::BaseCot;
use circuit_psi::bedoza::{BeDOZa, BeDOZaTriple};
use circuit_psi::mascot::triple::{MascotTripleReceiver, MascotTripleSender, REPETITION};
use circuit_psi::network::tcp_channel::{connect_with_retry, listen_to};
use circuit_psi::pre_ot::OTPre;
use circuit_psi::scalar_field::{FOURQ_SCALAR_BITS, fq};
use circuit_psi::vole::field_config::{FE, FE_LIMBS};
use circuit_psi::vole_triple::LPN21;
use circuit_psi::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender};
use std::time::Instant;
use swanky_channel_legacy::AesRng;
use swanky_channel_legacy::AbstractChannel;

const DEFAULT_ADDR: &str = "127.0.0.1:19110";
const DELTA_SENDER: u64 = 97;
const DELTA_RECEIVER: u64 = 131;

fn open_bedoza_values<IO: AbstractChannel>(
    io: &mut IO,
    shares: &[BeDOZa],
    comm: &mut u64,
) -> Result<Vec<FE>> {
    if shares.is_empty() {
        return Ok(vec![]);
    }

    for share in shares {
        io.write_bytes(&share.bedoza_sender().val().to_bytes_le())
            .context("failed to send opened sender value")?;
    }
    for share in shares {
        io.write_bytes(&share.bedoza_sender().pad().to_bytes_le())
            .context("failed to send opened sender pad")?;
    }
    io.flush().context("failed to flush opened sender shares")?;
    *comm += (shares.len() as u64) * 64;

    let key = shares[0].bedoza_receiver().key();
    for (i, share) in shares.iter().enumerate() {
        if share.bedoza_receiver().key() != key {
            bail!("BeDOZa opening key mismatch at index {}", i);
        }
    }

    let mut peer_values = Vec::with_capacity(shares.len());
    for _ in shares {
        let mut bytes = [0u8; 32];
        io.read_bytes(&mut bytes)
            .context("failed to receive opened peer value")?;
        let v = FE::from_bytes_le(&bytes)
            .map_err(|e| anyhow!("failed to parse opened peer value: {:?}", e))?;
        peer_values.push(v);
    }

    let mut peer_pads = Vec::with_capacity(shares.len());
    for _ in shares {
        let mut bytes = [0u8; 32];
        io.read_bytes(&mut bytes)
            .context("failed to receive opened peer pad")?;
        let p = FE::from_bytes_le(&bytes)
            .map_err(|e| anyhow!("failed to parse opened peer pad: {:?}", e))?;
        peer_pads.push(p);
    }

    for (i, ((&value, &pad), share)) in peer_values
        .iter()
        .zip(peer_pads.iter())
        .zip(shares.iter())
        .enumerate()
    {
        if key * value - pad != share.bedoza_receiver().tag() {
            bail!("BeDOZa opening tag verification failed at index {}", i);
        }
    }

    Ok(shares
        .iter()
        .zip(peer_values.iter())
        .map(|(share, &peer_value)| share.bedoza_sender().val() + peer_value)
        .collect())
}

fn open_authenticated_triples<IO: AbstractChannel>(
    io: &mut IO,
    triples: &[BeDOZaTriple],
    comm: &mut u64,
) -> Result<Vec<(FE, FE, FE)>> {
    let a_shares = triples.iter().map(|t| t.0).collect::<Vec<_>>();
    let b_shares = triples.iter().map(|t| t.1).collect::<Vec<_>>();
    let c_shares = triples.iter().map(|t| t.2).collect::<Vec<_>>();

    let opened_a = open_bedoza_values(io, &a_shares, comm)?;
    let opened_b = open_bedoza_values(io, &b_shares, comm)?;
    let opened_c = open_bedoza_values(io, &c_shares, comm)?;

    Ok((0..triples.len())
        .map(|i| (opened_a[i], opened_b[i], opened_c[i]))
        .collect())
}

fn run_sender(addr: &str, n: usize) -> Result<()> {
    let mut io = connect_with_retry(addr).with_context(|| format!("connect {addr}"))?;
    let mut comm = 0u64;
    let mut mascot = MascotTripleSender::new();
    let local_key = fq(DELTA_SENDER);
    let ot_times = n.max(1) * REPETITION;

    // Direction 1: this side is OT receiver (party=1), peer is OT sender (party=0).
    let mut cot_when_receiver = BaseCot::new(1, false);
    cot_when_receiver.cot_gen_pre(&mut io, None, &mut comm);
    let mut ot_when_receiver = OTPre::<FE_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
    cot_when_receiver.cot_gen_preot(
        &mut io,
        &mut ot_when_receiver,
        FOURQ_SCALAR_BITS * ot_times,
        None,
        &mut comm,
    );

    // Direction 2: this side is OT sender (party=0), peer is OT receiver (party=1).
    let mut cot_when_sender = BaseCot::new(0, false);
    cot_when_sender.cot_gen_pre(&mut io, None, &mut comm);
    let mut ot_when_sender = OTPre::<FE_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
    cot_when_sender.cot_gen_preot(
        &mut io,
        &mut ot_when_sender,
        FOURQ_SCALAR_BITS * ot_times,
        None,
        &mut comm,
    );

    let mut vole_rng = AesRng::new();
    // Sender role initializes VOLE sender first (peer initializes VOLE receiver first).
    let mut auth_vole_sender =
        BufferedVoleSender::init(&mut io, LPN21)
            .map_err(|e| anyhow!("init auth VOLE sender failed: {e}"))?;
    let mut auth_vole_receiver = BufferedVoleReceiver::init(
        &mut io,
        -local_key,
        LPN21,
    )
    .map_err(|e| anyhow!("init auth VOLE receiver failed: {e}"))?;

    let start = Instant::now();
    let local = mascot.triples(
        &mut io,
        &mut ot_when_receiver,
        &mut ot_when_sender,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        local_key,
        n,
        &mut comm,
    );
    let elapsed = start.elapsed();

    let opened = open_authenticated_triples(&mut io, &local, &mut comm)?;
    let ok = opened.iter().all(|(a, b, c)| *c == *a * *b);

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
    let mut mascot = MascotTripleReceiver::new();
    let local_key = fq(DELTA_RECEIVER);
    let ot_times = n.max(1) * REPETITION;

    // Direction 1 complement: this side is OT sender (party=0).
    let mut cot_when_sender = BaseCot::new(0, false);
    cot_when_sender.cot_gen_pre(&mut io, None, &mut comm);
    let mut ot_when_sender = OTPre::<FE_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
    cot_when_sender.cot_gen_preot(
        &mut io,
        &mut ot_when_sender,
        FOURQ_SCALAR_BITS * ot_times,
        None,
        &mut comm,
    );

    // Direction 2 complement: this side is OT receiver (party=1).
    let start = Instant::now();
    let mut cot_when_receiver = BaseCot::new(1, false);
    cot_when_receiver.cot_gen_pre(&mut io, None, &mut comm);
    let mut ot_when_receiver = OTPre::<FE_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
    cot_when_receiver.cot_gen_preot(
        &mut io,
        &mut ot_when_receiver,
        FOURQ_SCALAR_BITS * ot_times,
        None,
        &mut comm,
    );

    let mut vole_rng = AesRng::new();
    // Receiver role initializes VOLE receiver first (peer initializes VOLE sender first).
    let mut auth_vole_receiver = BufferedVoleReceiver::init(
        &mut io,
        -local_key,
        LPN21,
    )
    .map_err(|e| anyhow!("init auth VOLE receiver failed: {e}"))?;
    let mut auth_vole_sender =
        BufferedVoleSender::init(&mut io, LPN21)
            .map_err(|e| anyhow!("init auth VOLE sender failed: {e}"))?;

    println!("OT precomputation done: {:?}", start.elapsed());

    let start = Instant::now();
    let local = mascot.triples(
        &mut io,
        &mut ot_when_receiver,
        &mut ot_when_sender,
        &mut auth_vole_sender,
        &mut auth_vole_receiver,
        local_key,
        n,
        &mut comm,
    );
    let elapsed = start.elapsed();

    let opened = open_authenticated_triples(&mut io, &local, &mut comm)?;
    let ok = opened.iter().all(|(a, b, c)| *c == *a * *b);

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
