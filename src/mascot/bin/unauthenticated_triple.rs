use anyhow::{Context, Result, bail};
use circuit_psi::base_cot::BaseCot;
use circuit_psi::comm_util::{receive_fe, send_fe};
use circuit_psi::mascot::triple::{MascotTripleReceiver, MascotTripleSender, TripleShare};
use circuit_psi::network::tcp_channel::{connect_swanky_with_retry, listen_swanky};
use circuit_psi::pre_ot::OTPre;
use circuit_psi::scalar_field::FOURQ_SCALAR_BITS;
use std::time::Instant;

const DEFAULT_ADDR: &str = "127.0.0.1:19110";
const KEY_OT_LIMBS: usize = 1;

fn exchange_shares<IO: swanky_channel_legacy::AbstractChannel>(
    io: &mut IO,
    local: &[TripleShare],
    comm: &mut u64,
) -> Result<Vec<TripleShare>> {
    let mut payload = Vec::with_capacity(local.len() * 3);
    for share in local {
        payload.push(share.a);
        payload.push(share.b);
        payload.push(share.c);
    }
    *comm += send_fe(io, &payload).context("failed to send local shares")?;
    let peer = receive_fe(io).context("failed to receive peer shares")?;
    if peer.len() != local.len() * 3 {
        bail!(
            "expected {} elements in peer shares, got {}",
            local.len() * 3,
            peer.len()
        );
    }

    let mut out = Vec::with_capacity(local.len());
    for i in 0..local.len() {
        out.push(TripleShare {
            a: peer[3 * i],
            b: peer[3 * i + 1],
            c: peer[3 * i + 2],
        });
    }
    Ok(out)
}

fn verify(local: TripleShare, peer: TripleShare) -> bool {
    let a = local.a + peer.a;
    let b = local.b + peer.b;
    let c = local.c + peer.c;
    c == a * b
}

fn run_sender(addr: &str, n: usize) -> Result<()> {
    let mut io = connect_swanky_with_retry(addr).with_context(|| format!("connect {addr}"))?;
    let mut comm = 0u64;
    let mut mascot = MascotTripleSender::new();
    let ot_times = n.max(1);

    // Direction 1: this side is OT receiver (party=1), peer is OT sender (party=0).
    let mut cot_when_receiver = BaseCot::new(1, false);
    cot_when_receiver.cot_gen_pre(&mut io, None, &mut comm);
    let mut ot_when_receiver = OTPre::<KEY_OT_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
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
    let mut ot_when_sender = OTPre::<KEY_OT_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
    cot_when_sender.cot_gen_preot(
        &mut io,
        &mut ot_when_sender,
        FOURQ_SCALAR_BITS * ot_times,
        None,
        &mut comm,
    );

    let start = Instant::now();
    let local = mascot.unauthenticated_triples(
        &mut io,
        &mut ot_when_receiver,
        &mut ot_when_sender,
        n,
        &mut comm,
    );
    let elapsed = start.elapsed();

    let peer = exchange_shares(&mut io, &local, &mut comm)?;
    let ok = local
        .iter()
        .zip(peer.iter())
        .all(|(l, p)| verify(*l, *p));

    println!("role: sender");
    println!("unauthenticated_triples n={}: {:?}", n, elapsed);
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
    let mut io = listen_swanky(addr).with_context(|| format!("listen {addr}"))?;
    let mut comm = 0u64;
    let mut mascot = MascotTripleReceiver::new();
    let ot_times = n.max(1);

    // Direction 1 complement: this side is OT sender (party=0).
    let mut cot_when_sender = BaseCot::new(0, false);
    cot_when_sender.cot_gen_pre(&mut io, None, &mut comm);
    let mut ot_when_sender = OTPre::<KEY_OT_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
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
    let mut ot_when_receiver = OTPre::<KEY_OT_LIMBS>::new(FOURQ_SCALAR_BITS, ot_times);
    cot_when_receiver.cot_gen_preot(
        &mut io,
        &mut ot_when_receiver,
        FOURQ_SCALAR_BITS * ot_times,
        None,
        &mut comm,
    );

    println!("OT precomputation done: {:?}", start.elapsed());

    let start = Instant::now();
    let local = mascot.unauthenticated_triples(
        &mut io,
        &mut ot_when_receiver,
        &mut ot_when_sender,
        n,
        &mut comm,
    );
    let elapsed = start.elapsed();

    let peer = exchange_shares(&mut io, &local, &mut comm)?;
    let ok = local
        .iter()
        .zip(peer.iter())
        .all(|(l, p)| verify(*l, *p));

    println!("role: receiver");
    println!("unauthenticated_triples n={}: {:?}", n, elapsed);
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
