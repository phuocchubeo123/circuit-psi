use circuit_psi::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::{defines::FE, scalar_field::fq},
    tcp_channel::{connect_with_retry, listen_to},
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use clap::Parser;
use eyre::WrapErr;
use std::{net::TcpListener, thread};
use swanky_channel_legacy::AesRng;

const DEFAULT_EXTEND_CHUNK: usize = 10_000;
const DEFAULT_MATERIALIZE_1: usize = 6_000;
const DEFAULT_MATERIALIZE_2: usize = 11_000;

#[derive(Debug, Clone, Copy, Parser)]
#[command(name = "test_buffered_vole_wrapper")]
struct Args {
    #[arg(long, default_value_t = DEFAULT_EXTEND_CHUNK)]
    extend_chunk: usize,
    #[arg(long, default_value_t = DEFAULT_MATERIALIZE_1)]
    materialize_1: usize,
    #[arg(long, default_value_t = DEFAULT_MATERIALIZE_2)]
    materialize_2: usize,
}

fn make_inputs(offset: u64, n: usize) -> Vec<FE> {
    (0..n).map(|i| fq(offset + i as u64)).collect()
}

fn sender_party(
    addr: &str,
    extend_chunk: usize,
    materialize_1: usize,
    materialize_2: usize,
) -> eyre::Result<(
    Vec<BeDOZaSender>,
    Vec<BeDOZaSender>,
    Vec<BeDOZaSender>,
    u64,
    u64,
    usize,
)> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{e}"))?;

    let _rng = AesRng::new();
    let mut vole = BufferedVoleSender::init(&mut channel, LPN21)?;

    let random_count = extend_chunk;
    let random_out = vole.random_auth(&mut channel, random_count)?;

    let inputs_1 = make_inputs(1_000, materialize_1);
    let inputs_2 = make_inputs(50_000, materialize_2);

    let out_1 = vole.commit_auth(&mut channel, &inputs_1)?;
    let out_2 = vole.commit_auth(&mut channel, &inputs_2)?;

    Ok((
        random_out,
        out_1,
        out_2,
        channel.bytes_sent(),
        channel.bytes_received(),
        vole.random_available(),
    ))
}

fn receiver_party(
    addr: &str,
    delta: FE,
    extend_chunk: usize,
    materialize_1: usize,
    materialize_2: usize,
) -> eyre::Result<(
    Vec<BeDOZaReceiver>,
    Vec<BeDOZaReceiver>,
    Vec<BeDOZaReceiver>,
    u64,
    u64,
    usize,
)> {
    let mut channel = connect_with_retry(addr).map_err(|e| eyre::eyre!("{e}"))?;

    let _rng = AesRng::new();
    let mut vole = BufferedVoleReceiver::init(&mut channel, delta, LPN21)?;

    let random_count = extend_chunk;
    let random_out = vole.random_auth(&mut channel, random_count)?;
    let out_1 = vole.commit_auth(&mut channel, materialize_1)?;
    let out_2 = vole.commit_auth(&mut channel, materialize_2)?;

    Ok((
        random_out,
        out_1,
        out_2,
        channel.bytes_sent(),
        channel.bytes_received(),
        vole.random_available(),
    ))
}

fn verify_batch(delta: FE, sender_out: &[BeDOZaSender], receiver_out: &[BeDOZaReceiver]) {
    assert_eq!(sender_out.len(), receiver_out.len());
    for (sv, rv) in sender_out.iter().zip(receiver_out.iter()) {
        assert_eq!(sv.val() * delta - sv.pad(), rv.tag());
    }
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let delta = fq(7);

    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("bind localhost listener")?;
    let addr_str = listener
        .local_addr()
        .wrap_err("read listener address")?
        .to_string();
    drop(listener);

    let sender_addr = addr_str.clone();
    let sender_handle = thread::spawn(move || {
        sender_party(
            &sender_addr,
            args.extend_chunk,
            args.materialize_1,
            args.materialize_2,
        )
    });
    let (receiver_random, receiver_1, receiver_2, receiver_sent, receiver_received, receiver_left) =
        receiver_party(
            &addr_str,
            delta,
            args.extend_chunk,
            args.materialize_1,
            args.materialize_2,
        )?;
    let (sender_random, sender_1, sender_2, sender_sent, sender_received, sender_left) =
        sender_handle
            .join()
            .expect("sender thread panicked")
            .wrap_err("sender party failed")?;

    verify_batch(delta, &sender_random, &receiver_random);
    verify_batch(delta, &sender_1, &receiver_1);
    verify_batch(delta, &sender_2, &receiver_2);

    println!(
        "buffered VOLE wrapper check passed. random_auth={}, materialized=({}, {})",
        args.extend_chunk,
        sender_1.len(),
        sender_2.len(),
    );
    println!(
        "random buffer left: sender={}, receiver={}",
        sender_left, receiver_left
    );
    println!(
        "sender bytes: sent={}, received={} | receiver bytes: sent={}, received={}",
        sender_sent, sender_received, receiver_sent, receiver_received
    );
    Ok(())
}
