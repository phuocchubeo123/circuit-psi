use circuit_psi::scalar_field::{FourQScalarField, fq};
use circuit_psi::tcp_channel::swanky_channel_from_tcp_stream;
use circuit_psi::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender};
use eyre::WrapErr;
use mac_n_cheese_vole::{
    mac::Mac,
    specialization::NoSpecialization,
    vole::VoleSizes,
};
use std::{
    net::{TcpListener, TcpStream},
    thread,
};
use swanky_aes_rng::AesRng;
use swanky_party::{IS_VERIFIER, Prover, Verifier};

type ExampleMac = (FourQScalarField, FourQScalarField, NoSpecialization);

const DEFAULT_EXTEND_1: usize = 1_000_000;
const DEFAULT_EXTEND_2: usize = 0;
const DEFAULT_MATERIALIZE_1: usize = 6_000;
const DEFAULT_MATERIALIZE_2: usize = 11_000;

fn make_base_voles(
    alpha: FourQScalarField,
    count: usize,
) -> (Vec<Mac<Prover, ExampleMac>>, Vec<Mac<Verifier, ExampleMac>>) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let x = fq((i as u64) + 1);
        let beta = fq((i as u64) * 7 + 9);
        sender.push(Mac::prover_new(swanky_party::IS_PROVER, x, beta));
        receiver.push(Mac::verifier_new(IS_VERIFIER, x * alpha + beta));
    }
    (sender, receiver)
}

fn connect_with_retry(addr: std::net::SocketAddr) -> eyre::Result<TcpStream> {
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(addr) {
            return Ok(stream);
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
    eyre::bail!("failed to connect to {addr}");
}

fn make_inputs(offset: u64, n: usize) -> Vec<FourQScalarField> {
    (0..n).map(|i| fq(offset + i as u64)).collect()
}

fn sender_party(
    listener: TcpListener,
    base_sender: Vec<Mac<Prover, ExampleMac>>,
    extend_1: usize,
    extend_2: usize,
    materialize_1: usize,
    materialize_2: usize,
) -> eyre::Result<(Vec<Mac<Prover, ExampleMac>>, Vec<Mac<Prover, ExampleMac>>, u64, u64, usize)> {
    let (socket, _) = listener.accept().wrap_err("sender accept")?;
    let mut channel = swanky_channel_from_tcp_stream(socket).map_err(|e| eyre::eyre!("{}", e))?;

    let mut rng = AesRng::new();
    let mut vole = BufferedVoleSender::<ExampleMac>::init(&mut channel, &mut rng, base_sender)?;
    let _added_1 = vole.extend_random(&mut channel, &mut rng, extend_1)?;
    let _added_2 = vole.extend_random(&mut channel, &mut rng, extend_2)?;

    let inputs_1 = make_inputs(1_000, materialize_1);
    let inputs_2 = make_inputs(50_000, materialize_2);
    let out_1 = vole.materialize_inputs(&mut channel, &inputs_1)?;
    let out_2 = vole.materialize_inputs(&mut channel, &inputs_2)?;

    Ok((
        out_1,
        out_2,
        channel.bytes_sent(),
        channel.bytes_received(),
        vole.random_available(),
    ))
}

fn receiver_party(
    addr: std::net::SocketAddr,
    delta: FourQScalarField,
    base_receiver: Vec<Mac<Verifier, ExampleMac>>,
    extend_1: usize,
    extend_2: usize,
    materialize_1: usize,
    materialize_2: usize,
) -> eyre::Result<(
    Vec<Mac<Verifier, ExampleMac>>,
    Vec<Mac<Verifier, ExampleMac>>,
    u64,
    u64,
    usize,
)> {
    let socket = connect_with_retry(addr)?;
    let mut channel = swanky_channel_from_tcp_stream(socket).map_err(|e| eyre::eyre!("{}", e))?;

    let mut rng = AesRng::new();
    let mut vole =
        BufferedVoleReceiver::<ExampleMac>::init(&mut channel, &mut rng, delta, base_receiver)?;
    let _added_1 = vole.extend_random(&mut channel, &mut rng, extend_1)?;
    let _added_2 = vole.extend_random(&mut channel, &mut rng, extend_2)?;

    let out_1 = vole.materialize_next(&mut channel, materialize_1)?;
    let out_2 = vole.materialize_next(&mut channel, materialize_2)?;

    Ok((
        out_1,
        out_2,
        channel.bytes_sent(),
        channel.bytes_received(),
        vole.random_available(),
    ))
}

fn verify_batch(
    alpha: FourQScalarField,
    sender_out: &[Mac<Prover, ExampleMac>],
    receiver_out: &[Mac<Verifier, ExampleMac>],
) {
    assert_eq!(sender_out.len(), receiver_out.len());
    for (sv, rv) in sender_out.iter().zip(receiver_out.iter()) {
        let (x, beta) = (*sv).into();
        assert_eq!(x * alpha + beta, rv.tag(IS_VERIFIER));
    }
}

fn main() -> eyre::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let extend_1 = args
        .get(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_EXTEND_1);
    let extend_2 = args
        .get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_EXTEND_2);
    let materialize_1 = args
        .get(3)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MATERIALIZE_1);
    let materialize_2 = args
        .get(4)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MATERIALIZE_2);

    let alpha = fq(7);
    let delta = -alpha;
    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let (base_sender, base_receiver) = make_base_voles(alpha, sizes.base_voles_needed);

    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("bind localhost listener")?;
    let addr = listener.local_addr().wrap_err("read listener address")?;

    let sender_handle = thread::spawn(move || {
        sender_party(
            listener,
            base_sender,
            extend_1,
            extend_2,
            materialize_1,
            materialize_2,
        )
    });
    let (receiver_1, receiver_2, receiver_sent, receiver_received, receiver_left) =
        receiver_party(
            addr,
            delta,
            base_receiver,
            extend_1,
            extend_2,
            materialize_1,
            materialize_2,
        )?;
    let (sender_1, sender_2, sender_sent, sender_received, sender_left) = sender_handle
        .join()
        .expect("sender thread panicked")
        .wrap_err("sender party failed")?;

    verify_batch(alpha, &sender_1, &receiver_1);
    verify_batch(alpha, &sender_2, &receiver_2);

    println!(
        "buffered VOLE wrapper check passed. extend=({}, {}), materialized=({}, {})",
        extend_1,
        extend_2,
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
