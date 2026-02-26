use circuit_psi::scalar_field::{FourQScalarField, fq};
use circuit_psi::tcp_channel::swanky_channel_from_tcp_stream;
use circuit_psi::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender};
use eyre::WrapErr;
use mac_n_cheese_vole::{mac::Mac, specialization::NoSpecialization, vole::VoleSizes};
use std::{
    net::{TcpListener, TcpStream},
    thread,
};
use swanky_aes_rng::AesRng;
use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier};

type ExampleMac = (FourQScalarField, FourQScalarField, NoSpecialization);

fn make_base_voles(
    alpha: FourQScalarField,
    count: usize,
) -> (Vec<Mac<Prover, ExampleMac>>, Vec<Mac<Verifier, ExampleMac>>) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let x = fq((i as u64) + 1);
        let beta = fq((i as u64) * 3 + 5);
        sender.push(Mac::prover_new(IS_PROVER, x, beta));
        receiver.push(Mac::verifier_new(IS_VERIFIER, x * alpha + beta));
    }
    (sender, receiver)
}

fn make_inputs(n: usize) -> Vec<FourQScalarField> {
    (0..n).map(|i| fq((i as u64) + 1000)).collect()
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

fn sender_party(
    listener: TcpListener,
    base_sender: Vec<Mac<Prover, ExampleMac>>,
    inputs: Vec<FourQScalarField>,
) -> eyre::Result<(Vec<Mac<Prover, ExampleMac>>, u64, u64, usize)> {
    let (socket, _) = listener.accept().wrap_err("sender accept")?;
    let mut channel = swanky_channel_from_tcp_stream(socket).map_err(|e| eyre::eyre!("{}", e))?;

    let mut rng = AesRng::new();
    let mut vole = BufferedVoleSender::<ExampleMac>::init(&mut channel, &mut rng, base_sender)?;
    let _added = vole.extend_random(&mut channel, &mut rng, inputs.len())?;
    let sender_output = vole.materialize_inputs(&mut channel, &inputs)?;

    Ok((
        sender_output,
        channel.bytes_sent(),
        channel.bytes_received(),
        vole.random_available(),
    ))
}

fn receiver_party(
    addr: std::net::SocketAddr,
    delta: FourQScalarField,
    base_receiver: Vec<Mac<Verifier, ExampleMac>>,
    output_len: usize,
) -> eyre::Result<(Vec<Mac<Verifier, ExampleMac>>, u64, u64, usize)> {
    let socket = connect_with_retry(addr)?;
    let mut channel = swanky_channel_from_tcp_stream(socket).map_err(|e| eyre::eyre!("{}", e))?;

    let mut rng = AesRng::new();
    let mut vole =
        BufferedVoleReceiver::<ExampleMac>::init(&mut channel, &mut rng, delta, base_receiver)?;
    let _added = vole.extend_random(&mut channel, &mut rng, output_len)?;
    let receiver_output = vole.materialize_next(&mut channel, output_len)?;

    Ok((
        receiver_output,
        channel.bytes_sent(),
        channel.bytes_received(),
        vole.random_available(),
    ))
}

fn main() -> eyre::Result<()> {
    let output_len = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10_000);

    let alpha = fq(7);
    let delta = -alpha;
    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let (base_sender, base_receiver) = make_base_voles(alpha, sizes.base_voles_needed);
    let inputs = make_inputs(output_len);

    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("bind localhost listener")?;
    let addr = listener.local_addr().wrap_err("read listener address")?;

    let sender_handle = thread::spawn(move || sender_party(listener, base_sender, inputs));
    let (receiver_output, receiver_sent, receiver_received, receiver_left) =
        receiver_party(addr, delta, base_receiver, output_len)?;
    let (sender_output, sender_sent, sender_received, sender_left) = sender_handle
        .join()
        .expect("sender thread panicked")
        .wrap_err("sender party failed")?;

    assert_eq!(sender_output.len(), receiver_output.len());
    for (sender_vole, receiver_vole) in sender_output.iter().zip(receiver_output.iter()) {
        let (x, beta) = (*sender_vole).into();
        assert_eq!(x * alpha + beta, receiver_vole.tag(IS_VERIFIER));
    }

    println!(
        "buffered mac-n-cheese VOLE check passed over FourQ scalar field ({} output VOLEs)",
        sender_output.len()
    );
    println!(
        "unused random VOLEs: sender={}, receiver={}",
        sender_left, receiver_left
    );
    println!(
        "sender bytes: sent={}, received={} | receiver bytes: sent={}, received={}",
        sender_sent, sender_received, receiver_sent, receiver_received
    );
    Ok(())
}
