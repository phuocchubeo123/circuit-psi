use circuit_psi::bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender};
use circuit_psi::scalar_field::{FourQScalarField, fq};
use circuit_psi::tcp_channel::{connect_with_retry, listen_to};
use circuit_psi::vole_triple::LPN21;
use circuit_psi::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender};
use eyre::WrapErr;
use circuit_psi::mac_n_cheese_vole::vole::VoleSizes;
use std::{
    net::TcpListener,
    thread,
};
use swanky_channel_legacy::AesRng;

fn make_base_voles(
    alpha: FourQScalarField,
    count: usize,
) -> (Vec<BeDOZaSender>, Vec<BeDOZaReceiver>) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let x = fq((i as u64) + 1);
        let beta = fq((i as u64) * 3 + 5);
        sender.push(BeDOZaSender::new(x, beta, false));
        receiver.push(BeDOZaReceiver::new(x * alpha + beta, alpha, false));
    }
    (sender, receiver)
}

fn make_inputs(n: usize) -> Vec<FourQScalarField> {
    (0..n).map(|i| fq((i as u64) + 1000)).collect()
}

fn sender_party(
    addr: &str,
    _base_sender: Vec<BeDOZaSender>,
    inputs: Vec<FourQScalarField>,
) -> eyre::Result<(Vec<BeDOZaSender>, u64, u64, usize)> {
    let mut channel = listen_to(addr).map_err(|e| eyre::eyre!("{}", e))?;

    let mut rng = AesRng::new();
    let mut vole = BufferedVoleSender::init(&mut channel, LPN21)?;
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
    addr: &str,
    delta: FourQScalarField,
    base_receiver: Vec<BeDOZaReceiver>,
    output_len: usize,
) -> eyre::Result<(Vec<BeDOZaReceiver>, u64, u64, usize)> {
    let mut channel = connect_with_retry(addr).map_err(|e| eyre::eyre!("{}", e))?;

    let mut rng = AesRng::new();
    let mut vole =
        BufferedVoleReceiver::init(&mut channel, delta, LPN21)?;
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
    let addr_str = listener.local_addr().wrap_err("read listener address")?.to_string();
    drop(listener);

    let sender_addr = addr_str.clone();
    let sender_handle = thread::spawn(move || sender_party(&sender_addr, base_sender, inputs));
    let (receiver_output, receiver_sent, receiver_received, receiver_left) =
        receiver_party(&addr_str, delta, base_receiver, output_len)?;
    let (sender_output, sender_sent, sender_received, sender_left) = sender_handle
        .join()
        .expect("sender thread panicked")
        .wrap_err("sender party failed")?;

    assert_eq!(sender_output.len(), receiver_output.len());
    for (sender_vole, receiver_vole) in sender_output.iter().zip(receiver_output.iter()) {
        assert_eq!(sender_vole.val() * alpha + sender_vole.pad(), receiver_vole.tag());
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
