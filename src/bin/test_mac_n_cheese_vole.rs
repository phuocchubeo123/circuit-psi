use circuit_psi::scalar_field::{FourQScalarField, fq};
use eyre::WrapErr;
use keyed_arena::KeyedArena;
use mac_n_cheese_vole::{
    mac::Mac,
    specialization::NoSpecialization,
    vole::{VoleReceiver, VoleSender, VoleSizes},
};
use std::{
    io::{BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    thread,
};
use swanky_aes_rng::AesRng;
use swanky_channel_legacy::{AbstractChannel, Channel};
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

fn connect_with_retry(addr: std::net::SocketAddr) -> eyre::Result<TcpStream> {
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(addr) {
            return Ok(stream);
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
    eyre::bail!("failed to connect to {addr}");
}

fn send_buffer(channel: &mut impl AbstractChannel, buf: &[u8]) -> eyre::Result<()> {
    channel.write_bytes(buf)?;
    channel.flush()?;
    Ok(())
}

fn recv_buffer(channel: &mut impl AbstractChannel, buf: &mut [u8]) -> eyre::Result<()> {
    channel.read_bytes(buf)?;
    Ok(())
}

fn sender_party(
    listener: TcpListener,
    base_sender: Vec<Mac<Prover, ExampleMac>>,
) -> eyre::Result<Vec<Mac<Prover, ExampleMac>>> {
    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let (socket, _) = listener.accept().wrap_err("sender accept")?;
    let mut channel = Channel::new(
        BufReader::new(socket.try_clone().wrap_err("clone sender socket")?),
        BufWriter::new(socket),
    );

    let mut rng = AesRng::new();
    let sender = VoleSender::<ExampleMac>::init(&mut channel, &mut rng)?;
    channel.flush()?;

    let arena = KeyedArena::with_capacity(0, 0);
    let selector = 1;
    let mut comms_1 = vec![0u8; sizes.comms_1s];
    let mut comms_2 = vec![0u8; sizes.comms_2r];
    let mut comms_3 = vec![0u8; sizes.comms_3s];
    let mut comms_4 = vec![0u8; sizes.comms_4r];
    let mut comms_5 = vec![0u8; sizes.comms_5s];

    let sender_stage2 = sender.send(
        &arena,
        selector,
        &mut AesRng::new(),
        &base_sender,
        &mut comms_1,
    )?;
    send_buffer(&mut channel, &comms_1)?;

    recv_buffer(&mut channel, &mut comms_2)?;
    let mut sender_output = vec![Mac::zero(); sizes.voles_outputted];
    let sender_stage3 = sender_stage2.stage2(
        &sender,
        &arena,
        &base_sender,
        &mut sender_output,
        &comms_2,
        &mut comms_3,
    )?;
    send_buffer(&mut channel, &comms_3)?;

    recv_buffer(&mut channel, &mut comms_4)?;
    sender_stage3.stage3(
        &sender,
        &arena,
        &base_sender,
        &mut sender_output,
        &comms_4,
        &mut comms_5,
    )?;
    send_buffer(&mut channel, &comms_5)?;

    Ok(sender_output)
}

fn receiver_party(
    addr: std::net::SocketAddr,
    delta: FourQScalarField,
    base_receiver: Vec<Mac<Verifier, ExampleMac>>,
) -> eyre::Result<Vec<Mac<Verifier, ExampleMac>>> {
    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let socket = connect_with_retry(addr)?;
    let mut channel = Channel::new(
        BufReader::new(socket.try_clone().wrap_err("clone receiver socket")?),
        BufWriter::new(socket),
    );

    let mut rng = AesRng::new();
    let receiver = VoleReceiver::<ExampleMac>::init(&mut channel, &mut rng, delta)?;
    channel.flush()?;

    let arena = KeyedArena::with_capacity(0, 0);
    let selector = 1;
    let mut comms_1 = vec![0u8; sizes.comms_1s];
    let mut comms_2 = vec![0u8; sizes.comms_2r];
    let mut comms_3 = vec![0u8; sizes.comms_3s];
    let mut comms_4 = vec![0u8; sizes.comms_4r];
    let mut comms_5 = vec![0u8; sizes.comms_5s];

    recv_buffer(&mut channel, &mut comms_1)?;
    let mut receiver_output = vec![Mac::zero(); sizes.voles_outputted];
    let receiver_stage2 = receiver.receive(
        &arena,
        selector,
        &mut AesRng::new(),
        &base_receiver,
        &mut receiver_output,
        &comms_1,
        &mut comms_2,
    )?;
    send_buffer(&mut channel, &comms_2)?;

    recv_buffer(&mut channel, &mut comms_3)?;
    let receiver_stage3 = receiver_stage2.stage2(
        &receiver,
        &arena,
        &base_receiver,
        &mut receiver_output,
        &comms_3,
        &mut comms_4,
    )?;
    send_buffer(&mut channel, &comms_4)?;

    recv_buffer(&mut channel, &mut comms_5)?;
    receiver_stage3.stage3(
        &receiver,
        &arena,
        &base_receiver,
        &mut receiver_output,
        &comms_5,
    )?;

    Ok(receiver_output)
}

fn main() -> eyre::Result<()> {
    let alpha = fq(7);
    let delta = -alpha;
    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let (base_sender, base_receiver) = make_base_voles(alpha, sizes.base_voles_needed);

    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("bind localhost listener")?;
    let addr = listener.local_addr().wrap_err("read listener address")?;

    let sender_handle = thread::spawn(move || sender_party(listener, base_sender));
    let receiver_output = receiver_party(addr, delta, base_receiver)?;
    let sender_output = sender_handle
        .join()
        .expect("sender thread panicked")
        .wrap_err("sender party failed")?;

    assert_eq!(sender_output.len(), receiver_output.len());
    for (sender_vole, receiver_vole) in sender_output.iter().zip(receiver_output.iter()) {
        let (x, beta) = (*sender_vole).into();
        assert_eq!(x * alpha + beta, receiver_vole.tag(IS_VERIFIER));
    }

    println!(
        "mac-n-cheese-vole TCP check passed over FourQ subgroup-order field ({} output VOLEs)",
        sender_output.len()
    );
    Ok(())
}
