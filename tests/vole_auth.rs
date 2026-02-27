use circuit_psi::{
    bedoza::vole_auth::{
        FourQVoleMac, authenticate_batch_with_peer_key_receiver,
        authenticate_batch_with_peer_key_sender,
    },
    scalar_field::{FourQScalarField, fq},
    tcp_channel::swanky_channel_from_tcp_stream,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use eyre::WrapErr;
use mac_n_cheese_vole::{mac::Mac, vole::VoleSizes};
use std::{
    net::{TcpListener, TcpStream},
    thread,
};
use swanky_aes_rng::AesRng;
use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier};

fn make_base_voles(
    key: FourQScalarField,
    count: usize,
) -> (
    Vec<Mac<Prover, FourQVoleMac>>,
    Vec<Mac<Verifier, FourQVoleMac>>,
) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let x = fq((i as u64) + 1);
        let beta = fq((i as u64) * 5 + 3);
        sender.push(Mac::prover_new(IS_PROVER, x, beta));
        receiver.push(Mac::verifier_new(IS_VERIFIER, x * key + beta));
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

#[test]
fn vole_authenticates_sender_batch_under_receiver_key() -> eyre::Result<()> {
    let owner_side = false;
    let receiver_key = fq(37);
    let delta = -receiver_key;
    let input_values: Vec<FourQScalarField> = (0..4096).map(|i| fq((i as u64) + 500)).collect();

    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let (base_sender, base_receiver) = make_base_voles(receiver_key, sizes.base_voles_needed);

    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("bind localhost listener")?;
    let addr = listener.local_addr().wrap_err("read listener address")?;
    let n = input_values.len();

    let sender_handle = thread::spawn(move || -> eyre::Result<_> {
        let (socket, _) = listener.accept().wrap_err("sender accept")?;
        let mut channel =
            swanky_channel_from_tcp_stream(socket).map_err(|e| eyre::eyre!("{}", e))?;
        let mut rng = AesRng::new();
        let mut vole =
            BufferedVoleSender::<FourQVoleMac>::init(&mut channel, &mut rng, base_sender)
                .wrap_err("init sender vole")?;
        let _added = vole
            .extend_random(&mut channel, &mut rng, n)
            .wrap_err("extend sender vole")?;
        authenticate_batch_with_peer_key_sender(&input_values, owner_side, &mut vole, &mut channel)
            .map_err(|e| eyre::eyre!("sender authenticate batch: {e}"))
    });

    let socket = connect_with_retry(addr)?;
    let mut channel = swanky_channel_from_tcp_stream(socket).map_err(|e| eyre::eyre!("{}", e))?;
    let mut rng = AesRng::new();
    let mut vole =
        BufferedVoleReceiver::<FourQVoleMac>::init(&mut channel, &mut rng, delta, base_receiver)
            .wrap_err("init receiver vole")?;
    let _added = vole
        .extend_random(&mut channel, &mut rng, n)
        .wrap_err("extend receiver vole")?;
    let receiver_authenticated = authenticate_batch_with_peer_key_receiver(
        n,
        owner_side,
        receiver_key,
        &mut vole,
        &mut channel,
    )
    .map_err(|e| eyre::eyre!("receiver authenticate batch: {e}"))?;

    let sender_authenticated = sender_handle
        .join()
        .expect("sender thread panicked")
        .wrap_err("sender failed")?;

    assert_eq!(sender_authenticated.len(), receiver_authenticated.len());
    for (sender, receiver) in sender_authenticated
        .iter()
        .zip(receiver_authenticated.iter())
    {
        assert_eq!(sender.side(), owner_side);
        assert_eq!(receiver.side(), owner_side);
        assert_eq!(receiver.key(), receiver_key);
        assert_eq!(
            receiver.tag(),
            receiver_key * sender.val() + sender.pad(),
            "receiver tag must authenticate sender value/pad under receiver key"
        );
    }

    Ok(())
}
