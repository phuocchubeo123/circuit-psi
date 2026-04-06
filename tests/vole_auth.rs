use circuit_psi::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    bedoza::vole_auth::{
        authenticate_batch_with_peer_key_receiver,
        authenticate_batch_with_peer_key_sender,
    },
    scalar_field::{FourQScalarField, fq},
    tcp_channel::{connect_with_retry, listen_to},
    vole_triple::LPN21,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use eyre::WrapErr;
use circuit_psi::mac_n_cheese_vole::vole::VoleSizes;
use std::{
    net::TcpListener,
    thread,
};
use swanky_channel_legacy::AesRng;

fn make_base_voles(
    key: FourQScalarField,
    count: usize,
) -> (
    Vec<BeDOZaSender>,
    Vec<BeDOZaReceiver>,
) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let x = fq((i as u64) + 1);
        let beta = fq((i as u64) * 5 + 3);
        sender.push(BeDOZaSender::new(x, beta, false));
        receiver.push(BeDOZaReceiver::new(x * key + beta, key, false));
    }
    (sender, receiver)
}

#[test]
fn vole_authenticates_sender_batch_under_receiver_key() -> eyre::Result<()> {
    let owner_side = false;
    let receiver_key = fq(37);
    let delta = -receiver_key;
    let input_values: Vec<FourQScalarField> = (0..4096).map(|i| fq((i as u64) + 500)).collect();

    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let (_base_sender, _base_receiver) = make_base_voles(receiver_key, sizes.base_voles_needed);

    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("bind localhost listener")?;
    let addr_str = listener
        .local_addr()
        .wrap_err("read listener address")?
        .to_string();
    drop(listener);
    let n = input_values.len();

    let sender_addr = addr_str.clone();
    let sender_handle = thread::spawn(move || -> eyre::Result<_> {
        let mut channel = listen_to(&sender_addr).map_err(|e| eyre::eyre!("{e}"))?;
        let mut rng = AesRng::new();
        let mut vole =
            BufferedVoleSender::init(&mut channel, LPN21)
                .wrap_err("init sender vole")?;
        let _added = vole
            .extend_random(&mut channel, &mut rng, n)
            .wrap_err("extend sender vole")?;
        authenticate_batch_with_peer_key_sender(&input_values, owner_side, &mut vole, &mut channel)
            .map_err(|e| eyre::eyre!("sender authenticate batch: {e}"))
    });

    let mut channel = connect_with_retry(&addr_str).map_err(|e| eyre::eyre!("{e}"))?;
    let mut rng = AesRng::new();
    let mut vole =
        BufferedVoleReceiver::init(&mut channel, delta, LPN21)
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
