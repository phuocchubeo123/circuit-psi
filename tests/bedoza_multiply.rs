use std::{net::TcpListener, thread};

use anyhow::Result;
use circuit_psi::{
    bedoza::{
        BeDOZa, BeDOZaTriple, batch_multiply,
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::{BeDOZaSender, send_open_shares},
        defines::FE,
    },
    tcp_channel::{TcpChannel, connect_with_retry, listen_to},
};
use swanky_serialization::CanonicalSerialize;

fn fe(n: u8) -> FE {
    let mut bytes = [0u8; 16];
    bytes[0] = n;
    FE::from_bytes(&bytes.into()).expect("valid FE encoding")
}

fn free_local_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral localhost port");
    listener
        .local_addr()
        .expect("read ephemeral localhost addr")
        .to_string()
}

fn make_cross_party_share(
    v0: FE,
    p0: FE,
    v1: FE,
    p1: FE,
    key0: FE,
    key1: FE,
) -> (BeDOZa, BeDOZa) {
    // Party 0 keeps side-0 sender and side-1 receiver (authenticates party 1 sender).
    let party0 = BeDOZa::new(
        BeDOZaSender::new(v0, p0, false),
        BeDOZaReceiver::new(key0 * v1 + p1, key0, true),
    );

    // Party 1 keeps side-1 sender and side-0 receiver (authenticates party 0 sender).
    let party1 = BeDOZa::new(
        BeDOZaSender::new(v1, p1, true),
        BeDOZaReceiver::new(key1 * v0 + p0, key1, false),
    );

    (party0, party1)
}

fn build_inputs(
    key0: FE,
    key1: FE,
) -> (
    Vec<BeDOZa>,
    Vec<BeDOZa>,
    Vec<BeDOZaTriple>,
    Vec<BeDOZa>,
    Vec<BeDOZa>,
    Vec<BeDOZaTriple>,
    Vec<FE>,
) {
    let mut p0_x = Vec::new();
    let mut p0_y = Vec::new();
    let mut p0_t = Vec::new();
    let mut p1_x = Vec::new();
    let mut p1_y = Vec::new();
    let mut p1_t = Vec::new();
    let mut expected_products = Vec::new();

    // Item 0
    {
        let x0 = fe(7);
        let x1 = fe(5);
        let y0 = fe(9);
        let y1 = fe(4);
        let a0 = fe(3);
        let a1 = fe(6);
        let b0 = fe(8);
        let b1 = fe(2);
        let c0 = fe(11);
        let c1 = (a0 + a1) * (b0 + b1) - c0;

        let (x_p0, x_p1) = make_cross_party_share(x0, fe(13), x1, fe(17), key0, key1);
        let (y_p0, y_p1) = make_cross_party_share(y0, fe(19), y1, fe(23), key0, key1);
        let (a_p0, a_p1) = make_cross_party_share(a0, fe(29), a1, fe(31), key0, key1);
        let (b_p0, b_p1) = make_cross_party_share(b0, fe(37), b1, fe(41), key0, key1);
        let (c_p0, c_p1) = make_cross_party_share(c0, fe(43), c1, fe(47), key0, key1);

        p0_x.push(x_p0);
        p0_y.push(y_p0);
        p0_t.push((a_p0, b_p0, c_p0));
        p1_x.push(x_p1);
        p1_y.push(y_p1);
        p1_t.push((a_p1, b_p1, c_p1));
        expected_products.push((x0 + x1) * (y0 + y1));
    }

    // Item 1
    {
        let x0 = fe(12);
        let x1 = fe(14);
        let y0 = fe(1);
        let y1 = fe(15);
        let a0 = fe(9);
        let a1 = fe(10);
        let b0 = fe(11);
        let b1 = fe(7);
        let c0 = fe(21);
        let c1 = (a0 + a1) * (b0 + b1) - c0;

        let (x_p0, x_p1) = make_cross_party_share(x0, fe(22), x1, fe(24), key0, key1);
        let (y_p0, y_p1) = make_cross_party_share(y0, fe(25), y1, fe(26), key0, key1);
        let (a_p0, a_p1) = make_cross_party_share(a0, fe(27), a1, fe(28), key0, key1);
        let (b_p0, b_p1) = make_cross_party_share(b0, fe(30), b1, fe(32), key0, key1);
        let (c_p0, c_p1) = make_cross_party_share(c0, fe(33), c1, fe(34), key0, key1);

        p0_x.push(x_p0);
        p0_y.push(y_p0);
        p0_t.push((a_p0, b_p0, c_p0));
        p1_x.push(x_p1);
        p1_y.push(y_p1);
        p1_t.push((a_p1, b_p1, c_p1));
        expected_products.push((x0 + x1) * (y0 + y1));
    }

    (p0_x, p0_y, p0_t, p1_x, p1_y, p1_t, expected_products)
}

fn send_openings_for_peer(
    x_shares: &[BeDOZa],
    y_shares: &[BeDOZa],
    triples: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<()> {
    let d_shares: Vec<BeDOZa> = x_shares
        .iter()
        .zip(triples.iter())
        .map(|(x_share, triple)| {
            let (a_share, _, _) = triple;
            x_share - a_share
        })
        .collect();
    let d_senders: Vec<BeDOZaSender> = d_shares.iter().map(|share| *share.bedoza_sender()).collect();
    send_open_shares(&d_senders, channel)?;

    let e_shares: Vec<BeDOZa> = y_shares
        .iter()
        .zip(triples.iter())
        .map(|(y_share, triple)| {
            let (_, b_share, _) = triple;
            y_share - b_share
        })
        .collect();
    let e_senders: Vec<BeDOZaSender> = e_shares.iter().map(|share| *share.bedoza_sender()).collect();
    send_open_shares(&e_senders, channel)?;

    Ok(())
}

fn run_batch_with_peer_sender(
    local_x: Vec<BeDOZa>,
    local_y: Vec<BeDOZa>,
    local_t: Vec<BeDOZaTriple>,
    peer_x: Vec<BeDOZa>,
    peer_y: Vec<BeDOZa>,
    peer_t: Vec<BeDOZaTriple>,
) -> Result<Vec<BeDOZa>> {
    let addr = free_local_addr();
    let server_addr = addr.clone();
    let sender_thread = thread::spawn(move || -> Result<()> {
        let mut channel = listen_to(&server_addr)?;
        send_openings_for_peer(&peer_x, &peer_y, &peer_t, &mut channel)
    });

    let mut client_channel = connect_with_retry(&addr)?;
    let result = batch_multiply(&local_x, &local_y, &local_t, &mut client_channel)?;

    sender_thread.join().expect("peer sender thread panicked")?;
    Ok(result)
}

fn assert_cross_authenticated(local: &BeDOZa, remote: &BeDOZa) {
    let expected = local.bedoza_receiver().key() * remote.bedoza_sender().val() + remote.bedoza_sender().pad();
    assert_eq!(local.bedoza_receiver().tag(), expected);
}

#[test]
fn batch_multiply_localhost_roundtrip() -> Result<()> {
    let key0 = fe(97);
    let key1 = fe(113);

    let (p0_x_a, p0_y_a, p0_t_a, p1_x_a, p1_y_a, p1_t_a, expected_products) = build_inputs(key0, key1);
    let z0 = run_batch_with_peer_sender(
        p0_x_a,
        p0_y_a,
        p0_t_a,
        p1_x_a,
        p1_y_a,
        p1_t_a,
    )?;

    // Rebuild the same deterministic inputs to run the opposite direction.
    let (p0_x_b, p0_y_b, p0_t_b, p1_x_b, p1_y_b, p1_t_b, _) = build_inputs(key0, key1);
    let z1 = run_batch_with_peer_sender(
        p1_x_b,
        p1_y_b,
        p1_t_b,
        p0_x_b,
        p0_y_b,
        p0_t_b,
    )?;

    assert_eq!(z0.len(), expected_products.len());
    assert_eq!(z1.len(), expected_products.len());

    for ((left, right), expected) in z0.iter().zip(z1.iter()).zip(expected_products.iter()) {
        let opened = left.bedoza_sender().val() + right.bedoza_sender().val();
        assert_eq!(opened, *expected);

        assert_cross_authenticated(left, right);
        assert_cross_authenticated(right, left);
    }

    Ok(())
}
