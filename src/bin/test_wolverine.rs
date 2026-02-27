use anyhow::{Context, Result, ensure};
use circuit_psi::{
    bedoza::{
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        defines::FE,
        wolverine::{wolverine_batch_mul_prove, wolverine_batch_mul_verify},
    },
    scalar_field::fq,
    tcp_channel::swanky_channel_from_tcp_stream,
};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

type SenderBatch = (
    Vec<BeDOZaSender>,
    Vec<BeDOZaSender>,
    Vec<BeDOZaSender>,
    BeDOZaSender,
);
type ReceiverBatch = (
    Vec<BeDOZaReceiver>,
    Vec<BeDOZaReceiver>,
    Vec<BeDOZaReceiver>,
    BeDOZaReceiver,
);

fn connect_with_retry(addr: SocketAddr) -> Result<TcpStream> {
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(addr) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(5));
    }
    anyhow::bail!("failed to connect to {}", addr);
}

fn make_batch(delta_1: FE, gates: usize, tamper_one_gate: bool) -> (SenderBatch, ReceiverBatch) {
    let mut a_sender = Vec::with_capacity(gates);
    let mut b_sender = Vec::with_capacity(gates);
    let mut c_sender = Vec::with_capacity(gates);

    let mut a_receiver = Vec::with_capacity(gates);
    let mut b_receiver = Vec::with_capacity(gates);
    let mut c_receiver = Vec::with_capacity(gates);

    for i in 0..gates {
        let a = fq((i as u64) + 2);
        let b = fq((i as u64) * 3 + 5);
        let mut c = a * b;
        if tamper_one_gate && i == gates / 2 {
            c += fq(1);
        }

        let pad_a = fq((i as u64) * 7 + 11);
        let pad_b = fq((i as u64) * 13 + 17);
        let pad_c = fq((i as u64) * 19 + 23);

        a_sender.push(BeDOZaSender::new(a, pad_a, false));
        b_sender.push(BeDOZaSender::new(b, pad_b, false));
        c_sender.push(BeDOZaSender::new(c, pad_c, false));

        a_receiver.push(BeDOZaReceiver::new(delta_1 * a + pad_a, delta_1, false));
        b_receiver.push(BeDOZaReceiver::new(delta_1 * b + pad_b, delta_1, false));
        c_receiver.push(BeDOZaReceiver::new(delta_1 * c + pad_c, delta_1, false));
    }

    let dummy_x = fq(1234567);
    let dummy_pad = fq(7654321);
    let dummy_sender = BeDOZaSender::new(dummy_x, dummy_pad, false);
    let dummy_receiver = BeDOZaReceiver::new(delta_1 * dummy_x + dummy_pad, delta_1, false);

    (
        (a_sender, b_sender, c_sender, dummy_sender),
        (a_receiver, b_receiver, c_receiver, dummy_receiver),
    )
}

fn run_round(delta_1: FE, gates: usize, tamper_one_gate: bool, expect_ok: bool) -> Result<()> {
    let ((a_s, b_s, c_s, dummy_s), (a_r, b_r, c_r, dummy_r)) =
        make_batch(delta_1, gates, tamper_one_gate);

    let listener = TcpListener::bind("127.0.0.1:0").context("bind localhost listener")?;
    let addr = listener.local_addr().context("read listener address")?;

    let prover_handle = thread::spawn(move || -> Result<()> {
        let (socket, _) = listener.accept().context("prover accept")?;
        let mut channel = swanky_channel_from_tcp_stream(socket)?;
        wolverine_batch_mul_prove(&a_s, &b_s, &c_s, &dummy_s, &mut channel)
            .context("prover failed in Wolverine batch-mul proof")
    });

    let socket = connect_with_retry(addr)?;
    let mut channel = swanky_channel_from_tcp_stream(socket)?;
    let verifier_result = wolverine_batch_mul_verify(&a_r, &b_r, &c_r, &dummy_r, &mut channel);

    let prover_result = prover_handle.join().expect("prover thread panicked");
    prover_result?;

    if expect_ok {
        verifier_result.context("verifier unexpectedly rejected valid batch")?;
    } else {
        ensure!(
            verifier_result.is_err(),
            "verifier unexpectedly accepted invalid batch"
        );
    }

    Ok(())
}

fn main() -> Result<()> {
    let gates = std::env::args()
        .nth(1)
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(4096);
    ensure!(gates > 0, "number of gates must be > 0");

    let delta_1 = fq(37);

    run_round(delta_1, gates, false, true)?;
    println!(
        "wolverine round 1 (valid) passed for {} multiplication gates",
        gates
    );

    run_round(delta_1, gates, true, false)?;
    println!("wolverine round 2 (tampered c) correctly failed verification");

    println!("wolverine batch-mul proof test completed");
    Ok(())
}
