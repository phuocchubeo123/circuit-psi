use anyhow::{Context, Result, ensure};
use circuit_psi::{
    bedoza::{
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        defines::FE,
        wolverine::{wolverine_batch_mul_prove, wolverine_batch_mul_verify},
    },
    scalar_field::fq,
    tcp_channel::{connect_with_retry, listen_to},
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
    vole_triple::LPN21,
};
use std::{
    net::TcpListener,
    thread,
};

type SenderBatch = (
    Vec<BeDOZaSender>,
    Vec<BeDOZaSender>,
    Vec<BeDOZaSender>,
);
type ReceiverBatch = (
    Vec<BeDOZaReceiver>,
    Vec<BeDOZaReceiver>,
    Vec<BeDOZaReceiver>,
);

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

        a_receiver.push(BeDOZaReceiver::new(delta_1 * a - pad_a, delta_1, false));
        b_receiver.push(BeDOZaReceiver::new(delta_1 * b - pad_b, delta_1, false));
        c_receiver.push(BeDOZaReceiver::new(delta_1 * c - pad_c, delta_1, false));
    }

    (
        (a_sender, b_sender, c_sender),
        (a_receiver, b_receiver, c_receiver),
    )
}

fn run_round(delta_1: FE, gates: usize, tamper_one_gate: bool, expect_ok: bool) -> Result<()> {
    let ((a_s, b_s, c_s), (a_r, b_r, c_r)) =
        make_batch(delta_1, gates, tamper_one_gate);

    let listener = TcpListener::bind("127.0.0.1:0").context("bind localhost listener")?;
    let addr_str = listener
        .local_addr()
        .context("read listener address")?
        .to_string();
    drop(listener);

    let prover_addr = addr_str.clone();
    let prover_handle = thread::spawn(move || -> Result<()> {
        let mut channel = listen_to(&prover_addr)?;
        let mut vole_sender = BufferedVoleSender::init(&mut channel, LPN21)
            .context("prover failed to init buffered VOLE sender")?;
        wolverine_batch_mul_prove(&a_s, &b_s, &c_s, &mut vole_sender, &mut channel)
            .context("prover failed in Wolverine batch-mul proof")
    });

    let mut channel = connect_with_retry(&addr_str)?;
    let mut vole_receiver = BufferedVoleReceiver::init(&mut channel, delta_1, LPN21)
        .context("verifier failed to init buffered VOLE receiver")?;
    let verifier_result =
        wolverine_batch_mul_verify(&a_r, &b_r, &c_r, &mut vole_receiver, &mut channel);

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
