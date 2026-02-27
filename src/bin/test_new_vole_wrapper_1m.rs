use circuit_psi::scalar_field::{FourQScalarField, fq};
use circuit_psi::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender};
use eyre::WrapErr;
use mac_n_cheese_vole::{mac::Mac, specialization::NoSpecialization, vole::VoleSizes};
use std::{thread, time::Instant};
use swanky_aes_rng::AesRng;
use swanky_channel_legacy::track_unix_channel_pair;
use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier};

type ExampleMac = (FourQScalarField, FourQScalarField, NoSpecialization);

const DEFAULT_TARGET_VOLES: usize = 1_000_000;

fn make_base_voles(
    alpha: FourQScalarField,
    count: usize,
) -> (Vec<Mac<Prover, ExampleMac>>, Vec<Mac<Verifier, ExampleMac>>) {
    let mut sender = Vec::with_capacity(count);
    let mut receiver = Vec::with_capacity(count);
    for i in 0..count {
        let x = fq((i as u64) + 1);
        let beta = fq((i as u64) * 11 + 17);
        sender.push(Mac::prover_new(IS_PROVER, x, beta));
        receiver.push(Mac::verifier_new(IS_VERIFIER, x * alpha + beta));
    }
    (sender, receiver)
}

fn make_inputs(n: usize) -> Vec<FourQScalarField> {
    (0..n).map(|i| fq((i as u64) + 5_000)).collect()
}

fn fold_field(mut acc: u128, value: FourQScalarField) -> u128 {
    let bytes = value.to_bytes_le();
    for chunk in bytes.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let word = u128::from_le_bytes(block);
        acc = acc.wrapping_mul(0x9e37_79b9_7f4a_7c15_6eed_0e9d_a4d9_4a4f) ^ word;
    }
    acc
}

fn main() -> eyre::Result<()> {
    let target_voles = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TARGET_VOLES);

    let alpha = fq(7);
    let delta = -alpha;
    let sizes = VoleSizes::of::<FourQScalarField, FourQScalarField>();
    let (base_sender, base_receiver) = make_base_voles(alpha, sizes.base_voles_needed);
    let inputs = make_inputs(target_voles);

    let (mut sender_channel, mut receiver_channel) = track_unix_channel_pair();

    let sender_thread = thread::spawn(move || -> eyre::Result<(usize, u128, usize, f64, u128)> {
        let start = Instant::now();
        let mut rng = AesRng::new();
        let mut vole = BufferedVoleSender::<ExampleMac>::init(&mut sender_channel, &mut rng, base_sender)
            .wrap_err("init sender VOLE")?;
        let _added = vole
            .extend_random(&mut sender_channel, &mut rng, target_voles)
            .wrap_err("extend sender random VOLEs")?;
        let sender_output = vole
            .materialize_inputs(&mut sender_channel, &inputs)
            .wrap_err("materialize sender VOLE inputs")?;

        let mut checksum = 0u128;
        for mac in sender_output {
            let (x, beta) = mac.prover_extract(IS_PROVER);
            checksum = fold_field(checksum, x * alpha + beta);
        }

        Ok((
            target_voles,
            checksum,
            vole.random_available(),
            sender_channel.total_kilobytes(),
            start.elapsed().as_millis(),
        ))
    });

    let receiver_start = Instant::now();
    let mut rng = AesRng::new();
    let mut receiver_vole =
        BufferedVoleReceiver::<ExampleMac>::init(&mut receiver_channel, &mut rng, delta, base_receiver)
            .wrap_err("init receiver VOLE")?;
    let _added = receiver_vole
        .extend_random(&mut receiver_channel, &mut rng, target_voles)
        .wrap_err("extend receiver random VOLEs")?;
    let receiver_output = receiver_vole
        .materialize_next(&mut receiver_channel, target_voles)
        .wrap_err("materialize receiver VOLE outputs")?;

    let mut receiver_checksum = 0u128;
    for mac in receiver_output {
        receiver_checksum = fold_field(receiver_checksum, mac.tag(IS_VERIFIER));
    }
    let receiver_elapsed_ms = receiver_start.elapsed().as_millis();
    let receiver_left = receiver_vole.random_available();
    let receiver_kb = receiver_channel.total_kilobytes();

    let (sender_count, sender_checksum, sender_left, sender_kb, sender_elapsed_ms) = sender_thread
        .join()
        .expect("sender thread panicked")
        .wrap_err("sender side failed")?;

    assert_eq!(sender_count, target_voles);
    assert_eq!(sender_checksum, receiver_checksum);

    println!(
        "1M VOLE wrapper stress test passed: produced {} VOLEs over FourQ scalar field",
        sender_count
    );
    println!(
        "checksums match (sender=0x{sender_checksum:032x}, receiver=0x{receiver_checksum:032x})"
    );
    println!(
        "leftover random VOLEs: sender={}, receiver={}",
        sender_left, receiver_left
    );
    println!(
        "communication (total KB): sender={:.2}, receiver={:.2}",
        sender_kb, receiver_kb
    );
    println!(
        "elapsed (ms): sender={}, receiver={}",
        sender_elapsed_ms, receiver_elapsed_ms
    );

    Ok(())
}
