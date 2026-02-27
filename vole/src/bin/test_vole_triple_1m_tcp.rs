extern crate psi_vole;

use psi_vole::socket_channel::TcpChannel;
use psi_vole::vole_triple::{LPN17, VoleTriple};
use std::error::Error;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

type FE = psi_vole::fourq_field::FourQScalarField;

const DEFAULT_SIZE: usize = 1_000_000;

fn connect_with_retry(addr: SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
    for _ in 0..500 {
        if let Ok(stream) = TcpStream::connect(addr) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(format!("failed to connect to {addr}").into())
}

fn fold_field(mut acc: u128, value: FE) -> u128 {
    let bytes = value.to_bytes_le();
    for chunk in bytes.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let word = u128::from_le_bytes(block);
        acc = acc.wrapping_mul(0x9e37_79b9_7f4a_7c15_6eed_0e9d_a4d9_4a4f) ^ word;
    }
    acc
}

fn checksum_pair(y: &[FE], z: &[FE]) -> u128 {
    let mut acc = 0u128;
    for (&yi, &zi) in y.iter().zip(z.iter()) {
        acc = fold_field(acc, yi);
        acc = fold_field(acc, zi);
    }
    acc
}

fn rand_field_element() -> FE {
    loop {
        let bytes = rand::random::<[u8; 32]>();
        if let Ok(fe) = FE::from_bytes_le(&bytes) {
            return fe;
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let size = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_SIZE);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let receiver_handle = thread::spawn(move || -> Result<(u64, u128, u128, u128), String> {
        let mut comm: u64 = 0;
        let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
        let mut channel = TcpChannel::new(stream);

        let mut vole = VoleTriple::new(1, true, &mut channel, LPN17, &mut comm);
        let setup_start = Instant::now();
        vole.setup_receiver(&mut channel, &mut comm);
        let setup_ms = setup_start.elapsed().as_millis();

        vole.extend_initialization();

        let mut y = vec![FE::zero(); size];
        let mut z = vec![FE::zero(); size];
        let extend_start = Instant::now();
        vole.extend(&mut channel, &mut y, &mut z, size, &mut comm);
        let extend_ms = extend_start.elapsed().as_millis();

        vole.check_triple(&mut channel, FE::zero(), &y, &z, size);
        let checksum = checksum_pair(&y, &z);
        Ok((comm, setup_ms, extend_ms, checksum))
    });

    let mut comm_sender: u64 = 0;
    let stream = connect_with_retry(addr)?;
    let mut channel = TcpChannel::new(stream);

    let mut vole_sender = VoleTriple::new(0, true, &mut channel, LPN17, &mut comm_sender);
    let delta = rand_field_element();

    let setup_start = Instant::now();
    vole_sender.setup_sender(&mut channel, delta, &mut comm_sender);
    let sender_setup_ms = setup_start.elapsed().as_millis();

    vole_sender.extend_initialization();

    let mut y_sender = vec![FE::zero(); size];
    let mut z_sender = vec![FE::zero(); size];
    let extend_start = Instant::now();
    vole_sender.extend(&mut channel, &mut y_sender, &mut z_sender, size, &mut comm_sender);
    let sender_extend_ms = extend_start.elapsed().as_millis();

    vole_sender.check_triple(&mut channel, delta, &y_sender, &z_sender, size);
    let sender_checksum = checksum_pair(&y_sender, &z_sender);

    let (comm_receiver, receiver_setup_ms, receiver_extend_ms, receiver_checksum) = receiver_handle
        .join()
        .map_err(|_| "receiver thread panicked".to_string())?
        .map_err(|e| format!("receiver failed: {e}"))?;

    println!("psi-vole TCP check passed for {size} VOLE triples");
    println!(
        "setup ms: sender={sender_setup_ms}, receiver={receiver_setup_ms} | extend ms: sender={sender_extend_ms}, receiver={receiver_extend_ms}"
    );
    println!(
        "comm bytes: sender={comm_sender}, receiver={comm_receiver}"
    );
    println!(
        "checksums: sender=0x{sender_checksum:032x}, receiver=0x{receiver_checksum:032x}"
    );

    Ok(())
}
