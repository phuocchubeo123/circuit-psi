extern crate psi_vole;
extern crate lambdaworks_math;

use std::net::{TcpListener, TcpStream};
use psi_vole::comm_channel::CommunicationChannel;
use psi_vole::socket_channel::TcpChannel;
use std::time::Instant;

pub type FE = psi_vole::fourq_field::FourQScalarField;

fn bench_32byte<IO: CommunicationChannel>(channel: &mut IO) {
    const size: usize = 10000;
    let elements = [[0u8; 32]; 4];

    let start = Instant::now();
    for i in 0..size {
        let x = channel.receive_block::<32>().unwrap();
    }
    let duration = start.elapsed();

    println!("Receive {} elements in {:?}", size, duration);
}

fn main() {
    let element_count = 100_000; // Number of elements to receive

    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Benchmark receive_stark252
    let start = Instant::now();
    let elements = channel
        .receive_stark252()
        .expect("Failed to receive elements");
    let duration = start.elapsed();

    println!("Received {} elements in {:?}", elements.len(), duration);

    // Receive the bits
    let received_bits = channel.receive_bits().expect("Failed to receive bits");

    println!("Receiver: Received bits: {:?}", received_bits);
    println!("Receiver: Bits received successfully.");

    bench_32byte(&mut channel);
}
