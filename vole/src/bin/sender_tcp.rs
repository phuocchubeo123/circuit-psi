// send and receive 100_000 32-byte blocks in <100ms

extern crate psi_vole;
extern crate lambdaworks_math;
extern crate rand;

use psi_vole::socket_channel::TcpChannel;
use psi_vole::comm_channel::CommunicationChannel;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::random;
use std::net::TcpStream;
use std::time::Instant;

pub type FE = psi_vole::fourq_field::FourQScalarField;

pub fn rand_field_element() -> FE {
    loop {
        let bytes = rand::random::<[u8; 32]>();
        if let Ok(fe) = FE::from_bytes_le(&bytes) {
            return fe;
        }
    }
}

fn bench_32byte<IO: CommunicationChannel>(channel: &mut IO) {
    const size: usize = 10000;
    let elements = [[0u8; 32]; 4];

    let start = Instant::now();
    for i in 0..size {
        channel.send_block::<32>(&elements).unwrap();
    }
    let duration = start.elapsed();

    println!("Sent {} elements in {:?}", size, duration);
}

fn main() {
    let element_count = 100_000; // Number of elements to send

    // Connect to the receiver
    let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
    let mut channel = TcpChannel::new(stream);

    // Generate random elements
    let elements: Vec<FE> = (0..element_count)
        .map(|_| rand_field_element())
        .collect();

    // Benchmark send_stark252
    let start = Instant::now();
    channel
        .send_stark252(&elements)
        .expect("Failed to send elements");
    let duration = start.elapsed();

    println!("Sent {} elements in {:?}", element_count, duration);

     // Bits to send
    let bits_to_send = vec![true, false, true, true, false, true, false, false, true, true];
    println!("Sender: Sending bits: {:?}", bits_to_send);

    // Send the bits
    channel.send_bits(&bits_to_send).expect("Failed to send bits");

    println!("Sender: Bits sent successfully.");

    bench_32byte(&mut channel);
}
