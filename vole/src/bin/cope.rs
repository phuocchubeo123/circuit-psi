extern crate psi_vole;
extern crate lambdaworks_math;
extern crate rand;

use psi_vole::socket_channel::TcpChannel;
use psi_vole::cope::Cope;
use psi_vole::utils::rand_field_element;
use std::env;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;
use lambdaworks_math::field::traits::IsPrimeField;

pub type FE = psi_vole::fourq_field::FourQScalarField;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");
    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver logic
        // Listen for the sender
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        // Set up COPE for receiver (BOB)
        let m = psi_vole::fourq_field::FOURQ_SCALAR_BITS; // Number of field elements
        let mut receiver_cope = Cope::new(1, m);

        // Receiver initializes
        receiver_cope.initialize_receiver(&mut channel, &mut comm);

        // Generate a random u
        let u = rand_field_element();
        println!("Receiver u: {}", u);

        // Test extend
        let single_result = receiver_cope.extend_receiver(&mut channel, u, &mut comm);
        receiver_cope.check_triple(&mut channel, &[u], &[single_result], 1);

        let start = Instant::now();

        // Test extend_batch
        let batch_size = 20000;
        let u_batch: Vec<FE> = (0..batch_size).map(|_| rand_field_element()).collect();
        let mut batch_result = vec![FE::zero(); batch_size];
        receiver_cope.extend_receiver_batch(&mut channel, &mut batch_result, &u_batch, batch_size, &mut comm);

        let duration = start.elapsed();
        println!("Time taken: {:?}", duration);

        receiver_cope.check_triple(&mut channel, &u_batch, &batch_result, batch_size);

    } else if role == "sender" {
        // Sender logic
        // Connect to the receiver
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        // Set up COPE for sender (ALICE)
        let m = psi_vole::fourq_field::FOURQ_SCALAR_BITS; // Number of field elements
        let mut sender_cope = Cope::new(0, m);

        // Generate a random delta
        let delta = rand_field_element();
        println!("Sender delta: {}", delta);

        // Sender initializes with delta
        sender_cope.initialize_sender(&mut channel, delta, &mut comm);

        // Test extend
        let single_result = sender_cope.extend_sender(&mut channel, &mut comm);
        sender_cope.check_triple(&mut channel, &[delta], &[single_result], 1);

        let start = Instant::now();

        // Test extend_batch
        let batch_size = 20000;
        let mut batch_result = vec![FE::zero(); batch_size];
        sender_cope.extend_sender_batch(&mut channel, &mut batch_result, batch_size, &mut comm);

        let duration = start.elapsed();
        println!("Time taken: {:?}", duration);

        sender_cope.check_triple(&mut channel, &[delta], &batch_result, batch_size);

    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
