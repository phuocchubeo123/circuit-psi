extern crate psi_vole;
extern crate lambdaworks_math;
extern crate rand;

use psi_vole::socket_channel::TcpChannel;
use psi_vole::base_svole::BaseSvole;
use psi_vole::utils::rand_field_element;
use std::env;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

pub type FE = psi_vole::fourq_field::FourQScalarField;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");
    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver logic
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
        println!("Waiting for sender...");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        // Set up BaseSvole
        let mut receiver_svole = BaseSvole::new_receiver(&mut channel, &mut comm);

        // Test triple generation
        let batch_size = 20000;
        let mut shares = vec![FE::zero(); batch_size];
        let mut u_batch = vec![FE::zero(); batch_size];

        let start = Instant::now();

        receiver_svole.triple_gen_recv(&mut channel, &mut shares, &mut u_batch, batch_size, &mut comm);

        let duration = start.elapsed();
        println!("Triple generation (recv) time: {:?}", duration);
    } else if role == "sender" {
        // Sender logic
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        // Set up BaseSvole
        let delta = rand_field_element();
        println!("Sender Delta: {}", delta);

        let mut sender_svole = BaseSvole::new_sender(&mut channel, delta, &mut comm);

        // Test triple generation
        let batch_size = 20000;
        let mut shares = vec![FE::zero(); batch_size];

        let start = Instant::now();

        sender_svole.triple_gen_send(&mut channel, &mut shares, batch_size, &mut comm);

        let duration = start.elapsed();
        println!("Triple generation (send) time: {:?}", duration);
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
