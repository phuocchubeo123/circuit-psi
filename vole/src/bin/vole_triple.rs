extern crate psi_vole;
extern crate lambdaworks_math;

use psi_vole::socket_channel::TcpChannel;
use psi_vole::vole_triple::{VoleTriple, LPN17};
use psi_vole::utils::rand_field_element;
use std::net::{TcpListener, TcpStream};
use std::env;
use std::time::Instant;

pub type FE = psi_vole::fourq_field::FourQScalarField;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");
    
    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver setup
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        let mut vole = VoleTriple::new(1, true, &mut channel, LPN17, &mut comm);
        
        let start = Instant::now();
        vole.setup_receiver(&mut channel, &mut comm);
        println!("Time taken for setup: {:?}", start.elapsed());

        vole.extend_initialization();

        const size: usize = 100_000;
        let mut y = [FE::zero(); size];
        let mut z = [FE::zero(); size];
        let start = Instant::now();
        vole.extend(&mut channel, &mut y, &mut z, size, &mut comm);
        println!("Time taken for one extend: {:?}", start.elapsed());
    } else if role == "sender" {
        // Sender setup
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        let mut vole = VoleTriple::new(0, true, &mut channel, LPN17, &mut comm);

        let delta = rand_field_element();
        vole.setup_sender(&mut channel, delta, &mut comm);

        vole.extend_initialization();

        const size: usize = 100_000;
        let mut y = [FE::zero(); size];
        let mut z = [FE::zero(); size];
        vole.extend(&mut channel, &mut y, &mut z, size, &mut comm);
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
