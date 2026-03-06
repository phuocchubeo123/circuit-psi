extern crate psi_ot;
extern crate psi_network;
extern crate rand;

use psi_ot::iknp::IKNP;
use psi_network::tcp_channel::TcpChannel;
use std::env;
use std::net::{TcpListener, TcpStream};
use rand::Rng;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");
    const LENGTH: usize = 3000;

    if role == "receiver" {
        // Receiver logic
        // Bind and wait for a connection from the sender
        let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind to address");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut io = TcpChannel::new(stream);

        let mut receiver_iknp = IKNP::new(true);
        receiver_iknp.setup_recv(&mut io, None, None);

        let mut data = vec![[0u8; 16]; LENGTH];
        let mut rng = rand::rng();
        let r: [bool; LENGTH] = [(); LENGTH].map(|_| rng.random_bool(0.5)); // Example choice bits

        receiver_iknp.recv_cot(&mut io, &mut data, &r, LENGTH);

        data = vec![[0u8; 16]; LENGTH];
        receiver_iknp.recv_cot(&mut io, &mut data, &r, LENGTH);

        data = vec![[0u8; 16]; LENGTH];
        receiver_iknp.recv_cot(&mut io, &mut data, &r, LENGTH);

        println!("Total bytes sent: {}", io.get_bytes_sent());
        println!("Total bytes received: {}", io.get_bytes_received());
    } else if role == "sender" {
        // Sender logic
        // Establish connection to the receiver
        let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to receiver");
        let mut io = TcpChannel::new(stream);

        let mut sender_iknp = IKNP::new(true);

        sender_iknp.setup_send(&mut io, None, None);

        let mut data = vec![[0u8; 16]; LENGTH];
        sender_iknp.send_cot(&mut io, &mut data, LENGTH);

        data = vec![[0u8; 16]; LENGTH];
        sender_iknp.send_cot(&mut io, &mut data, LENGTH);

        data = vec![[0u8; 16]; LENGTH];
        sender_iknp.send_cot(&mut io, &mut data, LENGTH);

        println!("Total bytes sent: {}", io.get_bytes_sent());
        println!("Total bytes received: {}", io.get_bytes_received());
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }
}
