extern crate psi_vole;

use psi_vole::ot::OTCO;
use psi_vole::socket_channel::TcpChannel;
use std::env;
use std::net::{TcpListener, TcpStream};

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");
    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver logic
        let stream = TcpStream::connect("127.0.0.1:12345").expect("Failed to connect to sender");
        let mut channel = TcpChannel::new(stream);

        // Example choices
        let choices = vec![false, true];
        let mut output = Vec::new();

        // Initialize OTCO and receive
        let mut otco = OTCO::new();
        otco.recv(&mut channel, &choices, &mut output, &mut comm);

        // Verify the output
        println!("Received output: {:?}", output);
    } else if role == "sender" {
        // Sender logic
        let listener = TcpListener::bind("127.0.0.1:12345").expect("Failed to bind server");
        println!("Sender is listening on 127.0.0.1:12345");

        for stream in listener.incoming() {
            let stream = stream.expect("Failed to accept connection");
            let mut channel = TcpChannel::new(stream);

            // Example data
            let data0 = vec![[0u8; 16]; 2];
            let data1 = vec![[1u8; 16]; 2];

            // Initialize OTCO and send
            let mut otco = OTCO::new();
            otco.send(&mut channel, &data0, &data1, &mut comm);

            println!("Sender finished sending data");
        }
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
