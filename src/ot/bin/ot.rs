extern crate psi_ot;
extern crate psi_network;

use psi_network::tcp_channel::{connect_with_retry_tcp, listen_tcp};
use psi_ot::otco::OTCO;
use std::env;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");

    if role == "receiver" {
        // Receiver logic
        let mut channel = connect_with_retry_tcp("127.0.0.1:12345").expect("Failed to connect to sender");

        // Example choices
        let choices = vec![false, true];
        let mut output = Vec::new();

        // Initialize OTCO and receive
        let mut otco = OTCO::new();
        otco.recv(&mut channel, &choices, &mut output);

        // Verify the output
        println!("Received output: {:?}", output);
        println!("Receiver communication: {:?}", channel.get_bytes_sent());
    } else if role == "sender" {
        // Sender logic
        let mut channel = listen_tcp("127.0.0.1:12345").expect("Failed to bind server");
        println!("Sender is listening on 127.0.0.1:12345");

        // Example data
        let data0 = vec![[0u8; 16]; 2];
        let data1 = vec![[1u8; 16]; 2];

        // Initialize OTCO and send
        let mut otco = OTCO::new();
        otco.send(&mut channel, &data0, &data1);

        println!("Sender finished sending data");
        println!("Sender communication: {:?}", channel.get_bytes_sent());
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }
}
