extern crate psi_ot;
extern crate psi_network;
extern crate rand;

use psi_network::tcp_channel::TcpChannel;
use psi_ot::base_cot::BaseCot;
use psi_ot::pre_ot::OTPre;
use std::net::TcpStream;
use std::env;
use std::net::TcpListener;
use std::time::Instant;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");

    if role == "receiver" {
        // Listen for the sender
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
        println!("Waiting for sender...");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the receiver (BOB)
        let mut receiver_cot = BaseCot::new(1, false);

        // Set up the receiver's precomputation phase
        receiver_cot.cot_gen_pre(&mut channel, None);

        // Original COT generation
        let size = 60; // Number of COTs
        let times = 100;
        let mut choice_bits = vec![false; size];
        for bit in &mut choice_bits {
            *bit = rand::random();
        }

        let mut receiver_pre_ot = OTPre::<2>::new(size, times);
        receiver_cot.cot_gen_preot(&mut channel, &mut receiver_pre_ot, size * times, None);

        let start = Instant::now();
        for _ in 0..times {
            receiver_pre_ot.choices_recver(&mut channel, &choice_bits);
        }
        receiver_pre_ot.reset();
        // Receive data using OTPre
        for s in 0..times {
            let mut received_data = vec![[0u128; 2]; size];
            receiver_pre_ot.recv(&mut channel, &mut received_data, &choice_bits, size, s);

            for i in 0..size {
                println!("OT number: {}", s * size + i);
                println!("Receiver OT message: {:?}", received_data[i]);
            }
        }

        let duration = start.elapsed();
        println!("Time taken: {:?}", duration);
        println!("Total data sent: {} bytes", channel.get_bytes_sent());
        println!("Total data received: {} bytes", channel.get_bytes_received());
    } else if role == "sender" {
        // Connect to the receiver
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the sender (ALICE)
        let mut sender_cot = BaseCot::new(0, false);

        // Set up the sender's precomputation phase
        sender_cot.cot_gen_pre(&mut channel, None);

        // Original COT generation
        let size = 60; // Number of COTs
        let times = 100;

        let mut sender_pre_ot = OTPre::<2>::new(size, times);
        sender_cot.cot_gen_preot(&mut channel, &mut sender_pre_ot, size*times, None);
        for _ in 0..times {
            sender_pre_ot.choices_sender(&mut channel);
        }
        sender_pre_ot.reset();

        for s in 0..times {
            // Send data using OTPre
            let mut m0 = vec![[0u128; 2]; size];
            let mut m1 = vec![[0u128; 2]; size];
            for i in 0..size {
                m0[i] = [s as u128; 2];
                m1[i] = [(s + 1) as u128; 2];
            }
            sender_pre_ot.send(&mut channel, &m0, &m1, size, s);

            for i in 0..size {
                println!("OT number: {}", s*size + i);
                println!("Sender OT message 0: {:?}", m0);
                println!("Sender OT message 1: {:?}", m1);
            }
        }

        println!("Total data sent: {} bytes", channel.get_bytes_sent());
        println!("Total data received: {} bytes", channel.get_bytes_received());
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }
}
