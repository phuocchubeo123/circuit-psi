extern crate psi_vole;
extern crate lambdaworks_math;
extern crate rand;

use psi_vole::spfss_sender::SpfssSenderFp;
use psi_vole::spfss_receiver::SpfssRecverFp;
use psi_vole::comm_channel::CommunicationChannel;
use psi_vole::socket_channel::TcpChannel;
use psi_vole::base_cot::BaseCot;
use psi_vole::preot::OTPre;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::random;
use std::env;
use std::net::{TcpListener, TcpStream};
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

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args().nth(1).expect("Please specify 'sender' or 'receiver' as an argument");
    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver logic
        // Listen for the sender
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
        println!("Waiting for sender...");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the receiver (BOB)
        let mut receiver_cot = BaseCot::new(1, false);

        // Set up the receiver's precomputation phase
        receiver_cot.cot_gen_pre(&mut channel, None, &mut comm);

        // Original COT generation
        const depth: usize = 4;
        let size = depth - 1; // Number of COTs
        let times = 100;
        let mut choice_bits = vec![false; size * times];
        // Populate random choice bits
        for bit in &mut choice_bits {
            *bit = rand::random();
        }

        // New COT generation using OTPre
        let mut receiver_pre_ot = OTPre::new(size, times);
        receiver_cot.cot_gen_preot(&mut channel, &mut receiver_pre_ot, size * times, Some(&choice_bits), &mut comm);

        let received_data = channel.receive_stark252().expect("Failed to receive delta and gamma");
        let delta = received_data[0];
        let gamma = received_data[1];

        let mut ggm_tree_mem = [FE::zero(); 1 << (depth - 1)];
        for i in 0..times {
            receiver_pre_ot.choices_recver(&mut channel, &[false; depth - 1], &mut comm);
        }
        channel.flush();
        receiver_pre_ot.reset();

        for i in 0..times {
            let beta = rand_field_element();
            let delta2 = gamma + delta * beta;
            // Initialize Spfss for the receiver
            let mut receiver_spfss = SpfssRecverFp::new(depth);

            receiver_spfss.recv(&mut channel, &mut receiver_pre_ot, 0, &mut comm);
            receiver_spfss.compute(&mut ggm_tree_mem, delta2);
            // receiver_spfss.consistency_check(&mut channel, delta2, beta);
        }
    } else if role == "sender" {
        // Connect to the receiver
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the sender (ALICE)
        let mut sender_cot = BaseCot::new(0, false);

        // Set up the sender's precomputation phase
        sender_cot.cot_gen_pre(&mut channel, None, &mut comm);

        // Original COT generation
        const depth: usize = 4;
        let size = depth - 1; // Number of COTs
        let times = 100;
        // New COT generation using OTPre
        let mut sender_pre_ot = OTPre::new(size, times);
        sender_cot.cot_gen_preot(&mut channel, &mut sender_pre_ot, size * times, None, &mut comm);

        let delta = rand_field_element();
        let gamma = rand_field_element();
        channel.send_stark252(&[delta.clone(), gamma.clone()]).expect("Failed to send delta and gamma");
        let mut ggm_tree_mem = [FE::zero(); 1 << (depth - 1)];

        let start = Instant::now();
        for i in 0..times {
            sender_pre_ot.choices_sender(&mut channel, &mut comm);
        }
        channel.flush();
        sender_pre_ot.reset();

        for i in 0..times {
            // Initialize Spfss for the sender
            let mut sender_spfss = SpfssSenderFp::new(depth);

            sender_spfss.compute(&mut ggm_tree_mem, delta, gamma);
            sender_spfss.send(&mut channel, &mut sender_pre_ot, 0, &mut comm);
            channel.flush();

            // sender_spfss.consistency_check(&mut channel, gamma);
        }
        let duration = start.elapsed();
        println!("Time taken: {:?}", duration);
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
