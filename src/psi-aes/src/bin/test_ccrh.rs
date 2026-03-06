extern crate psi_aes;

use psi_aes::hash::CCRH;
use std::time::Instant;

fn benchmark_ccrh() {
    let ccrh = CCRH::new();
    let inputs = vec![[0x01u8; 32]; 1_000_000]; // 1 million input blocks
    let mut outputs = vec![[0u8; 32]; 1_000_000];

    println!("Starting benchmark for 1 million CCRH hashes...");

    let start = Instant::now();
    ccrh.hn(&mut outputs, &inputs);
    let duration = start.elapsed();

    println!("Time taken for 1 million CCRH hashes: {:?}", duration);
}

fn main() {
    benchmark_ccrh();
}
