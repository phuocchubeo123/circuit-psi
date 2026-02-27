extern crate rayon;
extern crate sha3;

use std::time::Instant;
use sha3::{Digest, Keccak256};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

fn sequential_hashing(mut sender_outputs_hash: Vec<[u8; 32]>, log_size_p: usize) -> Vec<[u8; 32]> {
    let mut current_size = sender_outputs_hash.len();
    for i in 0..log_size_p-1 {
        current_size >>= 1;
        // let start = Instant::now();
        for j in 0..current_size {
            let mut hasher = Keccak256::new();
            hasher.update(sender_outputs_hash[2 * j]);
            hasher.update(sender_outputs_hash[2 * j + 1]);
            sender_outputs_hash[j].copy_from_slice(&hasher.finalize());
        }
        // println!("⏳ Sequential execution time for layer {}: {:.6?} sec", i, start.elapsed());
    }
    sender_outputs_hash
}

fn parallel_hashing(mut sender_outputs_hash: Vec<[u8; 32]>, log_size_p: usize) -> Vec<[u8; 32]> {
    let mut current_size = sender_outputs_hash.len();

    for i in 0..log_size_p-1 {
        current_size >>= 1;
        // let start = Instant::now();
        sender_outputs_hash[..current_size*2].par_chunks_mut(2).enumerate().for_each(|(j, chunk)| {
            let mut hasher = Keccak256::new();
            hasher.update(chunk[0]);
            hasher.update(chunk[1]);
            chunk[0].copy_from_slice(&hasher.finalize());
        });
        // println!("⏳ Parallel execution time for layer {}: {:.6?} sec", i, start.elapsed());
    }

    sender_outputs_hash
}

fn main() {
    ThreadPoolBuilder::new()
        .num_threads(8)  // Change this number to your preference
        .build_global()
        .unwrap();

    println!("🚀 Rayon is using {} threads", rayon::current_num_threads());

    let start = Instant::now();
    for log_size_p in 1..21 {
        let num_elements = 1 << log_size_p;
        let sender_outputs_hash = vec![[0u8; 32]; num_elements];
        // println!("🚀 Running Sequential Hashing...");
        sequential_hashing(sender_outputs_hash.clone(), log_size_p);
    }
    println!("⏳ Sequential execution time: {:.6?} sec", start.elapsed());

    let start = Instant::now();
    for log_size_p in 1..21 {
        let num_elements = 1 << log_size_p;
        let sender_outputs_hash = vec![[0u8; 32]; num_elements];
        // println!("\n🚀 Running Parallel Hashing...");
        parallel_hashing(sender_outputs_hash.clone(), log_size_p);
    }
    println!("⏳ Parallel execution time: {:.6?} sec", start.elapsed());
}
