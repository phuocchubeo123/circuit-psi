extern crate psi_aes;
extern crate lambdaworks_math;
extern crate rand;
extern crate aes;

use psi_aes::prg::PRG;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use std::time::Instant;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

const NUM_BLOCKS: usize = 10_000_000; // 2^18 blocks

fn main() {
    // Initialize AES key
    let key = GenericArray::from_slice(&[0u8; 16]);
    let aes = Aes128::new(key);

    // Create blocks for encryption
    let mut blocks = (0..NUM_BLOCKS)
        .map(|i| GenericArray::from([i as u8; 16]))
        .collect::<Vec<_>>();

    // Reinitialize blocks for parallel encryption
    let mut blocks_parallel = blocks.clone();

    // Benchmark encrypt_block (one block at a time)
    let start = Instant::now();
    for block in &mut blocks {
        aes.encrypt_block(block);
    }
    let duration_single = start.elapsed();
    println!(
        "Time to encrypt {} blocks with encrypt_block (sequential): {:?}",
        NUM_BLOCKS, duration_single
    );


    // Benchmark encrypt_blocks (multiple blocks in parallel)
    let start = Instant::now();
    aes.encrypt_blocks(&mut blocks_parallel);
    let duration_parallel = start.elapsed();
    println!(
        "Time to encrypt {} blocks with encrypt_blocks (parallel): {:?}",
        NUM_BLOCKS, duration_parallel
    );

    // Compare results
    if blocks == blocks_parallel {
        println!("Both methods produced identical results.");
    } else {
        println!("Mismatch between sequential and parallel encryption results.");
    }

    let mut new_blocks = vec![[0u8; 16]; NUM_BLOCKS];
    let mut prg = PRG::new(None, 0);

    let start = Instant::now();
    prg.random_16byte_block(&mut new_blocks);
    let duration_parallel = start.elapsed();
    println!(
        "Time to encrypt {} blocks with random_block: {:?}",
        NUM_BLOCKS, duration_parallel
    );
}