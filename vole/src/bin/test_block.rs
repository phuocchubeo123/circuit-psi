// To convert from [u8; 32] -> [u128; 2]: around 50ms

extern crate rand;
use std::time::Instant;
use std::convert::TryInto;
use rand::Rng;

fn u8_to_i128_array(input: [u8; 32]) -> [u128; 2] {
    // Split the input into two 16-byte chunks
    let chunk1 = &input[0..16]; // First 16 bytes
    let chunk2 = &input[16..32]; // Last 16 bytes

    // Convert each chunk into an i128 using from_le_bytes (little-endian)
    let int1 = u128::from_le_bytes(chunk1.try_into().expect("Failed to convert chunk1"));
    let int2 = u128::from_le_bytes(chunk2.try_into().expect("Failed to convert chunk2"));

    [int1, int2]
}

fn xor_block(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    [
        a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3],
        a[4] ^ b[4], a[5] ^ b[5], a[6] ^ b[6], a[7] ^ b[7],
        a[8] ^ b[8], a[9] ^ b[9], a[10] ^ b[10], a[11] ^ b[11],
        a[12] ^ b[12], a[13] ^ b[13], a[14] ^ b[14], a[15] ^ b[15],
        a[16] ^ b[16], a[17] ^ b[17], a[18] ^ b[18], a[19] ^ b[19],
        a[20] ^ b[20], a[21] ^ b[21], a[22] ^ b[22], a[23] ^ b[23],
        a[24] ^ b[24], a[25] ^ b[25], a[26] ^ b[26], a[27] ^ b[27],
        a[28] ^ b[28], a[29] ^ b[29], a[30] ^ b[30], a[31] ^ b[31],
    ]
}

fn xor_u128(a: &[u128; 2], b: &[u128; 2]) -> [u128; 2] {
    [a[0]^b[0], a[1]^b[1]]
}

fn bench_xor() {
        // Number of blocks to generate
    let num_blocks = 1_000_000;

    // Create a vector to hold [u8; 32] blocks
    let mut a: Vec<[u8; 32]> = Vec::with_capacity(num_blocks);
    let mut b: Vec<[u8; 32]> = Vec::with_capacity(num_blocks);

    for _ in 0..num_blocks {
        let mut block = [0u8; 32];
        rand::thread_rng().fill(&mut block);
        a.push(block);
        rand::thread_rng().fill(&mut block);
        b.push(block);
    }

    let start = Instant::now();
    for i in 0..num_blocks {
        let c = xor_block(&a[i], &b[i]);
    }
    println!("Time taken to xor blocks: {:?}", start.elapsed());

    // Create a vector to hold [u128; 2] blocks
    let mut a_u128: Vec<[u128; 2]> = Vec::with_capacity(num_blocks);
    let mut b_u128: Vec<[u128; 2]> = Vec::with_capacity(num_blocks);

    for block in &a {
        let chunk1 = u128::from_le_bytes(block[0..16].try_into().unwrap());
        let chunk2 = u128::from_le_bytes(block[16..32].try_into().unwrap());
        a_u128.push([chunk1, chunk2]);
    }
    for block in &b {
        let chunk1 = u128::from_le_bytes(block[0..16].try_into().unwrap());
        let chunk2 = u128::from_le_bytes(block[16..32].try_into().unwrap());
        b_u128.push([chunk1, chunk2]);
    }

    let start = Instant::now();
    for i in 0..num_blocks {
        let c = xor_u128(&a_u128[i], &b_u128[i]);
    }
    println!("Time taken to xor u128: {:?}", start.elapsed());

}

fn main() {
    // Create an example [u8; 32] array
    let input: [u8; 32] = [0; 32];

    // Perform the operation 1 million times and measure the time
    let start = Instant::now();
    for _ in 0..1_000_000 {
        let _result = u8_to_i128_array(input);
    }
    let duration = start.elapsed();

    // Print the elapsed time
    println!("Completed 1 million conversions in: {:?}", duration);

    bench_xor();
}
