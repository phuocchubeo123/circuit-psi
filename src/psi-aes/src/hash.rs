use sha2::{Digest, Sha256};
use aes::Aes256;
use aes::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};
use std::convert::TryInto;

/// Constants for the hash buffer and digest size
const HASH_BUFFER_SIZE: usize = 64;
const DIGEST_SIZE: usize = 32;

/// Represents a block as 128 bits (16 bytes)
pub type Block = [u8; 16];

/// Hash struct for managing incremental and static SHA-256 operations
pub struct Hash {
    hasher: Sha256,
    buffer: [u8; HASH_BUFFER_SIZE],
    size: usize,
}

impl Hash {
    /// Creates a new `Hash` instance
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            buffer: [0u8; HASH_BUFFER_SIZE],
            size: 0,
        }
    }

    /// Adds data to the hash input
    pub fn put(&mut self, data: &[u8]) {
        if data.len() >= HASH_BUFFER_SIZE {
            self.hasher.update(data);
        } else if self.size + data.len() < HASH_BUFFER_SIZE {
            self.buffer[self.size..self.size + data.len()].copy_from_slice(data);
            self.size += data.len();
        } else {
            self.hasher.update(&self.buffer[..self.size]);
            self.buffer[..data.len()].copy_from_slice(data);
            self.size = data.len();
        }
    }

    /// Adds one or more blocks to the hash input
    pub fn put_block(&mut self, blocks: &[Block]) {
        let byte_data = unsafe { std::slice::from_raw_parts(blocks.as_ptr() as *const u8, blocks.len() * 16) };
        self.put(byte_data);
    }

    /// Computes the final hash digest and writes it to the output
    pub fn digest(&mut self, output: &mut [u8; DIGEST_SIZE]) {
        if self.size > 0 {
            self.hasher.update(&self.buffer[..self.size]);
            self.size = 0;
        }
        let result = self.hasher.finalize_reset();
        output.copy_from_slice(&result[..DIGEST_SIZE]);
        self.reset();
    }

    /// Resets the hash state for reuse
    pub fn reset(&mut self) {
        self.hasher = Sha256::new();
        self.size = 0;
    }

    pub fn hash_32byte_block(&self, data: &[u8; 32]) -> [u8; DIGEST_SIZE] {
        Self::hash_once(data)
    }

    /// Computes a SHA-256 hash in one step
    pub fn hash_once(data: &[u8]) -> [u8; DIGEST_SIZE] {
        let mut hash = Self::new();
        let mut output = [0u8; DIGEST_SIZE];
        hash.put(data);
        hash.digest(&mut output);
        output
    }

    /// Computes a 128-bit block (first 16 bytes of the SHA-256 digest)
    pub fn hash_for_block(data: &[u8]) -> Block {
        let digest = Self::hash_once(data);
        let mut block = [0u8; 16];
        block.copy_from_slice(&digest[..16]);
        block
    }

    /// Key Derivation Function (KDF)
    pub fn kdf(point: &[u8], id: u64) -> Block {
        let mut combined = Vec::with_capacity(point.len() + 8);
        combined.extend_from_slice(point);            // Add point data
        combined.extend_from_slice(&id.to_le_bytes()); // Append `id` as little-endian bytes

        Self::hash_for_block(&combined)
    }
}

// I need to revisit CCRH in the future
pub struct CCRH {
}

impl CCRH {
    pub fn new() -> Self {
        CCRH {}
    }

    /// Permute blocks using AES encryption
    pub fn permute_block(&self, blocks: &mut [[u8; 32]]) {
        for block in blocks.iter_mut() {
            let aes_key = Aes256::new(GenericArray::from_slice(block));
            let mut permuted_block: [_; 2] = core::array::from_fn(|i| GenericArray::clone_from_slice(&[i as u8; 16]));
            // Encrypt the 4 blocks using the AES key
            aes_key.encrypt_blocks(&mut permuted_block);
            let new_block = [permuted_block[0].as_slice(), permuted_block[1].as_slice()].concat();
            block.copy_from_slice(&new_block);
        }
    }

    /// Single hash function
    pub fn h(&self, input: &[u8; 32]) -> [u8; 32] {
        let t = sigma(input);

        let mut blocks = vec![t];
        self.permute_block(&mut blocks);

        xor_block(&t, &blocks[0])
    }

    /// Hash multiple blocks
    pub fn hn(&self, output: &mut [[u8; 32]], input: &[[u8; 32]]) {
        let len = input.len();
        let mut tmp: Vec<[u8; 32]> = vec![[0; 32]; len];

        for (i, block) in input.iter().enumerate() {
            tmp[i] = block.clone();
            tmp[i] = sigma(&tmp[i]);
            output[i] = tmp[i];
        }

        self.permute_block(&mut tmp);

        for i in 0..len {
            output[i] = xor_block(&output[i], &tmp[i]);
        }
    }

}

/// A helper function to simulate sigma operation
// I think it can be arbitrary: https://eprint.iacr.org/2019/074.pdf
fn sigma(input: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];

    // Basically rotating each pair of 4-bytes
    output[0..4].copy_from_slice(&input[4..8]);
    output[4..8].copy_from_slice(&input[0..4]);
    output[8..12].copy_from_slice(&input[12..16]);
    output[12..16].copy_from_slice(&input[8..12]);
    output[16..20].copy_from_slice(&input[20..24]);
    output[20..24].copy_from_slice(&input[16..20]);
    output[24..28].copy_from_slice(&input[28..32]);
    output[28..32].copy_from_slice(&input[20..24]);

    // Apply a mask and XOR: (a & mask) ^ shuffled
    let mask: [u8; 32] = [0xFF; 8].iter().chain(&[0x00; 8]).chain(&[0xFF; 8]).chain(&[0x00; 8]).copied().collect::<Vec<u8>>().try_into().unwrap();
    for i in 0..32 {
        output[i] ^= input[i] & mask[i];
    }

    output
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