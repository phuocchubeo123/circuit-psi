use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

// Here, we model fixed key AES as random permutation
pub struct CCRH {
    aes: Aes128,
}

impl CCRH {
    pub fn new() -> Self {
        let key = [0u8; 16];
        let aes = Aes128::new(GenericArray::from_slice(&key));
        Self {
            aes
        }
    }

    pub fn hash_blocks(&self, output: &mut [[u8; 16]], input: &[[u8; 16]], length: usize) {
        let scratch: Vec<[u8; 16]> = input.iter().map(|&x| sigma(x)).collect();
        let mut generic_scratch: Vec<_> = scratch.iter().map(|x| GenericArray::clone_from_slice(x)).collect();
        self.aes.encrypt_blocks(&mut generic_scratch);
        for (i, enc) in generic_scratch.iter().enumerate() {
            output[i].copy_from_slice(enc);
        }
        for i in 0..length {
            output[i] = xor_block(output[i], scratch[i]);
        }
    }
}

pub fn sigma(a: [u8; 16]) -> [u8; 16] {
    [a[0] ^ a[8], a[1] ^ a[9], a[2] ^ a[10], a[3] ^ a[11],
     a[4] ^ a[12], a[5] ^ a[13], a[6] ^ a[14], a[7] ^ a[15],
     a[8], a[9], a[10], a[11],
     a[12], a[13], a[14], a[15]]
}

pub fn xor_block(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3],
     a[4] ^ b[4], a[5] ^ b[5], a[6] ^ b[6], a[7] ^ b[7],
     a[8] ^ b[8], a[9] ^ b[9], a[10] ^ b[10], a[11] ^ b[11],
     a[12] ^ b[12], a[13] ^ b[13], a[14] ^ b[14], a[15] ^ b[15]]
}