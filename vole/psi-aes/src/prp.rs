use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::Rng;

pub struct PRP {
    aes: Aes128,
}

impl PRP {
    pub fn new(key: Option<&[u8; 16]>) -> Self {
        let mut aes_key = [0u8; 16];
        if let Some(k) = key {
            aes_key.copy_from_slice(k);
        } else {
            let mut rng = rand::thread_rng();
            rng.fill(&mut aes_key);
        }

        let aes = Aes128::new(GenericArray::from_slice(&aes_key));

        PRP {
            aes: aes,
        }
    }

    pub fn permute_block(&self, data: &mut [[u8; 16]], nblocks: usize) {
        let mut aes_block: Vec<_> = data[0..nblocks]
            .iter()
            .map(|x| GenericArray::clone_from_slice(x))
            .collect();
        self.aes.encrypt_blocks(&mut aes_block);
        for (i, encrypted) in aes_block.iter().enumerate() {
            data[i].copy_from_slice(encrypted);
        }
    }
}

pub fn xor_block_array(a: &mut [[u8; 16]], b: &[[u8; 16]]) {
    for (block, other_block) in a.iter_mut().zip(b.iter()) {
        // Unroll the loop manually for 16 bytes
        block[0] ^= other_block[0];
        block[1] ^= other_block[1];
        block[2] ^= other_block[2];
        block[3] ^= other_block[3];
        block[4] ^= other_block[4];
        block[5] ^= other_block[5];
        block[6] ^= other_block[6];
        block[7] ^= other_block[7];
        block[8] ^= other_block[8];
        block[9] ^= other_block[9];
        block[10] ^= other_block[10];
        block[11] ^= other_block[11];
        block[12] ^= other_block[12];
        block[13] ^= other_block[13];
        block[14] ^= other_block[14];
        block[15] ^= other_block[15];
    }
}