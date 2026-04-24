use crate::math::defines::FE;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand08::Rng;

pub struct FieldPRP {
    key: [u8; 32],
}

impl FieldPRP {
    pub fn new(seed: Option<&[u8; 32]>) -> Self {
        let mut key = [0u8; 32];
        if let Some(s) = seed {
            key.copy_from_slice(s);
        } else {
            rand08::thread_rng().fill(&mut key);
        }
        Self { key }
    }

    pub fn permute_block(&self, data: &mut [FE], nblocks: usize) {
        let blocks = nblocks.min(data.len());
        let seed0 = GenericArray::clone_from_slice(&self.key[..16]);
        let seed1 = GenericArray::clone_from_slice(&self.key[16..]);

        for element in data.iter_mut().take(blocks) {
            let aes_key = Aes256::new(GenericArray::from_slice(&element.to_bytes_le()));
            let mut tmp = [seed0.clone(), seed1.clone()];
            aes_key.encrypt_blocks(&mut tmp);
            let mut bytes = [0u8; 32];
            bytes[..16].copy_from_slice(tmp[0].as_slice());
            bytes[16..].copy_from_slice(tmp[1].as_slice());
            *element = FE::from_bytes_le_mod_order(&bytes);
        }
    }
}
