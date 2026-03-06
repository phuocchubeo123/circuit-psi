use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

pub struct TwoKeyPRPF2k {
    aes_key: [Aes128; 2],
}

impl TwoKeyPRPF2k {
    pub fn new(keys: [[u8; 16]; 2]) -> Self {
        let aes_key_0 = Aes128::new(GenericArray::from_slice(&keys[0]));
        let aes_key_1 = Aes128::new(GenericArray::from_slice(&keys[1]));

        TwoKeyPRPF2k {
            aes_key: [aes_key_0, aes_key_1],
        }
    }

    pub fn expand_left(&self, old: &[u128], new: &mut [u128]) {
        let old_bytes: Vec<[u8; 16]> = old.iter().map(|x| x.to_le_bytes()).collect();
        let mut old_array: Vec<_> = old_bytes.iter().map(|x| GenericArray::clone_from_slice(x)).collect();
        self.aes_key[0].encrypt_blocks(&mut old_array);
        new.iter_mut().enumerate().for_each(|(i, x)| {
            let mut new_x = [0u8; 16];
            new_x.copy_from_slice(old_array[i].as_slice());
            *x = u128::from_le_bytes(new_x);
        });
    }

    pub fn expand_right(&self, old: &[u128], new: &mut [u128]) {
        let old_bytes: Vec<[u8; 16]> = old.iter().map(|x| x.to_le_bytes()).collect();
        let mut old_array: Vec<_> = old_bytes.iter().map(|x| GenericArray::clone_from_slice(x)).collect();
        self.aes_key[1].encrypt_blocks(&mut old_array);
        new.iter_mut().enumerate().for_each(|(i, x)| {
            let mut new_x = [0u8; 16];
            new_x.copy_from_slice(old_array[i].as_slice());
            *x = u128::from_le_bytes(new_x);
        });
    }
}