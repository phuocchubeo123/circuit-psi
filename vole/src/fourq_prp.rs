use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::Rng;

pub type FE = crate::fourq_field::FourQScalarField;

pub struct TwoKeyPRP {}

impl TwoKeyPRP {
    pub fn new() -> Self {
        Self {}
    }

    pub fn node_expand_1to2(&self, children: &mut [FE], parent: &FE) {
        assert_eq!(children.len(), 2, "node_expand_1to2 expects 2 children");

        let parent_bytes = parent.to_bytes_le();
        let aes_key = Aes256::new(GenericArray::from_slice(&parent_bytes));
        let mut expanded_parent: [_; 4] =
            core::array::from_fn(|i| GenericArray::clone_from_slice(&[i as u8; 16]));
        aes_key.encrypt_blocks(&mut expanded_parent);

        let mut left_child_bytes = [0u8; 32];
        left_child_bytes[..16].copy_from_slice(expanded_parent[0].as_slice());
        left_child_bytes[16..].copy_from_slice(expanded_parent[1].as_slice());
        let mut right_child_bytes = [0u8; 32];
        right_child_bytes[..16].copy_from_slice(expanded_parent[2].as_slice());
        right_child_bytes[16..].copy_from_slice(expanded_parent[3].as_slice());

        children[0] = FE::from_bytes_le_mod_order(&left_child_bytes);
        children[1] = FE::from_bytes_le_mod_order(&right_child_bytes);
    }

    pub fn node_expand_2to4(&self, children: &mut [FE], parents: &[FE]) {
        assert!(children.len() >= 4, "node_expand_2to4 expects at least 4 children");
        assert!(parents.len() >= 2, "node_expand_2to4 expects at least 2 parents");
        self.node_expand_1to2(&mut children[0..2], &parents[0]);
        self.node_expand_1to2(&mut children[2..4], &parents[1]);
    }
}

pub struct FieldPRP {
    key: [u8; 32],
}

impl FieldPRP {
    pub fn new(seed: Option<&[u8; 32]>) -> Self {
        let mut key = [0u8; 32];
        if let Some(s) = seed {
            key.copy_from_slice(s);
        } else {
            rand::thread_rng().fill(&mut key);
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
