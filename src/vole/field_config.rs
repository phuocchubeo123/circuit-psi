use crate::math::defines::{FE, FE_LIMBS};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

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
        assert!(
            children.len() >= 4,
            "node_expand_2to4 expects at least 4 children"
        );
        assert!(
            parents.len() >= 2,
            "node_expand_2to4 expects at least 2 parents"
        );
        self.node_expand_1to2(&mut children[0..2], &parents[0]);
        self.node_expand_1to2(&mut children[2..4], &parents[1]);
    }
}

pub fn fe_to_u128_limbs(value: FE) -> [u128; FE_LIMBS] {
    let bytes = value.to_bytes_le();
    let mut limbs = [0u128; FE_LIMBS];
    for (i, chunk) in bytes.chunks_exact(16).take(FE_LIMBS).enumerate() {
        limbs[i] = u128::from_le_bytes(chunk.try_into().unwrap());
    }
    limbs
}
