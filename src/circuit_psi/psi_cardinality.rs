use crate::{
    math::{defines::FE, group::Group},
    shuffled_oprf::{
        two_side_shuffle_inputer::TwoSideInputer, two_side_shuffle_shuffler::TwoSideShuffler,
    },
    tcp_channel::SwankyChannel,
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use anyhow::{Result, anyhow, ensure};
use rand::{Rng, RngExt};
use std::collections::HashSet;

fn exchange_set_size(local_len: usize, channel: &mut SwankyChannel) -> Result<usize> {
    channel
        .send(&(local_len as u64).to_le_bytes())
        .map_err(|e| anyhow!("Failed to send local set size: {e}"))?;
    let remote_len_bytes = channel
        .receive()
        .map_err(|e| anyhow!("Failed to receive remote set size: {e}"))?;
    ensure!(
        remote_len_bytes.len() == 8,
        "Expected 8 bytes for remote set size, got {}",
        remote_len_bytes.len()
    );

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&remote_len_bytes);
    Ok(u64::from_le_bytes(bytes) as usize)
}

fn random_permutation<RNG: Rng>(n: usize, rng: &mut RNG) -> Vec<usize> {
    let mut permutation: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        permutation.swap(i, j);
    }
    permutation
}

fn intersection_cardinality(left: &[Group], right: &[Group]) -> usize {
    let left_set: HashSet<[u8; 32]> = left.iter().map(Group::to_bytes).collect();
    let right_set: HashSet<[u8; 32]> = right.iter().map(Group::to_bytes).collect();
    left_set.intersection(&right_set).count()
}

pub struct PsiCardinalitySender {
    delta0: FE,
    k0: FE,
    auth_vole_sender: BufferedVoleSender,
    auth_vole_receiver: BufferedVoleReceiver,
    product_vole_sender: BufferedVoleSender,
    product_vole_receiver: BufferedVoleReceiver,
}

impl PsiCardinalitySender {
    pub fn new(delta: FE, k0: FE, channel: &mut SwankyChannel) -> Result<Self> {
        // Init order must match PsiCardinalityReceiver::new exactly.
        let auth_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {e}"))?;
        let auth_vole_receiver = BufferedVoleReceiver::init(channel, delta, LPN21)
            .map_err(|e| anyhow!("init auth receiver VOLE failed: {e}"))?;
        let product_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init product sender VOLE failed: {e}"))?;
        let product_vole_receiver = BufferedVoleReceiver::init(channel, k0, LPN21)
            .map_err(|e| anyhow!("init product receiver VOLE failed: {e}"))?;

        Ok(Self {
            delta0: delta,
            k0,
            auth_vole_sender,
            auth_vole_receiver,
            product_vole_sender,
            product_vole_receiver,
        })
    }

    pub fn delta0(&self) -> FE {
        self.delta0
    }

    pub fn k0(&self) -> FE {
        self.k0
    }

    pub fn run<RNG: Rng>(
        &mut self,
        sender_set: &[FE],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<usize> {
        ensure!(
            !sender_set.is_empty(),
            "PSI cardinality sender requires a non-empty set"
        );

        let receiver_set_len = exchange_set_size(sender_set.len(), channel)?;
        ensure!(
            receiver_set_len > 0,
            "PSI cardinality sender received an empty remote set size"
        );

        let receiver_permutation = random_permutation(receiver_set_len, rng);
        let two_side_runner = TwoSideInputer::new(self.delta0, self.k0);
        let two_side_oprf = two_side_runner.run_full_two_side_shuffled_oprf(
            sender_set,
            &receiver_permutation,
            rng,
            &mut self.auth_vole_sender,
            &mut self.auth_vole_receiver,
            &mut self.product_vole_sender,
            &mut self.product_vole_receiver,
            channel,
        )?;
        let sender_oprfs = two_side_oprf.inputer_output;
        let receiver_oprfs = two_side_oprf.shuffler_output;

        Ok(intersection_cardinality(
            &sender_oprfs.shuffled_oprf,
            &receiver_oprfs.shuffled_oprf,
        ))
    }
}

pub struct PsiCardinalityReceiver {
    delta1: FE,
    k1: FE,
    auth_vole_sender: BufferedVoleSender,
    auth_vole_receiver: BufferedVoleReceiver,
    product_vole_sender: BufferedVoleSender,
    product_vole_receiver: BufferedVoleReceiver,
}

impl PsiCardinalityReceiver {
    pub fn new(delta1: FE, k1: FE, channel: &mut SwankyChannel) -> Result<Self> {
        // Init order must match PsiCardinalitySender::new exactly.
        let auth_vole_receiver = BufferedVoleReceiver::init(channel, delta1, LPN21)
            .map_err(|e| anyhow!("init auth receiver VOLE failed: {e}"))?;
        let auth_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {e}"))?;
        let product_vole_receiver = BufferedVoleReceiver::init(channel, k1, LPN21)
            .map_err(|e| anyhow!("init product receiver VOLE failed: {e}"))?;
        let product_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init product sender VOLE failed: {e}"))?;

        Ok(Self {
            delta1,
            k1,
            auth_vole_sender,
            auth_vole_receiver,
            product_vole_sender,
            product_vole_receiver,
        })
    }

    pub fn delta1(&self) -> FE {
        self.delta1
    }

    pub fn k1(&self) -> FE {
        self.k1
    }

    pub fn run<RNG: Rng>(
        &mut self,
        receiver_set: &[FE],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<usize> {
        ensure!(
            !receiver_set.is_empty(),
            "PSI cardinality receiver requires a non-empty set"
        );

        let sender_set_len = exchange_set_size(receiver_set.len(), channel)?;
        ensure!(
            sender_set_len > 0,
            "PSI cardinality receiver received an empty remote set size"
        );

        let sender_permutation = random_permutation(sender_set_len, rng);
        let two_side_runner = TwoSideShuffler::new(self.delta1, self.k1);
        let two_side_oprf = two_side_runner.run_full_two_side_shuffled_oprf(
            &sender_permutation,
            receiver_set,
            rng,
            &mut self.auth_vole_sender,
            &mut self.auth_vole_receiver,
            &mut self.product_vole_receiver,
            &mut self.product_vole_sender,
            channel,
        )?;
        let sender_oprfs = two_side_oprf.shuffler_output;
        let receiver_oprfs = two_side_oprf.inputer_output;

        Ok(intersection_cardinality(
            &sender_oprfs.shuffled_oprf,
            &receiver_oprfs.shuffled_oprf,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::intersection_cardinality;
    use crate::math::group::Group;

    #[test]
    fn counts_group_intersection_as_set() {
        let g1 = Group::base_point();
        let g2 = g1.clone() + Group::base_point();
        let g3 = g2.clone() + Group::base_point();

        let left = vec![g1.clone(), g2.clone(), g2.clone()];
        let right = vec![g2, g3];

        assert_eq!(intersection_cardinality(&left, &right), 1);
    }
}
