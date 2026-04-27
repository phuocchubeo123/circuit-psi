use crate::{
    bedoza::{
        bedoza_receiver::{BeDOZaReceiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, send_open_shares},
        comm_util::{receive_fe_vec, send_fe_vec},
        wolverine::{wolverine_batch_mul_prove, wolverine_batch_mul_verify},
    },
    math::{defines::FE, group::Group},
    shuffled_oprf::{shuffle_inputer::Inputer, shuffle_shuffler::Shuffler},
    tcp_channel::SwankyChannel,
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use anyhow::{Result, anyhow, ensure};
use rand::{Rng, RngExt};
use std::collections::HashSet;

fn random_permutation<RNG: Rng>(n: usize, rng: &mut RNG) -> Vec<usize> {
    let mut permutation: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        permutation.swap(i, j);
    }
    permutation
}

fn group_set(values: &[Group]) -> HashSet<[u8; 32]> {
    values.iter().map(Group::to_bytes).collect()
}

fn membership_bitmap(values: &[Group], membership_set: &HashSet<[u8; 32]>) -> Vec<FE> {
    values
        .iter()
        .map(|value| {
            if membership_set.contains(&value.to_bytes()) {
                FE::one()
            } else {
                FE::zero()
            }
        })
        .collect()
}

fn relabel_sender_shares(shares: &[BeDOZaSender], _side: bool) -> Vec<BeDOZaSender> {
    shares.to_vec()
}

fn relabel_receiver_shares(shares: &[BeDOZaReceiver], _side: bool) -> Vec<BeDOZaReceiver> {
    shares.to_vec()
}

fn prove_bitmap_shuffle(
    authenticated_original_bitmap: &[BeDOZaSender],
    authenticated_permutation: &[BeDOZaSender],
    shuffled_bitmap: &[FE],
    auth_vole_sender: &mut BufferedVoleSender,
    channel: &mut SwankyChannel,
) -> Result<()> {
    ensure!(
        authenticated_original_bitmap.len() == authenticated_permutation.len(),
        "shuffle proof length mismatch: original={} permutation={}",
        authenticated_original_bitmap.len(),
        authenticated_permutation.len()
    );
    ensure!(
        authenticated_original_bitmap.len() == shuffled_bitmap.len(),
        "shuffle proof length mismatch: original={} shuffled={}",
        authenticated_original_bitmap.len(),
        shuffled_bitmap.len()
    );
    ensure!(
        authenticated_original_bitmap.len() > 1,
        "mq_rpmt shuffle proof requires at least 2 sender inputs"
    );

    let challenges = receive_fe_vec(channel)
        .map_err(|e| anyhow!("failed to receive mq_rpmt shuffle challenges: {e}"))?;
    ensure!(
        challenges.len() == 3,
        "expected 3 mq_rpmt shuffle challenges, got {}",
        challenges.len()
    );
    let alpha = challenges[0];
    let beta = challenges[1];
    let gamma = challenges[2];

    let authenticated_permuted_terms: Vec<BeDOZaSender> = authenticated_permutation
        .iter()
        .zip(shuffled_bitmap.iter())
        .map(|(pi_i, &bit_i)| (*pi_i * beta) + (alpha + gamma * bit_i))
        .collect();
    let permuted_term_values: Vec<FE> = authenticated_permutation
        .iter()
        .zip(shuffled_bitmap.iter())
        .map(|(pi_i, &bit_i)| alpha + beta * pi_i.val() + gamma * bit_i)
        .collect();
    let mut permuted_running = permuted_term_values[0];
    let permuted_running_products: Vec<FE> = permuted_term_values
        .iter()
        .skip(1)
        .map(|&term| {
            permuted_running *= term;
            permuted_running
        })
        .collect();
    let authenticated_permuted_running_products = auth_vole_sender
        .commit_auth(channel, &permuted_running_products)
        .map_err(|e| {
            anyhow!("permuted bitmap chain: failed to authenticate running products: {e}")
        })?;
    let mut permuted_left_chain = Vec::with_capacity(authenticated_permuted_running_products.len());
    permuted_left_chain.push(authenticated_permuted_terms[0]);
    permuted_left_chain.extend_from_slice(
        &authenticated_permuted_running_products
            [..authenticated_permuted_running_products.len() - 1],
    );
    wolverine_batch_mul_prove(
        &permuted_left_chain,
        &authenticated_permuted_terms[1..],
        &authenticated_permuted_running_products,
        auth_vole_sender,
        channel,
    )
    .map_err(|e| anyhow!("permuted bitmap chain: Wolverine chain proof failed: {e}"))?;

    let authenticated_original_terms: Vec<BeDOZaSender> = authenticated_original_bitmap
        .iter()
        .enumerate()
        .map(|(i, bit_i)| (*bit_i * gamma) + (alpha + beta * FE::from(i as u64)))
        .collect();
    let original_term_values: Vec<FE> = authenticated_original_bitmap
        .iter()
        .enumerate()
        .map(|(i, bit_i)| alpha + beta * FE::from(i as u64) + gamma * bit_i.val())
        .collect();
    let mut original_running = original_term_values[0];
    let original_running_products: Vec<FE> = original_term_values
        .iter()
        .skip(1)
        .map(|&term| {
            original_running *= term;
            original_running
        })
        .collect();
    let authenticated_original_running_products = auth_vole_sender
        .commit_auth(channel, &original_running_products)
        .map_err(|e| {
            anyhow!("original bitmap chain: failed to authenticate running products: {e}")
        })?;
    let mut original_left_chain = Vec::with_capacity(authenticated_original_running_products.len());
    original_left_chain.push(authenticated_original_terms[0]);
    original_left_chain.extend_from_slice(
        &authenticated_original_running_products
            [..authenticated_original_running_products.len() - 1],
    );
    wolverine_batch_mul_prove(
        &original_left_chain,
        &authenticated_original_terms[1..],
        &authenticated_original_running_products,
        auth_vole_sender,
        channel,
    )
    .map_err(|e| anyhow!("original bitmap chain: Wolverine chain proof failed: {e}"))?;

    send_open_shares(
        &[
            authenticated_permuted_running_products
                [authenticated_permuted_running_products.len() - 1],
            authenticated_original_running_products
                [authenticated_original_running_products.len() - 1],
        ],
        channel,
    )
    .map_err(|e| anyhow!("failed to open mq_rpmt final chain products: {e}"))?;

    Ok(())
}

fn verify_bitmap_shuffle<RNG: Rng>(
    authenticated_original_bitmap: &[BeDOZaReceiver],
    authenticated_permutation: &[BeDOZaReceiver],
    shuffled_bitmap: &[FE],
    rng: &mut RNG,
    auth_vole_receiver: &mut BufferedVoleReceiver,
    channel: &mut SwankyChannel,
) -> Result<()> {
    ensure!(
        authenticated_original_bitmap.len() == authenticated_permutation.len(),
        "shuffle verification length mismatch: original={} permutation={}",
        authenticated_original_bitmap.len(),
        authenticated_permutation.len()
    );
    ensure!(
        authenticated_original_bitmap.len() == shuffled_bitmap.len(),
        "shuffle verification length mismatch: original={} shuffled={}",
        authenticated_original_bitmap.len(),
        shuffled_bitmap.len()
    );
    ensure!(
        authenticated_original_bitmap.len() > 1,
        "mq_rpmt shuffle verification requires at least 2 sender inputs"
    );

    let alpha = FE::from_bytes_le_mod_order(&rng.random::<[u8; 32]>());
    let beta = FE::from_bytes_le_mod_order(&rng.random::<[u8; 32]>());
    let gamma = FE::from_bytes_le_mod_order(&rng.random::<[u8; 32]>());
    send_fe_vec(&[alpha, beta, gamma], channel)
        .map_err(|e| anyhow!("failed to send mq_rpmt shuffle challenges: {e}"))?;

    let authenticated_permuted_terms: Vec<BeDOZaReceiver> = authenticated_permutation
        .iter()
        .zip(shuffled_bitmap.iter())
        .map(|(pi_i, &bit_i)| (*pi_i * beta) + (alpha + gamma * bit_i))
        .collect();
    let authenticated_permuted_running_products = auth_vole_receiver
        .commit_auth(channel, authenticated_permuted_terms.len() - 1)
        .map_err(|e| anyhow!("permuted bitmap chain: failed to receive running products: {e}"))?;
    let mut permuted_left_chain = Vec::with_capacity(authenticated_permuted_running_products.len());
    permuted_left_chain.push(authenticated_permuted_terms[0]);
    permuted_left_chain.extend_from_slice(
        &authenticated_permuted_running_products
            [..authenticated_permuted_running_products.len() - 1],
    );
    wolverine_batch_mul_verify(
        &permuted_left_chain,
        &authenticated_permuted_terms[1..],
        &authenticated_permuted_running_products,
        auth_vole_receiver,
        channel,
    )
    .map_err(|e| anyhow!("permuted bitmap chain: Wolverine chain verification failed: {e}"))?;

    let authenticated_original_terms: Vec<BeDOZaReceiver> = authenticated_original_bitmap
        .iter()
        .enumerate()
        .map(|(i, bit_i)| (*bit_i * gamma) + (alpha + beta * FE::from(i as u64)))
        .collect();
    let authenticated_original_running_products = auth_vole_receiver
        .commit_auth(channel, authenticated_original_terms.len() - 1)
        .map_err(|e| anyhow!("original bitmap chain: failed to receive running products: {e}"))?;
    let mut original_left_chain = Vec::with_capacity(authenticated_original_running_products.len());
    original_left_chain.push(authenticated_original_terms[0]);
    original_left_chain.extend_from_slice(
        &authenticated_original_running_products
            [..authenticated_original_running_products.len() - 1],
    );
    wolverine_batch_mul_verify(
        &original_left_chain,
        &authenticated_original_terms[1..],
        &authenticated_original_running_products,
        auth_vole_receiver,
        channel,
    )
    .map_err(|e| anyhow!("original bitmap chain: Wolverine chain verification failed: {e}"))?;

    let opened = receive_open_shares(
        &[
            authenticated_permuted_running_products
                [authenticated_permuted_running_products.len() - 1],
            authenticated_original_running_products
                [authenticated_original_running_products.len() - 1],
        ],
        channel,
    )
    .map_err(|e| anyhow!("failed to receive mq_rpmt final chain products: {e}"))?;
    ensure!(
        opened[0] == opened[1],
        "mq_rpmt shuffle proof failed: final chain products differ"
    );

    Ok(())
}

pub struct MqRpmtSender {
    delta0: FE,
    k0: FE,
    auth_vole_sender: BufferedVoleSender,
    auth_vole_receiver: BufferedVoleReceiver,
    product_vole_sender: BufferedVoleSender,
    product_vole_receiver: BufferedVoleReceiver,
}

pub struct MqRpmtSenderOutput {
    pub authenticated_original_bitmap: Vec<BeDOZaReceiver>,
    pub shuffled_bitmap: Vec<FE>,
}

impl MqRpmtSender {
    pub fn new(delta0: FE, k0: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let auth_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init auth sender VOLE failed: {e}"))?;
        let auth_vole_receiver = BufferedVoleReceiver::init(channel, delta0, LPN21)
            .map_err(|e| anyhow!("init auth receiver VOLE failed: {e}"))?;
        let product_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init product sender VOLE failed: {e}"))?;
        let product_vole_receiver = BufferedVoleReceiver::init(channel, k0, LPN21)
            .map_err(|e| anyhow!("init product receiver VOLE failed: {e}"))?;

        Ok(Self {
            delta0,
            k0,
            auth_vole_sender,
            auth_vole_receiver,
            product_vole_sender,
            product_vole_receiver,
        })
    }

    pub fn run<RNG: Rng>(
        &mut self,
        sender_set: &[FE],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<MqRpmtSenderOutput> {
        ensure!(
            sender_set.len() > 1,
            "mq_rpmt sender requires at least 2 sender inputs"
        );

        let receiver_set_len = exchange_set_size(sender_set.len(), channel)?;
        ensure!(
            receiver_set_len > 1,
            "mq_rpmt sender requires at least 2 receiver inputs"
        );

        let inputer = Inputer::new(self.delta0, self.k0);
        let sender_oprf = inputer.run_full_shuffled_oprf(
            sender_set,
            rng,
            &mut self.auth_vole_sender,
            &mut self.auth_vole_receiver,
            &mut self.product_vole_sender,
            channel,
        )?;

        let shuffler = Shuffler::new(self.delta0, self.k0);
        let receiver_permutation = random_permutation(receiver_set_len, rng);
        let receiver_oprf = shuffler.run_full_shuffled_oprf(
            &receiver_permutation,
            rng,
            &mut self.auth_vole_sender,
            &mut self.auth_vole_receiver,
            &mut self.product_vole_receiver,
            channel,
        )?;

        let receiver_oprf_set = group_set(&receiver_oprf.shuffled_oprf);
        let shuffled_bitmap = membership_bitmap(&sender_oprf.shuffled_oprf, &receiver_oprf_set);

        let proof_original_bitmap = self
            .auth_vole_receiver
            .commit_auth(channel, sender_set.len())
            .map_err(|e| anyhow!("failed to receive authenticated original bitmap: {e}"))?;
        verify_bitmap_shuffle(
            &proof_original_bitmap,
            &sender_oprf.authenticated_permutation,
            &shuffled_bitmap,
            rng,
            &mut self.auth_vole_receiver,
            channel,
        )?;

        Ok(MqRpmtSenderOutput {
            authenticated_original_bitmap: relabel_receiver_shares(&proof_original_bitmap, true),
            shuffled_bitmap,
        })
    }
}

pub struct MqRpmtReceiver {
    delta1: FE,
    k1: FE,
    auth_vole_sender: BufferedVoleSender,
    auth_vole_receiver: BufferedVoleReceiver,
    product_vole_sender: BufferedVoleSender,
    product_vole_receiver: BufferedVoleReceiver,
}

pub struct MqRpmtReceiverOutput {
    pub original_bitmap: Vec<FE>,
    pub authenticated_original_bitmap: Vec<BeDOZaSender>,
    pub shuffled_bitmap: Vec<FE>,
}

impl MqRpmtReceiver {
    pub fn new(delta1: FE, k1: FE, channel: &mut SwankyChannel) -> Result<Self> {
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

    pub fn run<RNG: Rng>(
        &mut self,
        receiver_set: &[FE],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<MqRpmtReceiverOutput> {
        ensure!(
            receiver_set.len() > 1,
            "mq_rpmt receiver requires at least 2 receiver inputs"
        );

        let sender_set_len = exchange_set_size(receiver_set.len(), channel)?;
        ensure!(
            sender_set_len > 1,
            "mq_rpmt receiver requires at least 2 sender inputs"
        );

        let sender_permutation = random_permutation(sender_set_len, rng);
        let shuffler = Shuffler::new(self.delta1, self.k1);
        let sender_oprf = shuffler.run_full_shuffled_oprf(
            &sender_permutation,
            rng,
            &mut self.auth_vole_sender,
            &mut self.auth_vole_receiver,
            &mut self.product_vole_receiver,
            channel,
        )?;

        let inputer = Inputer::new(self.delta1, self.k1);
        let receiver_oprf = inputer.run_full_shuffled_oprf(
            receiver_set,
            rng,
            &mut self.auth_vole_sender,
            &mut self.auth_vole_receiver,
            &mut self.product_vole_sender,
            channel,
        )?;

        let receiver_oprf_set = group_set(&receiver_oprf.shuffled_oprf);
        let original_bitmap = membership_bitmap(&sender_oprf.unshuffled_oprf, &receiver_oprf_set);
        let shuffled_bitmap = membership_bitmap(&sender_oprf.shuffled_oprf, &receiver_oprf_set);

        let proof_original_bitmap = self
            .auth_vole_sender
            .commit_auth(channel, &original_bitmap)
            .map_err(|e| anyhow!("failed to authenticate original bitmap for proof: {e}"))?;
        prove_bitmap_shuffle(
            &proof_original_bitmap,
            &sender_oprf.authenticated_permutation,
            &shuffled_bitmap,
            &mut self.auth_vole_sender,
            channel,
        )?;

        Ok(MqRpmtReceiverOutput {
            original_bitmap,
            authenticated_original_bitmap: relabel_sender_shares(&proof_original_bitmap, true),
            shuffled_bitmap,
        })
    }
}

fn exchange_set_size(local_len: usize, channel: &mut SwankyChannel) -> Result<usize> {
    channel
        .send(&(local_len as u64).to_le_bytes())
        .map_err(|e| anyhow!("failed to send local set size: {e}"))?;
    let remote_len_bytes = channel
        .receive()
        .map_err(|e| anyhow!("failed to receive remote set size: {e}"))?;
    ensure!(
        remote_len_bytes.len() == 8,
        "expected 8 bytes for remote set size, got {}",
        remote_len_bytes.len()
    );

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&remote_len_bytes);
    Ok(u64::from_le_bytes(bytes) as usize)
}
