use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple,
        bedoza_multiply::{batch_multiply_cross_owned_receiver, batch_multiply_cross_owned_sender},
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        open_values_receive, open_values_send,
    },
    circuit_psi::mq_rpmt::{prove_bitmap_shuffle, verify_bitmap_shuffle},
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
use std::{collections::HashSet, time::Instant};

fn filter_nonzero(values: Vec<FE>) -> Vec<FE> {
    values
        .into_iter()
        .filter(|value| *value != FE::zero())
        .collect()
}

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

pub struct TwoSidePsuOutput {
    pub sender_only_shares: Vec<BeDOZa>,
    pub receiver_only_shares: Vec<BeDOZa>,
}

pub struct TwoSidePsuSender {
    delta0: FE,
    k0: FE,
    auth_vole_sender: BufferedVoleSender,
    auth_vole_receiver: BufferedVoleReceiver,
    product_vole_sender: BufferedVoleSender,
    product_vole_receiver: BufferedVoleReceiver,
}

impl TwoSidePsuSender {
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
        sender_only_triples: &[BeDOZaTriple],
        receiver_only_triples: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<TwoSidePsuOutput> {
        ensure!(
            sender_set.len() > 1,
            "two_side_psu sender requires at least 2 sender inputs"
        );
        ensure!(
            sender_set.len() == sender_only_triples.len(),
            "two_side_psu sender-only input/triple length mismatch: inputs={} triples={}",
            sender_set.len(),
            sender_only_triples.len()
        );
        ensure!(
            sender_only_triples.len() > 1,
            "two_side_psu sender requires at least 2 sender-only triples"
        );
        ensure!(
            receiver_only_triples.len() > 1,
            "two_side_psu sender requires at least 2 receiver-only triples"
        );
        let psi_cardinality_start = Instant::now();

        let receiver_set_len = exchange_set_size(sender_set.len(), channel)?;
        ensure!(
            receiver_set_len > 1,
            "two_side_psu sender requires at least 2 receiver inputs"
        );
        ensure!(
            receiver_set_len == receiver_only_triples.len(),
            "two_side_psu receiver-only input/triple length mismatch: inputs={} triples={}",
            receiver_set_len,
            receiver_only_triples.len()
        );

        // Run both shuffled OPRF directions in one merged transcript.
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
        let sender_oprf = two_side_oprf.inputer_output;
        let receiver_oprf = two_side_oprf.shuffler_output;

        let sender_oprf_set = group_set(&sender_oprf.shuffled_oprf);
        let receiver_oprf_set = group_set(&receiver_oprf.shuffled_oprf);

        let sender_shuffled_bitmap =
            membership_bitmap(&sender_oprf.shuffled_oprf, &receiver_oprf_set);
        let receiver_original_bitmap =
            membership_bitmap(&receiver_oprf.unshuffled_oprf, &sender_oprf_set);
        let receiver_shuffled_bitmap =
            membership_bitmap(&receiver_oprf.shuffled_oprf, &sender_oprf_set);
        println!(
            "two_side_psu_sender_ms_before_verify_bitmap_shuffle={}",
            psi_cardinality_start.elapsed().as_millis()
        );

        // Verify sender-set bitmap proof from peer.
        let sender_mq_rpmt_start = Instant::now();
        let authenticated_sender_original_bitmap = self
            .auth_vole_receiver
            .commit_auth(channel, sender_set.len())
            .map_err(|e| anyhow!("failed to receive authenticated sender original bitmap: {e}"))?;
        verify_bitmap_shuffle(
            &authenticated_sender_original_bitmap,
            &sender_oprf.authenticated_permutation,
            &sender_shuffled_bitmap,
            rng,
            &mut self.auth_vole_receiver,
            channel,
        )?;
        println!(
            "two_side_psu_sender_mq_rpmt_ms={}",
            sender_mq_rpmt_start.elapsed().as_millis()
        );

        ensure!(
            sender_oprf.authenticated_inputs.len() == authenticated_sender_original_bitmap.len(),
            "two_side_psu sender-only input/bitmap length mismatch: inputs={} bitmap={}",
            sender_oprf.authenticated_inputs.len(),
            authenticated_sender_original_bitmap.len()
        );
        ensure!(
            sender_oprf.authenticated_inputs.len() == sender_only_triples.len(),
            "two_side_psu sender-only input/triple length mismatch: inputs={} triples={}",
            sender_oprf.authenticated_inputs.len(),
            sender_only_triples.len()
        );

        // Complement the authenticated bitmap to obtain 1 - b for sender elements.
        let authenticated_sender_complement_bitmap: Vec<BeDOZaReceiver> =
            authenticated_sender_original_bitmap
                .iter()
                .map(|share| (*share * -FE::one()) + FE::one())
                .collect();

        let sender_first_batch_multiply_start = Instant::now();
        let sender_only_shares = batch_multiply_cross_owned_sender(
            &sender_oprf.authenticated_inputs,
            &authenticated_sender_complement_bitmap,
            sender_only_triples,
            channel,
        )?;
        println!(
            "two_side_psu_sender_first_batch_multiply_ms={}",
            sender_first_batch_multiply_start.elapsed().as_millis()
        );

        // Prove receiver-set bitmap proof to peer using the same shuffled OPRF transcript.
        let authenticated_receiver_original_bitmap = self
            .auth_vole_sender
            .commit_auth(channel, &receiver_original_bitmap)
            .map_err(|e| {
                anyhow!("failed to authenticate receiver original bitmap for proof: {e}")
            })?;
        prove_bitmap_shuffle(
            &authenticated_receiver_original_bitmap,
            &receiver_oprf.authenticated_permutation,
            &receiver_shuffled_bitmap,
            &mut self.auth_vole_sender,
            channel,
        )?;

        ensure!(
            receiver_oprf.authenticated_inputs.len()
                == authenticated_receiver_original_bitmap.len(),
            "two_side_psu receiver-only input/bitmap length mismatch: inputs={} bitmap={}",
            receiver_oprf.authenticated_inputs.len(),
            authenticated_receiver_original_bitmap.len()
        );
        ensure!(
            receiver_oprf.authenticated_inputs.len() == receiver_only_triples.len(),
            "two_side_psu receiver-only input/triple length mismatch: inputs={} triples={}",
            receiver_oprf.authenticated_inputs.len(),
            receiver_only_triples.len()
        );

        // Complement the authenticated bitmap to obtain 1 - b for receiver elements.
        let authenticated_receiver_complement_bitmap: Vec<BeDOZaSender> =
            authenticated_receiver_original_bitmap
                .iter()
                .map(|share| (*share * -FE::one()) + FE::one())
                .collect();
        let receiver_only_shares = batch_multiply_cross_owned_receiver(
            &receiver_oprf.authenticated_inputs,
            &authenticated_receiver_complement_bitmap,
            receiver_only_triples,
            channel,
        )?;

        Ok(TwoSidePsuOutput {
            sender_only_shares,
            receiver_only_shares,
        })
    }

    pub fn run_and_open<RNG: Rng>(
        &mut self,
        sender_set: &[FE],
        sender_only_triples: &[BeDOZaTriple],
        receiver_only_triples: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<FE>> {
        let output = self.run(
            sender_set,
            sender_only_triples,
            receiver_only_triples,
            rng,
            channel,
        )?;

        open_two_side_psu_send(&output.sender_only_shares, channel)?;
        let opened_receiver_difference =
            open_two_side_psu_receive(&output.receiver_only_shares, channel)?;
        Ok(filter_nonzero(opened_receiver_difference))
    }
}

pub struct TwoSidePsuReceiver {
    delta1: FE,
    k1: FE,
    auth_vole_sender: BufferedVoleSender,
    auth_vole_receiver: BufferedVoleReceiver,
    product_vole_sender: BufferedVoleSender,
    product_vole_receiver: BufferedVoleReceiver,
}

impl TwoSidePsuReceiver {
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
        sender_only_triples: &[BeDOZaTriple],
        receiver_only_triples: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<TwoSidePsuOutput> {
        ensure!(
            receiver_set.len() > 1,
            "two_side_psu receiver requires at least 2 receiver inputs"
        );
        ensure!(
            sender_only_triples.len() > 1,
            "two_side_psu receiver requires at least 2 sender-only triples"
        );
        ensure!(
            receiver_set.len() == receiver_only_triples.len(),
            "two_side_psu receiver-only input/triple length mismatch: inputs={} triples={}",
            receiver_set.len(),
            receiver_only_triples.len()
        );
        let psi_cardinality_start = Instant::now();

        let sender_set_len = exchange_set_size(receiver_set.len(), channel)?;
        ensure!(
            sender_set_len > 1,
            "two_side_psu receiver requires at least 2 sender inputs"
        );
        ensure!(
            sender_set_len == sender_only_triples.len(),
            "two_side_psu sender-only input/triple length mismatch: inputs={} triples={}",
            sender_set_len,
            sender_only_triples.len()
        );

        // Run both shuffled OPRF directions in one merged transcript.
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
        let sender_oprf = two_side_oprf.shuffler_output;
        let receiver_oprf = two_side_oprf.inputer_output;

        let sender_oprf_set = group_set(&sender_oprf.shuffled_oprf);
        let receiver_oprf_set = group_set(&receiver_oprf.shuffled_oprf);

        let sender_original_bitmap =
            membership_bitmap(&sender_oprf.unshuffled_oprf, &receiver_oprf_set);
        let sender_shuffled_bitmap =
            membership_bitmap(&sender_oprf.shuffled_oprf, &receiver_oprf_set);
        let receiver_shuffled_bitmap =
            membership_bitmap(&receiver_oprf.shuffled_oprf, &sender_oprf_set);
        println!(
            "two_side_psu_receiver_ms_before_verify_bitmap_shuffle={}",
            psi_cardinality_start.elapsed().as_millis()
        );

        // Prove sender-set bitmap proof to peer.
        let authenticated_sender_original_bitmap = self
            .auth_vole_sender
            .commit_auth(channel, &sender_original_bitmap)
            .map_err(|e| anyhow!("failed to authenticate sender original bitmap for proof: {e}"))?;
        prove_bitmap_shuffle(
            &authenticated_sender_original_bitmap,
            &sender_oprf.authenticated_permutation,
            &sender_shuffled_bitmap,
            &mut self.auth_vole_sender,
            channel,
        )?;

        ensure!(
            sender_oprf.authenticated_inputs.len() == authenticated_sender_original_bitmap.len(),
            "two_side_psu sender-only input/bitmap length mismatch: inputs={} bitmap={}",
            sender_oprf.authenticated_inputs.len(),
            authenticated_sender_original_bitmap.len()
        );
        ensure!(
            sender_oprf.authenticated_inputs.len() == sender_only_triples.len(),
            "two_side_psu sender-only input/triple length mismatch: inputs={} triples={}",
            sender_oprf.authenticated_inputs.len(),
            sender_only_triples.len()
        );

        // Complement the authenticated bitmap to obtain 1 - b for sender elements.
        let authenticated_sender_complement_bitmap: Vec<BeDOZaSender> =
            authenticated_sender_original_bitmap
                .iter()
                .map(|share| (*share * -FE::one()) + FE::one())
                .collect();
        let receiver_first_batch_multiply_start = Instant::now();
        let sender_only_shares = batch_multiply_cross_owned_receiver(
            &sender_oprf.authenticated_inputs,
            &authenticated_sender_complement_bitmap,
            sender_only_triples,
            channel,
        )?;
        println!(
            "two_side_psu_receiver_first_batch_multiply_ms={}",
            receiver_first_batch_multiply_start.elapsed().as_millis()
        );

        // Verify receiver-set bitmap proof from peer.
        let receiver_mq_rpmt_start = Instant::now();
        let authenticated_receiver_original_bitmap = self
            .auth_vole_receiver
            .commit_auth(channel, receiver_set.len())
            .map_err(|e| {
                anyhow!("failed to receive authenticated receiver original bitmap: {e}")
            })?;
        verify_bitmap_shuffle(
            &authenticated_receiver_original_bitmap,
            &receiver_oprf.authenticated_permutation,
            &receiver_shuffled_bitmap,
            rng,
            &mut self.auth_vole_receiver,
            channel,
        )?;
        println!(
            "two_side_psu_receiver_mq_rpmt_ms={}",
            receiver_mq_rpmt_start.elapsed().as_millis()
        );

        ensure!(
            receiver_oprf.authenticated_inputs.len()
                == authenticated_receiver_original_bitmap.len(),
            "two_side_psu receiver-only input/bitmap length mismatch: inputs={} bitmap={}",
            receiver_oprf.authenticated_inputs.len(),
            authenticated_receiver_original_bitmap.len()
        );
        ensure!(
            receiver_oprf.authenticated_inputs.len() == receiver_only_triples.len(),
            "two_side_psu receiver-only input/triple length mismatch: inputs={} triples={}",
            receiver_oprf.authenticated_inputs.len(),
            receiver_only_triples.len()
        );

        // Complement the authenticated bitmap to obtain 1 - b for receiver elements.
        let authenticated_receiver_complement_bitmap: Vec<BeDOZaReceiver> =
            authenticated_receiver_original_bitmap
                .iter()
                .map(|share| (*share * -FE::one()) + FE::one())
                .collect();

        let receiver_only_shares = batch_multiply_cross_owned_sender(
            &receiver_oprf.authenticated_inputs,
            &authenticated_receiver_complement_bitmap,
            receiver_only_triples,
            channel,
        )?;

        Ok(TwoSidePsuOutput {
            sender_only_shares,
            receiver_only_shares,
        })
    }

    pub fn run_and_open<RNG: Rng>(
        &mut self,
        receiver_set: &[FE],
        sender_only_triples: &[BeDOZaTriple],
        receiver_only_triples: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<FE>> {
        let output = self.run(
            receiver_set,
            sender_only_triples,
            receiver_only_triples,
            rng,
            channel,
        )?;

        let opened_sender_difference =
            open_two_side_psu_receive(&output.sender_only_shares, channel)?;
        open_two_side_psu_send(&output.receiver_only_shares, channel)?;
        Ok(filter_nonzero(opened_sender_difference))
    }
}

pub fn open_two_side_psu_send(psu_shares: &[BeDOZa], channel: &mut SwankyChannel) -> Result<()> {
    open_values_send(psu_shares, channel)
        .map_err(|e| anyhow!("failed to send two_side_psu opening: {e}"))
}

pub fn open_two_side_psu_receive(
    psu_shares: &[BeDOZa],
    channel: &mut SwankyChannel,
) -> Result<Vec<FE>> {
    open_values_receive(psu_shares, channel)
        .map_err(|e| anyhow!("failed to receive two_side_psu opening: {e}"))
}
