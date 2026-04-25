use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple,
        bedoza_multiply::{batch_multiply_cross_owned_receiver, batch_multiply_cross_owned_sender},
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        open_values_receive, open_values_send,
    },
    circuit_psi::mq_rpmt::{MqRpmtReceiver, MqRpmtSender},
    math::defines::FE,
    tcp_channel::SwankyChannel,
    vole::{
        vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
        vole_triple::LPN21,
    },
};
use anyhow::{Result, anyhow, ensure};
use rand::Rng;

pub struct TwoSidePsuOutput {
    pub sender_only_shares: Vec<BeDOZa>,
    pub receiver_only_shares: Vec<BeDOZa>,
}

pub struct TwoSidePsuSender {
    sender_input_vole_sender: BufferedVoleSender,
    receiver_input_vole_receiver: BufferedVoleReceiver,
    sender_only_mq_rpmt: MqRpmtSender,
    receiver_only_mq_rpmt: MqRpmtReceiver,
}

impl TwoSidePsuSender {
    pub fn new(delta0: FE, k0: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let sender_input_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init sender input VOLE sender failed: {e}"))?;
        let receiver_input_vole_receiver = BufferedVoleReceiver::init(channel, delta0, LPN21)
            .map_err(|e| anyhow!("init receiver input VOLE receiver failed: {e}"))?;
        let sender_only_mq_rpmt = MqRpmtSender::new(delta0, k0, channel)
            .map_err(|e| anyhow!("init sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt = MqRpmtReceiver::new(delta0, k0, channel)
            .map_err(|e| anyhow!("init receiver-only mq_rpmt failed: {e}"))?;

        Ok(Self {
            sender_input_vole_sender,
            receiver_input_vole_receiver,
            sender_only_mq_rpmt,
            receiver_only_mq_rpmt,
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
            receiver_only_triples.len() > 1,
            "two_side_psu sender requires at least 2 receiver-only triples"
        );

        let authenticated_sender_inputs = self
            .sender_input_vole_sender
            .commit_auth(channel, sender_set)
            .map_err(|e| anyhow!("failed to authenticate sender inputs: {e}"))?;
        let authenticated_receiver_inputs = self
            .receiver_input_vole_receiver
            .commit_auth(channel, receiver_only_triples.len())
            .map_err(|e| anyhow!("failed to receive authenticated receiver inputs: {e}"))?;

        let sender_only_mq_rpmt_output = self
            .sender_only_mq_rpmt
            .run(sender_set, rng, channel)
            .map_err(|e| anyhow!("sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt_output = self
            .receiver_only_mq_rpmt
            .run(sender_set, rng, channel)
            .map_err(|e| anyhow!("receiver-only mq_rpmt failed: {e}"))?;

        ensure!(
            authenticated_sender_inputs.len()
                == sender_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu sender-only input/bitmap length mismatch: inputs={} bitmap={}",
            authenticated_sender_inputs.len(),
            sender_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );
        ensure!(
            authenticated_receiver_inputs.len()
                == receiver_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu receiver-only input/bitmap length mismatch: inputs={} bitmap={}",
            authenticated_receiver_inputs.len(),
            receiver_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );

        // Complement the authenticated bitmap to obtain 1 - b for sender elements.
        let authenticated_sender_complement_bitmap: Vec<BeDOZaReceiver> =
            sender_only_mq_rpmt_output
                .authenticated_original_bitmap
                .iter()
                .map(|share| (*share * -FE::one()) + FE::one())
                .collect();
        // Complement the authenticated bitmap to obtain 1 - b for receiver elements.
        let authenticated_receiver_complement_bitmap: Vec<BeDOZaSender> =
            receiver_only_mq_rpmt_output
                .authenticated_original_bitmap
                .iter()
                .map(|share| (*share * -FE::one()) + FE::one())
                .collect();

        let sender_only_shares = batch_multiply_cross_owned_sender(
            &authenticated_sender_inputs,
            &authenticated_sender_complement_bitmap,
            sender_only_triples,
            channel,
        )?;
        let receiver_only_shares = batch_multiply_cross_owned_receiver(
            &authenticated_receiver_inputs,
            &authenticated_receiver_complement_bitmap,
            receiver_only_triples,
            channel,
        )?;

        Ok(TwoSidePsuOutput {
            sender_only_shares,
            receiver_only_shares,
        })
    }
}

pub struct TwoSidePsuReceiver {
    sender_input_vole_receiver: BufferedVoleReceiver,
    receiver_input_vole_sender: BufferedVoleSender,
    sender_only_mq_rpmt: MqRpmtReceiver,
    receiver_only_mq_rpmt: MqRpmtSender,
}

impl TwoSidePsuReceiver {
    pub fn new(delta1: FE, k1: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let sender_input_vole_receiver = BufferedVoleReceiver::init(channel, delta1, LPN21)
            .map_err(|e| anyhow!("init sender input VOLE receiver failed: {e}"))?;
        let receiver_input_vole_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init receiver input VOLE sender failed: {e}"))?;
        let sender_only_mq_rpmt = MqRpmtReceiver::new(delta1, k1, channel)
            .map_err(|e| anyhow!("init sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt = MqRpmtSender::new(delta1, k1, channel)
            .map_err(|e| anyhow!("init receiver-only mq_rpmt failed: {e}"))?;

        Ok(Self {
            sender_input_vole_receiver,
            receiver_input_vole_sender,
            sender_only_mq_rpmt,
            receiver_only_mq_rpmt,
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

        let authenticated_sender_inputs = self
            .sender_input_vole_receiver
            .commit_auth(channel, sender_only_triples.len())
            .map_err(|e| anyhow!("failed to receive authenticated sender inputs: {e}"))?;
        let authenticated_receiver_inputs = self
            .receiver_input_vole_sender
            .commit_auth(channel, receiver_set)
            .map_err(|e| anyhow!("failed to authenticate receiver inputs: {e}"))?;

        let sender_only_mq_rpmt_output = self
            .sender_only_mq_rpmt
            .run(receiver_set, rng, channel)
            .map_err(|e| anyhow!("sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt_output = self
            .receiver_only_mq_rpmt
            .run(receiver_set, rng, channel)
            .map_err(|e| anyhow!("receiver-only mq_rpmt failed: {e}"))?;

        ensure!(
            authenticated_sender_inputs.len()
                == sender_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu sender-only input/bitmap length mismatch: inputs={} bitmap={}",
            authenticated_sender_inputs.len(),
            sender_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );
        ensure!(
            authenticated_receiver_inputs.len()
                == receiver_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu receiver-only input/bitmap length mismatch: inputs={} bitmap={}",
            authenticated_receiver_inputs.len(),
            receiver_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );

        // Complement the authenticated bitmap to obtain 1 - b for sender elements.
        let authenticated_sender_complement_bitmap: Vec<BeDOZaSender> = sender_only_mq_rpmt_output
            .authenticated_original_bitmap
            .iter()
            .map(|share| (*share * -FE::one()) + FE::one())
            .collect();
        // Complement the authenticated bitmap to obtain 1 - b for receiver elements.
        let authenticated_receiver_complement_bitmap: Vec<BeDOZaReceiver> =
            receiver_only_mq_rpmt_output
                .authenticated_original_bitmap
                .iter()
                .map(|share| (*share * -FE::one()) + FE::one())
                .collect();

        let sender_only_shares = batch_multiply_cross_owned_receiver(
            &authenticated_sender_inputs,
            &authenticated_sender_complement_bitmap,
            sender_only_triples,
            channel,
        )?;
        let receiver_only_shares = batch_multiply_cross_owned_sender(
            &authenticated_receiver_inputs,
            &authenticated_receiver_complement_bitmap,
            receiver_only_triples,
            channel,
        )?;

        Ok(TwoSidePsuOutput {
            sender_only_shares,
            receiver_only_shares,
        })
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
