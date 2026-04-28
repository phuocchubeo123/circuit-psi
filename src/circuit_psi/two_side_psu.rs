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
};
use anyhow::{Result, anyhow, ensure};
use rand::Rng;

fn filter_nonzero(values: Vec<FE>) -> Vec<FE> {
    values.into_iter().filter(|value| *value != FE::zero()).collect()
}

pub struct TwoSidePsuOutput {
    pub sender_only_shares: Vec<BeDOZa>,
    pub receiver_only_shares: Vec<BeDOZa>,
}

pub struct TwoSidePsuSender {
    sender_only_mq_rpmt: MqRpmtSender,
    receiver_only_mq_rpmt: MqRpmtReceiver,
}

impl TwoSidePsuSender {
    pub fn new(delta0: FE, k0: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let sender_only_mq_rpmt = MqRpmtSender::new(delta0, k0, channel)
            .map_err(|e| anyhow!("init sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt = MqRpmtReceiver::new(delta0, k0, channel)
            .map_err(|e| anyhow!("init receiver-only mq_rpmt failed: {e}"))?;

        Ok(Self {
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

        let sender_only_mq_rpmt_output = self
            .sender_only_mq_rpmt
            .run(sender_set, rng, channel)
            .map_err(|e| anyhow!("sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt_output = self
            .receiver_only_mq_rpmt
            .run(sender_set, rng, channel)
            .map_err(|e| anyhow!("receiver-only mq_rpmt failed: {e}"))?;

        ensure!(
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len()
                == sender_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu sender-only input/bitmap length mismatch: inputs={} bitmap={}",
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            sender_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );
        ensure!(
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len()
                == receiver_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu receiver-only input/bitmap length mismatch: inputs={} bitmap={}",
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            receiver_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );
        ensure!(
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len() == sender_only_triples.len(),
            "two_side_psu sender-only input/triple length mismatch: inputs={} triples={}",
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            sender_only_triples.len()
        );
        ensure!(
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len()
                == receiver_only_triples.len(),
            "two_side_psu receiver-only input/triple length mismatch: inputs={} triples={}",
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            receiver_only_triples.len()
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
            &sender_only_mq_rpmt_output.authenticated_sender_inputs,
            &authenticated_sender_complement_bitmap,
            sender_only_triples,
            channel,
        )?;
        let receiver_only_shares = batch_multiply_cross_owned_receiver(
            &receiver_only_mq_rpmt_output.authenticated_sender_inputs,
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
        let opened_receiver_difference = open_two_side_psu_receive(&output.receiver_only_shares, channel)?;
        Ok(filter_nonzero(opened_receiver_difference))
    }
}

pub struct TwoSidePsuReceiver {
    sender_only_mq_rpmt: MqRpmtReceiver,
    receiver_only_mq_rpmt: MqRpmtSender,
}

impl TwoSidePsuReceiver {
    pub fn new(delta1: FE, k1: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let sender_only_mq_rpmt = MqRpmtReceiver::new(delta1, k1, channel)
            .map_err(|e| anyhow!("init sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt = MqRpmtSender::new(delta1, k1, channel)
            .map_err(|e| anyhow!("init receiver-only mq_rpmt failed: {e}"))?;

        Ok(Self {
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

        let sender_only_mq_rpmt_output = self
            .sender_only_mq_rpmt
            .run(receiver_set, rng, channel)
            .map_err(|e| anyhow!("sender-only mq_rpmt failed: {e}"))?;
        let receiver_only_mq_rpmt_output = self
            .receiver_only_mq_rpmt
            .run(receiver_set, rng, channel)
            .map_err(|e| anyhow!("receiver-only mq_rpmt failed: {e}"))?;

        ensure!(
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len()
                == sender_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu sender-only input/bitmap length mismatch: inputs={} bitmap={}",
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            sender_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );
        ensure!(
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len()
                == receiver_only_mq_rpmt_output
                    .authenticated_original_bitmap
                    .len(),
            "two_side_psu receiver-only input/bitmap length mismatch: inputs={} bitmap={}",
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            receiver_only_mq_rpmt_output
                .authenticated_original_bitmap
                .len()
        );
        ensure!(
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len() == sender_only_triples.len(),
            "two_side_psu sender-only input/triple length mismatch: inputs={} triples={}",
            sender_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            sender_only_triples.len()
        );
        ensure!(
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len()
                == receiver_only_triples.len(),
            "two_side_psu receiver-only input/triple length mismatch: inputs={} triples={}",
            receiver_only_mq_rpmt_output.authenticated_sender_inputs.len(),
            receiver_only_triples.len()
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
            &sender_only_mq_rpmt_output.authenticated_sender_inputs,
            &authenticated_sender_complement_bitmap,
            sender_only_triples,
            channel,
        )?;
        let receiver_only_shares = batch_multiply_cross_owned_sender(
            &receiver_only_mq_rpmt_output.authenticated_sender_inputs,
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

        let opened_sender_difference = open_two_side_psu_receive(&output.sender_only_shares, channel)?;
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
