use crate::{
    bedoza::{
        BeDOZaTriple,
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

pub struct OneSidePsuSender {
    mq_rpmt: MqRpmtSender,
}

impl OneSidePsuSender {
    pub fn new(delta0: FE, k0: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let mq_rpmt = MqRpmtSender::new(delta0, k0, channel)
            .map_err(|e| anyhow!("init mq_rpmt sender failed: {e}"))?;

        Ok(Self { mq_rpmt })
    }

    pub fn run<RNG: Rng>(
        &mut self,
        sender_set: &[FE],
        triple_shares: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<()> {
        ensure!(
            sender_set.len() > 1,
            "one_side_psu sender requires at least 2 sender inputs"
        );
        ensure!(
            sender_set.len() == triple_shares.len(),
            "one_side_psu sender input/triple length mismatch: inputs={} triples={}",
            sender_set.len(),
            triple_shares.len()
        );

        let mq_rpmt_output = self
            .mq_rpmt
            .run(sender_set, rng, channel)
            .map_err(|e| anyhow!("mq_rpmt sender failed: {e}"))?;
        ensure!(
            mq_rpmt_output.authenticated_sender_inputs.len() == triple_shares.len(),
            "one_side_psu sender input/triple length mismatch: inputs={} triples={}",
            mq_rpmt_output.authenticated_sender_inputs.len(),
            triple_shares.len()
        );

        // Complement the authenticated bitmap to obtain 1 - b before multiplying by sender inputs.
        let authenticated_complement_bitmap: Vec<BeDOZaReceiver> = mq_rpmt_output
            .authenticated_original_bitmap
            .iter()
            .map(|share| (*share * -FE::one()) + FE::one())
            .collect();

        let psu_shares = batch_multiply_cross_owned_sender(
            &mq_rpmt_output.authenticated_sender_inputs,
            &authenticated_complement_bitmap,
            triple_shares,
            channel,
        )?;

        open_values_send(&psu_shares, channel)
            .map_err(|e| anyhow!("failed to send one_side_psu opening: {e}"))
    }

    pub fn run_and_open<RNG: Rng>(
        &mut self,
        sender_set: &[FE],
        triple_shares: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<()> {
        self.run(sender_set, triple_shares, rng, channel)
    }
}

pub struct OneSidePsuReceiver {
    mq_rpmt: MqRpmtReceiver,
}

impl OneSidePsuReceiver {
    pub fn new(delta1: FE, k1: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let mq_rpmt = MqRpmtReceiver::new(delta1, k1, channel)
            .map_err(|e| anyhow!("init mq_rpmt receiver failed: {e}"))?;

        Ok(Self { mq_rpmt })
    }

    pub fn run<RNG: Rng>(
        &mut self,
        receiver_set: &[FE],
        triple_shares: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<FE>> {
        ensure!(
            receiver_set.len() > 1,
            "one_side_psu receiver requires at least 2 receiver inputs"
        );
        ensure!(
            triple_shares.len() > 1,
            "one_side_psu receiver requires at least 2 triples"
        );

        let mq_rpmt_output = self
            .mq_rpmt
            .run(receiver_set, rng, channel)
            .map_err(|e| anyhow!("mq_rpmt receiver failed: {e}"))?;

        ensure!(
            mq_rpmt_output.authenticated_sender_inputs.len()
                == mq_rpmt_output.authenticated_original_bitmap.len(),
            "one_side_psu receiver input/bitmap length mismatch: inputs={} bitmap={}",
            mq_rpmt_output.authenticated_sender_inputs.len(),
            mq_rpmt_output.authenticated_original_bitmap.len()
        );
        ensure!(
            mq_rpmt_output.authenticated_sender_inputs.len() == triple_shares.len(),
            "one_side_psu receiver input/triple length mismatch: inputs={} triples={}",
            mq_rpmt_output.authenticated_sender_inputs.len(),
            triple_shares.len()
        );

        // Complement the authenticated bitmap to obtain 1 - b before opening X \ Y.
        let authenticated_complement_bitmap: Vec<BeDOZaSender> = mq_rpmt_output
            .authenticated_original_bitmap
            .iter()
            .map(|share| (*share * -FE::one()) + FE::one())
            .collect();

        let psu_shares = batch_multiply_cross_owned_receiver(
            &mq_rpmt_output.authenticated_sender_inputs,
            &authenticated_complement_bitmap,
            triple_shares,
            channel,
        )?;

        open_values_receive(&psu_shares, channel)
            .map_err(|e| anyhow!("failed to receive one_side_psu opening: {e}"))
    }

    pub fn run_and_open<RNG: Rng>(
        &mut self,
        receiver_set: &[FE],
        triple_shares: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<FE>> {
        let opened_products = self.run(receiver_set, triple_shares, rng, channel)?;
        Ok(filter_nonzero(opened_products))
    }
}
