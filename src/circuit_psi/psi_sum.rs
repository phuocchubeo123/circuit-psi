use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple,
        bedoza_multiply::{batch_multiply_cross_owned_receiver, batch_multiply_cross_owned_sender},
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

fn sum_bedoza_values(values: &[BeDOZa]) -> Result<BeDOZa> {
    ensure!(
        !values.is_empty(),
        "psi_sum requires at least one product share"
    );

    let mut acc = values[0];
    for value in values.iter().skip(1) {
        acc = acc + value;
    }

    Ok(acc)
}

pub struct PsiSumSender {
    mq_rpmt: MqRpmtSender,
    payload_auth_sender: BufferedVoleSender,
}

impl PsiSumSender {
    pub fn new(delta0: FE, k0: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let mq_rpmt = MqRpmtSender::new(delta0, k0, channel)
            .map_err(|e| anyhow!("init mq_rpmt sender failed: {e}"))?;
        let payload_auth_sender = BufferedVoleSender::init(channel, LPN21)
            .map_err(|e| anyhow!("init payload auth sender VOLE failed: {e}"))?;

        Ok(Self {
            mq_rpmt,
            payload_auth_sender,
        })
    }

    pub fn run<RNG: Rng>(
        &mut self,
        sender_set: &[FE],
        sender_payloads: &[FE],
        triple_shares: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<BeDOZa> {
        ensure!(
            sender_set.len() > 1,
            "psi_sum sender requires at least 2 sender inputs"
        );
        ensure!(
            sender_set.len() == sender_payloads.len(),
            "psi_sum sender input/payload length mismatch: inputs={} payloads={}",
            sender_set.len(),
            sender_payloads.len()
        );
        ensure!(
            sender_set.len() == triple_shares.len(),
            "psi_sum sender input/triple length mismatch: inputs={} triples={}",
            sender_set.len(),
            triple_shares.len()
        );
        let authenticated_sender_payloads = self
            .payload_auth_sender
            .commit_auth(channel, sender_payloads)
            .map_err(|e| anyhow!("failed to authenticate sender payloads: {e}"))?;
        ensure!(
            authenticated_sender_payloads.len() == triple_shares.len(),
            "psi_sum sender payload/triple length mismatch: payloads={} triples={}",
            authenticated_sender_payloads.len(),
            triple_shares.len()
        );

        let mq_rpmt_output = self
            .mq_rpmt
            .run(sender_set, rng, channel)
            .map_err(|e| anyhow!("mq_rpmt sender failed: {e}"))?;
        ensure!(
            mq_rpmt_output.authenticated_sender_inputs.len() == triple_shares.len(),
            "psi_sum sender input/triple length mismatch: inputs={} triples={}",
            mq_rpmt_output.authenticated_sender_inputs.len(),
            triple_shares.len()
        );
        ensure!(
            authenticated_sender_payloads.len() == mq_rpmt_output.authenticated_sender_inputs.len(),
            "psi_sum sender payload/input length mismatch: payloads={} inputs={}",
            authenticated_sender_payloads.len(),
            mq_rpmt_output.authenticated_sender_inputs.len()
        );

        let products = batch_multiply_cross_owned_sender(
            &authenticated_sender_payloads,
            &mq_rpmt_output.authenticated_original_bitmap,
            triple_shares,
            channel,
        )?;

        sum_bedoza_values(&products)
    }
}

pub struct PsiSumReceiver {
    mq_rpmt: MqRpmtReceiver,
    payload_auth_receiver: BufferedVoleReceiver,
}

impl PsiSumReceiver {
    pub fn new(delta1: FE, k1: FE, channel: &mut SwankyChannel) -> Result<Self> {
        let mq_rpmt = MqRpmtReceiver::new(delta1, k1, channel)
            .map_err(|e| anyhow!("init mq_rpmt receiver failed: {e}"))?;
        let payload_auth_receiver = BufferedVoleReceiver::init(channel, delta1, LPN21)
            .map_err(|e| anyhow!("init payload auth receiver VOLE failed: {e}"))?;

        Ok(Self {
            mq_rpmt,
            payload_auth_receiver,
        })
    }

    pub fn run<RNG: Rng>(
        &mut self,
        receiver_set: &[FE],
        triple_shares: &[BeDOZaTriple],
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<BeDOZa> {
        ensure!(
            receiver_set.len() > 1,
            "psi_sum receiver requires at least 2 receiver inputs"
        );
        ensure!(
            triple_shares.len() > 1,
            "psi_sum receiver requires at least 2 triples"
        );
        let authenticated_sender_payloads = self
            .payload_auth_receiver
            .commit_auth(channel, triple_shares.len())
            .map_err(|e| anyhow!("failed to receive authenticated sender payloads: {e}"))?;
        ensure!(
            authenticated_sender_payloads.len() == triple_shares.len(),
            "psi_sum receiver payload/triple length mismatch: payloads={} triples={}",
            authenticated_sender_payloads.len(),
            triple_shares.len()
        );

        let mq_rpmt_output = self
            .mq_rpmt
            .run(receiver_set, rng, channel)
            .map_err(|e| anyhow!("mq_rpmt receiver failed: {e}"))?;

        ensure!(
            mq_rpmt_output.authenticated_sender_inputs.len()
                == mq_rpmt_output.authenticated_original_bitmap.len(),
            "psi_sum receiver input/bitmap length mismatch: inputs={} bitmap={}",
            mq_rpmt_output.authenticated_sender_inputs.len(),
            mq_rpmt_output.authenticated_original_bitmap.len()
        );
        ensure!(
            mq_rpmt_output.authenticated_sender_inputs.len() == triple_shares.len(),
            "psi_sum receiver input/triple length mismatch: inputs={} triples={}",
            mq_rpmt_output.authenticated_sender_inputs.len(),
            triple_shares.len()
        );
        ensure!(
            authenticated_sender_payloads.len() == mq_rpmt_output.authenticated_sender_inputs.len(),
            "psi_sum receiver payload/input length mismatch: payloads={} inputs={}",
            authenticated_sender_payloads.len(),
            mq_rpmt_output.authenticated_sender_inputs.len()
        );

        let products = batch_multiply_cross_owned_receiver(
            &authenticated_sender_payloads,
            &mq_rpmt_output.authenticated_original_bitmap,
            triple_shares,
            channel,
        )?;

        sum_bedoza_values(&products)
    }
}

pub fn open_psi_sum_send(sum_share: &BeDOZa, channel: &mut SwankyChannel) -> Result<()> {
    open_values_send(&[*sum_share], channel)
        .map_err(|e| anyhow!("failed to send psi_sum opening: {e}"))
}

pub fn open_psi_sum_receive(sum_share: &BeDOZa, channel: &mut SwankyChannel) -> Result<FE> {
    let opened = open_values_receive(&[*sum_share], channel)
        .map_err(|e| anyhow!("failed to receive psi_sum opening: {e}"))?;
    Ok(opened[0])
}
