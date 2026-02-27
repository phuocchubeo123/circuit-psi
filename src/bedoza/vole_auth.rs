use crate::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender, defines::FE},
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use anyhow::{Result, anyhow};
use mac_n_cheese_vole::specialization::NoSpecialization;
use swanky_aes_rng::AesRng;
use swanky_channel_legacy::AbstractChannel;
use swanky_party::{IS_PROVER, IS_VERIFIER};

pub type FourQVoleMac = (FE, FE, NoSpecialization);

fn ensure_sender_capacity<C: AbstractChannel>(
    vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
    needed: usize,
    channel: &mut C,
) -> Result<()> {
    if vole_sender.random_available() >= needed {
        return Ok(());
    }
    let missing = needed - vole_sender.random_available();
    // Extension reserves a fresh base subset from each newly generated VOLE
    // batch for the next extension round; only the remainder is consumable.
    let mut rng = AesRng::new();
    vole_sender
        .extend_random(channel, &mut rng, missing)
        .map_err(|e| anyhow!("failed to extend sender random VOLE buffer: {e}"))?;
    Ok(())
}

fn ensure_receiver_capacity<C: AbstractChannel>(
    vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
    needed: usize,
    channel: &mut C,
) -> Result<()> {
    if vole_receiver.random_available() >= needed {
        return Ok(());
    }
    let missing = needed - vole_receiver.random_available();
    // Same note as sender side: each extension round rotates to fresh reserved
    // base VOLEs and appends only non-reserved outputs to the random buffer.
    let mut rng = AesRng::new();
    vole_receiver
        .extend_random(channel, &mut rng, missing)
        .map_err(|e| anyhow!("failed to extend receiver random VOLE buffer: {e}"))?;
    Ok(())
}

pub fn authenticate_batch_with_peer_key_sender<C: AbstractChannel>(
    values: &[FE],
    owner_side: bool,
    vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
    channel: &mut C,
) -> Result<Vec<BeDOZaSender>> {
    ensure_sender_capacity(vole_sender, values.len(), channel)?;

    let sender_macs = vole_sender
        .materialize_inputs(channel, values)
        .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?;
    Ok(sender_macs
        .into_iter()
        .map(|mac| {
            let (value, pad) = mac.prover_extract(IS_PROVER);
            BeDOZaSender::new(value, pad, owner_side)
        })
        .collect())
}

pub fn authenticate_batch_with_peer_key_receiver<C: AbstractChannel>(
    expected_count: usize,
    owner_side: bool,
    local_key: FE,
    vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
    channel: &mut C,
) -> Result<Vec<BeDOZaReceiver>> {
    ensure_receiver_capacity(vole_receiver, expected_count, channel)?;

    let receiver_macs = vole_receiver
        .materialize_next(channel, expected_count)
        .map_err(|e| anyhow!("failed to materialize receiver VOLE outputs: {e}"))?;
    Ok(receiver_macs
        .into_iter()
        .map(|mac| BeDOZaReceiver::new(mac.tag(IS_VERIFIER), local_key, owner_side))
        .collect())
}

pub fn vole_share_product_sender<C: AbstractChannel>(
    x_values: &[FE],
    mul_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
    channel: &mut C,
) -> Result<Vec<FE>> {
    ensure_sender_capacity(mul_vole_sender, x_values.len(), channel)?;

    let sender_macs = mul_vole_sender
        .materialize_inputs(channel, x_values)
        .map_err(|e| anyhow!("failed to materialize sender VOLE inputs for product shares: {e}"))?;

    // VOLE relation: tag_i = k1 * x_i + beta_i, so define additive share
    // u_i := -beta_i and let receiver-side share be v_i := tag_i.
    Ok(sender_macs
        .into_iter()
        .map(|mac| {
            let (_, beta_i) = mac.prover_extract(IS_PROVER);
            -beta_i
        })
        .collect())
}

pub fn vole_share_product_receiver<C: AbstractChannel>(
    expected_count: usize,
    mul_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
    channel: &mut C,
) -> Result<Vec<FE>> {
    ensure_receiver_capacity(mul_vole_receiver, expected_count, channel)?;

    let receiver_macs = mul_vole_receiver
        .materialize_next(channel, expected_count)
        .map_err(|e| {
            anyhow!("failed to materialize receiver VOLE outputs for product shares: {e}")
        })?;

    Ok(receiver_macs
        .into_iter()
        .map(|mac| mac.tag(IS_VERIFIER))
        .collect())
}
