use crate::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender, defines::FE},
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use anyhow::{Result, anyhow};
use swanky_channel_legacy::AbstractChannel;

pub fn authenticate_batch_with_peer_key_sender<C: AbstractChannel>(
    values: &[FE],
    owner_side: bool,
    vole_sender: &mut BufferedVoleSender,
    channel: &mut C,
) -> Result<Vec<BeDOZaSender>> {
    let sender_macs = vole_sender
        .commit_auth(channel, values)
        .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?;
    Ok(sender_macs
        .into_iter()
        .map(|s| BeDOZaSender::new(s.val(), s.pad(), owner_side))
        .collect())
}

pub fn authenticate_batch_with_peer_key_receiver<C: AbstractChannel>(
    expected_count: usize,
    owner_side: bool,
    local_key: FE,
    vole_receiver: &mut BufferedVoleReceiver,
    channel: &mut C,
) -> Result<Vec<BeDOZaReceiver>> {
    let receiver_macs = vole_receiver
        .commit_auth(channel, expected_count)
        .map_err(|e| anyhow!("failed to materialize receiver VOLE outputs: {e}"))?;
    Ok(receiver_macs
        .into_iter()
        .map(|r| BeDOZaReceiver::new(r.tag(), local_key, owner_side))
        .collect())
}

pub fn vole_share_product_sender<C: AbstractChannel>(
    x_values: &[FE],
    mul_vole_sender: &mut BufferedVoleSender,
    channel: &mut C,
) -> Result<Vec<FE>> {
    let sender_macs = mul_vole_sender
        .commit_auth(channel, x_values)
        .map_err(|e| anyhow!("failed to materialize sender VOLE inputs for product shares: {e}"))?;

    // VOLE relation: tag_i = k1 * x_i + beta_i, so define additive share
    // u_i := -beta_i and let receiver-side share be v_i := tag_i.
    Ok(sender_macs
        .into_iter()
        .map(|s| -s.pad())
        .collect())
}

pub fn vole_share_product_receiver<C: AbstractChannel>(
    expected_count: usize,
    mul_vole_receiver: &mut BufferedVoleReceiver,
    channel: &mut C,
) -> Result<Vec<FE>> {
    let receiver_macs = mul_vole_receiver
        .commit_auth(channel, expected_count)
        .map_err(|e| {
            anyhow!("failed to materialize receiver VOLE outputs for product shares: {e}")
        })?;

    Ok(receiver_macs
        .into_iter()
        .map(|r| r.tag())
        .collect())
}
