use crate::{
    bedoza::{
        BeDOZa, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender, defines::FE, share_values
    },
    tcp_channel::TcpChannel,
};
use anyhow::{anyhow, Result};

pub fn shuffle_proof(
    vals: &[FE],
    authenticated_key: (BeDOZaSender, BeDOZaReceiver),
    prepared_bedoza_shares: &[BeDOZa],
    prepared_triple_shares: &[BeDOZa],
    channel: &mut TcpChannel
) -> Result<()> {
    // First, share the values x1, x2, ..., xn
    // Using BeDOZa, we authenticate both shares of the values as well
    let (bedoza_sender_shares, bedoza_receiver_shares) = share_values(vals, prepared_bedoza_senders, prepared_bedoza_receivers, channel)
        .map_err(|e| anyhow!("Failed to share values using BeDOZa: {}", e))?;

    // Next, obtain shares for 1/(k+x1), 1/(k+x2), ...
    // First obtain shares for (k+x1), (k+x2), ...
    let k_plus_x_sender_shares = bedoza_sender_shares.iter()
        .map(|share| share.add(&authenticated_key.0))
        .collect::<Vec<BeDOZaSender>>();
    let k_plus_x_receiver_shares = bedoza_receiver_shares.iter()
        .map(|share| share.add(&authenticated_key.1))
        .collect::<Vec<BeDOZaReceiver>>();

    Ok(())
}