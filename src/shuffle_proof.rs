use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple, batch_multiply, share_values,
        defines::FE,
    },
    tcp_channel::TcpChannel,
};
use anyhow::{anyhow, Result};

pub fn shuffle_proof(
    vals: &[FE],
    authenticated_key: &BeDOZa,
    prepared_bedoza_shares: &[BeDOZa],
    prepared_randomness: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel
) -> Result<()> {
    // First, share the values x1, x2, ..., xn
    // Using BeDOZa, we authenticate both shares of the values as well
    let bedoza_shared = share_values(vals, prepared_bedoza_shares, channel)
        .map_err(|e| anyhow!("Failed to share values using BeDOZa: {}", e))?;

    // Next, obtain shares for 1/(k+x1), 1/(k+x2), ...
    // First obtain shares for (k+x1), (k+x2), ...
    let k_plus_x_shares: Vec<BeDOZa> = bedoza_shared.iter()
        .map(|share| {
            let sender_share = share.bedoza_sender().add(authenticated_key.bedoza_sender());
            let receiver_share = share.bedoza_receiver().add(&authenticated_key.bedoza_receiver());
            BeDOZa::new(sender_share, receiver_share)
        }).collect();

    // Multiply (k+x1), (k+x2), ... with the prepared randomness to get shares for (k+x1)*r1, (k+x2)*r2, ...
    let r_times_k_plus_x_shares = batch_multiply(&k_plus_x_shares, prepared_randomness, prepared_triple_shares, channel)
        .map_err(|e| anyhow!("Failed to batch multiply (k+xi) with randomness: {}", e))?;

    Ok(())
}