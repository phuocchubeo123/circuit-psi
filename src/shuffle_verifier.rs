use crate::{
    bedoza::{
        defines::FE,
        BeDOZa, BeDOZaTriple, receive_share_values,
        batch_multiply,
        open_values_receive, open_values_send,
    },
    tcp_channel::TcpChannel,
};
use anyhow::{anyhow, Result};

pub fn shuffle_verifier_step1(
    authenticated_key: &BeDOZa,
    prepared_bedoza_shares: &[BeDOZa],
    prepared_randomness: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel
) -> Result<Vec<BeDOZa>> {
    // Step 1: Given inputs x1, x2, ..., xn
    // We want to obtain shares for 1 / (k + x1), 1 / (k + x2), ..., where k is an authenticated key

    // First, receive shares for x1, x2, ..., xn from the prover
    let bedoza_shared = receive_share_values(prepared_bedoza_shares, channel)
        .map_err(|e| anyhow!("Failed to receive shared values using BeDOZa: {}", e))?;

    // Next, obtain shares for 1/(k+x1), 1/(k+x2), ...
    // First obtain shares for (k+x1), (k+x2), ...
    let k_plus_x_shares: Vec<BeDOZa> = bedoza_shared.iter()
        .map(|share| share + authenticated_key)
        .collect();

    // Multiply (k+x1), (k+x2), ... with the prepared randomness to get shares for (k+x1)*r1, (k+x2)*r2, ...
    let r_times_k_plus_x_shares = batch_multiply(&k_plus_x_shares, prepared_randomness, prepared_triple_shares, channel)
        .map_err(|e| anyhow!("Failed to batch multiply (k+xi) with randomness: {}", e))?;

    // Open the shares of (k+xi)*ri to both parties
    // Sending verifier share to prover
    open_values_send(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to send (k+xi)*ri shares: {}", e))?;
    // Receive prover share from prover
    let r_times_k_plus_x_value: Vec<FE> = open_values_receive(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to open (k+xi)*ri shares: {}", e))?;

    // Inverse the opened values to get 1/((k+xi)*ri)
    let inv_r_times_k_plus_x_value: Vec<FE> = r_times_k_plus_x_value.iter()
        .map(|&val| {
            val.inv()
                .map_err(|e| anyhow!("Failed to invert (k+xi)*ri value: {:?}", e))
        })
        .collect::<Result<Vec<FE>>>()?;

    // Multiply the inverted values with the randomness ri to get shares for 1/(k+xi)
    let inv_k_plus_x_shares: Vec<BeDOZa> = prepared_randomness.iter()
        .zip(inv_r_times_k_plus_x_value.iter())
        .map(|(rand_share, &inv_val)| {
            rand_share * inv_val
        })
        .collect();

    Ok(inv_k_plus_x_shares)
}

pub fn shuffle_verifier_step2(
    u: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {


    unimplemented!()
}