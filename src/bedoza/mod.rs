pub mod bedoza_sender;
pub mod bedoza_receiver;
pub mod comm_util;
pub mod defines;

use crate::{
    bedoza::{
        bedoza_receiver::{BeDOZaReceiver, receive_open_shares}, 
        bedoza_sender::BeDOZaSender, 
        comm_util::send_fe_vec, 
        defines::FE,
    }, 
    tcp_channel::TcpChannel,
};
use anyhow::{anyhow, ensure, Result};

// Contains some functionalities for BeDOZa here

pub struct BeDOZa {
    bedoza_sender: BeDOZaSender,
    bedoza_receiver: BeDOZaReceiver,
}

impl BeDOZa {

}


pub fn share_values(
    vals: &[FE], 
    prepared_bedoza_shares: &[BeDOZa],
    channel: &mut TcpChannel) 
-> Result<(Vec<BeDOZaSender>, Vec<BeDOZaReceiver>)> {
    ensure!(vals.len() == prepared_bedoza_senders.len(), 
        "Length mismatch between vals and prepared_bedoza_senders: lhs = {}, rhs = {}", vals.len(), prepared_bedoza_senders.len());
    ensure!(vals.len() == prepared_bedoza_receivers.len(), 
        "Length mismatch between vals and prepared_bedoza_receivers: lhs = {}, rhs = {}", vals.len(), prepared_bedoza_receivers.len());

    // Open the prepared shared randomness to the sharer
    let open_prepared_bedoza_receivers = receive_open_shares(prepared_bedoza_receivers, channel)
        .map_err(|e| anyhow!("Failed to receive open BeDOZaReceiver shares: {}", e))?;
    let open_prepared_random_values: Vec<FE> = open_prepared_bedoza_receivers.iter()
        .zip(prepared_bedoza_senders.iter())
        .map(|(&x, y)| x + y.val()).collect();

    // Then the sharer masks his values and sends them to the other party
    let masked_vals = vals.iter()
        .zip(open_prepared_random_values.iter())
        .map(|(&v, &r)| v - r).collect::<Vec<FE>>();
    send_fe_vec(&masked_vals, channel)
        .map_err(|e| anyhow!("Failed to send masked vals: {}", e))?;

    // Now add the masked value to the prepared shares to get shares for the actual values
    let bedoza_sender_share: Vec<BeDOZaSender> = prepared_bedoza_senders.iter()
        .zip(masked_vals.iter())
        .map(|(prepared_share, &masked_val)| {
            prepared_share.add_constant(masked_val)
        }).collect();

    let bedoza_receiver_share: Vec<BeDOZaReceiver> = prepared_bedoza_receivers.iter()
        .zip(masked_vals.iter())
        .map(|(prepared_share, &masked_val)| {
            prepared_share.add_constant(masked_val)
        }).collect();

    Ok((bedoza_sender_share, bedoza_receiver_share))
}
