pub mod bedoza_sender;
pub mod bedoza_receiver;
pub mod comm_util;
pub mod defines;

use crate::{
    bedoza::{
        bedoza_receiver::BeDOZaReceiver, 
        bedoza_sender::BeDOZaSender, 
        comm_util::send_fe_vec, 
        defines::{FE, random_fe_vec}
    }, 
    tcp_channel::TcpChannel,
};
use anyhow::{anyhow, ensure, Result};

// Contains some functionalities for BeDOZa here

pub fn share_values(
    vals: &[FE], 
    prepared_bedoza_senders: &[BeDOZaSender],
    prepared_bedoza_receivers: &[BeDOZaReceiver],
    side: bool,
    channel: &mut TcpChannel) 
-> Result<(Vec<BeDOZaSender>, Vec<BeDOZaReceiver>)> {
    ensure!(vals.len() == prepared_bedoza_senders.len(), 
        "Length mismatch between vals and prepared_bedoza_senders: lhs = {}, rhs = {}", vals.len(), prepared_bedoza_senders.len());
    ensure!(vals.len() == prepared_bedoza_receivers.len(), 
        "Length mismatch between vals and prepared_bedoza_receivers: lhs = {}, rhs = {}", vals.len(), prepared_bedoza_receivers.len());

    let n = vals.len();

    // Randomly sample the other party's share, then send to the other party
    let other_shares = random_fe_vec(n)
        .map_err(|e| anyhow!("Error sampling random FE value: {}", e))?;
    send_fe_vec(&other_shares, channel)
        .map_err(|e| anyhow!("Failed to send other_shares to the other party: {}", e))?;

    // Get my shares by subtracting other party's shares from the values
    let my_shares: Vec<FE> = vals.iter().zip(other_shares.iter()).map(|(x, y)| x - y).collect();

    // Authenticate my shares, as bedoza sender
    let bedoza_sender_share = BeDOZaSender::authenticate(&my_shares, prepared_bedoza_senders, side, channel)
        .map_err(|e| anyhow!("Failed to authenticate share for the first share: {}", e))?;

    // Authenticate other party's shares, as bedoza receiver
    let bedoza_receiver_share = BeDOZaReceiver::authenticate(side, channel)
        .map_err(|e| anyhow!("Failed to receive authenticated share for the second share: {}", e))?;

    Ok((bedoza_sender_share, bedoza_receiver_share))
}
