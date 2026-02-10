pub mod bedoza_sender;
pub mod bedoza_receiver;
pub mod comm_util;
pub mod defines;

use crate::{
    bedoza::{
        bedoza_receiver::{BeDOZaReceiver, receive_open_shares}, 
        bedoza_sender::{BeDOZaSender, send_open_shares},
        comm_util::{send_fe_vec, receive_fe_vec},
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
    pub fn new(sender: BeDOZaSender, receiver: BeDOZaReceiver) -> Self {
        BeDOZa {
            bedoza_sender: sender,
            bedoza_receiver: receiver,
        }
    }

    pub fn bedoza_sender(&self) -> &BeDOZaSender {
        &self.bedoza_sender
    }

    pub fn bedoza_receiver(&self) -> &BeDOZaReceiver {
        &self.bedoza_receiver
    }

    pub fn add(&self, other: &BeDOZa) -> Result<BeDOZa> {
        ensure!(self.bedoza_sender().side() == other.bedoza_sender().side(), 
            "Cannot add BeDOZa shares from different sides: lhs side = {}, rhs side = {}", self.bedoza_sender().side(), other.bedoza_sender().side());
        Ok(BeDOZa {
            bedoza_sender: self.bedoza_sender().add(&other.bedoza_sender()),
            bedoza_receiver: self.bedoza_receiver().add(&other.bedoza_receiver()),
        })
    }

    pub fn sub(&self, other: &BeDOZa) -> Result<BeDOZa> {
        ensure!(self.bedoza_sender().side() == other.bedoza_sender().side(), 
            "Cannot subtract BeDOZa shares from different sides: lhs side = {}, rhs side = {}", self.bedoza_sender().side(), other.bedoza_sender().side());
        Ok(BeDOZa {
            bedoza_sender: self.bedoza_sender().sub(&other.bedoza_sender()),
            bedoza_receiver: self.bedoza_receiver().sub(&other.bedoza_receiver()),
        })
    }

    pub fn mult_constant(&self, constant: FE) -> BeDOZa {
        BeDOZa {
            bedoza_sender: self.bedoza_sender().mult_constant(constant),
            bedoza_receiver: self.bedoza_receiver().mult_constant(constant),
        }
    }
}

pub type BeDOZaTriple = (BeDOZa, BeDOZa, BeDOZa);


pub fn share_values(
    vals: &[FE], 
    prepared_bedoza_shares: &[BeDOZa],
    channel: &mut TcpChannel) 
-> Result<Vec<BeDOZa>> {
    ensure!(vals.len() == prepared_bedoza_shares.len(), 
        "Length mismatch between vals and prepared_bedoza_senders: lhs = {}, rhs = {}", vals.len(), prepared_bedoza_shares.len());

    let prepared_bedoza_receivers = prepared_bedoza_shares.iter().map(|share| *share.bedoza_receiver()).collect::<Vec<BeDOZaReceiver>>();
    let prepared_bedoza_senders = prepared_bedoza_shares.iter().map(|share| *share.bedoza_sender()).collect::<Vec<BeDOZaSender>>();

    // Open the prepared shared randomness to the sharer
    let open_prepared_bedoza_receivers = receive_open_shares(&prepared_bedoza_receivers, channel)
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
    let bedoza_shared: Vec<BeDOZa> = prepared_bedoza_senders.iter()
        .zip(prepared_bedoza_receivers.iter())
        .zip(masked_vals.iter())
        .map(|((prepared_sender, prepared_receiver), &masked_val)| {
            let sender_share = prepared_sender.add_constant(masked_val);
            let receiver_share = prepared_receiver.add_constant(masked_val);
            BeDOZa {
                bedoza_sender: sender_share,
                bedoza_receiver: receiver_share,
            }
        }).collect();

    Ok(bedoza_shared)
}

pub fn receive_share_values(
    prepared_bedoza_shares: &[BeDOZa],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    let prepared_bedoza_receivers = prepared_bedoza_shares.iter().map(|share| *share.bedoza_receiver()).collect::<Vec<BeDOZaReceiver>>();
    let prepared_bedoza_senders = prepared_bedoza_shares.iter().map(|share| *share.bedoza_sender()).collect::<Vec<BeDOZaSender>>();

    send_open_shares(&prepared_bedoza_senders, channel)
        .map_err(|e| anyhow!("Failed to send open BeDOZaSender shares: {}", e))?;

    let masked_vals = receive_fe_vec(channel)
        .map_err(|e| anyhow!("Failed to receive masked vals: {}", e))?;

    let bedoza_shared: Vec<BeDOZa> = prepared_bedoza_senders.iter()
        .zip(prepared_bedoza_receivers.iter())
        .zip(masked_vals.iter())
        .map(|((prepared_sender, prepared_receiver), &masked_val)| {
            let sender_share = prepared_sender.add_constant(masked_val);
            let receiver_share = prepared_receiver.add_constant(masked_val);
            BeDOZa {
                bedoza_sender: sender_share,
                bedoza_receiver: receiver_share,
            }
        }).collect();
    
    Ok(bedoza_shared)
}

pub fn batch_multiply(
    x_shares: &[BeDOZa],
    y_shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    ensure!(x_shares.len() == y_shares.len(), 
        "Length mismatch between x_shares and y_shares: lhs = {}, rhs = {}", x_shares.len(), y_shares.len());
    ensure!(x_shares.len() == triple_shares.len(), 
        "Length mismatch between x_shares and triple_shares: lhs = {}, rhs = {}", x_shares.len(), triple_shares.len());

    // First compute d = x - a and e = y - b
    let d_shares: Vec<BeDOZa> = x_shares.iter().zip(triple_shares.iter()).map(|(x_share, triple_share)| {
        let (a_share, _, _) = triple_share;
        x_share.sub(a_share).map_err(|e| anyhow!("Failed to subtract a_share from x_share: {}", e))
    }).collect::<Result<Vec<BeDOZa>>>()?;

    let e_shares: Vec<BeDOZa> = y_shares.iter().zip(triple_shares.iter()).map(|(y_share, triple_share)| {
        let (_, b_share, _) = triple_share;
        y_share.sub(b_share).map_err(|e| anyhow!("Failed to subtract b_share from y_share: {}", e))
    }).collect::<Result<Vec<BeDOZa>>>()?;

    // Now open d and e to both parties
    let d_receivers: Vec<BeDOZaReceiver> = d_shares.iter().map(|share| *share.bedoza_receiver()).collect();
    let d_receiver_values = receive_open_shares(&d_receivers, channel)
        .map_err(|e| anyhow!("Failed to receive open d shares: {}", e))?;
    let d_values: Vec<FE> = d_shares.iter().zip(d_receiver_values.iter()).map(|(share, &receiver_value)| share.bedoza_sender().val() + receiver_value).collect();

    let e_receivers: Vec<BeDOZaReceiver> = e_shares.iter().map(|share| *share.bedoza_receiver()).collect();
    let e_receiver_values = receive_open_shares(&e_receivers, channel)
        .map_err(|e| anyhow!("Failed to receive open e shares: {}", e))?;
    let e_values: Vec<FE> = e_shares.iter().zip(e_receiver_values.iter()).map(|(share, &receiver_value)| share.bedoza_sender().val() + receiver_value).collect();

    // Compute db and ea locally


    Ok(d_shares) // Not correct
}