pub mod bedoza_receiver;
pub mod bedoza_sender;
pub mod comm_util;
pub mod defines;

use crate::{
    bedoza::{
        bedoza_receiver::{BeDOZaReceiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, send_open_shares},
        comm_util::{receive_fe_vec, send_fe_vec},
        defines::FE,
    },
    tcp_channel::TcpChannel,
};
use anyhow::{Result, anyhow, ensure};
use std::ops::{Add, Mul, Sub};

// Contains some functionalities for BeDOZa here

#[derive(Clone, Copy)]
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
}

pub type BeDOZaTriple = (BeDOZa, BeDOZa, BeDOZa);

pub fn share_values(
    vals: &[FE],
    prepared_bedoza_shares: &[BeDOZa],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    ensure!(
        vals.len() == prepared_bedoza_shares.len(),
        "Length mismatch between vals and prepared_bedoza_senders: lhs = {}, rhs = {}",
        vals.len(),
        prepared_bedoza_shares.len()
    );

    let prepared_bedoza_receivers = prepared_bedoza_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect::<Vec<BeDOZaReceiver>>();
    let prepared_bedoza_senders = prepared_bedoza_shares
        .iter()
        .map(|share| *share.bedoza_sender())
        .collect::<Vec<BeDOZaSender>>();

    // Receive the opening for prepared shared randomness from the receiver
    let open_prepared_bedoza_receivers =
        receive_open_shares(&prepared_bedoza_receivers, channel)
            .map_err(|e| anyhow!("Failed to receive open BeDOZaReceiver shares: {}", e))?;
    let open_prepared_random_values: Vec<FE> = open_prepared_bedoza_receivers
        .iter()
        .zip(prepared_bedoza_senders.iter())
        .map(|(x, y)| x + y.val())
        .collect();

    // Then the sharer masks his values and sends them to the other party
    let masked_vals = vals
        .iter()
        .zip(open_prepared_random_values.iter())
        .map(|(&v, &r)| v - r)
        .collect::<Vec<FE>>();
    send_fe_vec(&masked_vals, channel).map_err(|e| anyhow!("Failed to send masked vals: {}", e))?;

    // Now add the masked value to the prepared shares to get shares for the actual values
    let bedoza_shared: Vec<BeDOZa> = prepared_bedoza_senders
        .iter()
        .zip(prepared_bedoza_receivers.iter())
        .zip(masked_vals.iter())
        .map(
            |((prepared_sender, prepared_receiver), &masked_val)| BeDOZa {
                bedoza_sender: prepared_sender + masked_val,
                bedoza_receiver: prepared_receiver + masked_val,
            },
        )
        .collect();

    Ok(bedoza_shared)
}

pub fn receive_share_values(
    prepared_bedoza_shares: &[BeDOZa],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    let prepared_bedoza_receivers = prepared_bedoza_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect::<Vec<BeDOZaReceiver>>();
    let prepared_bedoza_senders = prepared_bedoza_shares
        .iter()
        .map(|share| *share.bedoza_sender())
        .collect::<Vec<BeDOZaSender>>();

    // Open the prepared shared randomness to the sender
    send_open_shares(&prepared_bedoza_senders, channel)
        .map_err(|e| anyhow!("Failed to send open BeDOZaSender shares: {}", e))?;

    // Receive masked sender's values
    let masked_vals =
        receive_fe_vec(channel).map_err(|e| anyhow!("Failed to receive masked vals: {}", e))?;

    let bedoza_shared: Vec<BeDOZa> = prepared_bedoza_senders
        .iter()
        .zip(prepared_bedoza_receivers.iter())
        .zip(masked_vals.iter())
        .map(
            |((prepared_sender, prepared_receiver), &masked_val)| BeDOZa {
                bedoza_sender: prepared_sender + masked_val,
                bedoza_receiver: prepared_receiver + masked_val,
            },
        )
        .collect();

    Ok(bedoza_shared)
}

pub fn open_values_send(bedoza_shares: &[BeDOZa], channel: &mut TcpChannel) -> Result<()> {
    let bedoza_senders: Vec<BeDOZaSender> = bedoza_shares
        .iter()
        .map(|share| *share.bedoza_sender())
        .collect();
    send_open_shares(&bedoza_senders, channel)
        .map_err(|e| anyhow!("Failed to send open shares: {}", e))?;

    Ok(())
}

pub fn open_values_receive(bedoza_shares: &[BeDOZa], channel: &mut TcpChannel) -> Result<Vec<FE>> {
    let bedoza_receivers: Vec<BeDOZaReceiver> = bedoza_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect();
    let received_values = receive_open_shares(&bedoza_receivers, channel)
        .map_err(|e| anyhow!("Failed to receive open shares: {}", e))?;

    let reconstructed_values: Vec<FE> = bedoza_shares
        .iter()
        .zip(received_values.iter())
        .map(|(share, &receiver_value)| share.bedoza_sender().val() + receiver_value)
        .collect();

    Ok(reconstructed_values)
}

pub fn batch_multiply(
    x_shares: &[BeDOZa],
    y_shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    ensure!(
        x_shares.len() == y_shares.len(),
        "Length mismatch between x_shares and y_shares: lhs = {}, rhs = {}",
        x_shares.len(),
        y_shares.len()
    );
    ensure!(
        x_shares.len() == triple_shares.len(),
        "Length mismatch between x_shares and triple_shares: lhs = {}, rhs = {}",
        x_shares.len(),
        triple_shares.len()
    );

    // First compute d = x - a and e = y - b
    let d_shares: Vec<BeDOZa> = x_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(x_share, triple_share)| {
            let (a_share, _, _) = triple_share;
            x_share - a_share
        })
        .collect();

    let e_shares: Vec<BeDOZa> = y_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(y_share, triple_share)| {
            let (_, b_share, _) = triple_share;
            y_share - b_share
        })
        .collect();

    // Now open d and e to both parties
    let d_receivers: Vec<BeDOZaReceiver> = d_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect();
    let d_receiver_values = receive_open_shares(&d_receivers, channel)
        .map_err(|e| anyhow!("Failed to receive open d shares: {}", e))?;
    let d_values: Vec<FE> = d_shares
        .iter()
        .zip(d_receiver_values.iter())
        .map(|(share, &receiver_value)| share.bedoza_sender().val() + receiver_value)
        .collect();

    let e_receivers: Vec<BeDOZaReceiver> = e_shares
        .iter()
        .map(|share| *share.bedoza_receiver())
        .collect();
    let e_receiver_values = receive_open_shares(&e_receivers, channel)
        .map_err(|e| anyhow!("Failed to receive open e shares: {}", e))?;
    let e_values: Vec<FE> = e_shares
        .iter()
        .zip(e_receiver_values.iter())
        .map(|(share, &receiver_value)| share.bedoza_sender().val() + receiver_value)
        .collect();

    // Compute db and ea locally
    let db_shares: Vec<BeDOZa> = d_values
        .iter()
        .zip(triple_shares.iter())
        .map(|(&d, triple_share)| {
            let (_, b_share, _) = triple_share;
            b_share * d
        })
        .collect();

    let ea_shares: Vec<BeDOZa> = e_values
        .iter()
        .zip(triple_shares.iter())
        .map(|(&e, triple_share)| {
            let (a_share, _, _) = triple_share;
            a_share * e
        })
        .collect();

    let de_values: Vec<FE> = d_values
        .iter()
        .zip(e_values.iter())
        .map(|(&d, &e)| d * e)
        .collect();

    // Compute the final result: c = ab + db + ea + de
    let xy_shares: Vec<BeDOZa> = triple_shares
        .iter()
        .zip(db_shares.iter())
        .zip(ea_shares.iter())
        .zip(de_values.iter())
        .map(|((((_, _, c_share), db_share), ea_share), &de)| c_share + db_share + ea_share + de)
        .collect();

    Ok(xy_shares)
}

fn multiplication_opening_shares(
    x_shares: &[BeDOZa],
    y_shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
) -> Result<(Vec<BeDOZa>, Vec<BeDOZa>)> {
    ensure!(
        x_shares.len() == y_shares.len(),
        "Length mismatch between x_shares and y_shares: lhs = {}, rhs = {}",
        x_shares.len(),
        y_shares.len()
    );
    ensure!(
        x_shares.len() == triple_shares.len(),
        "Length mismatch between x_shares and triple_shares: lhs = {}, rhs = {}",
        x_shares.len(),
        triple_shares.len()
    );

    let d_shares: Vec<BeDOZa> = x_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(x_share, triple_share)| {
            let (a_share, _, _) = triple_share;
            x_share - a_share
        })
        .collect();

    let e_shares: Vec<BeDOZa> = y_shares
        .iter()
        .zip(triple_shares.iter())
        .map(|(y_share, triple_share)| {
            let (_, b_share, _) = triple_share;
            y_share - b_share
        })
        .collect();

    Ok((d_shares, e_shares))
}

pub fn send_batch_multiply_openings(
    x_shares: &[BeDOZa],
    y_shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<()> {
    let (d_shares, e_shares) = multiplication_opening_shares(x_shares, y_shares, triple_shares)?;
    open_values_send(&d_shares, channel)
        .map_err(|e| anyhow!("Failed to send d-share openings: {}", e))?;
    open_values_send(&e_shares, channel)
        .map_err(|e| anyhow!("Failed to send e-share openings: {}", e))?;
    Ok(())
}

pub fn batch_multiply_interactive(
    x_shares: &[BeDOZa],
    y_shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    send_batch_multiply_openings(x_shares, y_shares, triple_shares, channel)?;
    batch_multiply(x_shares, y_shares, triple_shares, channel)
}

pub fn take_vec_prod(
    shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<BeDOZa> {
    ensure!(
        !shares.is_empty(),
        "Cannot take product of an empty vector of shares"
    );

    let mut current_len = shares.len();
    let mut triples_used = 0;
    let mut new_shares = shares.to_vec();
    let mut current_number_of_shares = 0;

    loop {
        if current_len == 1 {
            break;
        }
        let half_len = current_len / 2;
        let (left, right) = new_shares
            [current_number_of_shares..current_number_of_shares + current_len]
            .split_at(half_len);
        current_number_of_shares += current_len;

        ensure!(
            triples_used + half_len <= triple_shares.len(),
            "Not enough triple shares to take product: need at least {}, got {}",
            triples_used + half_len,
            triple_shares.len()
        );

        if right.len() > left.len() {
            let last_share_right = *right.last().unwrap();
            let multiplied_shares = batch_multiply(
                left,
                &right[..half_len],
                &triple_shares[triples_used..triples_used + half_len],
                channel,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to batch multiply shares while taking vector product: {}",
                    e
                )
            })?;
            new_shares.extend(multiplied_shares);
            new_shares.push(last_share_right);
            current_len = half_len + 1;
        } else {
            let multiplied_shares = batch_multiply(
                left,
                right,
                &triple_shares[triples_used..triples_used + half_len],
                channel,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to batch multiply shares while taking vector product: {}",
                    e
                )
            })?;
            new_shares.extend(multiplied_shares);
            current_len = half_len;
        }

        triples_used += half_len;
    }

    Ok(*new_shares.last().unwrap())
}

pub fn take_vec_prod_interactive(
    shares: &[BeDOZa],
    triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<BeDOZa> {
    ensure!(
        !shares.is_empty(),
        "Cannot take product of an empty vector of shares"
    );

    let mut current_len = shares.len();
    let mut triples_used = 0;
    let mut new_shares = shares.to_vec();
    let mut current_number_of_shares = 0;

    loop {
        if current_len == 1 {
            break;
        }
        let half_len = current_len / 2;
        let (left, right) = new_shares
            [current_number_of_shares..current_number_of_shares + current_len]
            .split_at(half_len);
        current_number_of_shares += current_len;

        ensure!(
            triples_used + half_len <= triple_shares.len(),
            "Not enough triple shares to take product: need at least {}, got {}",
            triples_used + half_len,
            triple_shares.len()
        );

        if right.len() > left.len() {
            let last_share_right = *right.last().unwrap();
            let multiplied_shares = batch_multiply_interactive(
                left,
                &right[..half_len],
                &triple_shares[triples_used..triples_used + half_len],
                channel,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to batch multiply shares while taking vector product: {}",
                    e
                )
            })?;
            new_shares.extend(multiplied_shares);
            new_shares.push(last_share_right);
            current_len = half_len + 1;
        } else {
            let multiplied_shares = batch_multiply_interactive(
                left,
                right,
                &triple_shares[triples_used..triples_used + half_len],
                channel,
            )
            .map_err(|e| {
                anyhow!(
                    "Failed to batch multiply shares while taking vector product: {}",
                    e
                )
            })?;
            new_shares.extend(multiplied_shares);
            current_len = half_len;
        }

        triples_used += half_len;
    }

    Ok(*new_shares.last().unwrap())
}

impl Add<&BeDOZa> for &BeDOZa {
    type Output = BeDOZa;

    fn add(self, other: &BeDOZa) -> BeDOZa {
        BeDOZa {
            bedoza_sender: self.bedoza_sender() + other.bedoza_sender(),
            bedoza_receiver: self.bedoza_receiver() + other.bedoza_receiver(),
        }
    }
}

impl Add<BeDOZa> for &BeDOZa {
    type Output = BeDOZa;

    fn add(self, other: BeDOZa) -> BeDOZa {
        self + &other
    }
}

impl Add<&BeDOZa> for BeDOZa {
    type Output = BeDOZa;

    fn add(self, other: &BeDOZa) -> BeDOZa {
        &self + other
    }
}

impl Add for BeDOZa {
    type Output = BeDOZa;

    fn add(self, other: BeDOZa) -> BeDOZa {
        &self + &other
    }
}

impl Add<FE> for &BeDOZa {
    type Output = BeDOZa;

    fn add(self, constant: FE) -> BeDOZa {
        BeDOZa {
            bedoza_sender: self.bedoza_sender() + constant,
            bedoza_receiver: self.bedoza_receiver() + constant,
        }
    }
}

impl Add<FE> for BeDOZa {
    type Output = BeDOZa;

    fn add(self, constant: FE) -> BeDOZa {
        &self + constant
    }
}

impl Sub<FE> for &BeDOZa {
    type Output = BeDOZa;

    fn sub(self, constant: FE) -> BeDOZa {
        BeDOZa {
            bedoza_sender: self.bedoza_sender() - constant,
            bedoza_receiver: self.bedoza_receiver() - constant,
        }
    }
}

impl Sub<FE> for BeDOZa {
    type Output = BeDOZa;

    fn sub(self, constant: FE) -> BeDOZa {
        &self - constant
    }
}

impl Sub<&BeDOZa> for &BeDOZa {
    type Output = BeDOZa;

    fn sub(self, other: &BeDOZa) -> BeDOZa {
        BeDOZa {
            bedoza_sender: self.bedoza_sender() - other.bedoza_sender(),
            bedoza_receiver: self.bedoza_receiver() - other.bedoza_receiver(),
        }
    }
}

impl Sub for BeDOZa {
    type Output = BeDOZa;

    fn sub(self, other: BeDOZa) -> BeDOZa {
        &self - &other
    }
}

impl Mul<FE> for &BeDOZa {
    type Output = BeDOZa;

    fn mul(self, constant: FE) -> BeDOZa {
        BeDOZa {
            bedoza_sender: self.bedoza_sender() * constant,
            bedoza_receiver: self.bedoza_receiver() * constant,
        }
    }
}

impl Mul<FE> for BeDOZa {
    type Output = BeDOZa;

    fn mul(self, constant: FE) -> BeDOZa {
        &self * constant
    }
}
