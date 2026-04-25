pub mod bedoza_multiply;
pub mod bedoza_receiver;
pub mod bedoza_sender;
pub mod comm_util;
pub mod wolverine;

use crate::{
    bedoza::{
        bedoza_receiver::{BeDOZaReceiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, send_open_shares},
        comm_util::{receive_fe_vec, send_fe_vec},
    },
    math::defines::FE,
    tcp_channel::SwankyChannel,
};
use anyhow::{Result, anyhow, ensure};
use std::ops::{Add, Mul, Sub};

// Contains some functionalities for BeDOZa here

#[derive(Clone, Copy)]
pub struct BeDOZa {
    bedoza_sender: BeDOZaSender,
    bedoza_receiver: BeDOZaReceiver,
    side: bool,
}

impl BeDOZa {
    pub fn new(sender: BeDOZaSender, receiver: BeDOZaReceiver, side: bool) -> Self {
        BeDOZa {
            bedoza_sender: sender,
            bedoza_receiver: receiver,
            side,
        }
    }

    pub fn bedoza_sender(&self) -> &BeDOZaSender {
        &self.bedoza_sender
    }

    pub fn bedoza_receiver(&self) -> &BeDOZaReceiver {
        &self.bedoza_receiver
    }

    pub fn side(&self) -> bool {
        self.side
    }
}

pub type BeDOZaTriple = (BeDOZa, BeDOZa, BeDOZa);

pub fn share_values(
    vals: &[FE],
    prepared_bedoza_shares: &[BeDOZa],
    channel: &mut SwankyChannel,
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
    let bedoza_shared: Vec<BeDOZa> = prepared_bedoza_shares
        .iter()
        .zip(masked_vals.iter())
        .map(|(prepared_share, &masked_val)| *prepared_share + masked_val)
        .collect();

    Ok(bedoza_shared)
}

pub fn receive_share_values(
    prepared_bedoza_shares: &[BeDOZa],
    channel: &mut SwankyChannel,
) -> Result<Vec<BeDOZa>> {
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

    let bedoza_shared: Vec<BeDOZa> = prepared_bedoza_shares
        .iter()
        .zip(masked_vals.iter())
        .map(|(prepared_share, &masked_val)| *prepared_share + masked_val)
        .collect();

    Ok(bedoza_shared)
}

pub fn open_values_send(bedoza_shares: &[BeDOZa], channel: &mut SwankyChannel) -> Result<()> {
    let bedoza_senders: Vec<BeDOZaSender> = bedoza_shares
        .iter()
        .map(|share| *share.bedoza_sender())
        .collect();
    send_open_shares(&bedoza_senders, channel)
        .map_err(|e| anyhow!("Failed to send open shares: {}", e))?;

    Ok(())
}

pub fn open_values_receive(
    bedoza_shares: &[BeDOZa],
    channel: &mut SwankyChannel,
) -> Result<Vec<FE>> {
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

impl Add<&BeDOZa> for &BeDOZa {
    type Output = BeDOZa;

    fn add(self, other: &BeDOZa) -> BeDOZa {
        assert_eq!(
            self.side(),
            other.side(),
            "Cannot add BeDOZa shares from different sides"
        );
        BeDOZa::new(
            self.bedoza_sender() + other.bedoza_sender(),
            self.bedoza_receiver() + other.bedoza_receiver(),
            self.side(),
        )
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
        if !self.side() {
            BeDOZa::new(
                self.bedoza_sender() + constant,
                *self.bedoza_receiver(),
                self.side(),
            )
        } else {
            BeDOZa::new(
                *self.bedoza_sender(),
                self.bedoza_receiver() + constant,
                self.side(),
            )
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
        if !self.side() {
            BeDOZa::new(
                self.bedoza_sender() - constant,
                *self.bedoza_receiver(),
                self.side(),
            )
        } else {
            BeDOZa::new(
                *self.bedoza_sender(),
                self.bedoza_receiver() - constant,
                self.side(),
            )
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
        assert_eq!(
            self.side(),
            other.side(),
            "Cannot subtract BeDOZa shares from different sides"
        );
        BeDOZa::new(
            self.bedoza_sender() - other.bedoza_sender(),
            self.bedoza_receiver() - other.bedoza_receiver(),
            self.side(),
        )
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
        BeDOZa::new(
            self.bedoza_sender() * constant,
            self.bedoza_receiver() * constant,
            self.side(),
        )
    }
}

impl Mul<FE> for BeDOZa {
    type Output = BeDOZa;

    fn mul(self, constant: FE) -> BeDOZa {
        &self * constant
    }
}
