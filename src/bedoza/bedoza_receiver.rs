use crate::{
    tcp_channel::TcpChannel,
    bedoza::{
        comm_util::receive_fe_vec,
        defines::FE,
    },
};
use anyhow::{anyhow, ensure, Result};

use std::ops::{Add, AddAssign};

// We assume that the offline phase is already done
// https://eprint.iacr.org/2010/514.pdf

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeDOZaReceiver {
    tag: FE, // We have tag = share * key + pad, where share and pad is possessed by the BeDOZaSender
    key: FE,
    side: bool, // Either 0 or 1. This variable indicate which side's share is this authenticated share. Remember in BeDOZa, both shares of a single value is authenticated.
}

impl BeDOZaReceiver {
    pub fn tag(&self) -> FE {
        self.tag
    }

    pub fn key(&self) -> FE {
        self.key
    }

    pub fn side(&self) -> bool {
        self.side
    }

    /// Add a public constant to an authenticated value.
    /// Only add the constant to the share of side 0
    pub fn add_constant(self, constant: FE) -> BeDOZaReceiver {
        if self.side() { // If side = true, don't do anything to the share
            BeDOZaReceiver {
                tag: self.tag(),
                key: self.key(),
                side: self.side(),
            }
        } else { // If side = false, add the constant to the share
            BeDOZaReceiver {
                tag: self.tag() + self.key() * constant,
                key: self.key(),
                side: self.side(),
            }
        }
    }

    pub fn authenticate(side: bool, channel: &mut TcpChannel) -> Result<Vec<BeDOZaReceiver>> {
        unimplemented!()
    }
}

/// Receive the shares from BeDOZaSender
pub fn receive_open_shares(bedoza_receivers: &[BeDOZaReceiver], channel: &mut TcpChannel) -> Result<Vec<FE>> {
    // First check whether keys of every BeDOZaReceiver are the same (since they come from the same person)
    let key = bedoza_receivers[0].key();
    for (i, bedoza_receiver) in bedoza_receivers.iter().enumerate() {
        ensure!(bedoza_receiver.key() == key, 
            "Key mismatch at bedoza_receiver index {}", i);
    }

    // Receive values and pads from BeDOZaSender
    let values = receive_fe_vec(channel)
        .map_err(|e| anyhow!("Failed to receive values: {}", e))?;
    let pads = receive_fe_vec(channel)
        .map_err(|e| anyhow!("Failed to receive pads: {}", e))?;

    ensure!(values.len() == pads.len(), 
        "Length mismatch between values and pads received: lhs = {}, rhs = {}", values.len(), pads.len());

    // Compute the received tags and compare them with the tags that I have
    let received_tags: Vec<FE> = values.iter().zip(pads.iter()).map(|(value, pad)| key * value + pad).collect();
    for (i, (&received_tag, bedoza_receiver)) in received_tags.iter().zip(bedoza_receivers.iter()).enumerate() {
        ensure!(received_tag == bedoza_receiver.tag(),
            "Tag mismatch at bedoza_receiver index {}", i);
    }

    Ok(values)
}

impl Add for BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn add(self, rhs: BeDOZaReceiver) -> BeDOZaReceiver {
        assert_eq!(self.key(), rhs.key(), "Key mismatch in BeDOZa addition: lhs = {:?}, rhs = {:?}", self.key(), rhs.key());
        assert_eq!(self.side(), rhs.side(), "Side mismatch in BeDOZa addition: lhs = {:?}, rhs = {:?}", self.side(), rhs.side());
        BeDOZaReceiver {
            tag: self.tag() + rhs.tag(),
            key: self.key(),
            side: self.side(),
        }
    }
}

impl Add<FE> for BeDOZaReceiver {
    type Output = BeDOZaReceiver;

    fn add(self, rhs: FE) -> BeDOZaReceiver {
        self.add_constant(rhs)
    }
}

impl AddAssign<FE> for BeDOZaReceiver {
    fn add_assign(&mut self, rhs: FE) {
        *self = self.add_constant(rhs);
    }
}
