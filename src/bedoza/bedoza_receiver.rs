use crate::{
    bedoza::{comm_util::receive_fe_vec, defines::FE},
    tcp_channel::SwankyChannel,
};
use anyhow::{Result, anyhow, ensure};

use std::ops::{Add, Mul, Sub};

// We assume that the offline phase is already done
// https://eprint.iacr.org/2010/514.pdf

#[derive(Clone, Copy)]
pub struct BeDOZaReceiver {
    tag: FE, // We have tag = share * key + pad, where share and pad is possessed by the BeDOZaSender
    key: FE,
    side: bool, // Either 0 or 1. This variable indicate which side's share is this authenticated share. Remember in BeDOZa, both shares of a single value is authenticated.
}

impl BeDOZaReceiver {
    pub fn new(tag: FE, key: FE, side: bool) -> Self {
        Self { tag, key, side }
    }

    pub fn tag(&self) -> FE {
        self.tag
    }

    pub fn key(&self) -> FE {
        self.key
    }

    pub fn side(&self) -> bool {
        self.side
    }
}

/// Receive the shares from BeDOZaSender
pub fn receive_open_shares(
    bedoza_receivers: &[BeDOZaReceiver],
    channel: &mut SwankyChannel,
) -> Result<Vec<FE>> {
    // First check whether keys of every BeDOZaReceiver are the same (since they come from the same person)
    let key = bedoza_receivers[0].key();
    for (i, bedoza_receiver) in bedoza_receivers.iter().enumerate() {
        ensure!(
            bedoza_receiver.key() == key,
            "Key mismatch at bedoza_receiver index {}",
            i
        );
    }

    // Receive values and pads from BeDOZaSender
    let values = receive_fe_vec(channel).map_err(|e| anyhow!("Failed to receive values: {}", e))?;
    let pads = receive_fe_vec(channel).map_err(|e| anyhow!("Failed to receive pads: {}", e))?;

    ensure!(
        values.len() == pads.len(),
        "Length mismatch between values and pads received: lhs = {}, rhs = {}",
        values.len(),
        pads.len()
    );

    // Compute the received tags and compare them with the tags that I have
    let received_tags: Vec<FE> = values
        .iter()
        .zip(pads.iter())
        .map(|(value, pad)| key * value + pad)
        .collect();
    for (i, (&received_tag, bedoza_receiver)) in received_tags
        .iter()
        .zip(bedoza_receivers.iter())
        .enumerate()
    {
        ensure!(
            received_tag == bedoza_receiver.tag(),
            "Tag mismatch at bedoza_receiver index {}",
            i
        );
    }

    Ok(values)
}

pub fn linear_comb_receiver(
    shares: &[BeDOZaReceiver],
    coeffs: &[FE],
    context: &str,
) -> Result<BeDOZaReceiver> {
    ensure!(!shares.is_empty(), "{}: empty share list", context);
    ensure!(
        shares.len() == coeffs.len(),
        "{}: length mismatch shares={} coeffs={}",
        context,
        shares.len(),
        coeffs.len()
    );

    let mut acc = shares[0] * coeffs[0];
    for (share, &coeff) in shares.iter().skip(1).zip(coeffs.iter().skip(1)) {
        acc = acc + (*share * coeff);
    }
    Ok(acc)
}

impl Add<&BeDOZaReceiver> for &BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn add(self, rhs: &BeDOZaReceiver) -> BeDOZaReceiver {
        assert_eq!(
            self.key(),
            rhs.key(),
            "Key mismatch in BeDOZa addition: lhs = {:?}, rhs = {:?}",
            self.key(),
            rhs.key()
        );
        assert_eq!(
            self.side(),
            rhs.side(),
            "Side mismatch in BeDOZa addition: lhs = {:?}, rhs = {:?}",
            self.side(),
            rhs.side()
        );
        BeDOZaReceiver {
            tag: self.tag() + rhs.tag(),
            key: self.key(),
            side: self.side(),
        }
    }
}

impl Add for BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn add(self, other: BeDOZaReceiver) -> BeDOZaReceiver {
        &self + &other
    }
}

impl Add<FE> for &BeDOZaReceiver {
    type Output = BeDOZaReceiver;

    fn add(self, constant: FE) -> BeDOZaReceiver {
        if self.side() {
            // If side = true, don't do anything to the share
            BeDOZaReceiver {
                tag: self.tag(),
                key: self.key(),
                side: self.side(),
            }
        } else {
            // If side = false, add the constant to the share
            BeDOZaReceiver {
                tag: self.tag() + self.key() * constant,
                key: self.key(),
                side: self.side(),
            }
        }
    }
}

impl Add<FE> for BeDOZaReceiver {
    type Output = BeDOZaReceiver;

    fn add(self, constant: FE) -> BeDOZaReceiver {
        &self + constant
    }
}

impl Sub<FE> for &BeDOZaReceiver {
    type Output = BeDOZaReceiver;

    fn sub(self, constant: FE) -> BeDOZaReceiver {
        if self.side() {
            // If side = true, don't do anything to the share
            BeDOZaReceiver {
                tag: self.tag(),
                key: self.key(),
                side: self.side(),
            }
        } else {
            // If side = false, subtract the constant from the share
            BeDOZaReceiver {
                tag: self.tag() - self.key() * constant,
                key: self.key(),
                side: self.side(),
            }
        }
    }
}

impl Sub<FE> for BeDOZaReceiver {
    type Output = BeDOZaReceiver;

    fn sub(self, constant: FE) -> BeDOZaReceiver {
        &self - constant
    }
}

impl Sub<&BeDOZaReceiver> for &BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn sub(self, rhs: &BeDOZaReceiver) -> BeDOZaReceiver {
        assert_eq!(
            self.key(),
            rhs.key(),
            "Key mismatch in BeDOZa subtraction: lhs = {:?}, rhs = {:?}",
            self.key(),
            rhs.key()
        );
        assert_eq!(
            self.side(),
            rhs.side(),
            "Side mismatch in BeDOZa subtraction: lhs = {:?}, rhs = {:?}",
            self.side(),
            rhs.side()
        );
        BeDOZaReceiver {
            tag: self.tag() - rhs.tag(),
            key: self.key(),
            side: self.side(),
        }
    }
}

impl Sub for BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn sub(self, other: BeDOZaReceiver) -> BeDOZaReceiver {
        &self - &other
    }
}

impl Mul<FE> for &BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn mul(self, constant: FE) -> BeDOZaReceiver {
        BeDOZaReceiver {
            tag: self.tag() * constant,
            key: self.key(),
            side: self.side(),
        }
    }
}

impl Mul<FE> for BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn mul(self, constant: FE) -> BeDOZaReceiver {
        &self * constant
    }
}
