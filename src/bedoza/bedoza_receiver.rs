use crate::{
    bedoza::comm_util::{receive_fe, receive_fe_vec}, 
    math::defines::{FE, random_fe_vec_from_rng},
    tcp_channel::SwankyChannel

};
use anyhow::{Result, anyhow, ensure};

use std::ops::{Add, Mul, Sub};
use rand::{RngExt, SeedableRng, rngs::StdRng};

// We assume that the offline phase is already done
// https://eprint.iacr.org/2010/514.pdf

#[derive(Clone, Copy)]
pub struct BeDOZaReceiver {
    tag: FE, // We have share * key = tag + pad, where share and pad are possessed by the BeDOZaSender
    key: FE,
}

impl BeDOZaReceiver {
    pub fn new(tag: FE, key: FE) -> Self {
        Self { tag, key }
    }

    pub fn tag(&self) -> FE {
        self.tag
    }

    pub fn key(&self) -> FE {
        self.key
    }
}

/// Receive the shares from BeDOZaSender
pub fn receive_open_shares(
    bedoza_receivers: &[BeDOZaReceiver],
    channel: &mut SwankyChannel,
) -> Result<Vec<FE>> {
    // Always consume the open protocol messages before performing validation checks.
    // This avoids leaving the sender blocked waiting for our seed on error paths.
    let start = std::time::Instant::now();
    let values = receive_fe_vec(channel).map_err(|e| anyhow!("Failed to receive values: {}", e))?;

    println!("Receive open shares so far: {:?}", start.elapsed());

    let mut rng = rand::rng();
    let seed: [u8; 32] = rng.random();
    channel.send(&seed)?;

    println!("Receive open shares so far: {:?}", start.elapsed());

    let acc_pad = receive_fe(channel).map_err(|e| anyhow!("Failed to receive pads: {}", e))?;

    println!("Receive open shares so far: {:?}", start.elapsed());

    ensure!(
        !bedoza_receivers.is_empty(),
        "Cannot open an empty list of BeDOZaReceiver shares"
    );
    ensure!(
        values.len() == bedoza_receivers.len(),
        "Length mismatch for opening shares: values={} receivers={}",
        values.len(),
        bedoza_receivers.len()
    );

    // Check whether keys of every BeDOZaReceiver are the same
    let key = bedoza_receivers[0].key();
    for (i, bedoza_receiver) in bedoza_receivers.iter().enumerate() {
        ensure!(
            bedoza_receiver.key() == key,
            "Key mismatch at bedoza_receiver index {}",
            i
        );
    }

    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, bedoza_receivers.len())?;
    let mut acc_val = FE::zero();
    let mut acc_tag = FE::zero();
    for (coeff, (value, bedoza_receiver)) in coeffs
        .iter()
        .zip(values.iter().zip(bedoza_receivers.iter()))
    {
        acc_val += coeff * value;
        acc_tag += coeff * bedoza_receiver.tag();
    }

    println!("Receive open shares so far: {:?}", start.elapsed());

    // Consistency check 
    ensure!(
        acc_tag + acc_pad == key * acc_val,
        "Tag mismatch for bedoza opening"
    );

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
        BeDOZaReceiver {
            tag: self.tag() + rhs.tag(),
            key: self.key(),
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
        BeDOZaReceiver {
            tag: self.tag() + self.key() * constant,
            key: self.key(),
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
        BeDOZaReceiver {
            tag: self.tag() - self.key() * constant,
            key: self.key(),
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
        BeDOZaReceiver {
            tag: self.tag() - rhs.tag(),
            key: self.key(),
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
        }
    }
}

impl Mul<FE> for BeDOZaReceiver {
    type Output = BeDOZaReceiver;
    fn mul(self, constant: FE) -> BeDOZaReceiver {
        &self * constant
    }
}
