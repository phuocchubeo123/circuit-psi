use crate::{
    bedoza::comm_util::send_fe_vec, 
    math::defines::{FE, random_fe_vec_from_rng}, 
    network::tcp_channel::SwankyChannel,
};
use anyhow::{Result, anyhow, ensure};
use std::ops::{Add, Mul, Sub};
use rand::{SeedableRng, rngs::StdRng};

#[derive(Copy, Clone)]
pub struct BeDOZaSender {
    val: FE,
    pad: FE,
}

impl BeDOZaSender {
    pub fn new(val: FE, pad: FE) -> Self {
        Self { val, pad }
    }

    pub fn val(&self) -> FE {
        self.val
    }

    pub fn pad(&self) -> FE {
        self.pad
    }
}

pub fn send_open_shares(
    bedoza_senders: &[BeDOZaSender],
    channel: &mut SwankyChannel,
) -> Result<()> {

    let vals: Vec<FE> = bedoza_senders
        .iter()
        .map(|bedoza_sender| bedoza_sender.val())
        .collect();
    send_fe_vec(&vals, channel).map_err(|e| anyhow!("Failed to send vals: {}", e))?;

    let pads: Vec<FE> = bedoza_senders
        .iter()
        .map(|bedoza_sender| bedoza_sender.pad())
        .collect();

    let seed_bytes = channel.receive()?;
    ensure!(
        seed_bytes.len() == 32,
        "Expected 32-byte seed from receiver, got {} bytes",
        seed_bytes.len()
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, bedoza_senders.len())?;
    let mut acc_pad = FE::zero();

    for (coeff, pad) in coeffs.iter().zip(pads.iter()) {
        acc_pad += coeff * pad;
    }


    send_fe_vec(&[acc_pad], channel).map_err(|e| anyhow!("Failed to send pads: {}", e))?;

    Ok(())
}

pub fn linear_comb_sender(
    shares: &[BeDOZaSender],
    coeffs: &[FE],
    context: &str,
) -> Result<BeDOZaSender> {
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

impl Add<&BeDOZaSender> for &BeDOZaSender {
    type Output = BeDOZaSender;

    fn add(self, other: &BeDOZaSender) -> BeDOZaSender {
        BeDOZaSender {
            val: self.val() + other.val(),
            pad: self.pad() + other.pad(),
        }
    }
}

impl Add for BeDOZaSender {
    type Output = BeDOZaSender;

    fn add(self, other: BeDOZaSender) -> BeDOZaSender {
        &self + &other
    }
}

impl Add<FE> for &BeDOZaSender {
    type Output = BeDOZaSender;

    fn add(self, constant: FE) -> BeDOZaSender {
        BeDOZaSender {
            val: self.val() + constant,
            pad: self.pad(),
        }
    }
}

impl Add<FE> for BeDOZaSender {
    type Output = BeDOZaSender;

    fn add(self, constant: FE) -> BeDOZaSender {
        &self + constant
    }
}

impl Sub<FE> for &BeDOZaSender {
    type Output = BeDOZaSender;

    fn sub(self, constant: FE) -> BeDOZaSender {
        BeDOZaSender {
            val: self.val() - constant,
            pad: self.pad(),
        }
    }
}

impl Sub<FE> for BeDOZaSender {
    type Output = BeDOZaSender;

    fn sub(self, constant: FE) -> BeDOZaSender {
        &self - constant
    }
}

impl Sub<&BeDOZaSender> for &BeDOZaSender {
    type Output = BeDOZaSender;

    fn sub(self, other: &BeDOZaSender) -> BeDOZaSender {
        BeDOZaSender {
            val: self.val() - other.val(),
            pad: self.pad() - other.pad(),
        }
    }
}

impl Sub for BeDOZaSender {
    type Output = BeDOZaSender;

    fn sub(self, other: BeDOZaSender) -> BeDOZaSender {
        &self - &other
    }
}

impl Mul<FE> for &BeDOZaSender {
    type Output = BeDOZaSender;

    fn mul(self, constant: FE) -> BeDOZaSender {
        BeDOZaSender {
            val: self.val() * constant,
            pad: self.pad() * constant,
        }
    }
}

impl Mul<FE> for BeDOZaSender {
    type Output = BeDOZaSender;

    fn mul(self, constant: FE) -> BeDOZaSender {
        &self * constant
    }
}
