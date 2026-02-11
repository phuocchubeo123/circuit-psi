use crate::{
    bedoza::{
        comm_util::send_fe_vec,
        defines::FE,
    },
    tcp_channel::TcpChannel
};
use std::ops::{Add, Mul, Sub};
use anyhow::{anyhow, Result};

#[derive(Copy, Clone)]
pub struct BeDOZaSender {
    val: FE,
    pad: FE,
    side: bool,
}

impl BeDOZaSender {
    pub fn new(val: FE, pad: FE, side: bool) -> Self {
        Self { val, pad, side }
    }

    pub fn val(&self) -> FE {
        self.val
    }

    pub fn pad(&self) -> FE {
        self.pad
    }

    pub fn side(&self) -> bool {
        self.side
    }
}

pub fn send_open_shares(bedoza_senders: &[BeDOZaSender], channel: &mut TcpChannel) -> Result<()> {
    let vals: Vec<FE> = bedoza_senders.iter().map(|bedoza_sender| bedoza_sender.val()).collect();
    let pads: Vec<FE> = bedoza_senders.iter().map(|bedoza_sender| bedoza_sender.pad()).collect();

    send_fe_vec(&vals, channel)
        .map_err(|e| anyhow!("Failed to send vals: {}", e))?;
    send_fe_vec(&pads, channel)
        .map_err(|e| anyhow!("Failed to send pads: {}", e))?;

    Ok(())
}

impl Add<&BeDOZaSender> for &BeDOZaSender {
    type Output = BeDOZaSender;

    fn add(self, other: &BeDOZaSender) -> BeDOZaSender {
        assert_eq!(self.side(), other.side(), "Cannot add BeDOZa senders from different sides");
        BeDOZaSender {
            val: self.val() + other.val(),
            pad: self.pad() + other.pad(),
            side: self.side(),
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
        if self.side() { // If side = true, don't do anything to the share
            BeDOZaSender {
                val: self.val(),
                pad: self.pad(),
                side: self.side(),
            }
        } else { // If side = false, add the constant to the share
            BeDOZaSender {
                val: self.val() + constant,
                pad: self.pad(),
                side: self.side(),
            }
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
        if self.side() { // If side = true, don't do anything to the share
            BeDOZaSender {
                val: self.val(),
                pad: self.pad(),
                side: self.side(),
            }
        } else { // If side = false, subtract the constant from the share
            BeDOZaSender {
                val: self.val() - constant,
                pad: self.pad(),
                side: self.side(),
            }
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
        assert_eq!(self.side(), other.side(), "Cannot subtract BeDOZa senders from different sides");
        BeDOZaSender {
            val: self.val() - other.val(),
            pad: self.pad() - other.pad(),
            side: self.side(),
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
            side: self.side(),
        }
    }
}

impl Mul<FE> for BeDOZaSender {
    type Output = BeDOZaSender;

    fn mul(self, constant: FE) -> BeDOZaSender {
        &self * constant
    }
}   
