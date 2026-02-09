use crate::{
    bedoza::{
        comm_util::send_fe_vec,
        defines::FE,
    },
    tcp_channel::TcpChannel
};
use anyhow::{anyhow, Result};

#[derive(Copy, Clone)]
pub struct BeDOZaSender {
    val: FE,
    pad: FE,
    side: bool,
}

impl BeDOZaSender {
    pub fn val(&self) -> FE {
        self.val
    }

    pub fn pad(&self) -> FE {
        self.pad
    }

    pub fn side(&self) -> bool {
        self.side
    }

    /// Add a public constant to an authenticated value.
    /// Only add the constant to the share of side 0
    pub fn add_constant(self, constant: FE) -> BeDOZaSender {
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

    pub fn add(self, other: &BeDOZaSender) -> BeDOZaSender {
        assert_eq!(self.side(), other.side(), "Cannot add BeDOZa senders from different sides");
        BeDOZaSender {
            val: self.val() + other.val(),
            pad: self.pad() + other.pad(),
            side: self.side(),
        }
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
