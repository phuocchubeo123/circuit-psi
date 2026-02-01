use crate::tcp_channel::TcpChannel;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    constants::RISTRETTO_BASEPOINT_POINT,
};
use anyhow::{anyhow, Result};
use std::ops::{Add, AddAssign, Sub, SubAssign, Neg};

pub struct Group {
    point: RistrettoPoint,
}

impl Group {
    pub fn base_point() -> Self {
        Self {
            point: RISTRETTO_BASEPOINT_POINT,
        }
    }

    pub fn new_from_u128_exponent(exp: u128) -> Self {
        let scalar = curve25519_dalek::scalar::Scalar::from(exp);
        Self {
            point: RISTRETTO_BASEPOINT_POINT * scalar,
        }
    }
}

impl Add for Group {
    type Output = Group;
    fn add(self, rhs: Group) -> Group {
        Group { point: self.point + rhs.point }
    }
}

impl<'a> Add<&'a Group> for Group {
    type Output = Group;
    fn add(self, rhs: &'a Group) -> Group {
        Group { point: self.point + rhs.point }
    }
}

impl<'a> Add<Group> for &'a Group {
    type Output = Group;
    fn add(self, rhs: Group) -> Group {
        Group { point: self.point + rhs.point }
    }
}

impl<'a, 'b> Add<&'b Group> for &'a Group {
    type Output = Group;
    fn add(self, rhs: &'b Group) -> Group {
        Group { point: self.point + rhs.point }
    }
}

impl AddAssign for Group {
    fn add_assign(&mut self, rhs: Group) {
        self.point += rhs.point;
    }
}

impl AddAssign<&Group> for Group {
    fn add_assign(&mut self, rhs: &Group) {
        self.point += rhs.point;
    }
}

// --------------------
// Subtraction and negation (often handy)
// --------------------
impl Sub for Group {
    type Output = Group;
    fn sub(self, rhs: Group) -> Group {
        Group { point: self.point - rhs.point }
    }
}

impl SubAssign for Group {
    fn sub_assign(&mut self, rhs: Group) {
        self.point -= rhs.point;
    }
}

impl Neg for Group {
    type Output = Group;
    fn neg(self) -> Group {
        Group { point: -self.point }
    }
}

pub fn send_group_elements(
    channel: &mut TcpChannel,
    elements: &[RistrettoPoint],
) -> Result<()> {
    let mut buf = Vec::with_capacity(elements.len() * 32);
    for elem in elements {
        buf.extend_from_slice(&elem.compress().to_bytes());
    }
    channel.send(&buf)?;
    Ok(())
}

pub fn receive_group_elements(
    channel: &mut TcpChannel,
    count: usize,
) -> Result<Vec<RistrettoPoint>> {
    let buf = channel.receive()?;
    if buf.len() != count * 32 {
        return Err(anyhow!(
            "Expected {} bytes, got {} bytes",
            count * 32,
            buf.len()
        ));
    }

    let mut elements = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * 32;
        let end = start + 32;
        let compressed = CompressedRistretto::from_slice(&buf[start..end])
            .map_err(|e| anyhow!("Failed to read compressed Ristretto point: {}", e))?;
        let point = compressed
            .decompress()
            .ok_or_else(|| anyhow!("Failed to decompress Ristretto point"))?;
        elements.push(point);
    }
    Ok(elements)
}