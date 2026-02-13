use crate::{
    bedoza::defines::FE,
    stark_scalar::{StarkPoint, StarkScalar},
    tcp_channel::TcpChannel,
};
use anyhow::{anyhow, Result};
use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::{
    short_weierstrass::point::{Endianness, PointFormat},
    short_weierstrass::curves::stark_curve::StarkCurve,
    traits::IsEllipticCurve,
};
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

pub type CurvePoint = StarkPoint;
const GROUP_POINT_BYTES: usize = 96;

pub struct Group {
    point: CurvePoint,
}

impl Group {
    pub fn base_point() -> Self {
        Self {
            point: StarkCurve::generator(),
        }
    }

    pub fn scalar_mul_mod(&self, scalar: &StarkScalar) -> Self {
        Self {
            point: self.point.operate_with_self(scalar.representative()),
        }
    }

    pub fn scalar_mul(&self, scalar: &FE) -> Self {
        self.scalar_mul_mod(scalar)
    }

    pub fn as_point(&self) -> &CurvePoint {
        &self.point
    }

    pub fn from_point(point: CurvePoint) -> Self {
        Self { point }
    }
}

impl Add for Group {
    type Output = Group;
    fn add(self, rhs: Group) -> Group {
        Group {
            point: self.point.operate_with(&rhs.point),
        }
    }
}

impl<'a> Add<&'a Group> for Group {
    type Output = Group;
    fn add(self, rhs: &'a Group) -> Group {
        Group {
            point: self.point.operate_with(&rhs.point),
        }
    }
}

impl<'a> Add<Group> for &'a Group {
    type Output = Group;
    fn add(self, rhs: Group) -> Group {
        Group {
            point: self.point.operate_with(&rhs.point),
        }
    }
}

impl<'a, 'b> Add<&'b Group> for &'a Group {
    type Output = Group;
    fn add(self, rhs: &'b Group) -> Group {
        Group {
            point: self.point.operate_with(&rhs.point),
        }
    }
}

impl AddAssign for Group {
    fn add_assign(&mut self, rhs: Group) {
        self.point = self.point.operate_with(&rhs.point);
    }
}

impl AddAssign<&Group> for Group {
    fn add_assign(&mut self, rhs: &Group) {
        self.point = self.point.operate_with(&rhs.point);
    }
}

// --------------------
// Subtraction and negation (often handy)
// --------------------
impl Sub for Group {
    type Output = Group;
    fn sub(self, rhs: Group) -> Group {
        Group {
            point: self.point.operate_with(&rhs.point.neg()),
        }
    }
}

impl SubAssign for Group {
    fn sub_assign(&mut self, rhs: Group) {
        self.point = self.point.operate_with(&rhs.point.neg());
    }
}

impl Neg for Group {
    type Output = Group;
    fn neg(self) -> Group {
        Group {
            point: self.point.neg(),
        }
    }
}

pub fn send_group_elements(
    elements: &[Group],
    channel: &mut TcpChannel,
) -> Result<()> {
    let mut buf = Vec::with_capacity(elements.len() * GROUP_POINT_BYTES);
    buf.extend(elements.len().to_le_bytes());
    for elem in elements {
        let encoded = elem.as_point().serialize(PointFormat::Projective, Endianness::LittleEndian);
        if encoded.len() != GROUP_POINT_BYTES {
            return Err(anyhow!(
                "Unexpected encoded group point size: expected {} bytes, got {} bytes",
                GROUP_POINT_BYTES,
                encoded.len()
            ));
        }
        buf.extend_from_slice(&encoded);
    }
    channel.send(&buf)?;
    Ok(())
}

pub fn receive_group_elements(
    channel: &mut TcpChannel,
) -> Result<Vec<Group>> {
    let buf = channel.receive()?;
    if buf.len() < 8 {
        return Err(anyhow!(
            "Received data too short to contain element count: expected at least 8 bytes, got {} bytes",
            buf.len()
        ));
    }
    let count = usize::from_le_bytes(buf[0..8].try_into().unwrap());

    if buf.len() != count * GROUP_POINT_BYTES + 8 {
        return Err(anyhow!(
            "Expected {} bytes, got {} bytes",
            count * GROUP_POINT_BYTES,
            buf.len()
        ));
    }

    let mut elements = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * GROUP_POINT_BYTES;
        let end = start + GROUP_POINT_BYTES;
        let point = CurvePoint::deserialize(
            &buf[start..end],
            PointFormat::Projective,
            Endianness::LittleEndian,
        )
        .map_err(|e| anyhow!("Failed to deserialize Stark curve point: {:?}", e))?;
        elements.push(Group::from_point(point));
    }
    Ok(elements)
}
