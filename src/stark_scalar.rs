use lambdaworks_math::{
    cyclic_group::IsGroup,
    errors::ByteConversionError,
    elliptic_curve::{short_weierstrass::curves::stark_curve::StarkCurve, traits::IsEllipticCurve},
    errors::CreationError,
    field::{
        element::FieldElement,
        errors::FieldError,
        fields::{
            fft_friendly::stark_252_prime_field::Stark252PrimeField,
            montgomery_backed_prime_fields::{IsModulus, U256PrimeField},
        },
    },
    traits::ByteConversion,
    unsigned_integer::element::U256,
};
use rand::{Rng, RngExt};

pub const STARK_CURVE_SUBGROUP_ORDER_HEX: &str =
    "800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

#[derive(Clone, Debug, Copy)]
pub struct StarkCurveSubgroupOrderModulus;

impl IsModulus<U256> for StarkCurveSubgroupOrderModulus {
    const MODULUS: U256 = U256::from_hex_unchecked(STARK_CURVE_SUBGROUP_ORDER_HEX);
}

pub type StarkScalarField = U256PrimeField<StarkCurveSubgroupOrderModulus>;
pub type StarkScalar = FieldElement<StarkScalarField>;
pub type StarkBaseFieldElement = FieldElement<Stark252PrimeField>;
pub type StarkPoint = <StarkCurve as IsEllipticCurve>::PointRepresentation;

pub fn subgroup_order() -> U256 {
    <StarkCurveSubgroupOrderModulus as IsModulus<U256>>::MODULUS
}

pub fn scalar_from_hex(hex: &str) -> Result<StarkScalar, CreationError> {
    StarkScalar::from_hex(hex)
}

pub fn scalar_from_u64(value: u64) -> StarkScalar {
    StarkScalar::from(value)
}

pub fn scalar_from_u128(value: u128) -> StarkScalar {
    let rep = U256::from(value);
    StarkScalar::from(&rep)
}

pub fn scalar_from_u256(value: U256) -> StarkScalar {
    StarkScalar::from(&value)
}

pub fn reduce_base_field(value: &StarkBaseFieldElement) -> StarkScalar {
    let rep = value.representative();
    StarkScalar::from(&rep)
}

pub fn add_mod(lhs: &StarkScalar, rhs: &StarkScalar) -> StarkScalar {
    lhs + rhs
}

pub fn sub_mod(lhs: &StarkScalar, rhs: &StarkScalar) -> StarkScalar {
    lhs - rhs
}

pub fn mul_mod(lhs: &StarkScalar, rhs: &StarkScalar) -> StarkScalar {
    lhs * rhs
}

pub fn neg_mod(value: &StarkScalar) -> StarkScalar {
    -value
}

pub fn inv_mod(value: &StarkScalar) -> Result<StarkScalar, FieldError> {
    value.inv()
}

pub fn mul_generator(scalar: &StarkScalar) -> StarkPoint {
    StarkCurve::generator().operate_with_self(scalar.representative())
}

pub fn mul_point(point: &StarkPoint, scalar: &StarkScalar) -> StarkPoint {
    point.operate_with_self(scalar.representative())
}

pub fn random_scalars_from_rng(
    rng: &mut impl Rng,
    count: usize,
) -> Result<Vec<StarkScalar>, ByteConversionError> {
    let mut scalars = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        scalars.push(StarkScalar::from_bytes_le(&bytes)?);
    }
    Ok(scalars)
}

pub fn random_scalars(count: usize) -> Result<Vec<StarkScalar>, ByteConversionError> {
    let mut rng = rand::rng();
    random_scalars_from_rng(&mut rng, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subgroup_order_reduces_to_zero_in_scalar_field() {
        let scalar = scalar_from_u256(subgroup_order());
        assert_eq!(scalar, StarkScalar::zero());
    }

    #[test]
    fn generator_times_subgroup_order_is_neutral() {
        let point = mul_generator(&scalar_from_u256(subgroup_order()));
        assert!(point.is_neutral_element());
    }
}
