use ff::{Field as _, PrimeField};
use std::hash::{Hash, Hasher};
use subtle::{Choice, CtOption};
use swanky_field::{FiniteField, FiniteRing, PrimeFiniteField as SwankyPrimeFiniteField};
use swanky_serialization::{BiggerThanModulus, CanonicalSerialize};

#[derive(PrimeField, serde::Serialize, serde::Deserialize)]
#[PrimeFieldModulus = "73846995687063900142583536357581573884798075859800097461294096333596429543"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct FourQScalarField([u64; 4]);

pub const FOURQ_ORDER_WORDS_LE: [u64; 4] = [
    0x2FB2_540E_C776_8CE7,
    0xDFBD_004D_FE0F_7999,
    0xF053_9782_9CBC_14E5,
    0x0029_CBC1_4E5E_0A72,
];

impl Hash for FourQScalarField {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_repr().as_ref().hash(state);
    }
}

impl CanonicalSerialize for FourQScalarField {
    type Serializer = swanky_serialization::ByteElementSerializer<Self>;
    type Deserializer = swanky_serialization::ByteElementDeserializer<Self>;
    type ByteReprLen = generic_array::typenum::U32;
    type FromBytesError = BiggerThanModulus;

    fn from_bytes(
        bytes: &generic_array::GenericArray<u8, Self::ByteReprLen>,
    ) -> std::result::Result<Self, Self::FromBytesError> {
        let mut repr = <Self as ff::PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes.as_ref());
        <Self as ff::PrimeField>::from_repr_vartime(repr).ok_or(BiggerThanModulus)
    }

    fn to_bytes(&self) -> generic_array::GenericArray<u8, Self::ByteReprLen> {
        let repr = self.to_repr();
        let mut out = generic_array::GenericArray::<u8, Self::ByteReprLen>::default();
        out.copy_from_slice(repr.as_ref());
        out
    }
}

impl std::iter::Sum for FourQScalarField {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(<Self as ff::Field>::ZERO, |acc, x| acc + x)
    }
}

impl std::iter::Product for FourQScalarField {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(<Self as ff::Field>::ONE, |acc, x| acc * x)
    }
}

impl num_traits::Zero for FourQScalarField {
    fn zero() -> Self {
        <Self as ff::Field>::ZERO
    }

    fn is_zero(&self) -> bool {
        bool::from(ff::Field::is_zero(self))
    }
}

impl num_traits::One for FourQScalarField {
    fn one() -> Self {
        <Self as ff::Field>::ONE
    }

    fn is_one(&self) -> bool {
        *self == <Self as ff::Field>::ONE
    }
}

impl std::ops::DivAssign<&Self> for FourQScalarField {
    fn div_assign(&mut self, rhs: &Self) {
        *self *= rhs.invert().unwrap();
    }
}

impl std::ops::DivAssign<Self> for FourQScalarField {
    fn div_assign(&mut self, rhs: Self) {
        *self /= &rhs;
    }
}

impl std::ops::Div<Self> for FourQScalarField {
    type Output = Self;

    fn div(mut self, rhs: Self) -> Self::Output {
        self /= rhs;
        self
    }
}

impl FiniteRing for FourQScalarField {
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        let mut repr = <Self as ff::PrimeField>::Repr::default();
        repr.as_mut()[0..16].copy_from_slice(x);
        <Self as ff::PrimeField>::from_repr_vartime(repr)
            .expect("FourQ subgroup order has >128 bits, so any 16-byte value is canonical")
    }

    fn random<R: rand08::Rng + ?Sized>(rng: &mut R) -> Self {
        <Self as ff::Field>::random(rng)
    }

    const ZERO: Self = <Self as ff::Field>::ZERO;
    const ONE: Self = <Self as ff::Field>::ONE;
}

impl FiniteField for FourQScalarField {
    type PrimeField = Self;
    const GENERATOR: Self = <Self as ff::PrimeField>::MULTIPLICATIVE_GENERATOR;
    type NumberOfBitsInBitDecomposition = generic_array::typenum::U246;

    fn bit_decomposition(
        &self,
    ) -> generic_array::GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        let repr = self.to_repr();
        let mut out: generic_array::GenericArray<bool, Self::NumberOfBitsInBitDecomposition> =
            Default::default();
        for (i, dst) in out.iter_mut().enumerate() {
            *dst = (repr.as_ref()[i / 8] & (1 << (i % 8))) != 0;
        }
        out
    }

    fn inverse(&self) -> Self {
        self.invert().unwrap()
    }
}

impl TryFrom<u128> for FourQScalarField {
    type Error = BiggerThanModulus;

    fn try_from(value: u128) -> std::result::Result<Self, Self::Error> {
        let mut repr = <Self as ff::PrimeField>::Repr::default();
        repr.as_mut()[0..16].copy_from_slice(&value.to_le_bytes());
        <Self as ff::PrimeField>::from_repr_vartime(repr).ok_or(BiggerThanModulus)
    }
}

impl SwankyPrimeFiniteField for FourQScalarField {
    fn modulus_int<const LIMBS: usize>() -> crypto_bigint::Uint<LIMBS> {
        assert!(LIMBS >= Self::MIN_LIMBS_NEEDED);
        let mut words = [0 as crypto_bigint::Word; LIMBS];
        words[0] = FOURQ_ORDER_WORDS_LE[0];
        words[1] = FOURQ_ORDER_WORDS_LE[1];
        words[2] = FOURQ_ORDER_WORDS_LE[2];
        words[3] = FOURQ_ORDER_WORDS_LE[3];
        crypto_bigint::Uint::from_words(words)
    }

    fn as_int<const LIMBS: usize>(&self) -> crypto_bigint::Uint<LIMBS> {
        assert!(LIMBS >= Self::MIN_LIMBS_NEEDED);
        let repr = self.to_repr();
        let mut words = [0 as crypto_bigint::Word; LIMBS];
        for (i, slot) in words.iter_mut().enumerate().take(4) {
            let start = i * 8;
            let mut limb = [0u8; 8];
            limb.copy_from_slice(&repr.as_ref()[start..start + 8]);
            *slot = u64::from_le_bytes(limb);
        }
        crypto_bigint::Uint::from_words(words)
    }

    fn try_from_int<const LIMBS: usize>(x: crypto_bigint::Uint<LIMBS>) -> CtOption<Self> {
        let words = x.as_words();
        let mut repr = <Self as ff::PrimeField>::Repr::default();
        for (i, word) in words.iter().enumerate().take(4) {
            let start = i * 8;
            repr.as_mut()[start..start + 8].copy_from_slice(&(*word as u64).to_le_bytes());
        }

        let mut high_zero = Choice::from(1u8);
        for word in words.iter().skip(4) {
            high_zero &= Choice::from((*word == 0) as u8);
        }

        let within_modulus = Choice::from((x < Self::modulus_int()) as u8);
        let parsed = <Self as ff::PrimeField>::from_repr(repr);
        CtOption::new(
            parsed.unwrap_or(<Self as ff::Field>::ZERO),
            parsed.is_some() & high_zero & within_modulus,
        )
    }
}

pub fn fq(n: u64) -> FourQScalarField {
    FourQScalarField::try_from(n as u128).expect("small constant is valid FourQ scalar field value")
}
