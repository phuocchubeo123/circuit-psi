use ff::{Field as _, PrimeField};

#[derive(
    PrimeField,
    serde::Serialize,
    serde::Deserialize,
)]
#[PrimeFieldModulus = "73846995687063900142583536357581573884798075859800097461294096333596429543"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct FourQScalarField([u64; 4]);

pub const FOURQ_SCALAR_BITS: usize = 246;
pub const FOURQ_ORDER_WORDS_LE: [u64; 4] = [
    0x2FB2_540E_C776_8CE7,
    0xDFBD_004D_FE0F_7999,
    0xF053_9782_9CBC_14E5,
    0x0029_CBC1_4E5E_0A72,
];

fn ge_words(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn sub_words(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (tmp, b1) = a[i].overflowing_sub(b[i]);
        let (tmp2, b2) = tmp.overflowing_sub(borrow);
        a[i] = tmp2;
        borrow = (b1 as u64) | (b2 as u64);
    }
}

impl FourQScalarField {
    pub fn zero() -> Self {
        <Self as ff::Field>::ZERO
    }

    pub fn one() -> Self {
        <Self as ff::Field>::ONE
    }

    pub fn inv(&self) -> Option<Self> {
        self.invert().into_option()
    }

    pub fn square(&self) -> Self {
        *self * *self
    }

    pub fn pow(&self, exp: usize) -> Self {
        let mut acc = Self::one();
        let mut base = *self;
        let mut e = exp;
        while e > 0 {
            if (e & 1) == 1 {
                acc *= base;
            }
            base = base.square();
            e >>= 1;
        }
        acc
    }

    pub fn to_bytes_le(&self) -> [u8; 32] {
        let repr = self.to_repr();
        let mut out = [0u8; 32];
        out.copy_from_slice(repr.as_ref());
        out
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.to_bytes_le()
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("expected 32 bytes for FourQ scalar");
        }
        let mut repr = <Self as ff::PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        <Self as ff::PrimeField>::from_repr_vartime(repr).ok_or("value is not in FourQ scalar field")
    }

    // Biased mapping: interpret bytes as a 256-bit integer and reduce modulo the
    // FourQ subgroup order. This is faster than rejection sampling.
    pub fn from_bytes_le_mod_order(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = i * 8;
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&bytes[start..start + 8]);
            *limb = u64::from_le_bytes(tmp);
        }

        // Keep only 246 bits.
        limbs[3] &= 0x003F_FFFF_FFFF_FFFF;
        if ge_words(&limbs, &FOURQ_ORDER_WORDS_LE) {
            sub_words(&mut limbs, &FOURQ_ORDER_WORDS_LE);
        }

        let mut reduced = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            reduced[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }

        Self::from_bytes_le(&reduced).expect("mod-reduced bytes must be in FourQ scalar field")
    }
}

pub fn random_fourq_elements_from_prg(prg: &mut psi_aes::prg::PRG, elements: &mut [FourQScalarField]) {
    const CHUNK: usize = 1024;
    let mut blocks = vec![[0u8; 32]; CHUNK];
    let mut offset = 0usize;

    while offset < elements.len() {
        let take = (elements.len() - offset).min(CHUNK);
        prg.random_32byte_block(&mut blocks[..take]);
        for i in 0..take {
            elements[offset + i] = FourQScalarField::from_bytes_le_mod_order(&blocks[i]);
        }
        offset += take;
    }
}
