use crate::{bedoza::defines::FE, tcp_channel::TcpChannel};
use anyhow::{Result, anyhow};
use fourq::point::Point;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

pub type CurvePoint = Point;
const GROUP_POINT_BYTES: usize = 32;
const ECCRYPTO_SUCCESS: u32 = 1;
const MSM_SCALAR_BITS: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PointAffine {
    x: [[u64; 2]; 2],
    y: [[u64; 2]; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PointExtProj {
    x: [[u64; 2]; 2],
    y: [[u64; 2]; 2],
    z: [[u64; 2]; 2],
    ta: [[u64; 2]; 2],
    tb: [[u64; 2]; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PointExtProjPrecomp {
    xy: [[u64; 2]; 2],
    yx: [[u64; 2]; 2],
    z2: [[u64; 2]; 2],
    t2: [[u64; 2]; 2],
}

unsafe extern "C" {
    fn ecc_mul_fixed(k: *mut u64, q: *mut PointAffine) -> bool;
    fn ecc_mul(p: *mut PointAffine, k: *mut u64, q: *mut PointAffine, clear_cofactor: bool)
    -> bool;
    fn encode(p: *mut PointAffine, encoded: *mut u8);
    fn decode(encoded: *const u8, p: *mut PointAffine) -> u32;
    fn point_setup(p: *mut PointAffine, q: *mut PointExtProj);
    fn R1_to_R2(p: *mut PointExtProj, q: *mut PointExtProjPrecomp);
    fn eccadd(q: *mut PointExtProjPrecomp, p: *mut PointExtProj);
    fn eccdouble(p: *mut PointExtProj);
    fn eccnorm(p: *mut PointExtProj, q: *mut PointAffine);
    fn fp2neg1271(a: *mut [[u64; 2]; 2]);
}

#[derive(Clone)]
pub struct Group {
    affine: PointAffine,
}

impl Group {
    pub fn base_point() -> Self {
        let mut k = [0u64; 4];
        k[0] = 1;
        let mut affine = PointAffine::default();
        let ok = unsafe { ecc_mul_fixed(k.as_mut_ptr(), &mut affine) };
        assert!(ok, "Failed to compute FourQ generator");

        Self { affine }
    }

    pub fn scalar_mul_mod(&self, scalar: &FE) -> Self {
        Self {
            affine: scalar_mul_affine(self.affine, scalar),
        }
    }

    pub fn scalar_mul(&self, scalar: &FE) -> Self {
        self.scalar_mul_mod(scalar)
    }

    pub fn as_point(&self) -> CurvePoint {
        affine_to_point(self.affine)
    }

    pub fn from_point(point: CurvePoint) -> Self {
        let affine = point_to_affine(&point).expect("Failed to convert FourQ point to affine");
        Self { affine }
    }
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        encode_affine(self.affine) == encode_affine(other.affine)
    }
}

impl Eq for Group {}

pub fn msm_pippenger(points: &[Group], scalars: &[FE]) -> Result<Group> {
    let window_bits = choose_pippenger_window_size(points.len());
    msm_pippenger_with_window(points, scalars, window_bits)
}

pub fn msm_pippenger_with_window(
    points: &[Group],
    scalars: &[FE],
    window_bits: usize,
) -> Result<Group> {
    if points.len() != scalars.len() {
        return Err(anyhow!(
            "Mismatched MSM inputs: {} points but {} scalars",
            points.len(),
            scalars.len()
        ));
    }
    if window_bits == 0 || window_bits > 20 {
        return Err(anyhow!(
            "Invalid Pippenger window size {} (must be in [1, 20])",
            window_bits
        ));
    }
    if points.is_empty() {
        return Ok(zero_group());
    }

    let num_buckets = (1usize << window_bits) - 1;
    let window_mask = (1u64 << window_bits) - 1;
    let num_windows = MSM_SCALAR_BITS.div_ceil(window_bits);
    let scalar_words: Vec<[u64; 4]> = scalars.iter().map(fe_to_fourq_words).collect();

    let point_precomp: Vec<PointExtProjPrecomp> = points
        .iter()
        .map(|p| {
            let mut ext = affine_to_extproj(p.affine);
            let mut pre = PointExtProjPrecomp::default();
            unsafe {
                R1_to_R2(&mut ext, &mut pre);
            }
            pre
        })
        .collect();
    let point_precomp_ptr = point_precomp.as_ptr();

    let identity_ext = neutral_extproj();
    let mut acc_ext = identity_ext;
    let mut buckets = vec![identity_ext; num_buckets];
    let mut bucket_used = vec![false; num_buckets];

    for window_idx in (0..num_windows).rev() {
        if window_idx != num_windows - 1 {
            for _ in 0..window_bits {
                double_extproj_in_place(&mut acc_ext);
            }
        }

        let bit_offset = window_idx * window_bits;
        buckets.fill(identity_ext);
        bucket_used.fill(false);

        for i in 0..scalar_words.len() {
            // SAFETY: `i` is in-bounds by construction of the loop range.
            let words = unsafe { scalar_words.get_unchecked(i) };
            let digit = extract_window_bits_words(words, bit_offset, window_bits, window_mask);
            if digit == 0 {
                continue;
            }
            let bucket_idx = digit - 1;
            // SAFETY: `bucket_idx` comes from `digit in [1, num_buckets]`.
            unsafe {
                *bucket_used.get_unchecked_mut(bucket_idx) = true;
            }
            unsafe {
                let point_ptr = point_precomp_ptr.add(i) as *mut PointExtProjPrecomp;
                let bucket_ptr = buckets.get_unchecked_mut(bucket_idx);
                eccadd(point_ptr, bucket_ptr);
            }
        }

        let mut running_ext = identity_ext;
        let mut has_running = false;
        for bucket_idx in (0..num_buckets).rev() {
            // SAFETY: loop index is in-bounds.
            let used = unsafe { *bucket_used.get_unchecked(bucket_idx) };
            if used {
                // SAFETY: loop index is in-bounds.
                let bucket = unsafe { *buckets.get_unchecked(bucket_idx) };
                if has_running {
                    add_extproj_in_place(&mut running_ext, &bucket);
                } else {
                    running_ext = bucket;
                    has_running = true;
                }
            }

            if has_running {
                add_extproj_in_place(&mut acc_ext, &running_ext);
            }
        }
    }

    Ok(Group {
        affine: extproj_to_affine(acc_ext),
    })
}

impl Add for Group {
    type Output = Group;
    fn add(self, rhs: Group) -> Group {
        Group {
            affine: add_affine(self.affine, rhs.affine),
        }
    }
}

impl<'a> Add<&'a Group> for Group {
    type Output = Group;
    fn add(self, rhs: &'a Group) -> Group {
        Group {
            affine: add_affine(self.affine, rhs.affine),
        }
    }
}

impl Add<Group> for &Group {
    type Output = Group;
    fn add(self, rhs: Group) -> Group {
        Group {
            affine: add_affine(self.affine, rhs.affine),
        }
    }
}

impl<'b> Add<&'b Group> for &Group {
    type Output = Group;
    fn add(self, rhs: &'b Group) -> Group {
        Group {
            affine: add_affine(self.affine, rhs.affine),
        }
    }
}

impl AddAssign for Group {
    fn add_assign(&mut self, rhs: Group) {
        self.affine = add_affine(self.affine, rhs.affine);
    }
}

impl AddAssign<&Group> for Group {
    fn add_assign(&mut self, rhs: &Group) {
        self.affine = add_affine(self.affine, rhs.affine);
    }
}

impl Sub for Group {
    type Output = Group;
    fn sub(self, rhs: Group) -> Group {
        Group {
            affine: add_affine(self.affine, neg_affine(rhs.affine)),
        }
    }
}

impl SubAssign for Group {
    fn sub_assign(&mut self, rhs: Group) {
        self.affine = add_affine(self.affine, neg_affine(rhs.affine));
    }
}

impl Neg for Group {
    type Output = Group;
    fn neg(self) -> Group {
        Group {
            affine: neg_affine(self.affine),
        }
    }
}

pub fn send_group_elements(elements: &[Group], channel: &mut TcpChannel) -> Result<()> {
    let mut buf = Vec::with_capacity(elements.len() * GROUP_POINT_BYTES + 8);
    buf.extend(elements.len().to_le_bytes());
    for elem in elements {
        let encoded = encode_affine(elem.affine);
        buf.extend_from_slice(&encoded);
    }
    channel.send(&buf)?;
    Ok(())
}

pub fn receive_group_elements(channel: &mut TcpChannel) -> Result<Vec<Group>> {
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
            count * GROUP_POINT_BYTES + 8,
            buf.len()
        ));
    }

    let mut elements = Vec::with_capacity(count);
    for i in 0..count {
        let start = 8 + i * GROUP_POINT_BYTES;
        let end = start + GROUP_POINT_BYTES;
        let mut affine = PointAffine::default();
        let status = unsafe { decode(buf[start..end].as_ptr(), &mut affine) };
        if status != ECCRYPTO_SUCCESS {
            return Err(anyhow!(
                "Failed to decode FourQ point at index {} with status {}",
                i,
                status
            ));
        }
        elements.push(Group { affine });
    }
    Ok(elements)
}

fn zero_group() -> Group {
    Group {
        affine: neutral_affine(),
    }
}

fn choose_pippenger_window_size(num_points: usize) -> usize {
    match num_points {
        0..=8 => 3,
        9..=32 => 4,
        33..=128 => 5,
        129..=512 => 6,
        513..=2_048 => 7,
        2_049..=8_192 => 8,
        8_193..=32_768 => 10,
        32_769..=131_072 => 12,
        131_073..=1_048_576 => 15,
        _ => 16,
    }
}

fn extract_window_bits_words(
    words: &[u64; 4],
    bit_offset: usize,
    width: usize,
    mask: u64,
) -> usize {
    let word_index = bit_offset / 64;
    if word_index >= words.len() {
        return 0;
    }

    let bit_in_word = bit_offset % 64;
    let mut digit = words[word_index] >> bit_in_word;

    if bit_in_word + width > 64 && word_index + 1 < words.len() {
        digit |= words[word_index + 1] << (64 - bit_in_word);
    }

    (digit & mask) as usize
}

fn fe_to_le_bytes_array(scalar: &FE) -> [u8; GROUP_POINT_BYTES] {
    scalar.to_bytes_le()
}

fn fe_to_fourq_words(scalar: &FE) -> [u64; 4] {
    let bytes = fe_to_le_bytes_array(scalar);
    let mut words = [0u64; 4];
    for (i, word) in words.iter_mut().enumerate() {
        let start = i * 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[start..start + 8]);
        *word = u64::from_le_bytes(limb);
    }
    words
}

fn scalar_mul_affine(point: PointAffine, scalar: &FE) -> PointAffine {
    let mut p = point;
    let mut q = PointAffine::default();
    let mut k = fe_to_fourq_words(scalar);
    let ok = unsafe { ecc_mul(&mut p, k.as_mut_ptr(), &mut q, false) };
    assert!(ok, "Failed FourQ scalar multiplication");
    q
}

fn neutral_affine() -> PointAffine {
    let mut k = [0u64; 4];
    let mut q = PointAffine::default();
    let ok = unsafe { ecc_mul_fixed(k.as_mut_ptr(), &mut q) };
    assert!(ok, "Failed to compute FourQ neutral point");
    q
}

fn neutral_extproj() -> PointExtProj {
    affine_to_extproj(neutral_affine())
}

fn point_to_affine(point: &CurvePoint) -> Result<PointAffine> {
    let mut bytes = [0u8; GROUP_POINT_BYTES];
    point.encode(&mut bytes);

    let mut affine = PointAffine::default();
    let status = unsafe { decode(bytes.as_ptr(), &mut affine) };
    if status != ECCRYPTO_SUCCESS {
        return Err(anyhow!(
            "Failed to decode FourQ point with status {}",
            status
        ));
    }
    Ok(affine)
}

fn encode_affine(mut affine: PointAffine) -> [u8; GROUP_POINT_BYTES] {
    let mut bytes = [0u8; GROUP_POINT_BYTES];
    unsafe {
        encode(&mut affine, bytes.as_mut_ptr());
    }
    bytes
}

fn affine_to_point(affine: PointAffine) -> CurvePoint {
    Point::decode(&encode_affine(affine))
}

fn affine_to_extproj(affine: PointAffine) -> PointExtProj {
    let mut affine_mut = affine;
    let mut ext = PointExtProj::default();
    unsafe {
        point_setup(&mut affine_mut, &mut ext);
    }
    ext
}

fn extproj_to_affine(ext: PointExtProj) -> PointAffine {
    let mut ext_mut = ext;
    let mut affine = PointAffine::default();
    unsafe {
        eccnorm(&mut ext_mut, &mut affine);
    }
    affine
}

fn add_extproj_in_place(acc: &mut PointExtProj, rhs: &PointExtProj) {
    let mut rhs_mut = *rhs;
    let mut rhs_pre = PointExtProjPrecomp::default();
    unsafe {
        R1_to_R2(&mut rhs_mut, &mut rhs_pre);
        eccadd(&mut rhs_pre, acc);
    }
}

fn double_extproj_in_place(point: &mut PointExtProj) {
    unsafe {
        eccdouble(point);
    }
}

fn add_affine(lhs: PointAffine, rhs: PointAffine) -> PointAffine {
    let mut lhs_aff = lhs;
    let mut rhs_aff = rhs;

    let mut lhs_ext = PointExtProj::default();
    let mut rhs_ext = PointExtProj::default();
    unsafe {
        point_setup(&mut lhs_aff, &mut lhs_ext);
        point_setup(&mut rhs_aff, &mut rhs_ext);
    }

    let mut rhs_pre = PointExtProjPrecomp::default();
    unsafe {
        R1_to_R2(&mut rhs_ext, &mut rhs_pre);
        eccadd(&mut rhs_pre, &mut lhs_ext);
    }

    let mut out_aff = PointAffine::default();
    unsafe {
        eccnorm(&mut lhs_ext, &mut out_aff);
    }
    out_aff
}

fn neg_affine(mut point: PointAffine) -> PointAffine {
    unsafe {
        fp2neg1271(&mut point.x);
    }
    point
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bedoza::defines::random_fe_vec;

    #[test]
    fn pippenger_matches_naive_msm() -> Result<()> {
        let n = 24;
        let point_scalars = random_fe_vec(n)?;
        let msm_scalars = random_fe_vec(n)?;

        let points: Vec<Group> = point_scalars
            .iter()
            .map(|s| Group::base_point().scalar_mul(s))
            .collect();

        let got = msm_pippenger(&points, &msm_scalars)?;

        let mut expected = zero_group();
        for (point, scalar) in points.iter().zip(msm_scalars.iter()) {
            expected += point.scalar_mul(scalar);
        }

        assert!(got == expected);
        Ok(())
    }
}
