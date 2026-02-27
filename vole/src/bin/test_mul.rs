use std::convert::TryInto;

fn mul128(a: &[u8; 16], b: &[u8; 16], res: &mut [[u8; 16]; 2]) {
    let mut r1 = [0u8; 16];
    let mut r2 = [0u8; 16];

    // Split inputs into low and high 64-bit parts
    let a_low = u64::from_le_bytes(a[0..8].try_into().unwrap());
    let a_high = u64::from_le_bytes(a[8..16].try_into().unwrap());
    let b_low = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let b_high = u64::from_le_bytes(b[8..16].try_into().unwrap());

    // Perform carry-less multiplications
    let tmp3 = clmul64(a_low, b_low); // Low * Low
    let tmp4 = clmul64(a_high, b_low); // High * Low
    let tmp5 = clmul64(a_low, b_high); // Low * High
    let tmp6 = clmul64(a_high, b_high); // High * High

    // Combine results
    let mid = tmp4 ^ tmp5; // XOR intermediate results
    let mid_low = mid & 0xFFFFFFFFFFFFFFFF; // Lower 64 bits shifted to high part of r1
    let mid_high = mid >> 64; // Higher 64 bits shifted to low part of r2

    r1[0..8].copy_from_slice(&((tmp3 & 0xFFFFFFFFFFFFFFFF) as u64).to_le_bytes()); // Low part of tmp3 to r1
    r1[8..16].copy_from_slice(&((tmp3 >> 64 ^ mid_low) as u64).to_le_bytes()); // High part of tmp3 ^ mid_low

    r2[0..8].copy_from_slice(&(((tmp6 ^ mid_high) & 0xFFFFFFFFFFFFFFFF) as u64).to_le_bytes()); // Low part of tmp6 ^ mid_high
    r2[8..16].copy_from_slice(&((tmp6 >> 64) as u64).to_le_bytes()); // High part of tmp6

    res[0] = r1;
    res[1] = r2;
}

// Helper function to perform 64-bit carry-less multiplication
fn clmul64(a: u64, b: u64) -> u128 {
    let mut result = 0u128;
    for i in 0..64 {
        if (b & (1 << i)) != 0 {
            result ^= (a as u128) << i;
        }
    }
    result
}

fn vector_inn_prdt_sum_no_red(res: &mut [[u8; 16]; 2], a: &[[u8; 16]], b: &[[u8; 16]]) {
    // let mut r1 = [0u8; 16]; // Accumulator for first half
    // let mut r2 = [0u8; 16]; // Accumulator for second half
    let mut r1 = [0u8; 16];
    let mut r2 = [0u8; 16];
    let mut r11 = [[0u8; 16]; 2];

    for i in 0..a.len() {
        mul128(&a[i], &b[i], &mut r11); // Perform 128-bit multiplication
        for byt in 0..16 {
            r1[byt] = r1[byt] ^ r11[0][byt];
            r2[byt] = r2[byt] ^ r11[1][byt];
        }
    }

    res[0] = r1;
    res[1] = r2;
}

fn main() {
    let mut a = vec![3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
    a.extend(vec![0u8; 8]);

    let mut b = vec![7u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
    b.extend(vec![0u8; 8]);

    let mut c = [[0u8; 16]; 2];
    mul128(&a.try_into().expect("1"), &b.try_into().expect("1"), &mut c);

    println!("{:?}", c);
}