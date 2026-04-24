use crate::comm_util::*;
use crate::ot::OTCO;
use crate::tcp_channel::SwankyChannel;
use psi_aes::prg::PRG;
use std::convert::TryInto;

const BLOCK_SIZE: usize = 1024 * 2;
const NUM_BITS: usize = 128;
const NUM_BYTES: usize = NUM_BITS / 8;

// IKNP OT Extension
// Prepares 128 base OTs
// Then extend them to arbitrary number of OTs with message length 128 bits
// Later these messages can be hashed into ROTs and can be further processed to become chosen input OTs
pub struct IKNP {
    pub(crate) base_ot: OTCO,
    delta: Option<[u8; NUM_BYTES]>,
    setup: bool,
    pub s: [bool; NUM_BITS],
    local_r: [bool; 2 * NUM_BITS],
    local_out: Vec<[u8; NUM_BYTES]>,
    g0: Option<Vec<PRG>>,
    g1: Option<Vec<PRG>>,
    malicious: bool,
    k0: Vec<[u8; 16]>,
    k1: Vec<[u8; 16]>,
}

impl IKNP {
    pub fn new(malicious: bool) -> Self {
        Self {
            base_ot: OTCO::new(),
            delta: None,
            setup: false,
            s: [false; NUM_BITS],
            local_r: [false; 2 * NUM_BITS],
            local_out: vec![[0u8; NUM_BYTES]; BLOCK_SIZE],
            g0: None,
            g1: None,
            malicious,
            k0: vec![[0u8; 16]; NUM_BITS],
            k1: vec![[0u8; 16]; NUM_BITS],
        }
    }

    pub fn setup_send(
        &mut self,
        io: &mut SwankyChannel,
        in_s: Option<&[bool]>,
        in_k0: Option<&[[u8; 16]]>,
        comm: &mut u64,
    ) {
        self.setup = true;

        if let Some(in_s) = in_s {
            self.s.copy_from_slice(in_s);
        } else {
            let mut prg = PRG::new(None, 0);
            prg.random_bool_array(&mut self.s);
        }

        if let Some(in_k0) = in_k0 {
            self.k0.copy_from_slice(in_k0);
        } else {
            self.k0.clear();
            self.base_ot.recv(io, &self.s, &mut self.k0, comm);
        }

        self.g0 = Some(
            self.k0
                .iter()
                .enumerate()
                .map(|(i, key)| {
                    let prg = PRG::new(Some(key), (i + (self.s[i] as usize) * NUM_BITS) as u64);
                    prg
                })
                .collect(),
        );

        self.delta = Some(bool_to_block(&self.s));
    }

    pub fn setup_recv(
        &mut self,
        io: &mut SwankyChannel,
        in_k0: Option<&[[u8; 16]]>,
        in_k1: Option<&[[u8; 16]]>,
        comm: &mut u64,
    ) {
        self.setup = true;

        if let (Some(in_k0), Some(in_k1)) = (in_k0, in_k1) {
            self.k0.copy_from_slice(in_k0);
            self.k1.copy_from_slice(in_k1);
        } else {
            let mut prg = PRG::new(None, 0);
            prg.random_16byte_block(&mut self.k0);
            prg.random_16byte_block(&mut self.k1);
            self.base_ot.send(io, &self.k0, &self.k1, comm);
        }

        self.g0 = Some(
            self.k0
                .iter()
                .enumerate()
                .map(|(i, key)| {
                    let prg = PRG::new(Some(key), i as u64);
                    prg
                })
                .collect(),
        );
        self.g1 = Some(
            self.k1
                .iter()
                .enumerate()
                .map(|(i, key)| {
                    let prg = PRG::new(Some(key), (i + NUM_BITS) as u64);
                    prg
                })
                .collect(),
        );
    }

    pub fn send_pre(
        &mut self,
        io: &mut SwankyChannel,
        out: &mut [[u8; NUM_BYTES]],
        length: usize,
        comm: &mut u64,
    ) {
        if !self.setup {
            self.setup_send(io, None, None, comm);
        }

        let mut idx = 0;
        while idx + BLOCK_SIZE <= length {
            self.send_pre_block(io, &mut out[idx..idx + BLOCK_SIZE], BLOCK_SIZE, comm);
            idx += BLOCK_SIZE;
        }

        let remaining = length - idx;
        if remaining > 0 {
            let mut temp_out = [[0u8; NUM_BYTES]; BLOCK_SIZE];
            self.send_pre_block(io, &mut temp_out, remaining, comm);
            out[idx..].copy_from_slice(&temp_out[..remaining]);
        }

        if self.malicious {
            let mut temp_out = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
            self.send_pre_block(io, &mut temp_out, 2 * NUM_BITS, comm);
            self.local_out.copy_from_slice(&temp_out);
        }
    }

    fn send_pre_block(
        &mut self,
        io: &mut SwankyChannel,
        out: &mut [[u8; NUM_BYTES]],
        length: usize,
        comm: &mut u64,
    ) {
        let local_block_size = (length + NUM_BITS - 1) / NUM_BITS * NUM_BITS;

        let mut t = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
        let mut res = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
        let mut tmp = receive_block::<NUM_BYTES>(io).expect("Failed to receive tmp to xor later");

        if let Some(prgs) = &mut self.g0 {
            for (i, prg) in prgs.iter_mut().enumerate() {
                let start = i * BLOCK_SIZE / NUM_BITS;
                let end = start + local_block_size / NUM_BITS;

                prg.random_16byte_block(&mut t[start..end]);

                if self.s[i] {
                    xor_blocks_arr(&mut res[start..end], &t[start..end], &tmp[start..end]);
                } else {
                    res[start..end].copy_from_slice(&t[start..end]);
                }
            }
        }

        transpose(out, &res);

        *comm += 0; // Only receive data in this function, does not send anything
    }

    pub fn recv_pre(
        &mut self,
        io: &mut SwankyChannel,
        out: &mut [[u8; NUM_BYTES]],
        r: &[bool],
        length: usize,
        comm: &mut u64,
    ) {
        if !self.setup {
            self.setup_recv(io, None, None, comm);
        }

        let mut block_r = vec![[0u8; NUM_BYTES]; (length + NUM_BITS - 1) / NUM_BITS];

        for (i, chunk) in r.chunks(NUM_BITS).enumerate() {
            block_r[i] = bool_to_block(chunk);
        }

        let mut idx = 0;

        while idx + BLOCK_SIZE <= length {
            self.recv_pre_block(
                io,
                &mut out[idx..idx + BLOCK_SIZE],
                &block_r[idx / NUM_BITS..(idx + BLOCK_SIZE) / NUM_BITS],
                BLOCK_SIZE,
                comm,
            );
            idx += BLOCK_SIZE;
        }

        let remaining = length - idx;
        if remaining > 0 {
            let mut temp_out = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
            self.recv_pre_block(
                io,
                &mut temp_out,
                &block_r[idx / NUM_BITS..],
                remaining,
                comm,
            );
            out[idx..].copy_from_slice(&temp_out[..remaining]);
        }

        if self.malicious {
            let mut prg = PRG::new(None, 0);
            let mut local_r = [false; 2 * NUM_BITS];
            prg.random_bool_array(&mut local_r);
            let mut local_r_block = vec![[0u8; NUM_BYTES]; 2];
            for (i, chunk) in local_r.chunks(NUM_BITS).enumerate() {
                local_r_block[i] = bool_to_block(chunk);
            }
            self.local_r.copy_from_slice(&local_r);
            let mut temp_out = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
            self.recv_pre_block(io, &mut temp_out, &local_r_block, 2 * NUM_BITS, comm);
            self.local_out.copy_from_slice(&temp_out);
        }
    }

    fn recv_pre_block(
        &mut self,
        io: &mut SwankyChannel,
        out: &mut [[u8; NUM_BYTES]],
        r: &[[u8; NUM_BYTES]],
        length: usize,
        comm: &mut u64,
    ) {
        let mut t = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
        let mut tmp = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
        let mut res = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
        let local_block_size = (length + NUM_BITS - 1) / NUM_BITS * NUM_BITS;

        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.g0, &mut self.g1) {
            for (i, (prg0, prg1)) in prgs_g0.iter_mut().zip(prgs_g1.iter_mut()).enumerate() {
                let start = i * BLOCK_SIZE / NUM_BITS;
                let end = start + local_block_size / NUM_BITS;

                prg0.random_16byte_block(&mut t[start..end]);
                prg1.random_16byte_block(&mut tmp[start..end]);

                xor_blocks_arr(&mut res[start..end], &t[start..end], &tmp[start..end]);
                xor_blocks_arr(&mut tmp[start..end], &res[start..end], r);
            }
        }

        *comm += send_block::<NUM_BYTES>(io, &tmp).expect("Sending tmp failed");

        transpose(out, &t);
    }

    pub fn send_cot(
        &mut self,
        io: &mut SwankyChannel,
        data: &mut [[u8; NUM_BYTES]],
        length: usize,
        comm: &mut u64,
    ) {
        self.send_pre(io, data, length, comm);

        if self.malicious {
            if !self.send_check(io, data, length, comm) {
                panic!("OT Extension check failed");
            }
        }
    }

    pub fn recv_cot(
        &mut self,
        io: &mut SwankyChannel,
        data: &mut [[u8; NUM_BYTES]],
        r: &[bool],
        length: usize,
        comm: &mut u64,
    ) {
        self.recv_pre(io, data, r, length, comm);

        if self.malicious {
            self.recv_check(io, data, r, length, comm);
        }
    }

    pub fn send_check(
        &mut self,
        io: &mut SwankyChannel,
        out: &[[u8; NUM_BYTES]],
        length: usize,
        comm: &mut u64,
    ) -> bool {
        let mut seed2 = [0u8; 16];
        let mut x = [0u8; NUM_BYTES];
        let mut t = [[0u8; NUM_BYTES]; 2];
        let mut q = [[0u8; NUM_BYTES]; 2];
        let mut tmp = [[0u8; NUM_BYTES]; 2];
        let mut chi = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
        q[0] = [0u8; NUM_BYTES];
        q[1] = [0u8; NUM_BYTES];

        seed2 = receive_block::<16>(io).expect("Failed to receive seed")[0];
        // println!("Seed received: {:?}", seed2);

        let mut chi_prg = PRG::new(Some(&seed2), 0);

        for i in 0..length / BLOCK_SIZE {
            chi_prg.random_16byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            xor_blocks(&mut q, &tmp);
        }

        let remain = length % BLOCK_SIZE;
        if remain != 0 {
            chi_prg.random_16byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi[..remain], &out[length - remain..]);
            xor_blocks(&mut q, &tmp);
        }

        // Handle local_out
        chi_prg.random_16byte_block(&mut chi);
        vector_inn_prdt_sum_no_red(&mut tmp, &chi, &self.local_out);
        xor_blocks(&mut q, &tmp);

        x = receive_block::<NUM_BYTES>(io).expect("Failed to receive x")[0];
        // Receive t
        let received_data = receive_block::<NUM_BYTES>(io).expect("Failed to receive t");
        assert_eq!(
            received_data.len(),
            2,
            "Expected exactly 2 elements in received data"
        );
        t = [received_data[0], received_data[1]]; // Convert Vec to array

        let delta = self.delta.expect("Delta must be set during setup");
        mul128(&x, &delta, &mut tmp);
        xor_blocks(&mut q, &tmp);

        cmp_blocks(&q, &t)
    }

    pub fn recv_check(
        &mut self,
        io: &mut SwankyChannel,
        out: &[[u8; NUM_BYTES]],
        r: &[bool],
        length: usize,
        comm: &mut u64,
    ) {
        let select = [[0u8; NUM_BYTES], [255u8; NUM_BYTES]]; // zero_block and all_one_block
        let mut seed2 = [0u8; 16];
        let mut x = [0u8; NUM_BYTES];
        let mut t = [[0u8; NUM_BYTES]; 2];
        let mut tmp = [[0u8; NUM_BYTES]; 2];
        let mut chi = vec![[0u8; NUM_BYTES]; BLOCK_SIZE];
        t[0] = [0u8; NUM_BYTES];
        t[1] = [0u8; NUM_BYTES];

        let mut prg = PRG::new(None, 0); // random key PRG
        let mut tmp_seed2 = [[0u8; 16]];
        prg.random_16byte_block(&mut tmp_seed2);
        seed2 = tmp_seed2[0];

        *comm += send_block::<16>(io, &[seed2]).expect("Failed to send seed");

        let mut chi_prg = PRG::new(Some(&seed2), 0);

        for i in 0..length / BLOCK_SIZE {
            chi_prg.random_16byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            xor_blocks(&mut t, &tmp);

            for j in 0..BLOCK_SIZE {
                for byt in 0..NUM_BYTES {
                    x[byt] = x[byt] ^ (chi[j][byt] & select[r[i * BLOCK_SIZE + j] as usize][byt]);
                }
            }
        }

        let remain = length % BLOCK_SIZE;
        if remain != 0 {
            chi_prg.random_16byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi[..remain], &out[length - remain..]);
            xor_blocks(&mut t, &tmp);

            for j in 0..remain {
                for byt in 0..NUM_BYTES {
                    x[byt] = x[byt] ^ (chi[j][byt] & select[r[length - remain + j] as usize][byt]);
                }
            }
        }

        // Handle local_out
        chi_prg.random_16byte_block(&mut chi);
        vector_inn_prdt_sum_no_red(&mut tmp, &chi, &self.local_out);
        xor_blocks(&mut t, &tmp);

        for j in 0..(NUM_BITS * 2) {
            for byt in 0..16 {
                x[byt] = x[byt] ^ (chi[j][byt] & select[self.local_r[j] as usize][byt]);
            }
        }

        *comm += send_block::<NUM_BYTES>(io, &[x]).expect("Failed to send x");
        *comm += send_block::<NUM_BYTES>(io, &t).expect("Failed to send t");
    }
}

fn mul128(a: &[u8; NUM_BYTES], b: &[u8; NUM_BYTES], res: &mut [[u8; NUM_BYTES]; 2]) {
    let mask: u128 = 0xFFFFFFFFFFFFFFFF;

    let mut r1 = [0u8; NUM_BYTES];
    let mut r2 = [0u8; NUM_BYTES];

    // Split inputs into 2 limbs (64 bits each)
    let a0 = u64::from_le_bytes(a[0..8].try_into().unwrap());
    let a1 = u64::from_le_bytes(a[8..16].try_into().unwrap());

    let b0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let b1 = u64::from_le_bytes(b[8..16].try_into().unwrap());

    // Perform carry-less multiplications
    let z00 = clmul64(a0, b0); // a0 * b0
    let z01 = clmul64(a0, b1) ^ clmul64(a1, b0); // (a0 * b1) ^ (a1 * b0)
    let z02 = clmul64(a1, b1);

    // Assemble the result into two 128-bit limbs
    r1[0..8].copy_from_slice(&((z00 & mask) as u64).to_le_bytes());
    r1[8..16].copy_from_slice(&((z00 >> 64 ^ (z01 & mask)) as u64).to_le_bytes());

    r2[0..8].copy_from_slice(&((z01 >> 64 ^ (z02 & mask)) as u64).to_le_bytes());
    r2[8..16].copy_from_slice(&((z02 >> 64) as u64).to_le_bytes());

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

fn vector_inn_prdt_sum_no_red(
    res: &mut [[u8; NUM_BYTES]; 2],
    a: &[[u8; NUM_BYTES]],
    b: &[[u8; NUM_BYTES]],
) {
    // let mut r1 = [0u8; 16]; // Accumulator for first half
    // let mut r2 = [0u8; 16]; // Accumulator for second half
    let mut r1 = [0u8; NUM_BYTES];
    let mut r2 = [0u8; NUM_BYTES];
    let mut r11 = [[0u8; NUM_BYTES]; 2];

    for i in 0..a.len() {
        mul128(&a[i], &b[i], &mut r11); // Perform 128-bit multiplication
        for byt in 0..NUM_BYTES {
            r1[byt] = r1[byt] ^ r11[0][byt];
            r2[byt] = r2[byt] ^ r11[1][byt];
        }
    }

    res[0] = r1;
    res[1] = r2;
}

// Helper functions
pub fn bool_to_block(bits: &[bool]) -> [u8; NUM_BYTES] {
    let mut block = [0u8; NUM_BYTES];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            block[i / 8] |= 1 << (i % 8);
        }
    }
    block
}

fn cmp_blocks(a: &[[u8; NUM_BYTES]], b: &[[u8; NUM_BYTES]]) -> bool {
    a == b
}

fn xor_blocks(a: &mut [[u8; NUM_BYTES]], b: &[[u8; NUM_BYTES]]) {
    for i in 0..a.len() {
        // Unroll for 16 bytes
        a[i][0] ^= b[i][0];
        a[i][1] ^= b[i][1];
        a[i][2] ^= b[i][2];
        a[i][3] ^= b[i][3];
        a[i][4] ^= b[i][4];
        a[i][5] ^= b[i][5];
        a[i][6] ^= b[i][6];
        a[i][7] ^= b[i][7];
        a[i][8] ^= b[i][8];
        a[i][9] ^= b[i][9];
        a[i][10] ^= b[i][10];
        a[i][11] ^= b[i][11];
        a[i][12] ^= b[i][12];
        a[i][13] ^= b[i][13];
        a[i][14] ^= b[i][14];
        a[i][15] ^= b[i][15];
    }
}

fn and_blocks(a: &mut [[u8; NUM_BYTES]], b: &[[u8; NUM_BYTES]]) {
    for i in 0..a.len() {
        a[i][0] &= b[i][0];
        a[i][1] &= b[i][1];
        a[i][2] &= b[i][2];
        a[i][3] &= b[i][3];
        a[i][4] &= b[i][4];
        a[i][5] &= b[i][5];
        a[i][6] &= b[i][6];
        a[i][7] &= b[i][7];
        a[i][8] &= b[i][8];
        a[i][9] &= b[i][9];
        a[i][10] &= b[i][10];
        a[i][11] &= b[i][11];
        a[i][12] &= b[i][12];
        a[i][13] &= b[i][13];
        a[i][14] &= b[i][14];
        a[i][15] &= b[i][15];
    }
}

fn xor_blocks_arr(res: &mut [[u8; NUM_BYTES]], x: &[[u8; NUM_BYTES]], y: &[[u8; NUM_BYTES]]) {
    for ((r, a), b) in res.iter_mut().zip(x.iter()).zip(y.iter()) {
        r[0] = a[0] ^ b[0];
        r[1] = a[1] ^ b[1];
        r[2] = a[2] ^ b[2];
        r[3] = a[3] ^ b[3];
        r[4] = a[4] ^ b[4];
        r[5] = a[5] ^ b[5];
        r[6] = a[6] ^ b[6];
        r[7] = a[7] ^ b[7];
        r[8] = a[8] ^ b[8];
        r[9] = a[9] ^ b[9];
        r[10] = a[10] ^ b[10];
        r[11] = a[11] ^ b[11];
        r[12] = a[12] ^ b[12];
        r[13] = a[13] ^ b[13];
        r[14] = a[14] ^ b[14];
        r[15] = a[15] ^ b[15];
    }
}

// Transpose a flattened NUM_BITS x BLOCK_SIZE array into a flattened BLOCK_SIZE x NUM_BITS array
fn transpose(out: &mut [[u8; NUM_BYTES]], t: &[[u8; NUM_BYTES]]) {
    for row in 0..NUM_BITS {
        for col in 0..BLOCK_SIZE {
            let idx = row * BLOCK_SIZE + col;
            let bit = (t[idx / NUM_BITS][(idx / 8) % NUM_BYTES] >> (idx % 8)) & 1;
            out[col][row / 8] |= bit << (row % 8);
        }
    }
}
