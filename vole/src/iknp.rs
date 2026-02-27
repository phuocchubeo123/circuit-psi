use crate::ot::OTCO;
use crate::comm_channel::CommunicationChannel;
use psi_aes::prg::PRG;
use std::convert::TryInto;

const BLOCK_SIZE: usize = 1024 * 2;
const NUM_BITS: usize = 256;

pub struct IKNP {
    pub(crate) base_ot: OTCO,
    delta: Option<[u8; 32]>,
    setup: bool,
    pub s: [bool; NUM_BITS],
    local_r: [bool; 2*NUM_BITS],
    local_out: Vec<[u8; 32]>,
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
            local_r: [false; 2*NUM_BITS],
            local_out: vec![[0u8; 32]; BLOCK_SIZE],
            g0: None,
            g1: None,
            malicious,
            k0: vec![[0u8; 16]; NUM_BITS],
            k1: vec![[0u8; 16]; NUM_BITS],
        }
    }

    pub fn setup_send<IO: CommunicationChannel>(&mut self, io: &mut IO, in_s: Option<&[bool]>, in_k0: Option<&[[u8; 16]]>, comm: &mut u64) {
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
            self.k0.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, (i + (self.s[i] as usize) * NUM_BITS) as u64);
                    prg.reseed(key, 0u64);
                    prg
                })
                .collect(),
        );

        self.delta = Some(bool_to_block(&self.s));
    }

    pub fn setup_recv<IO: CommunicationChannel>(&mut self, io: &mut IO, in_k0: Option<&[[u8; 16]]>, in_k1: Option<&[[u8; 16]]>, comm: &mut u64) {
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
            self.k0.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, i as u64);
                    prg.reseed(key, 0u64);
                    prg
                })
                .collect(),
        );
        self.g1 = Some(
            self.k1.iter()
                .enumerate()
                .map(|(i, key)| {
                    let mut prg = PRG::new(None, (i + NUM_BITS) as u64);
                    prg.reseed(key, 0u64);
                    prg
                })
                .collect(),
        );
    }

    pub fn send_pre<IO: CommunicationChannel>(&mut self, io: &mut IO, out: &mut [[u8; 32]], length: usize, comm: &mut u64) {
        if !self.setup {
            self.setup_send(io, None, None, comm);
        }

        let mut idx = 0;
        while idx + BLOCK_SIZE <= length {
            self.send_pre_block(io, &mut out[idx..idx+BLOCK_SIZE], BLOCK_SIZE, comm);
            idx += BLOCK_SIZE;
        }

        let remaining = length - idx;
        if remaining > 0 {
            let mut temp_out = [[0u8; 32]; BLOCK_SIZE];
            self.send_pre_block(io, &mut temp_out, remaining, comm);
            out[idx..].copy_from_slice(&temp_out[..remaining]);
        }

        if self.malicious {
            let mut temp_out = vec![[0u8; 32]; BLOCK_SIZE];
            self.send_pre_block(io, &mut temp_out, 2 * NUM_BITS, comm);
            self.local_out.copy_from_slice(&temp_out);
        }
    }

    fn send_pre_block<IO: CommunicationChannel>(&mut self, io: &mut IO, out: &mut [[u8; 32]], length: usize, comm: &mut u64) {
        let local_block_size = (length + NUM_BITS - 1) / NUM_BITS * NUM_BITS;

        let mut t = vec![[0u8; 32]; BLOCK_SIZE];
        let mut res = vec![[0u8; 32]; BLOCK_SIZE];
        let mut tmp = io.receive_block::<32>().expect("Failed to receive tmp to xor later");

        if let Some(prgs) = &mut self.g0 {
            for (i, prg) in prgs.iter_mut().enumerate() {
                let start = i * BLOCK_SIZE / NUM_BITS;
                let end = start + local_block_size / NUM_BITS;

                prg.random_32byte_block(&mut t[start..end]);

                if self.s[i] {
                    xor_blocks_arr(&mut res[start..end], &t[start..end], &tmp[start..end]);
                } else {
                    res[start..end].copy_from_slice(&t[start..end]);
                }
            }
        }

        transpose(out, &res, NUM_BITS, BLOCK_SIZE);
    }

    pub fn recv_pre<IO: CommunicationChannel>(&mut self, io: &mut IO, out: &mut [[u8; 32]], r: &[bool], length: usize, comm: &mut u64) {
        if !self.setup {
            self.setup_recv(io, None, None, comm);
        }

        let mut block_r = vec![[0u8; 32]; (length + NUM_BITS - 1) / NUM_BITS];

        for (i, chunk) in r.chunks(NUM_BITS).enumerate() {
            block_r[i] = bool_to_block(chunk);
        }

        let mut idx = 0;

        while idx + BLOCK_SIZE <= length {
            self.recv_pre_block(io, &mut out[idx..idx+BLOCK_SIZE], &block_r[idx / NUM_BITS..(idx + BLOCK_SIZE) / NUM_BITS], BLOCK_SIZE, comm);
            idx += BLOCK_SIZE;
        }

        let remaining = length - idx;
        if remaining > 0 {
            let mut temp_out = vec![[0u8; 32]; BLOCK_SIZE];
            self.recv_pre_block(io, &mut temp_out, &block_r[idx / NUM_BITS..], remaining, comm);
            out[idx..].copy_from_slice(&temp_out[..remaining]);
        }

        if self.malicious {
            let mut prg = PRG::new(None, 0);
            let mut local_r = [false; 2*NUM_BITS];
            prg.random_bool_array(&mut local_r);
            let mut local_r_block = vec![[0u8; 32]; 2];
            for (i, chunk) in local_r.chunks(NUM_BITS).enumerate() {
                local_r_block[i] = bool_to_block(chunk);
            }
            self.local_r.copy_from_slice(&local_r);
            let mut temp_out = vec![[0u8; 32]; BLOCK_SIZE];
            self.recv_pre_block(io, &mut temp_out, &local_r_block, 2 * NUM_BITS, comm);
            self.local_out.copy_from_slice(&temp_out);
        }
    }

    fn recv_pre_block<IO: CommunicationChannel>(&mut self, io: &mut IO, out: &mut [[u8; 32]], r: &[[u8; 32]], length: usize, comm: &mut u64) {
        let mut t = vec![[0u8; 32]; BLOCK_SIZE];
        let mut tmp = vec![[0u8; 32]; BLOCK_SIZE];
        let mut res = vec![[0u8; 32]; BLOCK_SIZE];
        let local_block_size = (length + NUM_BITS - 1) / NUM_BITS * NUM_BITS;

        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.g0, &mut self.g1) {
            for (i, (prg0, prg1)) in prgs_g0.iter_mut().zip(prgs_g1.iter_mut()).enumerate() {
                let start = i * BLOCK_SIZE / NUM_BITS;
                let end = start + local_block_size / NUM_BITS;

                prg0.random_32byte_block(&mut t[start..end]);
                prg1.random_32byte_block(&mut tmp[start..end]);

                xor_blocks_arr(&mut res[start..end], &t[start..end], &tmp[start..end]);
                xor_blocks_arr(&mut tmp[start..end], &res[start..end], r);
            }
        }

        *comm += io.send_block::<32>(&tmp).expect("Sending tmp failed");

        transpose(out, &t, NUM_BITS, BLOCK_SIZE);
    }

    pub fn send_cot<IO: CommunicationChannel>(&mut self, io: &mut IO, data: &mut [[u8; 32]], length: usize, comm: &mut u64) {
        self.send_pre(io, data, length, comm);

        if self.malicious {
            if !self.send_check(io, data, length, comm) {
                // panic!("OT Extension check failed");
                panic!("OT Extension check failed");
            } else {
                // println!("OT Extension IKNP successful!");
            }
        }
    }

    pub fn recv_cot<IO: CommunicationChannel>(&mut self, io: &mut IO, data: &mut [[u8; 32]], r: &[bool], length: usize, comm: &mut u64) {
        self.recv_pre(io, data, r, length, comm);

        if self.malicious {
            self.recv_check(io, data, r, length, comm);
        }
    }

    pub fn send_check<IO: CommunicationChannel>(&mut self, io: &mut IO, out: &[[u8; 32]], length: usize, comm: &mut u64) -> bool {
        let mut seed2 = [0u8; 16];
        let mut x = [0u8; 32];
        let mut t = [[0u8; 32]; 2];
        let mut q = [[0u8; 32]; 2];
        let mut tmp = [[0u8; 32]; 2];
        let mut chi = vec![[0u8; 32]; BLOCK_SIZE];
        q[0] = [0u8; 32];
        q[1] = [0u8; 32];

        seed2 = io.receive_block::<16>().expect("Failed to receive seed")[0];
        io.flush();

        // println!("Seed received: {:?}", seed2);

        let mut chi_prg = PRG::new(Some(&seed2), 0);

        for i in 0..length / BLOCK_SIZE {
            chi_prg.random_32byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            xor_blocks(&mut q, &tmp);
        }

        let remain = length % BLOCK_SIZE;
        if remain != 0 {
            chi_prg.random_32byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi[..remain], &out[length - remain..]);
            xor_blocks(&mut q, &tmp);
        }

        // Handle local_out
        chi_prg.random_32byte_block(&mut chi);
        vector_inn_prdt_sum_no_red(&mut tmp, &chi, &self.local_out);
        xor_blocks(&mut q, &tmp);

        x = io.receive_block::<32>().expect("Failed to receive x")[0];
        // Receive t
        let received_data = io.receive_block::<32>().expect("Failed to receive t");
        assert_eq!(received_data.len(), 2, "Expected exactly 2 elements in received data");
        t = [received_data[0], received_data[1]]; // Convert Vec to array

        let delta = self.delta.expect("Delta must be set during setup");
        mul256(&x, &delta, &mut tmp);
        xor_blocks(&mut q, &tmp);

        cmp_blocks(&q, &t)
    }

    pub fn recv_check<IO: CommunicationChannel>(&mut self, io: &mut IO, out: &[[u8; 32]], r: &[bool], length: usize, comm: &mut u64) {
        let select = [[0u8; 32], [255u8; 32]]; // zero_block and all_one_block
        let mut seed2 = [0u8; 16];
        let mut x = [0u8; 32];
        let mut t = [[0u8; 32]; 2];
        let mut tmp = [[0u8; 32]; 2];
        let mut chi = vec![[0u8; 32]; BLOCK_SIZE];
        t[0] = [0u8; 32];
        t[1] = [0u8; 32];

        let mut prg = PRG::new(None, 0);
        let mut tmp_seed2 = [[0u8; 16]];
        prg.random_16byte_block(&mut tmp_seed2);
        seed2 = tmp_seed2[0];

        // println!("Seed sent: {:?}", seed2);

        *comm += io.send_block::<16>(&[seed2]).expect("Failed to send seed");
        io.flush();

        let mut chi_prg = PRG::new(Some(&seed2), 0);

        for i in 0..length / BLOCK_SIZE {
            chi_prg.random_32byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi, &out[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            xor_blocks(&mut t, &tmp);

            for j in 0..BLOCK_SIZE {
                for byt in 0..32 {
                    x[byt] = x[byt] ^ (chi[j][byt] & select[r[i * BLOCK_SIZE + j] as usize][byt]);
                }
            }
        }

        let remain = length % BLOCK_SIZE;
        if remain != 0 {
            chi_prg.random_32byte_block(&mut chi);
            vector_inn_prdt_sum_no_red(&mut tmp, &chi[..remain], &out[length - remain..]);
            xor_blocks(&mut t, &tmp);

            for j in 0..remain {
                for byt in 0..32 {
                    x[byt] = x[byt] ^ (chi[j][byt] & select[r[length - remain + j] as usize][byt]);
                }
            }
        }

        // Handle local_out
        chi_prg.random_32byte_block(&mut chi);
        vector_inn_prdt_sum_no_red(&mut tmp, &chi, &self.local_out);
        xor_blocks(&mut t, &tmp);

        for j in 0..(NUM_BITS * 2) {
            for byt in 0..32 {
                x[byt] = x[byt] ^ (chi[j][byt] & select[self.local_r[j] as usize][byt]);
            }
        }

        *comm += io.send_block::<32>(&[x]).expect("Failed to send x");
        *comm += io.send_block::<32>(&t).expect("Failed to send t");
    }
}

fn mul256(a: &[u8; 32], b: &[u8; 32], res: &mut [[u8; 32]; 2]) {
    let mask: u128 = 0xFFFFFFFFFFFFFFFF;

    let mut r1 = [0u8; 32];
    let mut r2 = [0u8; 32];

    // Split inputs into 4 limbs (64 bits each)
    let a0 = u64::from_le_bytes(a[0..8].try_into().unwrap());
    let a1 = u64::from_le_bytes(a[8..16].try_into().unwrap());
    let a2 = u64::from_le_bytes(a[16..24].try_into().unwrap());
    let a3 = u64::from_le_bytes(a[24..32].try_into().unwrap());

    let b0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let b1 = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let b2 = u64::from_le_bytes(b[16..24].try_into().unwrap());
    let b3 = u64::from_le_bytes(b[24..32].try_into().unwrap());

    // Perform carry-less multiplications
    let z00 = clmul64(a0, b0); // a0 * b0
    let z01 = clmul64(a0, b1) ^ clmul64(a1, b0); // (a0 * b1) ^ (a1 * b0)
    let z02 = clmul64(a0, b2) ^ clmul64(a1, b1) ^ clmul64(a2, b0); // Mixed terms
    let z03 = clmul64(a0, b3) ^ clmul64(a1, b2) ^ clmul64(a2, b1) ^ clmul64(a3, b0);
    let z04 = clmul64(a1, b3) ^ clmul64(a2, b2) ^ clmul64(a3, b1);
    let z05 = clmul64(a2, b3) ^ clmul64(a3, b2);
    let z06 = clmul64(a3, b3);
    // println!("z06: {:?}", z06.to_le_bytes());
    // println!("z06: {:?}", (z06 >> 64).to_le_bytes());

    // Assemble the result into two 256-bit limbs
    r1[0..8].copy_from_slice(&((z00 & mask) as u64).to_le_bytes());
    r1[8..16].copy_from_slice(&((z00 >> 64 ^ (z01 & mask)) as u64).to_le_bytes());
    r1[16..24].copy_from_slice(&((z01 >> 64 ^ (z02 & mask)) as u64).to_le_bytes());
    r1[24..32].copy_from_slice(&((z02 >> 64 ^ (z03 & mask)) as u64).to_le_bytes());

    r2[0..8].copy_from_slice(&((z03 >> 64 ^ (z04 & mask)) as u64).to_le_bytes());
    r2[8..16].copy_from_slice(&((z04 >> 64 ^ (z05 & mask)) as u64).to_le_bytes());
    r2[16..24].copy_from_slice(&((z05 >> 64 ^ (z06 & mask)) as u64).to_le_bytes());
    r2[24..32].copy_from_slice(&((z06 >> 64) as u64).to_le_bytes());

    // println!("last 8 bits: {:?}, {:?}, {:?}", &a[24..32], &b[24..32], &r2[24..32]);
    // println!("a: {:?}", a);
    // println!("b: {:?}", b);

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

fn vector_inn_prdt_sum_no_red(res: &mut [[u8; 32]; 2], a: &[[u8; 32]], b: &[[u8; 32]]) {
    // let mut r1 = [0u8; 16]; // Accumulator for first half
    // let mut r2 = [0u8; 16]; // Accumulator for second half
    let mut r1 = [0u8; 32];
    let mut r2 = [0u8; 32];
    let mut r11 = [[0u8; 32]; 2];

    for i in 0..a.len() {
        mul256(&a[i], &b[i], &mut r11); // Perform 128-bit multiplication
        for byt in 0..32 {
            r1[byt] = r1[byt] ^ r11[0][byt];
            r2[byt] = r2[byt] ^ r11[1][byt];
        }
    }

    res[0] = r1;
    res[1] = r2;
}

// Helper functions
pub fn bool_to_block(bits: &[bool]) -> [u8; 32] {
    let mut block = [0u8; 32];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            block[i / 8] |= 1 << (i % 8);
        }
    }
    block
}

fn cmp_blocks(a: &[[u8; 32]], b: &[[u8; 32]]) -> bool {
    a == b
}

fn xor_blocks(a: &mut [[u8; 32]], b: &[[u8; 32]]) {
    for i in 0..a.len() {
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
        a[i][16] ^= b[i][16];
        a[i][17] ^= b[i][17];
        a[i][18] ^= b[i][18];
        a[i][19] ^= b[i][19];
        a[i][20] ^= b[i][20];
        a[i][21] ^= b[i][21];
        a[i][22] ^= b[i][22];
        a[i][23] ^= b[i][23];
        a[i][24] ^= b[i][24];
        a[i][25] ^= b[i][25];
        a[i][26] ^= b[i][26];
        a[i][27] ^= b[i][27];
        a[i][28] ^= b[i][28];
        a[i][29] ^= b[i][29];
        a[i][30] ^= b[i][30];
        a[i][31] ^= b[i][31];
    }
}

fn and_blocks(a: &mut [[u8; 32]], b: &[[u8; 32]]) {
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
        a[i][16] &= b[i][16];
        a[i][17] &= b[i][17];
        a[i][18] &= b[i][18];
        a[i][19] &= b[i][19];
        a[i][20] &= b[i][20];
        a[i][21] &= b[i][21];
        a[i][22] &= b[i][22];
        a[i][23] &= b[i][23];
        a[i][24] &= b[i][24];
        a[i][25] &= b[i][25];
        a[i][26] &= b[i][26];
        a[i][27] &= b[i][27];
        a[i][28] &= b[i][28];
        a[i][29] &= b[i][29];
        a[i][30] &= b[i][30];
        a[i][31] &= b[i][31];
    }
}

fn xor_blocks_arr(res: &mut [[u8; 32]], x: &[[u8; 32]], y: &[[u8; 32]]) {
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
        r[16] = a[16] ^ b[16];
        r[17] = a[17] ^ b[17];
        r[18] = a[18] ^ b[18];
        r[19] = a[19] ^ b[19];
        r[20] = a[20] ^ b[20];
        r[21] = a[21] ^ b[21];
        r[22] = a[22] ^ b[22];
        r[23] = a[23] ^ b[23];
        r[24] = a[24] ^ b[24];
        r[25] = a[25] ^ b[25];
        r[26] = a[26] ^ b[26];
        r[27] = a[27] ^ b[27];
        r[28] = a[28] ^ b[28];
        r[29] = a[29] ^ b[29];
        r[30] = a[30] ^ b[30];
        r[31] = a[31] ^ b[31];
    }
}


fn transpose(out: &mut [[u8; 32]], t: &[[u8; 32]], num_bits: usize, block_size: usize) {
    // println!("Size of out is: {} x {}", out.len(), out[0].len() * 8);
    // println!("Size of t is: {} x {}", t.len(), t[0].len() * 8);
    for row in 0..num_bits {
        for col in 0..block_size {
            let idx = row * block_size + col;
            let bit = (t[idx / num_bits][(idx / 8) % 32] >> (idx % 8)) & 1;
            let new_idx = col * num_bits + row;
            out[new_idx / num_bits][(new_idx / 8) % 32] |= bit << (new_idx % 8);
        }
    }
}