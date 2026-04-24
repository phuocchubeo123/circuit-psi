use crate::comm_util::{receive_bits, receive_u8, send_bits, send_u8};
use crate::tcp_channel::SwankyChannel;
use psi_aes::ccrh::CCRH;

pub struct OTPre<const NUM_LIMBS: usize> {
    pre_data: Vec<[u128; NUM_LIMBS]>,
    bits: Vec<bool>,
    n: usize,
    count: usize,
    length: usize,
    _delta: Option<[u8; 16]>,
}

impl<const NUM_LIMBS: usize> OTPre<NUM_LIMBS> {
    pub fn new(length: usize, times: usize) -> Self {
        let n = length * times;
        Self {
            pre_data: vec![[0u128; NUM_LIMBS]; 2 * n],
            bits: vec![false; n],
            n,
            count: 0,
            length,
            _delta: None,
        }
    }

    pub fn send_pre(&mut self, data: &[[u8; 16]], delta: [u8; 16]) {
        self._delta = Some(delta);
        let mut pre_hash_data = vec![[0u8; 16]; 2 * self.n];
        pre_hash_data[..self.n].copy_from_slice(data);
        for i in self.n..2 * self.n {
            pre_hash_data[i] = xor_block(&data[i - self.n], &delta);
        }

        let ccrh = CCRH::new();
        let mut hashed_data = vec![vec![[0u8; 16]; 2 * self.n]; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let tag = [i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let kxori: Vec<[u8; 16]> = pre_hash_data.iter().map(|x| xor_block(x, &tag)).collect();
            ccrh.hash_blocks(&mut hashed_data[i], &kxori, 2 * self.n);
        }
        for i in 0..2 * self.n {
            for j in 0..NUM_LIMBS {
                self.pre_data[i][j] = u128::from_le_bytes(hashed_data[j][i]);
            }
        }
    }

    pub fn recv_pre(&mut self, data: &[[u8; 16]], bits: Option<&[bool]>) {
        if let Some(b) = bits {
            self.bits[..self.n].copy_from_slice(b);
        } else {
            for (i, item) in data.iter().take(self.n).enumerate() {
                self.bits[i] = item[0] & 1 != 0;
            }
        }

        let mut pre_hash_data = vec![[0u8; 16]; self.n];
        pre_hash_data[..self.n].copy_from_slice(data);

        let ccrh = CCRH::new();
        let mut hashed_data = vec![vec![[0u8; 16]; self.n]; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            let tag = [i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let kxori: Vec<[u8; 16]> = pre_hash_data.iter().map(|x| xor_block(x, &tag)).collect();
            ccrh.hash_blocks(&mut hashed_data[i], &kxori, self.n);
        }
        for i in 0..self.n {
            for j in 0..NUM_LIMBS {
                self.pre_data[i][j] = u128::from_le_bytes(hashed_data[j][i]);
            }
        }
    }

    pub fn choices_sender(&mut self, io: &mut SwankyChannel, _comm: &mut u64) {
        self.choices_sender_batch(io, self.length, _comm);
    }

    pub fn choices_recver(&mut self, io: &mut SwankyChannel, choices: &[bool], comm: &mut u64) {
        self.choices_recver_batch(io, choices, self.length, comm);
    }

    pub fn choices_sender_batch(&mut self, io: &mut SwankyChannel, length: usize, _comm: &mut u64) {
        let received_bits = receive_bits(io).expect("Failed to receive bits");
        assert_eq!(received_bits.len(), length, "invalid OT choice length");
        assert!(
            self.count + length <= self.n,
            "OT choice sender out of precomputed range"
        );
        for (i, &bit) in received_bits.iter().enumerate() {
            self.bits[self.count + i] = bit;
        }
        self.count += length;
    }

    pub fn choices_recver_batch(
        &mut self,
        io: &mut SwankyChannel,
        choices: &[bool],
        length: usize,
        comm: &mut u64,
    ) {
        assert!(
            choices.len() >= length,
            "insufficient receiver choices: need {}, got {}",
            length,
            choices.len()
        );
        assert!(
            self.count + length <= self.n,
            "OT choice receiver out of precomputed range"
        );

        let mut adjusted_bits = vec![false; length];
        for i in 0..length {
            adjusted_bits[i] = choices[i] ^ self.bits[self.count + i];
            self.bits[self.count + i] = adjusted_bits[i];
        }
        *comm += send_bits(io, &adjusted_bits).expect("Failed to send bits");
        self.count += length;
    }

    pub fn send(
        &mut self,
        io: &mut SwankyChannel,
        m0: &[[u128; NUM_LIMBS]],
        m1: &[[u128; NUM_LIMBS]],
        length: usize,
        s: usize,
        comm: &mut u64,
    ) {
        self.send_with_offset(io, m0, m1, length, s * length, comm);
    }

    pub fn send_with_offset(
        &mut self,
        io: &mut SwankyChannel,
        m0: &[[u128; NUM_LIMBS]],
        m1: &[[u128; NUM_LIMBS]],
        length: usize,
        offset: usize,
        comm: &mut u64,
    ) {
        assert!(
            m0.len() >= length && m1.len() >= length,
            "insufficient OT sender payload length"
        );
        assert!(
            offset + length <= self.n,
            "OT send out of precomputed range"
        );

        let mut pad = vec![[0u128; NUM_LIMBS]; 2 * length];
        let k = offset;

        for i in 0..length {
            let idx = k + i;
            if !self.bits[idx] {
                pad[2 * i] = xor_message::<NUM_LIMBS>(&m0[i], &self.pre_data[idx]);
                pad[2 * i + 1] = xor_message::<NUM_LIMBS>(&m1[i], &self.pre_data[idx + self.n]);
            } else {
                pad[2 * i] = xor_message::<NUM_LIMBS>(&m0[i], &self.pre_data[idx + self.n]);
                pad[2 * i + 1] = xor_message::<NUM_LIMBS>(&m1[i], &self.pre_data[idx]);
            }
        }
        let serialized = serialize_u128_blocks(&pad);
        *comm += send_u8(io, &serialized).expect("Failed to send padded data");
    }

    pub fn recv(
        &mut self,
        io: &mut SwankyChannel,
        data: &mut [[u128; NUM_LIMBS]],
        b: &[bool],
        length: usize,
        s: usize,
        _comm: &mut u64,
    ) {
        self.recv_with_offset(io, data, b, length, s * length, _comm);
    }

    pub fn recv_with_offset(
        &mut self,
        io: &mut SwankyChannel,
        data: &mut [[u128; NUM_LIMBS]],
        b: &[bool],
        length: usize,
        offset: usize,
        _comm: &mut u64,
    ) {
        assert!(
            data.len() >= length,
            "insufficient OT receiver output length"
        );
        assert!(b.len() >= length, "insufficient OT receiver choice length");
        assert!(
            offset + length <= self.n,
            "OT recv out of precomputed range"
        );

        let raw = receive_u8(io).expect("Receive padded data failed");
        let pad = deserialize_u128_blocks::<NUM_LIMBS>(&raw);
        assert_eq!(pad.len(), 2 * length, "invalid OT padded payload size");

        let k = offset;
        for i in 0..length {
            let idx = if b[i] { 1 } else { 0 };
            data[i] = xor_message::<NUM_LIMBS>(&self.pre_data[k + i], &pad[2 * i + idx]);
        }
    }

    pub fn sender_random_ot_with_offset(
        &self,
        length: usize,
        offset: usize,
    ) -> (Vec<[u128; NUM_LIMBS]>, Vec<[u128; NUM_LIMBS]>) {
        assert!(
            offset + length <= self.n,
            "OT sender random OT out of precomputed range"
        );

        let mut m0 = vec![[0u128; NUM_LIMBS]; length];
        let mut m1 = vec![[0u128; NUM_LIMBS]; length];

        for i in 0..length {
            let idx = offset + i;
            if !self.bits[idx] {
                m0[i] = self.pre_data[idx];
                m1[i] = self.pre_data[idx + self.n];
            } else {
                m0[i] = self.pre_data[idx + self.n];
                m1[i] = self.pre_data[idx];
            }
        }

        (m0, m1)
    }

    pub fn receiver_random_ot_with_offset(
        &self,
        length: usize,
        offset: usize,
    ) -> Vec<[u128; NUM_LIMBS]> {
        assert!(
            offset + length <= self.n,
            "OT receiver random OT out of precomputed range"
        );

        self.pre_data[offset..offset + length].to_vec()
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }
}

fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    [
        a[0] ^ b[0],
        a[1] ^ b[1],
        a[2] ^ b[2],
        a[3] ^ b[3],
        a[4] ^ b[4],
        a[5] ^ b[5],
        a[6] ^ b[6],
        a[7] ^ b[7],
        a[8] ^ b[8],
        a[9] ^ b[9],
        a[10] ^ b[10],
        a[11] ^ b[11],
        a[12] ^ b[12],
        a[13] ^ b[13],
        a[14] ^ b[14],
        a[15] ^ b[15],
    ]
}

fn xor_message<const NUM_LIMBS: usize>(
    a: &[u128; NUM_LIMBS],
    b: &[u128; NUM_LIMBS],
) -> [u128; NUM_LIMBS] {
    let mut res = [0u128; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        res[i] = a[i] ^ b[i];
    }
    res
}

fn serialize_u128_blocks<const NUM_LIMBS: usize>(blocks: &[[u128; NUM_LIMBS]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blocks.len() * NUM_LIMBS * 16);
    for block in blocks {
        for limb in block {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }
    out
}

fn deserialize_u128_blocks<const NUM_LIMBS: usize>(raw: &[u8]) -> Vec<[u128; NUM_LIMBS]> {
    let block_len = NUM_LIMBS * 16;
    assert!(
        raw.len().is_multiple_of(block_len),
        "invalid u128-block payload length"
    );

    let mut out = vec![[0u128; NUM_LIMBS]; raw.len() / block_len];
    for (i, chunk) in raw.chunks_exact(block_len).enumerate() {
        for j in 0..NUM_LIMBS {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&chunk[j * 16..(j + 1) * 16]);
            out[i][j] = u128::from_le_bytes(bytes);
        }
    }
    out
}
