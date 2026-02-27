use crate::iknp::IKNP;
use psi_aes::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use crate::preot::OTPre;

pub struct BaseCot {
    party: usize, // Alice: 0, Bob: 1
    one: [u8; 32],
    minus_one: [u8; 32],
    ot_delta: Option<[u8; 32]>,
    iknp: IKNP,
    malicious: bool,
}

impl BaseCot {
    pub fn new(party: usize, malicious: bool) -> Self {
        let one = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]; // Little-endian representation of 1
        let minus_one = [
            254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ]; // Little-endian representation of u128::MAX - 1

        BaseCot {
            party,
            one,
            minus_one,
            ot_delta: None,
            iknp: IKNP::new(malicious),
            malicious,
        }
    }

    pub fn cot_gen_pre<IO: CommunicationChannel>(&mut self, io: &mut IO, deltain: Option<[u8; 32]>, comm: &mut u64) {
        if let Some(deltain) = deltain {
            if self.party == 0 {
                self.ot_delta = Some(deltain);
                let delta_bool = block_to_bool(&deltain);
                self.iknp.setup_send(io, Some(&delta_bool), None, comm);
            } else {
                self.iknp.setup_recv(io, None, None, comm);
            }
        } else {
            if self.party == 0 {
                let mut prg = PRG::new(None, 0);
                let mut tmp = [[0u8; 32]];
                prg.random_32byte_block(&mut tmp);
                let mut delta = tmp[0];
                delta = bitwise_and(&delta, &self.minus_one);
                delta = bitwise_xor(&delta, &self.one);
                self.ot_delta = Some(delta);
                let delta_bool = block_to_bool(&delta);
                self.iknp.setup_send(io, Some(&delta_bool), None, comm);
            } else {
                self.iknp.setup_recv(io, None, None, comm);
            }
        }
    }

    pub fn cot_gen<IO: CommunicationChannel>(&mut self, io: &mut IO, ot_data: &mut [[u8; 32]], size: usize, pre_bool: Option<&[bool]>, comm: &mut u64) {
        if self.party == 0 {
            self.iknp.send_cot(io, ot_data, size, comm);
            io.flush();
            for block in ot_data.iter_mut() {
                *block = bitwise_and(block, &self.minus_one);
            }
        } else {
            let mut prg = PRG::new(None, 0);
            let mut pre_bool_ini = vec![false; size];
            if let Some(pre_bool) = pre_bool {
                if !self.malicious {
                    pre_bool_ini.copy_from_slice(pre_bool);
                } else {
                    prg.random_bool_array(&mut pre_bool_ini);
                }
            } else {
                prg.random_bool_array(&mut pre_bool_ini);
            }

            self.iknp.recv_cot(io, ot_data, &pre_bool_ini, size, comm);

            let ch = [
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ]; 

            for (i, block) in ot_data.iter_mut().enumerate() {
                *block = bitwise_xor(&bitwise_and(block, &self.minus_one), &ch[pre_bool_ini[i] as usize]);
            }
        }
    }

    pub fn cot_gen_preot<IO: CommunicationChannel>(&mut self, io: &mut IO, pre_ot: &mut OTPre, size: usize, pre_bool: Option<&[bool]>, comm: &mut u64) {
        let mut ot_data = vec![[0u8; 32]; size]; // Allocate space for `ot_data`

        if self.party == 0 {
            // ALICE
            self.iknp.send_cot(io, &mut ot_data, size, comm);
            // io.flush();

            // Apply `minus_one` to all blocks
            for block in ot_data.iter_mut() {
                *block = bitwise_and(block, &self.minus_one);
            }

            // Call `send_pre` on `pre_ot`
            if let Some(delta) = self.ot_delta {
                pre_ot.send_pre(&ot_data, delta);
            }
        } else {
            // BOB
            let mut prg = PRG::new(None, 0);
            let mut pre_bool_ini = vec![false; size];

            // Initialize `pre_bool_ini`
            if let Some(pre_bool) = pre_bool {
                if !self.malicious {
                    pre_bool_ini.copy_from_slice(pre_bool);
                } else {
                    prg.random_bool_array(&mut pre_bool_ini);
                }
            } else {
                prg.random_bool_array(&mut pre_bool_ini);
            }

            // Call `recv_cot` on `iknp`
            self.iknp.recv_cot(io, &mut ot_data, &pre_bool_ini, size, comm);

            let ch = [
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ]; 

            // Modify `ot_data` based on `pre_bool_ini`
            for (i, block) in ot_data.iter_mut().enumerate() {
                *block = bitwise_xor(&bitwise_and(block, &self.minus_one), &ch[pre_bool_ini[i] as usize]);
            }

            // Call `recv_pre` on `pre_ot`
            pre_ot.recv_pre(&ot_data, Some(&pre_bool_ini));
        }
    }

    // Debugging check for COT
    pub fn check_cot<IO: CommunicationChannel>(&mut self, io: &mut IO, data: &[[u8; 32]], len: usize) -> bool {
        if self.party == 0 {
            if let Some(delta) = self.ot_delta {
                io.send_block::<32>(&[delta]).expect("Failed to send delta");
            }
            io.send_block::<32>(data).expect("Failed to send check data");
            io.flush();
            true
        } else {
            let mut tmp = vec![[0u8; 32]; len];
            let mut ch = [[0u8; 32]; 2];
            ch[1] = io.receive_block::<32>().expect("Failed to receiver delta")[0];
            ch[0] = [0u8; 32];
            tmp = io.receive_block::<32>().expect("Failed to receive check data");
            for i in 0..len {
                tmp[i] = bitwise_xor(&tmp[i], &ch[get_lsb(&data[i]) as usize]);
            }
            cmp_blocks(&tmp, data)
        }
    }
}

fn block_to_bool(block: &[u8; 32]) -> [bool; 256] {
    let mut result = [false; 256];
    for (i, byte) in block.iter().enumerate() {
        for bit in 0..8 {
            result[i * 8 + bit] = (byte >> bit) & 1 != 0;
        }
    }
    result
}

fn get_lsb(block: &[u8; 32]) -> bool {
    block[0] & 1 != 0
}

fn cmp_blocks(a: &[[u8; 32]], b: &[[u8; 32]]) -> bool {
    a == b
}

fn bitwise_xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    [
        a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3],
        a[4] ^ b[4], a[5] ^ b[5], a[6] ^ b[6], a[7] ^ b[7],
        a[8] ^ b[8], a[9] ^ b[9], a[10] ^ b[10], a[11] ^ b[11],
        a[12] ^ b[12], a[13] ^ b[13], a[14] ^ b[14], a[15] ^ b[15],
        a[16] ^ b[16], a[17] ^ b[17], a[18] ^ b[18], a[19] ^ b[19],
        a[20] ^ b[20], a[21] ^ b[21], a[22] ^ b[22], a[23] ^ b[23],
        a[24] ^ b[24], a[25] ^ b[25], a[26] ^ b[26], a[27] ^ b[27],
        a[28] ^ b[28], a[29] ^ b[29], a[30] ^ b[30], a[31] ^ b[31],
    ]
}

fn bitwise_and(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    [
        a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3],
        a[4] & b[4], a[5] & b[5], a[6] & b[6], a[7] & b[7],
        a[8] & b[8], a[9] & b[9], a[10] & b[10], a[11] & b[11],
        a[12] & b[12], a[13] & b[13], a[14] & b[14], a[15] & b[15],
        a[16] & b[16], a[17] & b[17], a[18] & b[18], a[19] & b[19],
        a[20] & b[20], a[21] & b[21], a[22] & b[22], a[23] & b[23],
        a[24] & b[24], a[25] & b[25], a[26] & b[26], a[27] & b[27],
        a[28] & b[28], a[29] & b[29], a[30] & b[30], a[31] & b[31],
    ]
}