use psi_aes::hash::CCRH;
use crate::comm_channel::CommunicationChannel;

pub struct OTPre {
    pre_data: Vec<[u8; 32]>,
    bits: Vec<bool>,
    n: usize,
    count: usize,
    length: usize,
    delta: Option<[u8; 32]>,
}

impl OTPre {
    /// Create a new `OTPre` instance
    pub fn new(length: usize, times: usize) -> Self {
        let n = length * times;
        Self {
            pre_data: vec![[0u8; 32]; 2 * n],
            bits: vec![false; n],
            n,
            count: 0,
            length,
            delta: None,
        }
    }

    /// Receives choice bits from the receiver and updates internal state
    pub fn choices_sender<IO: CommunicationChannel>(&mut self, io: &mut IO, comm: &mut u64) {
        let received_bits = io.receive_bits().expect("Failed to receive bits");
        for (i, &bit) in received_bits.iter().enumerate() {
            self.bits[self.count + i] = bit;
        }
        self.count += self.length;
    }

    /// Sends the adjusted choice bits to the sender
    pub fn choices_recver<IO: CommunicationChannel>(&mut self, io: &mut IO, choices: &[bool], comm: &mut u64) {
        let mut adjusted_bits = vec![false; self.length];
        for i in 0..self.length {
            adjusted_bits[i] = choices[i] ^ self.bits[self.count + i];
            self.bits[self.count+i] = adjusted_bits[i].clone();
        }
        *comm += io.send_bits(&adjusted_bits).expect("Failed to send bits");
        self.count += self.length;
    }

    /// Precompute data for the sender
    pub fn send_pre(&mut self, data: &[[u8; 32]], delta: [u8; 32]) {
        let ccrh = CCRH::new();
        self.delta = Some(delta);

        let n = self.n;
        ccrh.hn(&mut self.pre_data[..n], data);

        for i in 0..n {
            self.pre_data[n + i] = xor_block(&data[i], &delta);
        }

        let temp = self.pre_data[n..2 * n].to_vec(); // Copy to avoid overlapping borrows
        ccrh.hn(&mut self.pre_data[n..2 * n], &temp);
    }

    /// Precompute data for the receiver
    pub fn recv_pre(&mut self, data: &[[u8; 32]], bits: Option<&[bool]>) {
        let ccrh = CCRH::new();
        if let Some(b) = bits {
            self.bits[..self.n].copy_from_slice(b);
        } else {
            for i in 0..self.n {
                self.bits[i] = data[i][0] & 1 != 0; // Extract LSB
            }
        }
        ccrh.hn(&mut self.pre_data[..self.n], data);
    }

    /// Send data based on precomputed values
    pub fn send<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        m0: &[[u8; 32]],
        m1: &[[u8; 32]],
        length: usize,
        s: usize,
        comm: &mut u64,
    ) {
        let mut pad = vec![[0u8; 32]; 2*length];
        let k = s * length;

        for i in 0..length {
            let idx = k + i;
            if !self.bits[idx] {
                pad[2*i] = xor_block(&m0[i], &self.pre_data[idx]);
                pad[2*i+1] = xor_block(&m1[i], &self.pre_data[idx + self.n]);
            } else {
                pad[2*i] = xor_block(&m0[i], &self.pre_data[idx + self.n]);
                pad[2*i+1] = xor_block(&m1[i], &self.pre_data[idx]);
            }
        }
        *comm += io.send_block::<32>(&pad).expect("Failed to send padded data");
    }

    /// Receive and reconstruct data based on precomputed values
    pub fn recv<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        data: &mut [[u8; 32]],
        b: &[bool],
        length: usize,
        s: usize,
        comm: &mut u64,
    ) {
        let pad = io.receive_block::<32>().expect("Receive padded data failed");
        let k = s * length;

        for i in 0..length {
            let idx = if b[i] { 1 } else { 0 };
            data[i] = xor_block(&self.pre_data[k + i], &pad[2*i + idx]);
        }
    }

    /// Reset the internal counter
    pub fn reset(&mut self) {
        self.count = 0;
    }
}

fn xor_block(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
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