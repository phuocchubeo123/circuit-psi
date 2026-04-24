use crate::{
    comm_util::{receive_fe, send_fe},
    math::{
        defines::FE,
        scalar_field::{FOURQ_SCALAR_BITS, random_fourq_elements_from_prg},
    },
    network::tcp_channel::SwankyChannel,
    pre_ot::OTPre,
};
use psi_aes::prg::PRG;

const KEY_OT_LIMBS: usize = 1;

pub struct MascotCope {
    pub party: u8,
    m: usize,
    delta_bool: Vec<bool>,
    prg_g0: Option<Vec<PRG>>,
    prg_g1: Option<Vec<PRG>>,
    powers_of_two: Vec<FE>,
}

impl MascotCope {
    pub fn new(party: u8) -> Self {
        Self {
            party,
            m: FOURQ_SCALAR_BITS,
            delta_bool: vec![false; FOURQ_SCALAR_BITS],
            prg_g0: None,
            prg_g1: None,
            powers_of_two: vec![],
        }
    }

    fn delta_to_bool(delta: &FE, m: usize) -> Vec<bool> {
        let delta_bytes = delta.to_bytes_le();
        let mut delta_bool = vec![false; m];
        for i in 0..m {
            let byte_index = i / 8;
            let bit_index = i % 8;
            if byte_index < delta_bytes.len() {
                delta_bool[i] = (delta_bytes[byte_index] & (1 << bit_index)) != 0;
            }
        }
        delta_bool
    }

    fn precompute_powers_of_two(&mut self) {
        let mut powers = vec![FE::one(); self.m];
        let base = FE::from(2);
        for i in 1..self.m {
            powers[i] = powers[i - 1] * base;
        }
        self.powers_of_two = powers;
    }

    pub fn initialize_sender_pre_ot(
        &mut self,
        io: &mut SwankyChannel,
        delta: FE,
        pre_ot: &mut OTPre<KEY_OT_LIMBS>,
        ot_round: usize,
        comm: &mut u64,
    ) {
        self.delta_bool = Self::delta_to_bool(&delta, self.m);
        self.precompute_powers_of_two();

        pre_ot.choices_recver(io, &self.delta_bool, comm);
        let mut k_msg = vec![[0u128; KEY_OT_LIMBS]; self.m];
        pre_ot.recv(io, &mut k_msg, &self.delta_bool, self.m, ot_round, comm);

        self.prg_g0 = Some(
            k_msg
                .iter()
                .map(|msg| PRG::new(Some(&msg[0].to_le_bytes()), 0))
                .collect(),
        );
    }

    pub fn initialize_receiver_pre_ot(
        &mut self,
        io: &mut SwankyChannel,
        pre_ot: &mut OTPre<KEY_OT_LIMBS>,
        ot_round: usize,
        comm: &mut u64,
    ) {
        self.precompute_powers_of_two();

        let mut k0 = vec![[0u8; 16]; self.m];
        let mut k1 = vec![[0u8; 16]; self.m];
        let mut key_prg = PRG::new(None, 0);
        key_prg.random_16byte_block(&mut k0);
        key_prg.random_16byte_block(&mut k1);

        let mut k0_msg = vec![[0u128; KEY_OT_LIMBS]; self.m];
        let mut k1_msg = vec![[0u128; KEY_OT_LIMBS]; self.m];
        for i in 0..self.m {
            k0_msg[i] = [u128::from_le_bytes(k0[i])];
            k1_msg[i] = [u128::from_le_bytes(k1[i])];
        }

        pre_ot.choices_sender(io, comm);
        pre_ot.send(io, &k0_msg, &k1_msg, self.m, ot_round, comm);

        self.prg_g0 = Some(k0.iter().map(|key| PRG::new(Some(key), 0)).collect());
        self.prg_g1 = Some(k1.iter().map(|key| PRG::new(Some(key), 0)).collect());
    }

    pub fn extend_sender_batch(
        &mut self,
        io: &mut SwankyChannel,
        ret: &mut [FE],
        size: usize,
        _comm: &mut u64,
    ) {
        let mut w = vec![vec![FE::zero(); size]; self.m];
        let mut v = vec![vec![FE::zero(); size]; self.m];

        if let Some(prgs) = &mut self.prg_g0 {
            for (i, prg) in prgs.iter_mut().enumerate() {
                random_fourq_elements_from_prg(prg, &mut w[i]);
            }
        }

        let received_data = receive_fe(io).expect("Failed to receive v");
        for i in 0..self.m {
            for j in 0..size {
                v[i][j] = received_data[i * size + j];
            }
        }

        for i in 0..self.m {
            for j in 0..size {
                if self.delta_bool[i] {
                    v[i][j] = w[i][j] + v[i][j];
                } else {
                    v[i][j] = w[i][j];
                }
            }
        }

        self.prm2pr_batch(ret, &v);
    }

    pub fn extend_receiver_batch(
        &mut self,
        io: &mut SwankyChannel,
        ret: &mut [FE],
        u: &[FE],
        size: usize,
        comm: &mut u64,
    ) {
        let mut w0 = vec![vec![FE::zero(); size]; self.m];
        let mut w1 = vec![vec![FE::zero(); size]; self.m];
        let mut tau = vec![vec![FE::zero(); size]; self.m];

        if let (Some(prgs_g0), Some(prgs_g1)) = (&mut self.prg_g0, &mut self.prg_g1) {
            for i in 0..self.m {
                random_fourq_elements_from_prg(&mut prgs_g0[i], &mut w0[i]);
                random_fourq_elements_from_prg(&mut prgs_g1[i], &mut w1[i]);
                for j in 0..size {
                    w1[i][j] = w1[i][j] + u[j];
                    tau[i][j] = w0[i][j] - w1[i][j];
                }
            }
        }

        let tau_flat: Vec<FE> = tau.into_iter().flat_map(|row| row.into_iter()).collect();
        *comm += send_fe(io, &tau_flat).expect("Failed to send tau");
        self.prm2pr_batch(ret, &w0);
    }

    fn prm2pr_batch(&self, ret: &mut [FE], elements: &[Vec<FE>]) {
        for (j, result) in ret.iter_mut().enumerate() {
            *result = elements
                .iter()
                .zip(&self.powers_of_two)
                .fold(FE::zero(), |acc, (row, power)| acc + (row[j] * *power));
        }
    }
}
