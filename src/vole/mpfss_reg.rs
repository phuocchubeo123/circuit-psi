use crate::pre_ot::OTPre;
use crate::comm_util::*;
use swanky_channel_legacy::AbstractChannel;
use crate::spfss_sender::SpfssSenderFp;
use crate::spfss_receiver::SpfssRecverFp;
use crate::vole::field_config::FE_LIMBS;
use psi_aes::prg::PRG;
use psi_aes::hash::Hash;

pub type FE = crate::vole::field_config::FE;

// No multithreading
pub struct MpfssReg {
    party: usize,
    item_n: usize,
    idx_max: usize, 
    m: usize,
    tree_height: usize,
    leave_n: usize,
    tree_n: usize,
    is_malicious: bool,
    prg: PRG,
    secret_share_x: FE,
    ggm_tree: Vec<Vec<FE>>,
    check_chialpha_buf: Vec<FE>,
    check_vw_buf: Vec<FE>,
    item_pos_receiver: Vec<usize>,
    triple_y: Vec<FE>,
    triple_z: Vec<FE>,
}

impl MpfssReg {
    pub fn new(n: usize, t: usize, log_bin_sz: usize, party: usize) -> Self {
        // make sure n = t * leave_n
        MpfssReg {
            party: party,
            item_n: t,
            idx_max: n,
            m: 0,
            tree_height: log_bin_sz + 1,
            leave_n: 1 << log_bin_sz,
            tree_n: t,
            is_malicious: false,
            prg: PRG::new(None, 0),
            secret_share_x: FE::zero(),
            ggm_tree: vec![vec![FE::zero(); 1 << log_bin_sz]; t],
            check_chialpha_buf: vec![FE::zero(); t],
            check_vw_buf: vec![FE::zero(); t],
            item_pos_receiver: vec![0; t],
            triple_y: vec![FE::zero(); t+1],
            triple_z: vec![FE::zero(); t+1],
        }
    }

    pub fn set_malicious(&mut self) {
        self.is_malicious = true;
    }

    pub fn sender_init(&mut self, delta: FE) {
        self.secret_share_x = delta.clone();
    }

    pub fn receiver_init(&mut self) {
    }

    pub fn set_vec_x(&self, out_vec: &mut [FE], in_vec: &[FE]) {
        for i in 0..self.tree_n {
            let pt = i * self.leave_n + self.item_pos_receiver[i] % self.leave_n;
            out_vec[pt] += in_vec[i];
        }
    }

    pub fn mpfss_sender<IO: AbstractChannel>(&mut self, io: &mut IO, ot: &mut OTPre<FE_LIMBS>, triple_y: &[FE], sparse_vector: &mut [FE], comm: &mut u64) {
        // triple_y_recv = triple_y_send + delta * triple_z

        self.triple_y.copy_from_slice(&triple_y[..self.tree_n+1]);

        // Set up PreOT first
        for i in 0..self.tree_n {
            ot.choices_sender(io, comm);
        }
        io.flush();
        ot.reset();

        let mut seeds = vec![FE::zero(); self.tree_n];
        if self.is_malicious {
            self.seed_expand(io, &mut seeds, self.tree_n, comm);
        }
        io.flush();

        // Now start doing Spfss
        for i in 0..self.tree_n {
            let mut sender = SpfssSenderFp::new(self.tree_height);
            sender.compute(&mut self.ggm_tree[i], self.secret_share_x, self.triple_y[i]);
            sender.send(io, ot, i, comm);
            sparse_vector[i*self.leave_n..(i+1)*self.leave_n].copy_from_slice(&self.ggm_tree[i]);

            // Malicious check
            if self.is_malicious {
                sender.consistency_check_msg_gen(&mut self.check_vw_buf[i], seeds[i]);
            }
        }

        // consistency batch check
        if self.is_malicious {
            let x_star = receive_fe(io).expect("Failed to receive x_star")[0];
            // tmp should be equal to triple_y_recv[self.tree_n] - something
            let tmp = self.secret_share_x * x_star + self.triple_y[self.tree_n];
            let mut vb = FE::zero();
            vb = vb - tmp;
            for i in 0..self.tree_n {
                vb += self.check_vw_buf[i];
            }

            let hash = Hash::new();
            let digest = hash.hash_32byte_block(&vb.to_bytes_le());
            let h = FE::from_bytes_le_mod_order(&digest);
            *comm += send_fe(io, &[h]).expect("Failed to send h");
        }
    }

    pub fn mpfss_receiver<IO: AbstractChannel>(&mut self, io: &mut IO, ot: &mut OTPre<FE_LIMBS>, triple_y: &[FE], triple_z: &[FE], sparse_vector_y: &mut [FE], sparse_vector_z: &mut [FE], comm: &mut u64) {
        // triple_y_recv = triple_y_send + delta * triple_z

        self.triple_y.copy_from_slice(&triple_y[..self.tree_n+1]);
        self.triple_z.copy_from_slice(&triple_z[..self.tree_n+1]);

        for i in 0..self.tree_n {
            let b = vec![false; self.tree_height - 1];
            ot.choices_recver(io, &b, comm);
        }
        io.flush();
        ot.reset();

        let mut seeds = vec![FE::zero(); self.tree_n];
        if self.is_malicious {
            self.seed_expand(io, &mut seeds, self.tree_n, comm);
        }

        for i in 0..self.tree_n {
            let mut receiver = SpfssRecverFp::new(self.tree_height);
            self.item_pos_receiver[i] = receiver.get_index();
            receiver.recv(io, ot, i, comm);
            receiver.compute(&mut self.ggm_tree[i], self.triple_y[i]);
            sparse_vector_y[i*self.leave_n..(i+1)*self.leave_n].copy_from_slice(&self.ggm_tree[i]);
            for j in i*self.leave_n..(i+1)*self.leave_n {
                sparse_vector_z[j] = FE::zero();
            }
            sparse_vector_z[i*self.leave_n + self.item_pos_receiver[i]] = self.triple_z[i];

            if self.is_malicious {
                receiver.consistency_check_msg_gen(&mut self.check_chialpha_buf[i], &mut self.check_vw_buf[i], seeds[i]);
            }
        }

        if self.is_malicious {
            let mut beta_mul_chialpha = FE::zero();
            for i in 0..self.tree_n {
                beta_mul_chialpha += self.check_chialpha_buf[i] * self.triple_z[i];
            }
            let x_star = self.triple_z[self.tree_n] - beta_mul_chialpha;
            *comm += send_fe(io, &[x_star]).expect("Cannot send x_star.");

            let mut va = FE::zero();
            va = va - self.triple_y[self.tree_n];
            for i in 0..self.tree_n {
                va += self.check_vw_buf[i];
            }

            let hash = Hash::new();
            let digest = hash.hash_32byte_block(&va.to_bytes_le());
            let h = FE::from_bytes_le_mod_order(&digest);

            let r = receive_fe(io).expect("Cound not receive h from Sender")[0];

            if r != h {
                panic!("Consistency check for Mpfss failed!");
            }
        }

    }

    pub fn seed_expand<IO: AbstractChannel>(&mut self, io: &mut IO, seed: &mut [FE], threads: usize, comm: &mut u64) {
        let mut sd = [0u8; 16];
        if self.party == 0 {
            sd = receive_block::<16>(io).expect("Failed to receive seed")[0];
        } else {
            let mut sd_buf = vec![[0u8; 16]; 1];
            self.prg.random_16byte_block(&mut sd_buf);
            sd = sd_buf[0].clone();
            *comm += send_block::<16>(io, &[sd]).expect("Failed to send seed");
        }
        let mut prg2 = PRG::new(Some(&sd), 0);
        crate::scalar_field::random_fourq_elements_from_prg(&mut prg2, seed);
    }
}
