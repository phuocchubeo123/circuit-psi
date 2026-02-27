use crate::comm_channel::CommunicationChannel;
use crate::preot::OTPre;
use crate::fourq_prp::TwoKeyPRP;
use psi_aes::prg::PRG;
use psi_aes::hash::Hash;
use std::convert::TryInto;

pub type FE = crate::fourq_field::FourQScalarField;

fn fe_from_digest(_hash: &Hash, digest: [u8; 32]) -> FE {
    FE::from_bytes_le_mod_order(&digest)
}

pub struct SpfssSenderFp {
    seed: FE,
    delta: FE,
    secret_sum: FE,
    ggm_tree: Vec<FE>,
    m0: Vec<FE>,
    m1: Vec<FE>,
    depth: usize,
    leave_n: usize,
    prg: PRG,
}

impl SpfssSenderFp {
    /// Create a new SpfssSenderFp instance.
    pub fn new(depth: usize) -> Self {
        let leave_n = 1 << (depth - 1);
        let mut prg = PRG::new(None, 0);
        let mut seed = [FE::zero(); 1];
        crate::fourq_field::random_fourq_elements_from_prg(&mut prg, &mut seed);
        Self {
            seed: seed[0],
            delta: FE::zero(),
            secret_sum: FE::zero(),
            ggm_tree: vec![FE::zero(); leave_n],
            m0: vec![FE::zero(); depth - 1],
            m1: vec![FE::zero(); depth - 1],
            depth,
            leave_n,
            prg,
        }
    }

    /// Sender GGM tree infos thru OT
    pub fn compute(&mut self, ggm_tree_mem: &mut [FE], secret: FE, gamma: FE) {
        self.delta = secret.clone();
        self.ggm_tree_gen(ggm_tree_mem, secret, gamma);
    }

    /// Send OT messages and secret sum.
    pub fn send<IO: CommunicationChannel>(&mut self, io: &mut IO, ot: &mut OTPre, s: usize, comm: &mut u64) {
        let ot_msg_0 = self.m0
            .iter()
            .map(|x| x.to_bytes_le())
            .collect::<Vec<[u8; 32]>>();
        let ot_msg_1 = self.m1
            .iter()
            .map(|x| x.to_bytes_le())
            .collect::<Vec<[u8; 32]>>();

        ot.send(io, &ot_msg_0, &ot_msg_1, self.depth - 1, s, comm);
        *comm += io.send_stark252(&[self.secret_sum]).expect("Failed to send secret sum.");
    }

    /// Generate the GGM tree from the top.
    // Generate the GGM tree to ggm_tree_mem first, then copy it into self.ggm_tree for later check
    fn ggm_tree_gen(&mut self, ggm_tree_mem: &mut [FE], secret: FE, gamma: FE) {
        let mut prp = TwoKeyPRP::new();
        // Generate the first layer of the GGM tree
        prp.node_expand_1to2(&mut ggm_tree_mem[0..2], &self.seed);
        self.m0[0] = ggm_tree_mem[0];
        self.m1[0] = ggm_tree_mem[1];

        // Process all layers
        for h in 1..self.depth - 1 {
            self.m0[h] = FE::zero();
            self.m1[h] = FE::zero();
            let sz = 1 << h;
            for i in (0..sz).step_by(2) {
                prp.node_expand_2to4(
                    &mut self.ggm_tree[2*i..2*i+4], 
                    &ggm_tree_mem[i..i+2]
                );
                self.m0[h] += self.ggm_tree[i * 2] + self.ggm_tree[i * 2 + 2];
                self.m1[h] += self.ggm_tree[i * 2 + 1] + self.ggm_tree[i * 2 + 3];
            }
            ggm_tree_mem[..2*sz].copy_from_slice(&self.ggm_tree[..2*sz]);
        }

        // Compute the secret sum
        self.secret_sum = FE::zero();
        for node in ggm_tree_mem.iter().take(self.leave_n) {
            self.secret_sum = self.secret_sum - *node;
        }
        self.secret_sum += gamma;
    }

    /// Consistency check: Protocol PI_spsVOLE
    pub fn consistency_check<IO: CommunicationChannel>(&mut self, io: &mut IO, y: FE, comm: &mut u64) {
        // z = y + delta * beta

        let hash = Hash::new();
        let digest = hash.hash_32byte_block(&self.secret_sum.to_bytes_le());
        let uni_hash_seed = fe_from_digest(&hash, digest);
        let mut chi = vec![FE::zero(); self.leave_n];
        uni_hash_coeff_gen(&mut chi, uni_hash_seed, self.leave_n);

        // Receive x_star
        let x_star = io.receive_stark252().expect("Failed to receive x_star")[0];

        // Compute y_star
        let y_star = y - x_star * self.delta;

        // Compute V
        let v = vector_inner_product(&chi, &self.ggm_tree) - y_star;

        println!("v: {:?}", v);

        // Send V
        *comm += io.send_stark252(&[v]).expect("Failed to send V");
    }

    pub fn consistency_check_msg_gen(&mut self, v: &mut FE, seed: FE) {
        let mut chi = vec![FE::zero(); self.leave_n];

        let hash = Hash::new();
        let digest = hash.hash_32byte_block(&seed.to_bytes_le());
        let uni_hash_seed = fe_from_digest(&hash, digest);

        uni_hash_coeff_gen(&mut chi, uni_hash_seed, self.leave_n);

        *v = vector_inner_product(&chi, &self.ggm_tree);
    }
}

/// Compute modular inner product.
fn vector_inner_product(vec1: &[FE], vec2: &[FE]) -> FE {
    vec1.iter()
        .zip(vec2)
        .fold(FE::zero(), |acc, (v1, v2)| acc + (*v1 * *v2))
}

pub fn uni_hash_coeff_gen(coeff: &mut [FE], seed: FE, sz: usize) {
    if sz == 0 {
        return;
    }

    // Handle small `sz`
    coeff[0] = seed;
    if sz == 1 {
        return;
    }

    coeff[1] = coeff[0] * seed;
    if sz == 2 {
        return;
    }

    coeff[2] = coeff[1] * seed;
    if sz == 3 {
        return;
    }

    let multiplier = coeff[2] * seed;
    coeff[3] = multiplier;
    if sz == 4 {
        return;
    }

    // Compute the rest in batches of 4
    let mut i = 4;
    while i + 3 < sz {
        coeff[i] = coeff[i - 4] * multiplier;
        coeff[i + 1] = coeff[i - 3] * multiplier;
        coeff[i + 2] = coeff[i - 2] * multiplier;
        coeff[i + 3] = coeff[i - 1] * multiplier;
        i += 4;
    }

    // Handle remaining elements
    let remainder = sz % 4;
    if remainder != 0 {
        let start = sz - remainder;
        for j in 0..remainder {
            coeff[start + j] = coeff[start + j - 1] * seed;
        }
    }
}
