use crate::cope::Cope;
use psi_aes::prg::PRG;
use crate::comm_util::*;
use crate::tcp_channel::SwankyChannel;

pub type FE = crate::vole::field_config::FE;

pub struct BaseSvole {
    party: u8,              // 0 for sender, 1 for receiver
    cope: Cope,     // COPE instance
    delta: Option<FE>,      // Delta for the sender
}

impl BaseSvole {
    /// Sender's constructor
    pub fn new_sender(io: &mut SwankyChannel, delta: FE, comm: &mut u64) -> Self {
        let mut cope = Cope::new(0, crate::scalar_field::FOURQ_SCALAR_BITS);
        cope.initialize_sender(io, delta.clone(), comm);
        Self {
            party: 0,
            cope,
            delta: Some(delta),
        }
    }

    /// Receiver's constructor
    pub fn new_receiver(io: &mut SwankyChannel, comm: &mut u64) -> Self {
        let mut cope = Cope::new(1, crate::scalar_field::FOURQ_SCALAR_BITS);
        cope.initialize_receiver(io, comm);
        Self {
            party: 1,
            cope,
            delta: None,
        }
    }

    /// Sender: Triple generation
    pub fn triple_gen_send(&mut self, io: &mut SwankyChannel, share: &mut [FE], size: usize, comm: &mut u64) {
        // Generate share_recv = share_send + delta * u_recv
        self.cope.extend_sender_batch(io, share, size, comm);
        let mut b = vec![FE::zero(); 1];
        self.cope.extend_sender_batch(io, &mut b, 1, comm);
        self.sender_check(io, share, b[0], size, comm);
    }

    /// Receiver: Triple generation
    pub fn triple_gen_recv(&mut self, io: &mut SwankyChannel, share: &mut [FE], u: &mut [FE], size: usize, comm: &mut u64) {
        // Generate share_recv = share_send + delta * u_recv
        let mut prg = PRG::new(None, 0);
        let mut x = vec![FE::zero(); 1];
        crate::scalar_field::random_fourq_elements_from_prg(&mut prg, &mut x);

        crate::scalar_field::random_fourq_elements_from_prg(&mut prg, u);

        self.cope.extend_receiver_batch(io, share, u, size, comm);

        let mut c = vec![FE::zero(); 1];
        self.cope.extend_receiver_batch(io, &mut c, &x, 1, comm);

        self.receiver_check(io, share, u, c[0], x[0], size, comm);
    }

    /// Sender: Consistency check
    fn sender_check(&mut self, io: &mut SwankyChannel, share: &[FE], b: FE, size: usize, comm: &mut u64) {
        // Generate check seed and send it to Receiver
        let mut seed = vec![[0u8; 16]; 1];
        let mut seed_prg = PRG::new(None, 0);
        seed_prg.random_16byte_block(&mut seed);
        *comm += send_block::<16>(io, &seed).expect("Send seed for svole check failed");

        let chi = self.generate_hash_coeff(seed[0], size);

        let y = self.vector_inner_product_mod(share, &chi) + b;
        let mut xz = receive_fe(io).expect("Failed to receive xz");

        xz[1] = xz[1] * self.delta.unwrap();
        let y_check = y + xz[1];
        if y_check != xz[0] {
            panic!("Base sVOLE check failed!");
        } else {
            println!("Base sVOLE generated successfully!");
        }
    }

    /// Receiver: Consistency check
    fn receiver_check(&mut self, io: &mut SwankyChannel, share: &[FE], x: &[FE], c: FE, a: FE, size: usize, comm: &mut u64) {
        let seed = receive_block::<16>(io).expect("Cannot receive seed for check base sVOLE")[0];

        let chi = self.generate_hash_coeff(seed, size);

        let xz_0 = self.vector_inner_product_mod(share, &chi) + c;
        let xz_1 = self.vector_inner_product_mod(x, &chi) + a;

        *comm += send_fe(io, &[xz_0, xz_1]).expect("Failed to send xz");
    }

    /// Generate hash coefficients based on a seed
    fn generate_hash_coeff(&self, seed: [u8; 16], size: usize) -> Vec<FE> {
        let mut coeffs = vec![FE::zero(); size];
        let mut prg = PRG::new(Some(&seed), 0);
        crate::scalar_field::random_fourq_elements_from_prg(&mut prg, &mut coeffs);
        coeffs
    }

    /// Compute modular inner product
    fn vector_inner_product_mod(&self, vec1: &[FE], vec2: &[FE]) -> FE {
        vec1.iter().zip(vec2).fold(FE::zero(), |acc, (v1, v2)| acc + (*v1 * *v2))
    }
}
