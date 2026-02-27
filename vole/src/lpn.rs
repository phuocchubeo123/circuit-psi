use crate::fourq_prp::FieldPRP;
use psi_aes::prp::PRP;
use rayon::prelude::*;
use rayon::current_num_threads;

pub type FE = crate::fourq_field::FourQScalarField;

pub struct Lpn {
    party: usize,
    k: usize, 
    n: usize,
    M: Vec<FE>,
    preM: Vec<FE>,
    // prex: Vec<FE>,
    K: Vec<FE>,
    preK: Vec<FE>,
    A_idx: Vec<[usize; 10]>,
    A_weight: Vec<[FE; 10]>,
}

impl Lpn {
    pub fn new(k: usize, n: usize, seed: &[u8; 16], seed_field: &[u8; 32]) -> Self {
        let prp = PRP::new(Some(seed));
        let field_prp = FieldPRP::new(Some(seed_field));
        let mut A_idx = vec![[0usize; 10]; n];
        let mut A_weight = vec![[FE::zero(); 10]; n];

        A_idx.par_iter_mut().zip(A_weight.par_iter_mut()).enumerate().for_each(|(i, (r, w))| {
            let mut tmp = vec![[0u8; 16]; 10];
            let mut tmp2 = vec![[0u8; 32]; 10];
            for m in 0..10 {
                tmp[m][0..8].copy_from_slice(&(i).to_le_bytes());
                tmp[m][8..].copy_from_slice(&(m as usize).to_le_bytes());
                tmp2[m][0..8].copy_from_slice(&(i).to_le_bytes());
                tmp2[m][8..16].copy_from_slice(&(m as usize).to_le_bytes());
            }

            prp.permute_block(&mut tmp, 10);
            let r1: Vec<usize> = tmp
                .iter()
                .map(|x| ((u128::from_le_bytes(*x) >> 64) as usize) % k)
                .collect();

            r.copy_from_slice(&r1);
            let mut tmp_field: Vec<_> = tmp2
                .iter()
                .map(|x| FE::from_bytes_le(x).expect("Cannot get FE from bytes"))
                .collect();
            field_prp.permute_block(&mut tmp_field, 10);
            w.copy_from_slice(&tmp_field);
        });

        Self {
            party: 0,
            k: k,
            n: n,
            M: vec![FE::zero(); n],
            preM: vec![FE::zero(); k],
            K: vec![FE::zero(); n],
            preK: vec![FE::zero(); k],
            A_idx: A_idx,
            A_weight: A_weight,
        }
    }

    pub fn compute_K(&mut self, K: &mut [FE], kkK: &[FE]) {
        let num_threads = current_num_threads();
        let chunk_size = self.n / num_threads;

        K.par_iter_mut().enumerate().for_each(|(i, Ki)| {
            for m in 0..10 {
                *Ki += self.A_weight[i][m] * kkK[self.A_idx[i][m]];
            }
        });
    }

    pub fn compute_K_and_M(&mut self, K: &mut [FE], M: &mut [FE], kkK: &[FE], kkM: &[FE]) {
        K.par_iter_mut().zip(M.par_iter_mut()).enumerate().for_each(|(i, (Ki, Mi))| {
            for m in 0..10 {
                *Ki += self.A_weight[i][m] * kkK[self.A_idx[i][m]];
                *Mi += self.A_weight[i][m] * kkM[self.A_idx[i][m]];
            }
        });
    }

    pub fn compute_send(&mut self, K: &mut [FE], kkK: &[FE]) {
        self.party = 0;
        self.compute_K(K, kkK);
    }

    pub fn compute_recv(&mut self, K: &mut [FE], M: &mut [FE], kkK: &[FE], kkM: &[FE]) {
        self.party = 1;
        self.compute_K_and_M(K, M, kkK, kkM);
    }
}
