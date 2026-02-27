use lambdaworks_math::traits::AsBytes;
use lambdaworks_math::fft::cpu::bit_reversing::{in_place_bit_reverse_permute, reverse_index};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use lambdaworks_math::fft::cpu::roots_of_unity;
use lambdaworks_math::field::traits::RootsConfig;
use stark_platinum_prover::fri::Polynomial;
use rayon::prelude::*;
use rayon::{current_num_threads, scope};
use sha3::{Digest, Keccak256};
use std::time::Instant;
use std::thread;
use std::sync::{Arc, Mutex};
extern crate libc;

pub type FE = crate::fourq_field::FourQScalarField;

pub fn get_roots_of_unity(order: u64) -> Vec<FE> {
    assert!(
        order <= 1,
        "FourQ scalar field has 2-adicity 1; requested order {order} is unsupported"
    );
    let root = -FE::one();

    let mut roots = vec![FE::zero(); 1 << order];
    roots[0] = FE::one();

    let chunk = 1 << 14;

    for i in 1..chunk {
        roots[i] = roots[i-1] * root;
    }

    let root_pow = roots[chunk-1] * root;

    for i in 1..(roots.len() / chunk) {
        let roots_new: Vec<FE> = roots[(i-1)*chunk..i*chunk].par_iter().map(|x| *x * root_pow).collect();
        roots[i*chunk..(i+1)*chunk].copy_from_slice(&roots_new);
    }

    roots
}

pub fn rand_field_element() -> FE {
    loop {
        let bytes = rand::random::<[u8; 32]>();
        if let Ok(fe) = FE::from_bytes_le(&bytes) {
            return fe;
        }
    }
}

pub fn bit_reverse_permute(x: &[FE], size: usize) -> Vec<FE> {
    (0..size).into_par_iter().map(|i| x[reverse_index(i, size as u64)]).collect::<Vec<_>>()
}

pub fn parallel_fft(coefs: &[FE], roots_of_unity: &[FE], log_size: usize, log_blowup_factor: usize) -> Vec<FE> {
    let size = 1 << (log_size + log_blowup_factor);
    let mut res = vec![FE::zero(); size];
    res[..coefs.len()].copy_from_slice(coefs);
    res = bit_reverse_permute(&res, size);

    let mut stride = 1;
    let mut p: usize = log_size + log_blowup_factor - 1;
    let mask = size - 1;

    while stride < size {
        let num_threads = current_num_threads();
        let mut chunk_size = size / num_threads;
        chunk_size = (chunk_size + 2*stride - 1) / (2*stride) * 2*stride;

        if 4*stride > chunk_size {
            let mut small_chunk_size = stride / num_threads;
            for start in (0..size).step_by(2*stride) {
                let (left, right) = res[start..start+2*stride].split_at_mut(stride);
                left.par_chunks_mut(small_chunk_size)
                    .zip(right.par_chunks_mut(small_chunk_size))
                    .enumerate()
                    .for_each(|(i, (left_chunk, right_chunk))| {
                        for j in 0..left_chunk.len() {
                            let zp = roots_of_unity[((i*small_chunk_size+j) << p) & mask];
                            let a = left_chunk[j];
                            let b = right_chunk[j];
                            left_chunk[j] = a + zp * b;
                            right_chunk[j] = a - zp * b;
                        }
                    });
            }

        } else {
            res.par_chunks_mut(chunk_size)
                .enumerate()
                .for_each(|(i, chunk)| {
                    chunk.par_chunks_mut(2*stride).enumerate().for_each(|(i, small_chunk)| {
                        for j in 0..stride {
                            let zp = roots_of_unity[(j << p) & mask];
                            let a = small_chunk[j];
                            let b = small_chunk[j + stride];
                            small_chunk[j] = a + zp * b;
                            small_chunk[j + stride] = a - zp * b;
                        }
                    });
                });
        }

        stride *= 2;
        p -= 1;
    }

    res
}

pub fn parallel_ifft(coefs: &[FE], inv_roots_of_unity: &[FE], log_size: usize, log_blowup_factor: usize) -> Vec<FE> {
    let size = 1 << log_size;
    let mut res = vec![FE::zero(); size];
    res[..coefs.len()].copy_from_slice(coefs);

    let mut stride = size / 2;
    let mut p: usize = 0;
    let mask = size - 1;

    let FE_half = (FE::one() + FE::one()).inv().unwrap();

    while stride > 0 {
        let num_threads = current_num_threads();
        let mut chunk_size = size / num_threads;
        chunk_size = (chunk_size + 2*stride - 1) / (2*stride) * 2*stride;

        if 4*stride > chunk_size {
            let mut small_chunk_size = stride / num_threads;
            for start in (0..size).step_by(2*stride) {
                let (left, right) = res[start..start+2*stride].split_at_mut(stride);
                left.par_chunks_mut(small_chunk_size)
                    .zip(right.par_chunks_mut(small_chunk_size))
                    .enumerate()
                    .for_each(|(i, (left_chunk, right_chunk))| {
                        for j in 0..left_chunk.len() {
                            let zp = inv_roots_of_unity[((((i*small_chunk_size+j) as u64) << (p + log_blowup_factor)) & (mask as u64)) as usize];
                            let a = left_chunk[j];
                            let b = right_chunk[j];
                            left_chunk[j] = (a + b) * FE_half;
                            right_chunk[j] = (a - b) * zp * FE_half;
                        }
                    });
            }

        } else {
            res.par_chunks_mut(chunk_size)
                .enumerate()
                .for_each(|(i, chunk)| {
                    chunk.par_chunks_mut(2*stride).enumerate().for_each(|(i, small_chunk)| {
                        for j in 0..stride {
                            let zp = inv_roots_of_unity[(((j as u64) << (p + log_blowup_factor)) & (mask as u64)) as usize];
                            let a = small_chunk[j];
                            let b = small_chunk[j + stride];
                            small_chunk[j] = (a + b) * FE_half;
                            small_chunk[j + stride] = (a - b) * zp * FE_half;
                        }
                    });
                });
        }

        stride /= 2;
        p += 1;
    }

    res = bit_reverse_permute(&res, size);

    res
}

pub fn hash_leaves(unhashed_leaves: &[[FE; 2]]) -> Vec<[u8; 32]> {
    let num_threads = current_num_threads();
    let len = unhashed_leaves.len();
    let chunk_size = len / num_threads;
    let remainder = len % num_threads;

    // Create a vector of `num_threads` separate vectors for `hashed_leaves`
    let hashed_leaves_vecs: Vec<Arc<Mutex<Vec<[u8; 32]>>>> = (0..num_threads)
        .map(|_| Arc::new(Mutex::new(Vec::new())))
        .collect();

    let start = Instant::now();

    // Use Rayon to process data in chunks in parallel
    (0..num_threads).into_par_iter().for_each(|i| {
        let start_idx = i * chunk_size;
        let mut end_idx = 0;
        if i == num_threads - 1 {
            end_idx = len;
        } else {
            end_idx = start_idx + chunk_size;
        }

        let chunk_unhashed = &unhashed_leaves[start_idx..end_idx];

        // Compute the hashes for the chunk of data
        let local_hashed_chunk: Vec<[u8; 32]> = chunk_unhashed.iter().map(|unhashed| {
            let mut hasher = Keccak256::new();
            hasher.update(unhashed[0].as_bytes());
            hasher.update(unhashed[1].as_bytes());
            let mut hashed = [0u8; 32]; 
            hashed.copy_from_slice(&hasher.clone().finalize());
            hashed
        }).collect();

        // Lock the corresponding thread's hashed_leaves vector and append the result
        let mut hashed_leaves_lock = hashed_leaves_vecs[i].lock().unwrap();
        hashed_leaves_lock.extend(local_hashed_chunk);
    });

    // Concatenate all the results into a single vector
    let mut final_hashed_leaves = Vec::with_capacity(len);
    for hashed_vec in hashed_leaves_vecs {
        let hashed_vec_lock = hashed_vec.lock().unwrap();
        final_hashed_leaves.extend_from_slice(&hashed_vec_lock);
    }

    final_hashed_leaves
}




pub fn sibling_index(node_index: usize) -> usize {
    if node_index % 2 == 0 {
        node_index - 1
    } else {
        node_index + 1
    }
}

pub fn parent_index(node_index: usize) -> usize {
    if node_index % 2 == 0 {
        (node_index - 1) / 2
    } else {
        node_index / 2
    }
}
