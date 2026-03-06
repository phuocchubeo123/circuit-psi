use crate::utils::*;
use crate::comm_util::*;
use swanky_channel_legacy::AbstractChannel;
use psi_aes::prg::{PRG};
use lambdaworks_math::polynomial;
use lambdaworks_math::traits::ByteConversion;
use lambdaworks_math::fft::cpu::bit_reversing::{in_place_bit_reverse_permute, reverse_index};
use lambdaworks_math::field::traits::IsFFTField;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use lambdaworks_crypto::fiat_shamir::is_transcript::IsTranscript;
use lambdaworks_crypto::merkle_tree::proof::Proof;
// use lambdaworks_crypto::merkle_tree::merkle::MerkleTree;
use stark_platinum_prover::fri::fri_decommit::FriDecommitment;
use stark_platinum_prover::fri::{Polynomial};
use stark_platinum_prover::config::{Commitment, BatchedMerkleTreeBackend, BatchedMerkleTree};
use stark_platinum_prover::transcript::StoneProverTranscript;
use stark_platinum_prover::domain::Domain;
use rand::random;
use sha3::{Keccak256, Digest};
use lambdaworks_math::traits::AsBytes;
use serde::{Serialize, Deserialize};
use std::time::Instant;
use std::convert::TryInto;
use rayon::prelude::*;
use rayon::current_num_threads;
use rayon::{scope};
use std::thread;

pub type FE = crate::vole::field_config::FE;
pub type F = FE;

#[derive(Clone, Serialize, Deserialize)]
pub struct FriLayer
{
    pub evaluation: Vec<FE>,
    pub merkle_tree: MerkleTree,
}

impl FriLayer
{
    pub fn new(
        evaluation: &[FE],
        merkle_tree: MerkleTree,
    ) -> Self {
        Self {
            evaluation: evaluation.to_vec(),
            merkle_tree,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleTree
{
    pub root: [u8; 32],
    nodes: Vec<[u8; 32]>,
}

impl MerkleTree
{
    pub fn build(unhashed_leaves: &[[FE; 2]]) -> Self {
        // let start = Instant::now();
        let hashed_leaves: Vec<[u8; 32]> = hash_leaves(unhashed_leaves);
        let leaves_len = hashed_leaves.len();   
        // println!("Time to hash leaves: {:?}", start.elapsed());

        let mut nodes: Vec<[u8; 32]> = vec![hashed_leaves[0].clone(); leaves_len - 1];
        nodes.extend(hashed_leaves);
        // println!("Time to create leaves: {:?}", start.elapsed());

        let mut level_begin_index = leaves_len - 1;
        let mut level_end_index = 2 * level_begin_index;
        while level_begin_index != level_end_index {
            let new_level_begin_index = level_begin_index / 2;
            let new_level_length = level_begin_index - new_level_begin_index;

            let (new_level_iter, children_iter) =
                nodes[new_level_begin_index..level_end_index + 1].split_at_mut(new_level_length);

            let num_threads = current_num_threads();
            let chunk_size = new_level_length / num_threads;

            if chunk_size > 2 {
                new_level_iter.par_chunks_mut(chunk_size)
                    .zip(children_iter.par_chunks_exact(2*chunk_size))
                    .for_each(|(new_level, children)| {
                        new_level.iter_mut().zip(children.chunks_exact(2)).for_each(|(new_parent, children)| {
                            let mut hasher = Keccak256::new();
                            hasher.update(&children[0]);
                            hasher.update(&children[1]);
                            new_parent.copy_from_slice(&hasher.finalize());
                        });
                    });
            } else {
                new_level_iter.par_iter_mut().zip(children_iter.par_chunks_exact(2)).for_each(|(new_parent, children)| {
                    let mut hasher = Keccak256::new();
                    hasher.update(&children[0]);
                    hasher.update(&children[1]);
                    new_parent.copy_from_slice(&hasher.finalize());
                });
            }

            level_end_index = level_begin_index - 1;
            level_begin_index = new_level_begin_index;
        }

        // println!("Time to build Merkle tree: {:?}", start.elapsed());

        MerkleTree {
            root: nodes[0].clone(),
            nodes,
        }
    }

    pub fn get_proof_by_pos(&self, pos: usize) -> Proof<[u8; 32]> {
        let pos = pos + self.nodes.len() / 2;
        let merkle_path = self.build_merkle_path(pos);

        self.create_proof(merkle_path)
    }

    fn create_proof(&self, merkle_path: Vec<[u8; 32]>) -> Proof<[u8; 32]> {
        Proof { merkle_path }
    }

    fn build_merkle_path(&self, pos: usize) -> Vec<[u8; 32]> {
        let mut merkle_path = Vec::new();
        let mut pos = pos;

        while pos != 0 {
            let node = self.nodes.get(sibling_index(pos)).unwrap();
            merkle_path.push(node.clone());

            pos = parent_index(pos);
        }

        merkle_path
    }
}


// Returns both the random poly added and the final blinded poly
pub fn get_blind_poly(poly: &Polynomial<FE>, log_size: usize, log_blowup_factor: usize) -> (Polynomial<FE>, Polynomial<FE>) {
    let domain_size = 1 << log_size;

    let new_log_degree = log_size + log_blowup_factor;
    let new_degree = (1 << new_log_degree) - 1;
    let mut prg = PRG::new(None, 0);
    let mut blind_coefficients_bytes = vec![[0u8; 32]; new_degree - domain_size];

    prg.random_32byte_block(&mut blind_coefficients_bytes);

    let blind_coefficients: Vec<FE> = blind_coefficients_bytes
        .into_par_iter()
        .map(|x| FE::from_bytes_le(&x).expect("Cannot get FE from bytes"))
        .collect();

    let blind_poly = Polynomial::new(&blind_coefficients);

    let mut shifted_blind_coefficients: Vec<FE> = vec![FE::zero(); new_degree];
    shifted_blind_coefficients[domain_size..].copy_from_slice(&blind_coefficients);

    shifted_blind_coefficients[..blind_coefficients.len()].par_iter_mut().enumerate().for_each(|(i, shifted)| {
        *shifted = *shifted - blind_coefficients[i] + poly.coefficients[i];
    });
    shifted_blind_coefficients[domain_size-1] += poly.coefficients[domain_size-1];

    let new_poly = Polynomial::new(&shifted_blind_coefficients);

    (blind_poly, new_poly)
}

pub fn commit_poly(
    poly: &Polynomial<FE>,
    log_size: usize,
    log_blowup_factor: usize,
    log_fixed_points_num: usize,
    roots_of_unity: &[FE],
    roots_of_unity_inv: &[FE],
) -> (
    FE,
    Vec<FriLayer>, 
) {
    let start = Instant::now();

    let public_input_data = vec![]; // hopefully it's safe
    let mut transcript = StoneProverTranscript::new(&public_input_data);

    commit_phase(log_size, log_blowup_factor, poly, &mut transcript, log_fixed_points_num, roots_of_unity, roots_of_unity_inv)
}

pub fn commit_phase(
    log_size: usize,
    log_blowup_factor: usize,
    p_0: &Polynomial<FE>,
    transcript: &mut StoneProverTranscript,
    log_fixed_points_num: usize,
    roots_of_unity: &[FE],
    roots_of_unity_inv: &[FE],
) -> (
    FE,
    Vec<FriLayer>,
) {
    let FE_two_inv = (FE::one() + FE::one()).inv().unwrap();    
    let mut fri_layer_list = Vec::with_capacity(log_size);
    let mut current_layer: FriLayer;
    let mut current_poly = p_0.clone();
    let mut current_fixed_points_num = 1 << log_fixed_points_num;

    let mut current_evaluations = parallel_fft(&current_poly.coefficients, &roots_of_unity, log_size, log_blowup_factor);

    let mut current_size = current_evaluations.len();

    let mut new_evaluations = vec![FE::zero(); current_size];

    for layer in 0..log_size {
        // Commit the current folded poly (also include the original poly in the first step)
        current_layer = new_fri_layer_from_vec(&current_evaluations[..current_size], current_fixed_points_num);

        let new_data = &current_layer.merkle_tree.root;

        fri_layer_list.push(current_layer.clone()); // TODO: remove this clone
        // println!("Time to push to fri layer list: {:?}", start.elapsed());

        // >>>> Send commitment: [pₖ]
        transcript.append_bytes(new_data);

        // <<<< Receive challenge 𝜁ₖ₋₁
        // This lib already samples STARK-252 element
        let zeta = transcript.sample_field_element();
        current_fixed_points_num /= 2;

        // Manually fold the polynomial
        current_size /= 2;

        let num_threads = current_num_threads();
        let chunk_size = current_size / num_threads;

        if chunk_size > 0 {
            new_evaluations[..current_size].par_chunks_mut(chunk_size).enumerate().for_each(|(i, new_eval)| {
                new_eval.iter_mut().enumerate().for_each(|(j, new_eval_j)| {
                    let even = &current_evaluations[i*chunk_size + j];
                    let odd = &current_evaluations[i*chunk_size + j + current_size];
                    let root_inv = &roots_of_unity_inv[(i*chunk_size+j) << layer];

                    *new_eval_j = FE_two_inv * ((even + odd) + root_inv * zeta * (even - odd));
                });
            });
        } else {
            new_evaluations[..current_size].par_iter_mut().enumerate().for_each(|(i, new_eval)| {
            let even = &current_evaluations[i];
            let odd = &current_evaluations[i + current_size];
            let root_inv = &roots_of_unity_inv[i << layer];

            *new_eval = FE_two_inv * ((even + odd) + root_inv * zeta * (even - odd));
        });
        }

        // println!("Time to fold: {:?}", start.elapsed());

        current_evaluations[..current_size].copy_from_slice(&new_evaluations[..current_size]);
    }

    // <<<< Receive challenge: 𝜁ₙ₋₁
    let zeta = transcript.sample_field_element();

    let last_value = current_evaluations[0];

    // >>>> Send value: pₙ
    transcript.append_field_element(&last_value);

    (last_value, fri_layer_list)
}

pub fn new_fri_layer_from_vec(
    evaluation: &[FE],
    fixed_points_num: usize,
) -> FriLayer
{
    let start = Instant::now();
    let mut evals = evaluation.to_vec();
    evals = bit_reverse_permute(&evals, evals.len());
    let to_reverse = evals[..fixed_points_num].to_vec();
    evals[..fixed_points_num].copy_from_slice(&bit_reverse_permute(&to_reverse, fixed_points_num));

    let to_commit: Vec<[FE; 2]> = evals.par_chunks_exact(2).map(|chunk| [chunk[0].clone(), chunk[1].clone()]).collect();

    let merkle_tree = MerkleTree::build(&to_commit);
    FriLayer::new(
        &evals,
        merkle_tree,
    )
}

pub fn new_fri_layer(
    poly: &Polynomial<FE>,
    log_blowup_factor: usize,
    log_fixed_points_num: usize,
    log_poly_degree: usize,
    roots_of_unity: &[FE],
) -> FriLayer
{
    let fixed_points_num = 1 << log_fixed_points_num;

    let start = Instant::now();
    let mut evaluation = parallel_fft(&poly.coefficients, roots_of_unity, log_poly_degree, log_blowup_factor);
    println!("Time to compute FFT: {:?}", start.elapsed());

    let start = Instant::now();
    in_place_bit_reverse_permute(&mut evaluation);
    in_place_bit_reverse_permute(&mut evaluation[..fixed_points_num]);

    let mut to_commit = Vec::new();
    for chunk in evaluation.chunks(2) {
        to_commit.push([chunk[0].clone(), chunk[1].clone()]);
    }
    println!("Time to bit reverse: {:?}", start.elapsed());

    let start = Instant::now();
    let merkle_tree = MerkleTree::build(&to_commit);
    println!("Time to build Merkle tree: {:?}", start.elapsed());

    FriLayer::new(
        &evaluation,
        merkle_tree,
    )
}

pub fn query_phase(
    fri_layers: &[FriLayer],
    iotas: &[usize],
) -> Vec<FriDecommitment<F>>
{
    if !fri_layers.is_empty() {
        let start = Instant::now();
        let mut query_list: Vec<FriDecommitment<F>> = vec![];
        query_list = iotas
            .par_iter()
            .map(|iota_s| {
                let mut layers_evaluations_sym = Vec::new();
                let mut layers_auth_paths_sym = Vec::new();

                let mut index = *iota_s;
                for layer in fri_layers {
                    // symmetric element
                    let evaluation_sym = layer.evaluation[index ^ 1].clone();
                    let auth_path_sym = layer.merkle_tree.get_proof_by_pos(index >> 1);
                    layers_evaluations_sym.push(evaluation_sym);
                    layers_auth_paths_sym.push(auth_path_sym);

                    index >>= 1;
                }

                FriDecommitment {
                    layers_auth_paths: layers_auth_paths_sym,
                    layers_evaluations_sym,
                }
            })
            .collect();

        println!("How can this be slow {:?}", start.elapsed());

        query_list
    } else {
        vec![]
    }
}

pub fn verify_fri_query(
    last_value: FE,
    merkle_roots: &[[u8; 32]],
    fri_decommitment: &FriDecommitment<F>,
    iota: usize,
    evaluation: FE,
    evaluation_sym: FE,
    roots_of_unity: &[FE],
) -> bool {
    // Get zeta from Fiat-Shamir
    let public_input_data = vec![]; // hopefully it's safe
    let mut transcript = StoneProverTranscript::new(&public_input_data);

    let mut zetas = merkle_roots
        .iter()
        .map(|root| {
            // >>>> Send challenge 𝜁ₖ
            transcript.append_bytes(root);
            let element = transcript.sample_field_element();
            // <<<< Receive commitment: [pₖ] (the first one is [p₀])
            element
        })
        .collect::<Vec<FE>>();


    zetas.push(transcript.sample_field_element());

    // Start verifying, reconstruct every layer
    let evaluation_point = roots_of_unity[reverse_index(iota, roots_of_unity.len() as u64)].clone();

    let evaluation_point_inv = evaluation_point.inv().unwrap();
    let evaluation_point_vec: Vec<FE> = 
        core::iter::successors(Some(evaluation_point_inv), |evaluation_point| {
            Some(evaluation_point.square())
        })
        .take(merkle_roots.len())
        .collect();

    let mut v = evaluation;
    let mut index = iota;
    let FE_two_inv = FieldElement::<F>::from(2).inv().unwrap();

    merkle_roots
        .iter()
        .enumerate()
        .zip(&fri_decommitment.layers_auth_paths)
        .zip(&fri_decommitment.layers_evaluations_sym)
        .zip(evaluation_point_vec)
        .fold(
            true,
            |result,
            (
                (((i, merkle_root), auth_path_sym), evaluation_sym),
                evaluation_point_inv,
            )| {
                let openings_ok = verify_fri_layer_openings(
                    merkle_root,
                    auth_path_sym,
                    &v,
                    evaluation_sym,
                    index,
                );

                v = FE_two_inv * ((&v + evaluation_sym) + evaluation_point_inv *  &zetas[i] * (&v - evaluation_sym));

                // Update index for next iteration. The index of the squares in the next layer
                // is obtained by halving the current index. This is due to the bit-reverse
                // ordering of the elements in the Merkle tree.
                index >>= 1;

                if i < fri_decommitment.layers_evaluations_sym.len() - 1 {
                    result & openings_ok
                } else {
                    // Check that final value is the given by the prover
                    result & (v == last_value) & openings_ok
                }
            }
        )
}

pub fn verify_fri_layer_openings(
    merkle_root: &Commitment,
    auth_path_sym: &Proof<Commitment>,
    evaluation: &FE,
    evaluation_sym: &FE,
    iota: usize,
) -> bool
{
    let evaluations = if iota % 2 == 1 {
        vec![evaluation_sym.clone(), evaluation.clone()]
    } else {
        vec![evaluation.clone(), evaluation_sym.clone()]
    };

    auth_path_sym.verify::<BatchedMerkleTreeBackend<F>>(
        merkle_root,
        iota >> 1,
        &evaluations,
    )
}


pub fn fold_polynomial(
    poly: &Polynomial<FE>,
    beta: &FE,
) -> Polynomial<FE>
{
    let coef = poly.coefficients();
    let even_coef: Vec<FE> = coef.iter().step_by(2).cloned().collect();

    // odd coeficients of poly are multiplied by beta
    let odd_coef_mul_beta: Vec<FE> = coef
        .iter()
        .skip(1)
        .step_by(2)
        .map(|v| (v.clone()) * beta)
        .collect();

    let (even_poly, odd_poly) = polynomial::pad_with_zero_coefficients(
        &Polynomial::new(&even_coef),
        &Polynomial::new(&odd_coef_mul_beta),
    );
    let FE_two = FE::one() + FE::one();

    even_poly + odd_poly
}

pub fn send_fri<IO: AbstractChannel>(io: &mut IO, last_value: FE, fri_layers: &Vec<FriLayer>, comm: &mut u64) {
    *comm += send_stark252(io, &[last_value]).expect("Failed to send last value for commitment");
    let num_layers = fri_layers.len();
    *comm += send_u8(io, &(num_layers as u64).to_le_bytes()).expect("Failed to send num_layers commitment");
    for fri_layer in fri_layers.iter() {
        let serialized = serde_json::to_vec(fri_layer).expect("Failed to serialize fri layer");
        *comm += send_u8(io, &serialized).expect("Failed to send fri layers");
    }
}

pub fn receive_fri<IO: AbstractChannel>(io: &mut IO, comm: &mut u64) -> (FE, Vec<FriLayer>) {
    let last_value = receive_stark252(io).expect("Failed to receive P fri last value")[0];
    let num_layers = u64::from_le_bytes(receive_u8(io).unwrap().try_into().unwrap()) as usize;

    let mut fri_layers: Vec<FriLayer> = Vec::with_capacity(num_layers as usize);
    for i in 0..num_layers {
        let fri_layer_serialized = receive_u8(io).expect("Failed to receive P fri layer");
        fri_layers.push(serde_json::from_slice(&fri_layer_serialized).expect("Failed to deserialize P fri layer"));
    }

    (last_value, fri_layers)
}

pub fn send_decommit<IO: AbstractChannel>(io: &mut IO, decommits: &Vec<FriDecommitment<F>>, comm: &mut u64) {
    let serialized_data = serde_json::to_vec(&decommits).expect("Failed to serialize FriDecommitments");
    *comm += send_u8(io, &serialized_data).expect("Failed to send decommitments");
}

pub fn receive_decommit<IO: AbstractChannel>(io: &mut IO, comm: &mut u64) -> Vec<FriDecommitment<F>> {
    let serialized_data = receive_u8(io).expect("Failed to receive decommitments");
    serde_json::from_slice(&serialized_data).expect("Cannot deserialize decommitments")
}

pub fn send_merkle_path<IO: AbstractChannel>(io: &mut IO, merkle_path: &Vec<Proof<Commitment>>, comm: &mut u64) {
    let serialized_data = serde_json::to_vec(&merkle_path).expect("Failed to serialize Merkle path");
    *comm += send_u8(io, &serialized_data).expect("Failed to send Merkle paths");
}

pub fn receive_merkle_path<IO: AbstractChannel>(io: &mut IO, comm: &mut u64) -> Vec<Proof<Commitment>> {
    let serialized_data = receive_u8(io).expect("Failed to receive Merkle paths");
    serde_json::from_slice(&serialized_data).expect("Cannot deserialize Merkle paths")
}