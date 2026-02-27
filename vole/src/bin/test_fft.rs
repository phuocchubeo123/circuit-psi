extern crate psi_vole;
extern crate lambdaworks_math;
extern crate stark_platinum_prover;
extern crate rayon;

use psi_vole::utils::{rand_field_element, parallel_fft};
use psi_vole::fri::fold_polynomial;
use lambdaworks_math::fft::cpu::bit_reversing::{in_place_bit_reverse_permute, reverse_index};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use stark_platinum_prover::fri::Polynomial;
use rayon::prelude::*;
use std::time::Instant;

pub type FE = psi_vole::fourq_field::FourQScalarField;
pub type F = FE;

fn main() {
    let log_size: usize = 16;
    let log_blowup_factor = 0;
    let size = 1 << log_size;
    let p: Vec<FE> = (0..size).map(|_| rand_field_element()).collect();

    let poly = Polynomial::new(&p);

    let start = Instant::now();
    let evaluations = Polynomial::evaluate_fft::<F>(&poly, 1 << log_blowup_factor, None).unwrap();
    println!("Total time to evaluate: {:?}", start.elapsed());

    let roots_of_unity = get_powers_of_primitive_root_coset(
        (log_size + log_blowup_factor) as u64,
        size << log_blowup_factor as usize,
        &FE::one(),
    )
    .unwrap();
    let mut roots_of_unity_inv = roots_of_unity.clone();
    roots_of_unity_inv[1..].reverse();  

    let start = Instant::now();
    let ref2_evaluations = parallel_fft(&p, &roots_of_unity, log_size, log_blowup_factor);
    println!("Total time to parallel_fft: {:?}", start.elapsed());

    println!("Is parallel_fft equal to evaluate_fft? {}", evaluations == ref2_evaluations);


    // Also test folding
    let zeta = rand_field_element();
    let current_poly = poly.clone();

    let evals = parallel_fft(&current_poly.coefficients, &roots_of_unity, log_size, log_blowup_factor);

    let folded_poly = fold_polynomial(&current_poly, &zeta);
    let folded_roots_of_unity = get_powers_of_primitive_root_coset(
        (log_size + log_blowup_factor - 1) as u64,
        (size >> 1) << (log_blowup_factor) as usize,
        &FE::one(),
    ).unwrap();
    let folded_evals = parallel_fft(&folded_poly.coefficients, &folded_roots_of_unity, log_size-1, log_blowup_factor);

    let FE_two_inv = (FE::one() + FE::one()).inv().unwrap();

    let mut ref_folded_evals = vec![FE::zero(); 1 << (log_size + log_blowup_factor - 1)];
    for i in 0..folded_evals.len() {
        let even = evals[i];
        let odd = evals[i + (1 << (log_size + log_blowup_factor - 1))];
        let root_inv = roots_of_unity_inv[i];
        ref_folded_evals[i] = FE_two_inv * ((even + odd) + root_inv * zeta * (even - odd));
    }

    println!("Is folded_evals equal to ref_folded_evals? {}", folded_evals == ref_folded_evals);
}