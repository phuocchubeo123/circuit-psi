// takes 2ms to run 100_000 to_bytes_le()
// take 500ns to run 100_000 plus
// take 500ns to run 100_000 mult

extern crate lambdaworks_math;
extern crate rand;

use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use lambdaworks_math::traits::ByteConversion;
use rand::random;
use std::time::Instant;

pub type FE = psi_vole::fourq_field::FourQScalarField;

pub fn rand_field_element() -> FE {
    loop {
        let bytes = rand::random::<[u8; 32]>();
        if let Ok(fe) = FE::from_bytes_le(&bytes) {
            return fe;
        }
    }
}

fn main() {
    const size: usize = 100000;
    let mut x = [FE::zero(); size];
    for i in 0..size {
        x[i] = rand_field_element();
    }


    let mut y = [[0u8; 32]; size];

    let start = Instant::now();

    for i in 0..size {
        y[i] = x[i].to_bytes_le();
    }

    let duration = start.elapsed();
    println!("Time taken for {} iterations: {:?}", size, duration);

    let mut u = FE::zero();
    let start = Instant::now();

    for i in 0..size {
        u += x[i];
    }

    let duration = start.elapsed();
    println!("Time taken for {} iterations: {:?}", size, duration);

    let mut v = FE::one();
    let start = Instant::now();

    for i in 0..size {
        v *= x[i];
    }

    let duration = start.elapsed();
    println!("Time taken for {} iterations: {:?}", size, duration);

    let mut mem = [[FE::zero(); 16]; 600];
    for i in 0..600 {
        for j in 0..16 {
            mem[i][j] = rand_field_element();
        }
    }

    let mut dest = [FE::zero(); 16];
    let start = Instant::now();

    for i in 0..600 {
        dest.copy_from_slice(&mem[i]);
    }

    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);
}
