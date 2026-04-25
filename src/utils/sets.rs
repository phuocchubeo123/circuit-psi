use std::collections::HashSet;

use eyre::Result;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

use crate::math::defines::FE;

fn derive_seed(shared_seed: [u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_seed);
    hasher.update(label);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sample_unique_values(rng: &mut StdRng, count: usize, seen: &mut HashSet<[u8; 32]>) -> Vec<FE> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        if !seen.insert(bytes) {
            continue;
        }
        out.push(FE::from_bytes_le_mod_order(&bytes));
    }
    out
}

fn shuffle_values(rng: &mut StdRng, values: &mut [FE]) {
    for i in (1..values.len()).rev() {
        let j = rng.random_range(0..=i);
        values.swap(i, j);
    }
}

pub fn sample_correlated_sets(
    shared_seed: [u8; 32],
    set_size: usize,
    intersection_size: usize,
) -> Result<(Vec<FE>, Vec<FE>)> {
    eyre::ensure!(set_size > 0, "set size must be > 0");
    eyre::ensure!(
        intersection_size <= set_size,
        "intersection size {} exceeds set size {}",
        intersection_size,
        set_size
    );

    let mut seen = HashSet::with_capacity(2 * set_size - intersection_size);

    let mut common_rng = StdRng::from_seed(derive_seed(shared_seed, b"common-set"));
    let common = sample_unique_values(&mut common_rng, intersection_size, &mut seen);

    let mut sender_only_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-only-set"));
    let sender_only = sample_unique_values(
        &mut sender_only_rng,
        set_size - intersection_size,
        &mut seen,
    );

    let mut receiver_only_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-only-set"));
    let receiver_only = sample_unique_values(
        &mut receiver_only_rng,
        set_size - intersection_size,
        &mut seen,
    );

    let mut sender_set = common.clone();
    sender_set.extend(sender_only);
    let mut receiver_set = common;
    receiver_set.extend(receiver_only);

    let mut sender_shuffle_rng = StdRng::from_seed(derive_seed(shared_seed, b"sender-shuffle"));
    shuffle_values(&mut sender_shuffle_rng, &mut sender_set);

    let mut receiver_shuffle_rng = StdRng::from_seed(derive_seed(shared_seed, b"receiver-shuffle"));
    shuffle_values(&mut receiver_shuffle_rng, &mut receiver_set);

    Ok((sender_set, receiver_set))
}
