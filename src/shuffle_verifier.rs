use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple, batch_multiply_interactive,
        comm_util::{receive_fe, receive_fe_vec},
        defines::{FE, random_fe_vec_from_rng},
        open_values_receive, open_values_send, receive_share_values, share_values,
        take_vec_prod_interactive,
    },
    group::{Group, msm_pippenger, receive_group_elements, send_group_elements},
    tcp_channel::TcpChannel,
};
use anyhow::{Result, anyhow, ensure};
use rand::{RngExt, SeedableRng, rngs::StdRng};

fn powers(base: FE, n: usize) -> Vec<FE> {
    let mut out = Vec::with_capacity(n);
    if n == 0 {
        return out;
    }
    out.push(FE::one());
    for _ in 1..n {
        let next = *out.last().unwrap() * base;
        out.push(next);
    }
    out
}

fn checked_permute<T: Clone>(vals: &[T], permutation: &[usize]) -> Result<Vec<T>> {
    ensure!(
        permutation.len() == vals.len(),
        "Permutation length mismatch: permutation has {}, values have {}",
        permutation.len(),
        vals.len()
    );
    let mut out = Vec::with_capacity(vals.len());
    for &idx in permutation {
        ensure!(
            idx < vals.len(),
            "Permutation index {} out of range {}",
            idx,
            vals.len()
        );
        out.push(vals[idx].clone());
    }
    Ok(out)
}

pub fn shuffle_verifier_step1(
    authenticated_key: &BeDOZa,
    prepared_bedoza_shares: &[BeDOZa],
    prepared_randomness: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    // Step 1: Given inputs x1, x2, ..., xn
    // We want to obtain shares for 1 / (k + x1), 1 / (k + x2), ..., where k is an authenticated key

    // First, receive shares for x1, x2, ..., xn from the prover
    let bedoza_shared = receive_share_values(prepared_bedoza_shares, channel)
        .map_err(|e| anyhow!("Failed to receive shared values using BeDOZa: {}", e))?;

    // Next, obtain shares for 1/(k+x1), 1/(k+x2), ...
    // First obtain shares for (k+x1), (k+x2), ...
    let k_plus_x_shares: Vec<BeDOZa> = bedoza_shared
        .iter()
        .map(|share| share + authenticated_key)
        .collect();

    // Multiply (k+x1), (k+x2), ... with the prepared randomness to get shares for (k+x1)*r1, (k+x2)*r2, ...
    let r_times_k_plus_x_shares = batch_multiply_interactive(
        &k_plus_x_shares,
        prepared_randomness,
        prepared_triple_shares,
        channel,
    )
    .map_err(|e| anyhow!("Failed to batch multiply (k+xi) with randomness: {}", e))?;

    // Open the shares of (k+xi)*ri to both parties
    // Sending verifier share to prover
    open_values_send(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to send (k+xi)*ri shares: {}", e))?;
    // Receive prover share from prover
    let r_times_k_plus_x_value: Vec<FE> = open_values_receive(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to open (k+xi)*ri shares: {}", e))?;

    // Inverse the opened values to get 1/((k+xi)*ri)
    let inv_r_times_k_plus_x_value: Vec<FE> = r_times_k_plus_x_value
        .iter()
        .map(|&val| {
            val.inv()
                .map_err(|e| anyhow!("Failed to invert (k+xi)*ri value: {:?}", e))
        })
        .collect::<Result<Vec<FE>>>()?;

    // Multiply the inverted values with the randomness ri to get shares for 1/(k+xi)
    let inv_k_plus_x_shares: Vec<BeDOZa> = prepared_randomness
        .iter()
        .zip(inv_r_times_k_plus_x_value.iter())
        .map(|(rand_share, &inv_val)| rand_share * inv_val)
        .collect();

    Ok(inv_k_plus_x_shares)
}

pub fn shuffle_verifier_step2_permutation_commit(
    permutation: &[usize],
    prepared_permutation_shares: &[BeDOZa],
    prepared_permutation_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<(Vec<BeDOZa>, Vec<BeDOZa>)> {
    ensure!(
        permutation.len() == prepared_permutation_shares.len(),
        "Permutation/prepared share length mismatch: {} vs {}",
        permutation.len(),
        prepared_permutation_shares.len()
    );

    // Commit the permutation values as field elements.
    let permutation_fe: Vec<FE> = permutation
        .iter()
        .map(|&idx| FE::from(idx as u64))
        .collect();
    let permuted_shares = share_values(&permutation_fe, prepared_permutation_shares, channel)
        .map_err(|e| anyhow!("Failed to share permutation using BeDOZa: {}", e))?;

    // Receive challenge x from prover and commit to x^pi(i).
    let x = receive_fe(channel).map_err(|e| anyhow!("Failed to receive x challenge: {}", e))?;
    let x_pows = powers(x, permutation.len());
    let permuted_x_powers = checked_permute(&x_pows, permutation)?;
    let permuted_x_powers_shares =
        share_values(&permuted_x_powers, prepared_permutation_shares, channel)
            .map_err(|e| anyhow!("Failed to share permuted x powers using BeDOZa: {}", e))?;

    // Receive r, a challenges from prover.
    let challenges = receive_fe_vec(channel)
        .map_err(|e| anyhow!("Failed to receive permutation challenges: {}", e))?;
    ensure!(
        challenges.len() == 2,
        "Expected exactly 2 permutation challenges (r, a), got {}",
        challenges.len()
    );
    let r = challenges[0];
    let a = challenges[1];

    // Open product of (a * pi(i) + x^pi(i) - r) to prover.
    let permutation_minus_r_share: Vec<BeDOZa> = permuted_shares
        .iter()
        .zip(permuted_x_powers_shares.iter())
        .map(|(perm_share, x_power_share)| *perm_share * a + *x_power_share - r)
        .collect();

    let permutation_minus_r_prod = take_vec_prod_interactive(
        &permutation_minus_r_share,
        prepared_permutation_triple_shares,
        channel,
    )
    .map_err(|e| {
        anyhow!(
            "Failed to compute product share for permutation verification: {}",
            e
        )
    })?;

    open_values_send(&[permutation_minus_r_prod], channel)
        .map_err(|e| anyhow!("Failed to send permutation product share: {}", e))?;

    Ok((permuted_shares, permuted_x_powers_shares))
}

pub fn shuffle_verifier_multiexponentiation_proof(
    exp_shares: &[BeDOZa],
    bases: &[Group],
    channel: &mut TcpChannel,
) -> Result<()> {
    ensure!(
        !exp_shares.is_empty(),
        "Cannot prove with empty exponent shares"
    );
    ensure!(
        exp_shares.len() == bases.len(),
        "Length mismatch between exponent shares and bases: lhs = {}, rhs = {}",
        exp_shares.len(),
        bases.len()
    );

    // Each exponent has two shares, the prover already has one share.
    // The verifier sends the multiexponentiation with its own sender share and pad share.
    let exp_senders: Vec<FE> = exp_shares
        .iter()
        .map(|share| share.bedoza_sender().val())
        .collect();
    let exp_pad_senders: Vec<FE> = exp_shares
        .iter()
        .map(|share| share.bedoza_sender().pad())
        .collect();

    let multiexp_exp_sender = msm_pippenger(bases, &exp_senders).map_err(|e| {
        anyhow!(
            "Failed to compute multiexponentiation for exp shares: {}",
            e
        )
    })?;
    let multiexp_pad_sender = msm_pippenger(bases, &exp_pad_senders).map_err(|e| {
        anyhow!(
            "Failed to compute multiexponentiation for pad shares: {}",
            e
        )
    })?;

    send_group_elements(&[multiexp_exp_sender, multiexp_pad_sender], channel)
        .map_err(|e| anyhow!("Failed to send multiexponentiation proof elements: {}", e))?;

    Ok(())
}

pub fn shuffle_verifier_share_s(
    s: FE,
    prepared_s_share: &BeDOZa,
    prepared_s_inv_share: &BeDOZa,
    prepared_s_consistency_triple: &BeDOZaTriple,
    channel: &mut TcpChannel,
) -> Result<(BeDOZa, BeDOZa)> {
    let s_share = share_values(&[s], &[*prepared_s_share], channel)
        .map_err(|e| anyhow!("Failed to share mask s with prover: {}", e))?[0];

    let s_inv = s
        .inv()
        .map_err(|e| anyhow!("Failed to invert mask s for sharing: {:?}", e))?;
    let s_inv_share = share_values(&[s_inv], &[*prepared_s_inv_share], channel)
        .map_err(|e| anyhow!("Failed to share inverse mask s with prover: {}", e))?[0];

    // Prove correctness of inverse by opening (s * s_inv).
    let s_consistency = batch_multiply_interactive(
        &[s_share],
        &[s_inv_share],
        &[*prepared_s_consistency_triple],
        channel,
    )
    .map_err(|e| anyhow!("Failed to compute mask consistency proof: {}", e))?[0];
    open_values_send(&[s_consistency], channel)
        .map_err(|e| anyhow!("Failed to open mask consistency proof: {}", e))?;

    Ok((s_share, s_inv_share))
}

pub fn shuffle_verifier_step2(
    u: &[BeDOZa],
    permutation: &[usize],
    prepared_permutation_shares: &[BeDOZa],
    prepared_permutation_triple_shares: &[BeDOZaTriple],
    prepared_s_share: &BeDOZa,
    prepared_s_inv_share: &BeDOZa,
    prepared_s_consistency_triple: &BeDOZaTriple,
    prepared_x_powers_divided_by_s_triples: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<Group>> {
    ensure!(
        !u.is_empty(),
        "Cannot run shuffle protocol with empty input"
    );
    ensure!(
        permutation.len() == u.len(),
        "Permutation length mismatch: {} vs {}",
        permutation.len(),
        u.len()
    );

    // Receive g^u1_sender, g^u2_sender, ... from prover and verify authentication consistency.
    let g_u_senders = receive_group_elements(channel)
        .map_err(|e| anyhow!("Failed to receive g^ui from prover: {}", e))?;
    ensure!(
        g_u_senders.len() == u.len(),
        "Sender exponentiation length mismatch: expected {}, got {}",
        u.len(),
        g_u_senders.len()
    );

    // Sample challenge seed and send to prover.
    let mut rng = rand::rng();
    let challenge_seed: [u8; 32] = rng.random::<[u8; 32]>();
    channel
        .send(&challenge_seed)
        .map_err(|e| anyhow!("Failed to send challenge seed to prover: {}", e))?;
    let mut seeded_rng = StdRng::from_seed(challenge_seed);
    let random_coeffs = random_fe_vec_from_rng(&mut seeded_rng, u.len())
        .map_err(|e| anyhow!("Failed to generate random coefficients from seed: {}", e))?;

    // Receive prover's batched pad multiexp and verify tag equation.
    let multi_exp_pad_u_prover = receive_group_elements(channel).map_err(|e| {
        anyhow!(
            "Failed to receive multi-exponentiation for pads from prover: {}",
            e
        )
    })?;
    ensure!(
        multi_exp_pad_u_prover.len() == 1,
        "Expected one prover pad multiexponentiation element, got {}",
        multi_exp_pad_u_prover.len()
    );
    let multi_exp_pad_u_prover = multi_exp_pad_u_prover[0].clone();

    let multi_exp_u_prover = msm_pippenger(&g_u_senders, &random_coeffs).map_err(|e| {
        anyhow!(
            "Failed to compute multi-exponentiation for g^ui_sender: {}",
            e
        )
    })?;
    let tag_prover_scalar_sum = u
        .iter()
        .zip(random_coeffs.iter())
        .map(|(share, &coeff)| share.bedoza_receiver().tag() * coeff)
        .fold(FE::zero(), |acc, val| acc + val);
    let multi_exp_tag_prover = Group::base_point().scalar_mul(&tag_prover_scalar_sum);

    let key_u_prover = u[0].bedoza_receiver().key();
    for (i, share) in u.iter().enumerate() {
        ensure!(
            share.bedoza_receiver().key() == key_u_prover,
            "MAC key mismatch in prover share {}",
            i
        );
    }
    let expected_multi_exp = multi_exp_u_prover.scalar_mul(&key_u_prover) + multi_exp_pad_u_prover;
    ensure!(
        multi_exp_tag_prover.as_point() == expected_multi_exp.as_point(),
        "Verification failed for sender share exponentiation proof"
    );

    // Phase B / Step 2: commit permutation and x^pi(i).
    let (_permutation_shares, permuted_x_powers_shares) =
        shuffle_verifier_step2_permutation_commit(
            permutation,
            prepared_permutation_shares,
            prepared_permutation_triple_shares,
            channel,
        )
        .map_err(|e| anyhow!("Failed in permutation commitment step: {}", e))?;

    // Share mask s and inverse.
    let mut s = random_fe_vec_from_rng(&mut seeded_rng, 1)?[0];
    while s == FE::zero() {
        s = random_fe_vec_from_rng(&mut seeded_rng, 1)?[0];
    }
    let (_s_share, s_inv_share) = shuffle_verifier_share_s(
        s,
        prepared_s_share,
        prepared_s_inv_share,
        prepared_s_consistency_triple,
        channel,
    )
    .map_err(|e| anyhow!("Failed to share s/s_inv: {}", e))?;

    // Phase B / Step 3: send masked/permuted sender-share batch.
    let permuted_g_u_senders = checked_permute(&g_u_senders, permutation)?;
    let masked_permuted_g_u_senders: Vec<Group> = permuted_g_u_senders
        .iter()
        .map(|g| g.scalar_mul(&s))
        .collect();
    send_group_elements(&masked_permuted_g_u_senders, channel)
        .map_err(|e| anyhow!("Failed to send masked/permuted sender batch: {}", e))?;

    // Build authenticated exponents x^pi(i)/s and prove multiexponentiation consistency.
    let x_powers_divided_by_s_shares = batch_multiply_interactive(
        &permuted_x_powers_shares,
        &vec![s_inv_share; permuted_x_powers_shares.len()],
        prepared_x_powers_divided_by_s_triples,
        channel,
    )
    .map_err(|e| anyhow!("Failed to compute shares for x^pi(i)/s: {}", e))?;
    shuffle_verifier_multiexponentiation_proof(
        &x_powers_divided_by_s_shares,
        &masked_permuted_g_u_senders,
        channel,
    )
    .map_err(|e| {
        anyhow!(
            "Failed in multiexponentiation proof for shuffled sender batch: {}",
            e
        )
    })?;

    // Phase B / Step 4: send masked/permuted receiver-share batch.
    let u_verifier_vals: Vec<FE> = u.iter().map(|share| share.bedoza_sender().val()).collect();
    let permuted_u_verifier_vals = checked_permute(&u_verifier_vals, permutation)?;
    let masked_permuted_g_u_receivers: Vec<Group> = permuted_u_verifier_vals
        .iter()
        .map(|&val| Group::base_point().scalar_mul(&(val * s)))
        .collect();
    send_group_elements(&masked_permuted_g_u_receivers, channel)
        .map_err(|e| anyhow!("Failed to send masked/permuted receiver batch: {}", e))?;

    // Combine to masked outputs g_{pi(i)}^{u_{pi(i)} * s}.
    let masked_outputs: Vec<Group> = masked_permuted_g_u_senders
        .iter()
        .zip(masked_permuted_g_u_receivers.iter())
        .map(|(a, b)| a + b)
        .collect();

    // Phase B / Step 5: unmask with sigma = 1/s and send the final shuffled outputs.
    let sigma = s
        .inv()
        .map_err(|e| anyhow!("Failed to invert s while finalizing outputs: {:?}", e))?;
    let final_outputs: Vec<Group> = masked_outputs
        .iter()
        .map(|m| m.scalar_mul(&sigma))
        .collect();
    send_group_elements(&final_outputs, channel)
        .map_err(|e| anyhow!("Failed to send final shuffled outputs: {}", e))?;

    Ok(final_outputs)
}
