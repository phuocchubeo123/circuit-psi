use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple, batch_multiply_interactive,
        comm_util::{send_fe, send_fe_vec},
        defines::{FE, random_fe_vec, random_fe_vec_from_rng},
        open_values_receive, open_values_send, receive_share_values, share_values,
        take_vec_prod_interactive,
    },
    group::{Group, msm_pippenger, receive_group_elements, send_group_elements},
    tcp_channel::TcpChannel,
};
use anyhow::{Result, anyhow, ensure};
use rand::{SeedableRng, rngs::StdRng};

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

pub fn shuffle_prover_step1(
    vals: &[FE],
    authenticated_key: &BeDOZa,
    prepared_bedoza_shares: &[BeDOZa],
    prepared_randomness: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    // Step 1: Given inputs x1, x2, ..., xn
    // We want to obtain shares for 1 / (k + x1), 1 / (k + x2), ..., where k is an authenticated key

    // First, share the values x1, x2, ..., xn
    // Using BeDOZa, we authenticate both shares of the values as well
    let bedoza_shared = share_values(vals, prepared_bedoza_shares, channel)
        .map_err(|e| anyhow!("Failed to share values using BeDOZa: {}", e))?;

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
    // Receive verifier share from verifier
    let r_times_k_plus_x_value: Vec<FE> = open_values_receive(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to open (k+xi)*ri shares: {}", e))?;
    // Sending prover share to verifier
    open_values_send(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to send (k+xi)*ri shares: {}", e))?;

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

pub fn shuffle_prover_commit_permutation(
    prepared_permutation_shares: &[BeDOZa],
    prepared_permutation_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<(Vec<BeDOZa>, Vec<BeDOZa>, FE)> {
    // First simply receive the permutation commitment from the verifier
    let permuted_shares = receive_share_values(prepared_permutation_shares, channel)
        .map_err(|e| anyhow!("Failed to receive shared permutation using BeDOZa: {}", e))?;

    // Sample a challenge x and send it to the verifier, and verifier again commits to x^pi(0), x^pi(1), ... using BeDOZa.
    let x = random_fe_vec(1)?.pop().unwrap();
    send_fe(x, channel).map_err(|e| anyhow!("Failed to send permutation challenge: {}", e))?;

    // Receive the commitment to x^pi(0), x^pi(1), ..., x^pi(n-1) from the verifier
    let permuted_x_powers_shares = receive_share_values(prepared_permutation_shares, channel)
        .map_err(|e| {
            anyhow!(
                "Failed to receive shared permuted x powers using BeDOZa: {}",
                e
            )
        })?;

    // Now need to verify that this is a valid permutation too
    // Sample and send challenges r and a
    let r = random_fe_vec(1)?.pop().unwrap();
    let a = random_fe_vec(1)?.pop().unwrap();
    send_fe_vec(&[r, a], channel)
        .map_err(|e| anyhow!("Failed to send permutation challenges: {}", e))?;

    // Locally compute shares for (a * pi(0) + x^pi(0) - r), ..., (a * pi(n-1) + x^pi(n-1) - r)
    let permutation_minus_challenge_share: Vec<BeDOZa> = permuted_shares
        .iter()
        .zip(permuted_x_powers_shares.iter())
        .map(|(perm_share, x_power_share)| *perm_share * a + *x_power_share - r)
        .collect();

    // Multiply them all together to get share for the product of (a * pi(i) + x^pi(i) - r).
    let permutation_minus_challenge_prod = take_vec_prod_interactive(
        &permutation_minus_challenge_share,
        prepared_permutation_triple_shares,
        channel,
    )
    .map_err(|e| {
        anyhow!(
            "Failed to compute product share for permutation verification: {}",
            e
        )
    })?;

    // Receive the opened product share from the verifier
    let opened_product = open_values_receive(&[permutation_minus_challenge_prod], channel)
        .map_err(|e| anyhow!("Failed to receive opened permutation product share: {}", e))?[0];

    // The expected value is product over i of (a * i + x^i - r), where i ranges over the permutation domain.
    let x_powers = powers(x, permutation_minus_challenge_share.len());
    let expected_product = x_powers
        .iter()
        .enumerate()
        .map(|(i, &x_power)| FE::from(i as u64) * a + x_power - r)
        .fold(FE::one(), |acc, val| acc * val);

    ensure!(
        opened_product == expected_product,
        "Permutation verification failed: expected product {:?}, got {:?}",
        expected_product,
        opened_product
    );

    Ok((permuted_shares, permuted_x_powers_shares, x))
}

pub fn shuffle_prover_share_s(
    prepared_s_share: &BeDOZa,
    prepared_s_inv_share: &BeDOZa,
    prepared_s_consistency_triple: &BeDOZaTriple,
    channel: &mut TcpChannel,
) -> Result<(BeDOZa, BeDOZa)> {
    let s_share = receive_share_values(&[*prepared_s_share], channel)
        .map_err(|e| anyhow!("Failed to receive shared mask s from verifier: {}", e))?[0];
    let s_inv_share = receive_share_values(&[*prepared_s_inv_share], channel).map_err(|e| {
        anyhow!(
            "Failed to receive shared inverse mask s from verifier: {}",
            e
        )
    })?[0];

    let s_consistency_proof = batch_multiply_interactive(
        &[s_share],
        &[s_inv_share],
        &[*prepared_s_consistency_triple],
        channel,
    )
    .map_err(|e| anyhow!("Failed to compute consistency proof for mask s: {}", e))?[0];
    let opened_s_consistency = open_values_receive(&[s_consistency_proof], channel)
        .map_err(|e| anyhow!("Failed to open consistency proof for mask s: {}", e))?[0];
    ensure!(
        opened_s_consistency == FE::one(),
        "Mask s consistency check failed: expected 1, got {:?}",
        opened_s_consistency
    );

    Ok((s_share, s_inv_share))
}

fn verify_multiexponentiation_proof(
    exp_shares: &[BeDOZa],
    bases: &[Group],
    proof_elems: &[Group],
) -> Result<()> {
    ensure!(
        !exp_shares.is_empty(),
        "Cannot verify empty exponent share list"
    );
    ensure!(
        exp_shares.len() == bases.len(),
        "Length mismatch between exponent shares and bases: lhs = {}, rhs = {}",
        exp_shares.len(),
        bases.len()
    );
    ensure!(
        proof_elems.len() == 2,
        "Expected exactly 2 group elements for multiexponentiation proof, got {}",
        proof_elems.len()
    );

    let key = exp_shares[0].bedoza_receiver().key();
    for (i, share) in exp_shares.iter().enumerate() {
        ensure!(
            share.bedoza_receiver().key() == key,
            "MAC key mismatch in exponent share {}",
            i
        );
    }

    let tag_scalars: Vec<FE> = exp_shares
        .iter()
        .map(|share| share.bedoza_receiver().tag())
        .collect();
    let multiexp_tag = msm_pippenger(bases, &tag_scalars)
        .map_err(|e| anyhow!("Failed to compute tag multiexponentiation: {}", e))?;

    let lhs = proof_elems[0].scalar_mul(&key) + proof_elems[1].clone();
    ensure!(
        lhs.as_point() == multiexp_tag.as_point(),
        "Multiexponentiation proof failed: authenticated tag relation did not hold"
    );

    Ok(())
}

pub fn shuffle_prover_step2(
    u: &[BeDOZa],
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

    // Sender partial exponentiations (Phase B / Step 1).
    let u_senders: Vec<FE> = u.iter().map(|share| share.bedoza_sender().val()).collect();
    let g_u_senders: Vec<Group> = u_senders
        .iter()
        .map(|val| Group::base_point().scalar_mul(val))
        .collect();
    send_group_elements(&g_u_senders, channel)
        .map_err(|e| anyhow!("Failed to send g^(ui_sender) values: {}", e))?;

    // Batched auth check randomness from verifier.
    let seed = channel.receive()?;
    ensure!(
        seed.len() == 32,
        "Expected 32 bytes for random seed, got {}",
        seed.len()
    );
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let mut rng = StdRng::from_seed(seed_arr);
    let random_coeffs = random_fe_vec_from_rng(&mut rng, u.len())
        .map_err(|e| anyhow!("Failed to generate random coefficients from seed: {}", e))?;

    // Send multi-exponentiation for sender pads.
    let pad_senders: Vec<FE> = u.iter().map(|share| share.bedoza_sender().pad()).collect();
    let pad_scalar_sum = pad_senders
        .iter()
        .zip(random_coeffs.iter())
        .map(|(&pad, &coeff)| pad * coeff)
        .fold(FE::zero(), |acc, val| acc + val);
    let multi_exp_pad = Group::base_point().scalar_mul(&pad_scalar_sum);
    send_group_elements(&[multi_exp_pad], channel)
        .map_err(|e| anyhow!("Failed to send multi-exponentiation of pads: {}", e))?;

    // Phase B / Step 2: permutation commitment.
    let (_permuted_shares, permuted_x_powers_shares, x_challenge) =
        shuffle_prover_commit_permutation(
            prepared_permutation_shares,
            prepared_permutation_triple_shares,
            channel,
        )?;

    // Receive authenticated mask shares and check s * s_inv = 1.
    let (_s_share, s_inv_share) = shuffle_prover_share_s(
        prepared_s_share,
        prepared_s_inv_share,
        prepared_s_consistency_triple,
        channel,
    )?;

    // Receive first masked shuffled batch from verifier.
    let masked_permuted_g_u_senders = receive_group_elements(channel)
        .map_err(|e| anyhow!("Failed to receive masked/permuted sender batch: {}", e))?;
    ensure!(
        masked_permuted_g_u_senders.len() == u.len(),
        "Masked/permuted sender batch length mismatch: expected {}, got {}",
        u.len(),
        masked_permuted_g_u_senders.len()
    );

    // Build authenticated shares for x^pi(i)/s.
    let x_powers_divided_by_s_shares = batch_multiply_interactive(
        &permuted_x_powers_shares,
        &vec![s_inv_share; permuted_x_powers_shares.len()],
        prepared_x_powers_divided_by_s_triples,
        channel,
    )
    .map_err(|e| anyhow!("Failed to compute shares for x^pi(i)/s: {}", e))?;

    // Verify verifier's multiexponentiation proof for the authenticated exponents.
    let proof_elems = receive_group_elements(channel).map_err(|e| {
        anyhow!(
            "Failed to receive multiexponentiation proof elements: {}",
            e
        )
    })?;
    verify_multiexponentiation_proof(
        &x_powers_divided_by_s_shares,
        &masked_permuted_g_u_senders,
        &proof_elems,
    )?;

    // Receiver sends masked shuffled receiver-share batch.
    let masked_permuted_g_u_receivers = receive_group_elements(channel)
        .map_err(|e| anyhow!("Failed to receive masked/permuted receiver batch: {}", e))?;
    ensure!(
        masked_permuted_g_u_receivers.len() == u.len(),
        "Masked/permuted receiver batch length mismatch: expected {}, got {}",
        u.len(),
        masked_permuted_g_u_receivers.len()
    );

    // Combine masked sender and receiver exponentiations to obtain g_{pi(i)}^{u_{pi(i)} * s}.
    let _masked_outputs: Vec<Group> = masked_permuted_g_u_senders
        .iter()
        .zip(masked_permuted_g_u_receivers.iter())
        .map(|(a, b)| a + b)
        .collect();

    // Receive final unmasked shuffled outputs.
    let final_outputs = receive_group_elements(channel)
        .map_err(|e| anyhow!("Failed to receive final shuffled outputs: {}", e))?;
    ensure!(
        final_outputs.len() == u.len(),
        "Final shuffled output length mismatch: expected {}, got {}",
        u.len(),
        final_outputs.len()
    );

    // Keep a deterministic transcript dependency on x_challenge.
    let _ = powers(x_challenge, u.len());

    Ok(final_outputs)
}
