use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple, batch_multiply, bedoza_receiver::BeDOZaReceiver, bedoza_sender::{BeDOZaSender, share_values_sender}, comm_util::{receive_fe, receive_fe_vec}, defines::{FE, random_fe_vec_from_rng}, open_values_receive, open_values_send, receive_share_values, share_values, take_vec_prod
    }, 
    group::{Group, msm_pippenger, receive_group_elements, send_group_elements}, 
    tcp_channel::TcpChannel
};
use rand::{RngExt, rngs::StdRng, SeedableRng};
use anyhow::{ensure, anyhow, Result};

pub fn shuffle_verifier_step1(
    authenticated_key: &BeDOZa,
    prepared_bedoza_shares: &[BeDOZa],
    prepared_randomness: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel
) -> Result<Vec<BeDOZa>> {
    // Step 1: Given inputs x1, x2, ..., xn
    // We want to obtain shares for 1 / (k + x1), 1 / (k + x2), ..., where k is an authenticated key

    // First, receive shares for x1, x2, ..., xn from the prover
    let bedoza_shared = receive_share_values(prepared_bedoza_shares, channel)
        .map_err(|e| anyhow!("Failed to receive shared values using BeDOZa: {}", e))?;

    // Next, obtain shares for 1/(k+x1), 1/(k+x2), ...
    // First obtain shares for (k+x1), (k+x2), ...
    let k_plus_x_shares: Vec<BeDOZa> = bedoza_shared.iter()
        .map(|share| share + authenticated_key)
        .collect();

    // Multiply (k+x1), (k+x2), ... with the prepared randomness to get shares for (k+x1)*r1, (k+x2)*r2, ...
    let r_times_k_plus_x_shares = batch_multiply(&k_plus_x_shares, prepared_randomness, prepared_triple_shares, channel)
        .map_err(|e| anyhow!("Failed to batch multiply (k+xi) with randomness: {}", e))?;

    // Open the shares of (k+xi)*ri to both parties
    // Sending verifier share to prover
    open_values_send(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to send (k+xi)*ri shares: {}", e))?;
    // Receive prover share from prover
    let r_times_k_plus_x_value: Vec<FE> = open_values_receive(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to open (k+xi)*ri shares: {}", e))?;

    // Inverse the opened values to get 1/((k+xi)*ri)
    let inv_r_times_k_plus_x_value: Vec<FE> = r_times_k_plus_x_value.iter()
        .map(|&val| {
            val.inv()
                .map_err(|e| anyhow!("Failed to invert (k+xi)*ri value: {:?}", e))
        })
        .collect::<Result<Vec<FE>>>()?;

    // Multiply the inverted values with the randomness ri to get shares for 1/(k+xi)
    let inv_k_plus_x_shares: Vec<BeDOZa> = prepared_randomness.iter()
        .zip(inv_r_times_k_plus_x_value.iter())
        .map(|(rand_share, &inv_val)| {
            rand_share * inv_val
        })
        .collect();

    Ok(inv_k_plus_x_shares)
}

pub fn shuffle_verifier_step2_permutation_commit(
    permutation: &[usize],
    s: FE,
    s_inv: FE,
    s_share: &BeDOZa,
    s_inv_share: &BeDOZa,
    verifier_shares: &[BeDOZaSender],
    prepared_permutation_shares: &[BeDOZa],
    prepared_permutation_triple_shares: &[BeDOZaTriple],
    prepared_verifier_shares_times_s_triple: &[BeDOZaTriple],
    verifier_key: FE,
    channel: &mut TcpChannel,
) -> Result<(Vec<BeDOZa>, Vec<BeDOZa>)> {
    // This function not only commits a permutation pi(1), pi(2), ..., pi(n)
    // It also lets the prover send another random challenge x, and both commit to x^pi(1), x^pi(2), ..., x^pi(n), which is later useful for the shuffled OPRF itself
    // It would also let the prover send another random challenge y for the verifier_share_permute proving step, along with y's powers
    // Also commit to all permuted verifier shares * s, for the verifier_share_permute proving step
    // Everything is 0-indexed, so be careful when indexing

    // First simply commit this permutation
    let permutation_fe: Vec<FE> = permutation.iter().map(|&idx| FE::from(idx as u64)).collect();
    let permuted_shares = share_values(&permutation_fe, prepared_permutation_shares, channel)
        .map_err(|e| anyhow!("Failed to share permutation using BeDOZa: {}", e))?;

    //---------
    // Receive the challenges x and y from the prover, and commit to the secret-shared powers using BeDOZa
    let challenges = receive_fe_vec(channel)
        .map_err(|e| anyhow!("Failed to receive permutation challenge: {}", e))?;
    let x = challenges[0];
    let y = challenges[1];

    // Compute x^pi(1), x^pi(2), ..., x^pi(n)
    let mut non_permuted_x_powers = Vec::new();
    non_permuted_x_powers.push(x);
    for _ in 2..permutation.len() {
        non_permuted_x_powers.push(non_permuted_x_powers.last().unwrap() * x);
    }
    let permuted_x_powers: Vec<FE> = permutation.iter().map(|&idx| non_permuted_x_powers[idx-1]).collect();
    // Compute y^pi(1), y^pi(2), ..., y^pi(n)
    let mut non_permuted_y_powers = Vec::new();
    non_permuted_y_powers.push(FE::one());
    for _ in 1..permutation.len() {
        non_permuted_y_powers.push(non_permuted_y_powers.last().unwrap() * y);
    }
    let permuted_y_powers: Vec<FE> = permutation.iter().map(|&idx| non_permuted_y_powers[idx]).collect();

    // Commit to the permuted x powers and y powers using BeDOZa
    let permuted_powers_shares = share_values(&[permuted_x_powers, permuted_y_powers].concat(), prepared_permutation_shares, channel)
        .map_err(|e| anyhow!("Failed to share permuted x powers using BeDOZa: {}", e))?;
    let (permuted_x_powers_shares, permuted_y_powers_shares) = permuted_powers_shares.split_at(permutation.len());

    //-------
    // Commit to u_pi(1)_verifier * s, u_pi(2)_verifier * s, ..., u_pi(n)_verifier * s

    // First, commit to u1_verifier * s, u2_verifier * s, ..., un_verifier * s by doing batch multiplication
    let u_verifier_zero_parts: Vec<BeDOZaReceiver> = (0..verifier_shares.len()).map(|_| {
        BeDOZaReceiver::new(FE::zero(), verifier_key, false) // dummy prover share for BeDOZa of verifier share
    }).collect(); 
    let u_verifier_bedoza: Vec<BeDOZa> = verifier_shares.iter()
        .zip(u_verifier_zero_parts.iter()) 
        .map(|(&x, &y)| {
            BeDOZa::new(x, y)
        }).collect();
    let u_verifier_times_s_shares = batch_multiply(&u_verifier_bedoza, &vec![*s_share; verifier_shares.len()], prepared_verifier_shares_times_s_triple, channel)
        .map_err(|e| anyhow!("Failed to do batch_multiply between verifer shares and s: {}", e))?;

    // Now, just commit to u_pi(1)_verifier * s, u_pi(2)_verifier * s, ..., u_pi(n)_verifier * s, then prove consistency later
    let u_verifier_times_s: Vec<FE> = verifier_shares.iter()
        .map(|x| x.val() * s)
        .collect();
    let permuted_u_verifier_times_s = 

    // Now need to prove that this is a valid permutation too
    // Receive the challenges r, a from the prover
    let challenges = receive_fe_vec(channel)
        .map_err(|e| anyhow!("Failed to receive permutation challenge: {}", e))?;
    let r = challenges[0];
    let a = challenges[1];
    let b = challenges[2];

    // Locally obtain shares for (pi(1) + a * x^pi(1) + b * x^pi(1) - r), 
    let permutation_minus_r_share: Vec<BeDOZa> = permuted_shares.iter()
        .zip(permuted_x_powers_shares.iter())
        .map(|(perm_share, &x_power_share)| {
            perm_share * a + x_power_share - r
        })
        .collect();

    // Multiply them all together to get share for (pi(1) - r) * (pi(2) - r) * ... * (pi(n) - r)
    let permutation_minus_r_prod = take_vec_prod(
        &permutation_minus_r_share,
        prepared_permutation_triple_shares,
        channel,
    ).map_err(|e| anyhow!("Failed to compute product share for permutation verification: {}", e))?;

    // Open the product share to the prover. If it is correct the prover will just proceed. Job for verifier is done.
    // Sending verifier share to prover
    open_values_send(&[permutation_minus_r_prod], channel)
        .map_err(|e| anyhow!("Failed to send permutation product share: {}", e))?;

    Ok((permuted_shares, permuted_x_powers_shares))
}

pub fn shuffle_verifier_multiexponentiation_proof(
    exp_shares: &[BeDOZa],
    bases: &[Group],
    channel: &mut TcpChannel,
) -> Result<()> {
    // Each exponent has two shares, the prover already has one share
    // So the verifier just needs to send the multiexponentitation with the other shares as exponents
    
    // Compute the multiexponentiation with the verifier's shares as exponents
    let exp_senders: Vec<FE> = exp_shares.iter().map(|share| share.bedoza_sender().val()).collect();
    let exp_pad_senders: Vec<FE> = exp_shares.iter().map(|share| share.bedoza_sender().pad()).collect();

    // Compute the multiexponentiation for both exp and pads
    let multiexp_exp_sender = msm_pippenger(bases, &exp_senders)
        .map_err(|e| anyhow!("Failed to compute multiexponentiation for exp shares: {}", e))?;
    let multiexp_pad_sender = msm_pippenger(bases, &exp_pad_senders)
        .map_err(|e| anyhow!("Failed to compute multiexponentiation for pad shares: {}", e))?;

    // Send these two multiexponentiations to the prover
    send_group_elements(&[multiexp_exp_sender, multiexp_pad_sender], channel)
        .map_err(|e| anyhow!("Failed to send multiexponentiation results to prover: {}", e))?;

    // The prover will check that multiexp_exp_sender ^ key * multiexp_pad_sender = multiexp_tag_receiver, where RHS the prover has
    // The prover will also check that the true (not secret shared) multiexponentiation is equal to a value that the prover has 
    // The verifier job here is done

    Ok(())
}

pub fn shuffle_verifier_share_s(
    s: FE,
    prepared_s_share: &BeDOZa,
    prepared_s_inv_randomness: &BeDOZa,
    prepared_s_inv_triple: &BeDOZaTriple,
    prepared_s_verifier_share: &BeDOZaSender,
    prepared_s_verifier_consistency_randomness: &BeDOZa,
    prepared_s_verifier_consistency_triple: &BeDOZaTriple,
    channel: &mut TcpChannel,
) -> Result<(BeDOZa, BeDOZa, BeDOZaSender)> {
    // Share s with BeDOZa
    let s_share = share_values(&[s], &[*prepared_s_share], channel)
        .map_err(|e| anyhow!("Failed to share mask s with prover: {}", e))?[0];

    // Multiply with random r, then would be able to inverse
    let s_times_r_share = batch_multiply(&[s_share], &[*prepared_s_inv_randomness], &[*prepared_s_inv_triple], channel)
        .map_err(|e| anyhow!("Failed to multiply and get s * r: {}", e))?[0];
    // Reconstruct s * r
    open_values_send(&[s_times_r_share], channel)
        .map_err(|e| anyhow!("Failed to open s*r to prover: {}", e))?;
    let s_times_r = open_values_receive(&[s_times_r_share], channel)
        .map_err(|e| anyhow!("Failed to receive s*r from prover: {}", e))?[0];
    // Inverse s*r locally, then multiply locally with share of r to get share of 1/s
    let s_times_r_inv = s_times_r.inv().unwrap();
    let s_inv_share = prepared_s_inv_randomness * s_times_r_inv;

    // Share a bedoza_sender for s
    let s_verifier_share = share_values_sender(&[s], &[*prepared_s_verifier_share], channel)
        .map_err(|e| anyhow!("Failed to share bedoza_sender for s: {}", e))?[0];
    // Prove by subtracting s-s_verifier
    let s_verifiier_consistency_proof = BeDOZa::new(*s_share.bedoza_sender() - s_verifier_share, *s_share.bedoza_receiver());
    // Multiply with random value r to get r*(s-s_verifier). The prover will check whether this value is equal to 0.
    let s_verifier_consistency_times_r = batch_multiply(
        &[s_verifiier_consistency_proof], 
        &[*prepared_s_verifier_consistency_randomness], 
        &[*prepared_s_verifier_consistency_triple], 
        channel
    ).map_err(|e| anyhow!("Failed to multiply to get r * (s - s_verifier): {}", e))?[0];
    // Open this for prover to check if it is equal to 0. The verifier job here is done.
    open_values_send(&[s_verifier_consistency_times_r], channel)
        .map_err(|e| anyhow!("Failed to open r * (s - s_verifier): {}", e))?;

    Ok((s_share, s_inv_share, s_verifier_share))
}

pub fn shuffle_verifier_step2(
    u: &[BeDOZa],
    permutation: &[usize],
    prepared_permutation_shares: &[BeDOZa],
    prepared_permutation_triple_shares: &[BeDOZaTriple],
    prepared_s_share: &BeDOZa,
    prepared_s_inv_randomness: &BeDOZa, 
    prepared_s_inv_triple: &BeDOZaTriple, 
    prepared_s_verifier_share: &BeDOZaSender, 
    prepared_s_verifier_consistency_randomness: &BeDOZa, 
    prepared_s_verifier_consistency_triple: &BeDOZaTriple, 
    prepared_x_powers_divided_by_s_triples: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    // Receive g^u1_sender, g^u2_sender, ... from prover and also verify them 
    let g_u_senders = receive_group_elements(channel)
        .map_err(|e| anyhow!("Failed to receive g^ui from prover: {}", e))?;

    // Sample challenge seed and send to prover
    let mut rng = rand::rng();
    let challenge_seed: [u8; 32] = rng.random::<[u8; 32]>();
    channel.send(&challenge_seed)
        .map_err(|e| anyhow!("Failed to send challenge seed to prover: {}", e))?;
    // Generate challenge randomness from the seed
    let mut rng = StdRng::from_seed(challenge_seed);
    let random_coeffs = random_fe_vec_from_rng(&mut rng, u.len())
        .map_err(|e| anyhow!("Failed to generate random coefficients from seed: {}", e))?;

    // Receive g^{pad1*r1} * g^{pad2*r2} * ... g^{padn*rn} from prover to later verify the share exponents
    let multi_exp_pad_u_prover = receive_group_elements(channel)
        .map_err(|e| anyhow!("Failed to receive multi-exponentiation for pads from prover: {}", e))?[0].clone();
    // Now verify by verifying that random linear combination of the equations tag = key * val + pad
    // Take multi exponentiations of g^ui_sender with the random coefficients to get g^{sum(ci*ui_sender)}
    // This is the 1st set of exponentiations
    let multi_exp_u_prover = msm_pippenger(&g_u_senders, &random_coeffs)
        .map_err(|e| anyhow!("Failed to compute multi-exponentiation for g^ui_sender: {}", e))?;
    // Receive multi exponentiations of g^{ri*tag_i} 
    let tag_prover: Vec<FE> = u.iter()
        .map(|share| share.bedoza_receiver().tag())
        .collect();
    let tag_prover_scalar_sum = tag_prover.iter()
        .zip(random_coeffs.iter())
        .map(|(&tag, &coeff)| tag * coeff)
        .fold(FE::zero(), |acc, val| acc + val);
    let multi_exp_tag_prover = Group::base_point().scalar_mul(&tag_prover_scalar_sum);

    // Now can finally verify the equation by checking multi_exp_tag_prover == multi_exp_u_prover^key_u_prover + multi_exp_pad_u_prover
    let key_u_prover = u[0].bedoza_receiver().key(); // key should be the same across all shares, so just take the first one
    let multi_exp_u_prover_key = multi_exp_u_prover.scalar_mul(&key_u_prover);
    let expected_multi_exp = multi_exp_u_prover_key + multi_exp_pad_u_prover;
    ensure!(multi_exp_tag_prover.as_point() == expected_multi_exp.as_point(), "Verification failed for shuffle proof.");


    //------------------------
    // We now move on to doing shuffling
    // First off, just commit the permutation, and also commit to x^pi(1), x^pi(2), ..., x^pi(n) for a random challenge x from the prover, using BeDOZa
    let (permutation_shares, permuted_x_powers_shares) = shuffle_verifier_commit_permutation(
        permutation, 
        prepared_permutation_shares, 
        prepared_permutation_triple_shares, 
        channel
    ).map_err(|e| anyhow!("Failed in permutation commitment step: {}", e))?; 

    // Now the verifier sends back the exponentiations provided by the prover, masked by a mask, and also permute them
    // Firstly generate this mask s and secret share both s and 1/s it with the prover
    let s = random_fe_vec_from_rng(&mut rng, 1)?[0];
    let s_inv = s.inv().map_err(|e| anyhow!("Failed to invert mask s: {:?}", e))?;

    let (s_share, s_inv_share, s_verifier_share) = shuffle_verifier_share_s(
        s, 
        prepared_s_share, 
        prepared_s_inv_randomness, 
        prepared_s_inv_triple, 
        prepared_s_verifier_share, 
        prepared_s_verifier_consistency_randomness, 
        prepared_s_verifier_consistency_triple, 
        channel
    ).map_err(|e| anyhow!("Failed to share s, s_inv and s_verifier: {}", e))?;


    // Permute g^u1_sender, g^u2_sender, ..., g^un_sender into g^u_pi(1)_sender, g^u_pi(2)_sender, ..., g^u_pi(n)_sender
    let permuted_g_u_senders: Vec<Group> = permutation.iter().map(|&idx| g_u_senders[idx].clone()).collect();
    // Now raise them to the power of mask s
    // This is the 2nd set of exponentiations
    let masked_permuted_g_u_senders: Vec<Group> = permuted_g_u_senders.iter().map(|g| g.scalar_mul(&s)).collect();

    // Send the masked and permuted g^u_senders back to the prover
    send_group_elements(&masked_permuted_g_u_senders, channel)
        .map_err(|e| anyhow!("Failed to send masked and permuted g^u_senders to prover: {}", e))?;

    // Now need to prove that the group elements just sent are correctly computed.
    // Idea: We basically have to prove that the following two polynomials are equal, hence the coefficients: 
    // x^1 * s * u1_sender + x^2 * s * u2_sender + ... + x^n * s * un_sender
    // and
    // x^pi(1) * s * u_pi(1)_sender + x^pi(2) * s * u_pi(2)_sender + ... + x^pi(n) * s * u_pi(n)_sender
    // What do we have now?
    // Commitments to x^pi(1), x^pi(2), ..., x^pi(n)
    // Values for g^u1_sender, g^u2_sender, ..., g^un_sender, which we will call in short g11, g12, ..., g1n
    // Values for g^u_pi(1)_sender, g^u_pi(2)_sender, ..., g^u_pi(n)_sender, which we will call in short g21, g22, ..., g2n
    // The equation we need to check would be, the following two multi exponentiations are equal:
    // g11^{x^1 * s} * g12^{x^2 * s} * ... * g1n^{x^n * s} == g21^{x^pi(1)} * g22^{x^pi(2)} * ... * g2n^{x^pi(n)}
    // Which is equivalent to checking:
    // g11^{x^1} * g12^{x^2} * ... * g1n^{x^n} == g21^{x^pi(1)/s} * g22^{x^pi(2)/s} * ... * g2n^{x^pi(n)/s}
    // The LHS is fully known to the verifier, and the RHS now we will do a multiexponentiation proof, with the bases g21, g22, ... also known by the verifier

    // First, compute shares for x^pi(1)/s, x^pi(2)/s, ..., x^pi(n)/s
    let x_powers_divided_by_s_shares: Vec<BeDOZa> = batch_multiply(
        &permuted_x_powers_shares, 
        &[s_inv_share], 
        prepared_x_powers_divided_by_s_triples, 
        channel
    ).map_err(|e| anyhow!("Failed to compute shares for x^pi(i)/s: {}", e))?;

    // Now do the multiexponentiation proof with the prover, with bases g21, g22, ..., g2n and exponents x^pi(1)/s, x^pi(2)/s, ..., x^pi(n)/s
    // This will be the 3rd and the 4th set of exponentiations
    shuffle_verifier_multiexponentiation_proof(&x_powers_divided_by_s_shares, &permuted_g_u_senders, channel)
        .map_err(|e| anyhow!("Failed in multiexponentiation proof for shuffle verification: {}", e))?;

    // -------
    // Next step, much more tricky: Send the masked and permuted g^u_verifier to the prover
    // This is harder because the prover does not know what these shares are

    // First, we obtain shares for s * u1_verifier, s * u2_verifier, ..., s * un_verifier
    // The idea is to then let the verifier share the values s * u_pi(1)_verifier, s * u_pi(2)_verifier, ..., s * u_pi(n)_verifier, then prove consistency

    unimplemented!()
}
