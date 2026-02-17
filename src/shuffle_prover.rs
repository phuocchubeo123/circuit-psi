use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple, batch_multiply, comm_util::send_fe, 
        defines::{FE, random_fe_vec, random_fe_vec_from_rng}, 
        open_values_receive, open_values_send, receive_share_values, share_values,
        take_vec_prod,
    }, 
    group::{Group, send_group_elements}, 
    tcp_channel::TcpChannel,
};
use anyhow::{anyhow, ensure, Result};
use rand::{rngs::StdRng, SeedableRng};

pub fn shuffle_prover_step1(
    vals: &[FE],
    authenticated_key: &BeDOZa,
    prepared_bedoza_shares: &[BeDOZa],
    prepared_randomness: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel
) -> Result<Vec<BeDOZa>> {
    // Step 1: Given inputs x1, x2, ..., xn
    // We want to obtain shares for 1 / (k + x1), 1 / (k + x2), ..., where k is an authenticated key

    // First, share the values x1, x2, ..., xn
    // Using BeDOZa, we authenticate both shares of the values as well
    let bedoza_shared = share_values(vals, prepared_bedoza_shares, channel)
        .map_err(|e| anyhow!("Failed to share values using BeDOZa: {}", e))?;

    // Next, obtain shares for 1/(k+x1), 1/(k+x2), ...
    // First obtain shares for (k+x1), (k+x2), ...
    let k_plus_x_shares: Vec<BeDOZa> = bedoza_shared.iter()
        .map(|share| share + authenticated_key)
        .collect();

    // Multiply (k+x1), (k+x2), ... with the prepared randomness to get shares for (k+x1)*r1, (k+x2)*r2, ...
    let r_times_k_plus_x_shares = batch_multiply(&k_plus_x_shares, prepared_randomness, prepared_triple_shares, channel)
        .map_err(|e| anyhow!("Failed to batch multiply (k+xi) with randomness: {}", e))?;

    // Open the shares of (k+xi)*ri to both parties 
    // Receive verifier share from verifier
    let r_times_k_plus_x_value: Vec<FE> = open_values_receive(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to open (k+xi)*ri shares: {}", e))?;
    // Sending prover share to verifier
    open_values_send(&r_times_k_plus_x_shares, channel)
        .map_err(|e| anyhow!("Failed to send (k+xi)*ri shares: {}", e))?;

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

pub fn shuffle_prover_commit_permutation(
    prepared_permutation_shares: &[BeDOZa],
    prepared_permutation_triple_shares: &[BeDOZaTriple],
    channel: &mut TcpChannel,
) -> Result<Vec<BeDOZa>> {
    // First simply receive the permutation commitment from the verifier
    let permuted_shares = receive_share_values(prepared_permutation_shares, channel)
        .map_err(|e| anyhow!("Failed to receive shared permutation using BeDOZa: {}", e))?;

    // Now need to verify that this is a valid permutation too
    // Sample and send a challenge r value
    let challenge = random_fe_vec(1)?.pop().unwrap();
    send_fe(challenge, channel)
        .map_err(|e| anyhow!("Failed to send permutation challenge: {}", e))?;
    // Locally compute (pi(1) - r), (pi(2) - r), ..., (pi(n) - r) shares
    let permutation_minus_challenge_share: Vec<BeDOZa> = permuted_shares.iter()
        .map(|share| *share - challenge)
        .collect();
    // Multiply them all together to get share for (pi(1) - r) * (pi(2) - r) * ... * (pi(n) - r)
    let permutation_minus_challenge_prod = take_vec_prod(
        &permutation_minus_challenge_share,
        prepared_permutation_triple_shares,
        channel,
    ).map_err(|e| anyhow!("Failed to compute product share for permutation verification: {}", e))?;

    // Receive the opened product share from the verifier
    let opened_product = open_values_receive(&[permutation_minus_challenge_prod], channel)
        .map_err(|e| anyhow!("Failed to receive opened permutation product share: {}", e))?[0];
    // The expected value of this product is (1 - r) * (2 - r) * ... * (n - r). We can locally compute this and compare
    let expected_product = (1..=permutation_minus_challenge_share.len() as u64)
        .map(|i| FE::from(i) - challenge)
        .fold(FE::one(), |acc, val| acc * val);
    ensure!(opened_product == expected_product, "Permutation verification failed: expected product {:?}, got {:?}", expected_product, opened_product);

    Ok(permuted_shares)
}

pub fn shuffle_prover_step2(
    u: &[BeDOZa],
    prepared_s_share: &BeDOZa,
    channel: &mut TcpChannel
) -> Result<Vec<BeDOZa>> {
    // In order to be really concrete about the number of exponentiations, I need to implement this function in a big chunk
    // u is the vector contains shares for 1 / (k + x1), 1 / (k + x2), ..., 1 / (k + xn)

    // Send g^(u1_sender), g^(u2_sender), ..., g^(un_sender) to verifier
    // First just do exponentiation and send the values
    let u_senders: Vec<FE> = u.iter()
        .map(|share| share.bedoza_sender().val())
        .collect();
    let g_u_senders: Vec<Group> = u_senders.iter()
        .map(|val| Group::base_point().scalar_mul(val))
        .collect();
    send_group_elements(&g_u_senders, channel)
        .map_err(|e| anyhow!("Failed to send g^(ui_sender) values: {}", e))?;

    // Now need to send the proof too!
    // First receive the random linear combination from the verifier
    let seed = channel.receive()?;
    ensure!(seed.len() == 32, "Expected 32 bytes for random seed, got {}", seed.len());
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let mut rng = StdRng::from_seed(seed_arr);
    let random_coeffs = random_fe_vec_from_rng(&mut rng, u.len())
        .map_err(|e| anyhow!("Failed to generate random coefficients from seed: {}", e))?;

    // Send multi-exponentiation for the pads: g^{r1*pad1} * g^{r2*pad2} * ... * g^{rn*padn}
    let pad_senders: Vec<FE> = u.iter()
        .map(|share| share.bedoza_sender().pad())
        .collect();
    let pad_scalar_sum = pad_senders.iter()
        .zip(random_coeffs.iter())
        .map(|(&pad, &coeff)| pad * coeff)
        .fold(FE::zero(), |acc, val| acc + val);
    let multi_exp_pad = Group::base_point().scalar_mul(&pad_scalar_sum);
    send_group_elements(&[multi_exp_pad], channel)
        .map_err(|e| anyhow!("Failed to send multi-exponentiation of pads: {}", e))?;


    // -------------------------------
    // Next we move on to shuffling and raising these values to the same (masking power)
    // We also need to prove this thing is done correctly.

    // First receive the secret shared mask s from the verifier
    let s_share = receive_share_values(&[*prepared_s_share], channel)
        .map_err(|e| anyhow!("Failed to receive shared mask s from verifier: {}", e))?[0];


    unimplemented!()
}
