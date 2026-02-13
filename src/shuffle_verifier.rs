use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple, batch_multiply, 
        defines::{FE, random_fe_vec_from_rng}, 
        open_values_receive, open_values_send, receive_share_values
    }, 
    group::{Group, receive_group_elements, msm_pippenger}, 
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

pub fn shuffle_verifier_commit_permutation(
    channel: &mut TcpChannel,
) -> Result<()> {
    unimplemented!()
}

pub fn shuffle_verifier_step2(
    u: &[BeDOZa],
    prepared_triple_shares: &[BeDOZaTriple],
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
    let multi_exp_u_prover = msm_pippenger(&g_u_senders, &random_coeffs)
        .map_err(|e| anyhow!("Failed to compute multi-exponentiation for g^ui_sender: {}", e))?;
    // Take multi exponentiations of g^{ri*tag_i} 
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

    unimplemented!()
}