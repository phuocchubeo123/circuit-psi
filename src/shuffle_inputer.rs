use crate::{
    bedoza::{
        BeDOZa,
        bedoza_receiver::{BeDOZaReceiver, linear_comb_receiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, linear_comb_sender, send_open_shares},
        defines::{FE, powers, random_fe_vec_from_rng},
        vole_auth::{
            authenticate_batch_with_peer_key_receiver, authenticate_batch_with_peer_key_sender,
            vole_share_product_sender,
        },
        wolverine::{
            wolverine_batch_mul_prove, wolverine_batch_mul_public_output_verify,
            wolverine_batch_mul_verify,
        },
    }, group::{Group, msm_pippenger, receive_group_elements, send_group_elements}, 
    tcp_channel::SwankyChannel, 
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender}
};
use anyhow::{Result, anyhow, ensure};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

// Role naming:
// - Inputer (this module, previously "prover"): owns inputs and key delta_0.
// - Shuffler (peer, previously "verifier"): owns permutation and key delta_1.

#[derive(Clone, Copy, Debug)]
pub struct Inputer {
    delta_0: FE,
}

impl Inputer {
    pub fn new(delta_0: FE) -> Self {
        Self { delta_0 }
    }

    pub fn delta_0(&self) -> FE {
        self.delta_0
    }

    pub fn step0_authenticate_oprf_key_inputs_and_random_values(
        &self,
        vals: &[FE],
        vole_sender: &mut BufferedVoleSender,
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<(BeDOZa, Vec<BeDOZaSender>, Vec<BeDOZaSender>)> {
        // Inputer samples k0, authenticates it under shuffler key delta_1, then receives
        // shuffler's k1 authenticated under inputer key delta_0.
        let inputer_k0_sender = vole_sender.random_auth(channel, 1).map_err(|e| anyhow!("Failed to authenticate k0: {e}"))?[0];
        let shuffler_k1_receiver = vole_receiver.random_auth(channel, 1).map_err(|e| anyhow!("Failed to receive authenticated k1: {e}"))?[0];

        // Inputer commits its local input values with VOLE under the shuffler's key delta_1.
        let authenticated_xis = vole_sender.commit_auth(channel, vals).map_err(|e| anyhow!("Failed to authenticate input values: {e}"))?;

        // Inputer gets authenticated random values 
        let authenticated_ris = vole_sender.random_auth(channel, vals.len()).map_err(|e| anyhow!("Failed to authenticate random values: {e}"))?;

        Ok((
            BeDOZa::new(inputer_k0_sender, shuffler_k1_receiver),
            authenticated_xis,
            authenticated_ris,
        ))
    }

    pub fn step1_inputer_authenticates_r_times_x_plus_k0_and_proves(
        &self,
        authenticated_xis: &[BeDOZaSender],
        authenticated_ris: &[BeDOZaSender],
        authenticated_k0: &BeDOZaSender,
        vole_sender: &mut BufferedVoleSender,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<BeDOZaSender>> {
        ensure!(
            authenticated_xis.len() == authenticated_ris.len(),
            "step3 length mismatch: authenticated x values {} vs authenticated r values {}",
            authenticated_xis.len(),
            authenticated_ris.len()
        );

        let authenticated_x_plus_k0: Vec<BeDOZaSender> =
            authenticated_xis.iter().map(|x| x + authenticated_k0).collect();

        let r_times_x_plus_k0_values: Vec<FE> = authenticated_ris
            .iter()
            .zip(authenticated_x_plus_k0.iter())
            .map(|(&r_i, x_plus_k0_i)| r_i.val() * x_plus_k0_i.val())
            .collect();

        let authenticated_r_times_x_plus_k0 = vole_sender.commit_auth(channel, &r_times_x_plus_k0_values)
            .map_err(|e| anyhow!("Failed to authenticate ri*(xi + k0): {e}"))?;

        let authenticated_dummy_x = vole_sender.random_auth(channel, 1)
            .map_err(|e| anyhow!("Failed to generate random authenticated dummy: {e}"))?[0];

        wolverine_batch_mul_prove(
            authenticated_ris,
            &authenticated_x_plus_k0,
            &authenticated_r_times_x_plus_k0,
            &authenticated_dummy_x,
            channel,
        )?;

        Ok(authenticated_r_times_x_plus_k0)
    }

    pub fn step2_vole_share_x_times_k1_and_authenticate(
        &self,
        authenticated_xs: &[BeDOZaSender],
        authenticated_k1: &BeDOZaReceiver,
        vole_sender: &mut BufferedVoleSender,
        vole_receiver: &mut BufferedVoleReceiver,
        k1_vole_sender: &mut BufferedVoleSender,
        channel: &mut SwankyChannel,
    ) -> Result<(Vec<FE>, Vec<BeDOZaSender>, Vec<BeDOZaReceiver>)> {
        // 1) Use VOLE to produce additive shares of x_i * k1:
        //    inputer gets u_i, shuffler gets v_i, with u_i + v_i = x_i * k1.
        let x_values: Vec<FE> = authenticated_xs.iter().map(|x| x.val()).collect();
        let k1_auth_xis = k1_vole_sender.commit_auth(channel, &x_values)
            .map_err(|e| anyhow!("Failed to get secret shares of xi * k1: {e}"))?;
        let us: Vec<FE> = k1_auth_xis.iter().map(|share| share.pad()).collect();

        let k1_auth_rand = k1_vole_sender.random_auth(channel, 1)
            .map_err(|e| anyhow!("Failed to get secret shares of rand * k1: {e}"))?[0];

        // 2) Inputer authenticates u_i under shuffler key delta_1.
        let authenticated_us = vole_sender.commit_auth(channel, &us)
            .map_err(|e| anyhow!("Failed to authenticate ui values: {e}"))?;

        let authenticated_x0 = vole_sender.commit_auth(channel, &[k1_auth_rand.val()])
            .map_err(|e| anyhow!("Failed to authenticate x0 value: {e}"))?[0];
        let authenticated_u0 = vole_sender.commit_auth(channel, &[k1_auth_rand.pad()])
            .map_err(|e| anyhow!("Faile to authenticate u0 value: {e}"))?[0];
        let authenticated_v0 = vole_receiver.commit_auth(channel, 1)
            .map_err(|e| anyhow!("Failed to receive authenticated v0 value: {e}"))?[0];

        // 3) Shuffler authenticates v_i under inputer key delta_0 (inputer receives tags).
        let authenticated_vs = vole_receiver.commit_auth(channel, x_values.len())
            .map_err(|e| anyhow!("Failed to receive authenticated vi values: {e}"))?;

        // 4) Prove the correctness of authenticated ui and xi
        // Shuffler samples seed so it can independently reconstruct the same linear combination.
        let mut seed = [0u8; 32];
        channel
            .read_bytes(&mut seed)
            .map_err(|e| anyhow!("step5 failed to receive seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, authenticated_xs.len())?;

        let u_linear = linear_comb_sender(&authenticated_us, &coeffs, "step2 u linear comb")? + authenticated_u0;
        let x_linear = linear_comb_sender(authenticated_xs, &coeffs, "step2 x linear comb")? + authenticated_x0;

        // Open the linear combinations of ui and xi to prove that xi * k1 - ui = vi
        send_open_shares(&[u_linear, x_linear], channel).map_err(|e| anyhow!("Failed to open the linear combinations: {e}"))?;

        // 5) Prove the correctness of authenticated vi
        // Currently I do it by proving auth_k1 * x_linear - u_linear - auth_v_linear = 0. 
        let v_linear = linear_comb_receiver(&authenticated_vs, &coeffs, "step2 v linear comb")? + authenticated_v0;
        let authenticated_x_times_k1_minus_uv = x_linear.val() * authenticated_k1 - u_linear.val() - v_linear;

        let x_times_k1_minus_uv = receive_open_shares(authenticated_x_times_k1_minus_uv, channel)?[0];
        ensure!(
            x_times_k1_minus_uv == FE::zero(),
            "step2 consistency check failed: x_linear * k1 - u_linear - v_linear != 0"
        );

        Ok((us, authenticated_us, authenticated_vs))
    }

    pub fn step3_open_ri_x_plus_k0_plus_ui_and_receive_reauthenticate(
        &self,
        authenticated_r_times_x_plus_k0_sender: &[BeDOZaSender],
        authenticated_u_sender: &[BeDOZaSender],
        authenticated_vs: &[BeDOZaReceiver],
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<BeDOZaReceiver>> {
        ensure!(
            authenticated_r_times_x_plus_k0_sender.len() == authenticated_u_sender.len(),
            "step3 length mismatch: r(x+k0) commitments {} vs u commitments {}",
            authenticated_r_times_x_plus_k0_sender.len(),
            authenticated_u_sender.len()
        );
        ensure!(
            !authenticated_r_times_x_plus_k0_sender.is_empty(),
            "step3 cannot run on empty commitments"
        );

        let authenticated_r_times_x_plus_k: Vec<BeDOZaSender> = authenticated_r_times_x_plus_k0_sender
            .iter()
            .zip(authenticated_u_sender.iter())
            .map(|(lhs, rhs)| *lhs + *rhs)
            .collect();

        send_open_shares(&authenticated_r_times_x_plus_k, channel)
            .map_err(|e| anyhow!("Failed to open ri*(xi+k0)+ui: {e}"))?;

        // 2) Receive reauthentication
        // Receive shuffler's reauthentication of y_i := r_i*(x_i+k) under delta_0.
        let reauthenticated_r_x_k_receiver = vole_receiver.commit_auth(channel, authenticated_r_times_x_plus_k.len())
            .map_err(|e| anyhow!("Failed to receive reauthentication of ri*(xi+k): {e}"))?;

        // Shuffler chooses seed for batched sacrifice check.
        let mut seed = [0u8; 32];
        channel
            .read_bytes(&mut seed)
            .map_err(|e| anyhow!("step8 failed to receive seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs =
            random_fe_vec_from_rng(&mut seeded_rng, authenticated_r_times_x_plus_k.len())?;

        let reauth_linear = linear_comb_receiver(
            &reauthenticated_r_x_k_receiver,
            &coeffs,
            "step3 reauthenticated linear comb",
        ).map_err(|e| anyhow!("Failed to compute linear combination of reauthenticated ri*(xi+k): {e}"))?;
        let v_linear = linear_comb_receiver(
            &authenticated_vs,
            &coeffs,
            "step3 authenticated v linear comb",
        ).map_err(|e| anyhow!("Failed to compute linear combination of authenticated vi: {e}"))?;
        let auth_linear = linear_comb_sender(
            &authenticated_r_times_x_plus_k,
            &coeffs,
            "step3 authenticated linear comb",
        ).map_err(|e| anyhow!("Failed to compute linear combination of authenticated ri*(xi+k): {e}"))?;

        // Simply open the new random linear combination and compare with the old one.
        let opened = receive_open_shares(&[reauth_linear, v_linear], channel)?;
        let opened_reauth_linear = opened[0];
        let opened_v_linear = opened[1];

        ensure!(
            opened_reauth_linear == auth_linear.val() + opened_v_linear,
            "step8 consistency check failed: reauth batch != opened r(x+k0)+u batch + v batch"
        );

        Ok(reauthenticated_r_x_k_receiver)
    }

    // Checked until here

    pub fn step9_receive_authenticated_inverses_and_verify<C: AbstractChannel>(
        &self,
        authenticated_r_x_k_receiver: &[BeDOZaReceiver],
        inverse_auth_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut C,
    ) -> Result<Vec<BeDOZaReceiver>> {
        ensure!(
            !authenticated_r_x_k_receiver.is_empty(),
            "step9 cannot run on empty commitments"
        );

        // Receive shuffler-authenticated inverses under delta_0.
        let authenticated_inverse_receiver = authenticate_batch_with_peer_key_receiver(
            authenticated_r_x_k_receiver.len(),
            true,
            self.delta_0,
            inverse_auth_vole_receiver,
            channel,
        )?;

        // Prove y_i * y_i^{-1} = 1 with Wolverine (public-output multiplication).
        let public_ones = vec![FE::one(); authenticated_r_x_k_receiver.len()];
        wolverine_batch_mul_public_output_verify(
            authenticated_r_x_k_receiver,
            &authenticated_inverse_receiver,
            &public_ones,
            channel,
        )?;

        Ok(authenticated_inverse_receiver)
    }

    pub fn step10_send_g_ri_and_pad_consistency_proof<C: AbstractChannel>(
        &self,
        authenticated_ri_sender: &[BeDOZaSender],
        channel: &mut C,
    ) -> Result<Vec<Group>> {
        let _ = self.delta_0;
        ensure!(
            !authenticated_ri_sender.is_empty(),
            "step10 cannot run on empty ri commitments"
        );

        let g_ri: Vec<Group> = authenticated_ri_sender
            .iter()
            .map(|ri| Group::base_point().scalar_mul(&ri.val()))
            .collect();
        send_group_elements(&g_ri, channel)
            .map_err(|e| anyhow!("step10 failed to send g^ri values: {}", e))?;

        // Shuffler samples coefficients and sends seed.
        let mut seed_arr = [0u8; 32];
        channel
            .read_bytes(&mut seed_arr)
            .map_err(|e| anyhow!("step10 failed to receive seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed_arr);
        let alphas = random_fe_vec_from_rng(&mut seeded_rng, authenticated_ri_sender.len())?;

        // Send g^{sum_i alpha_i * pad_i}.
        let pad_linear = authenticated_ri_sender
            .iter()
            .zip(alphas.iter())
            .map(|(ri, &alpha_i)| ri.pad() * alpha_i)
            .fold(FE::zero(), |acc, term| acc + term);
        let g_pad_linear = Group::base_point().scalar_mul(&pad_linear);
        send_group_elements(&[g_pad_linear], channel)
            .map_err(|e| anyhow!("step10 failed to send pad consistency group element: {}", e))?;

        Ok(g_ri)
    }

    pub fn step11_receive_authenticated_permutation_values<C: AbstractChannel>(
        &self,
        expected_count: usize,
        permutation_auth_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut C,
    ) -> Result<Vec<BeDOZaReceiver>> {
        ensure!(expected_count > 0, "step11 expected_count must be non-zero");
        let authenticated_permutation = authenticate_batch_with_peer_key_receiver(
            expected_count,
            true,
            self.delta_0,
            permutation_auth_vole_receiver,
            channel,
        )?;
        Ok(authenticated_permutation)
    }

    pub fn step12_send_challenge_and_receive_authenticated_x_powers<
        C: AbstractChannel,
        RNG: Rng,
    >(
        &self,
        expected_count: usize,
        rng: &mut RNG,
        x_power_auth_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut C,
    ) -> Result<(FE, Vec<BeDOZaReceiver>)> {
        ensure!(expected_count > 0, "step12 expected_count must be non-zero");

        // Inputer samples and sends challenge x.
        let x = random_fe_vec_from_rng(rng, 1)?[0];
        channel
            .write_bytes(&x.to_bytes_le())
            .map_err(|e| anyhow!("step12 failed to send challenge x: {}", e))?;
        channel
            .flush()
            .map_err(|e| anyhow!("step12 failed to flush challenge x: {}", e))?;

        // Receive shuffler-authenticated x^{pi(i)} values under delta_0.
        let authenticated_x_powers = authenticate_batch_with_peer_key_receiver(
            expected_count,
            true,
            self.delta_0,
            x_power_auth_vole_receiver,
            channel,
        )?;

        Ok((x, authenticated_x_powers))
    }

    pub fn step13_receive_authenticated_xpi_times_inverse_and_verify<C: AbstractChannel>(
        &self,
        authenticated_x_powers_receiver: &[BeDOZaReceiver],
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut C,
    ) -> Result<(Vec<BeDOZaReceiver>, Vec<BeDOZaReceiver>)> {
        ensure!(
            !authenticated_x_powers_receiver.is_empty(),
            "step13 cannot run on empty commitments"
        );

        // Receive shuffler-authenticated permuted inverse batch:
        // [1 / r_{pi(i)}(x_{pi(i)}+k)]_i
        let authenticated_permuted_inverse = authenticate_batch_with_peer_key_receiver(
            authenticated_x_powers_receiver.len(),
            true,
            self.delta_0,
            vole_receiver,
            channel,
        )?;

        let authenticated_products = authenticate_batch_with_peer_key_receiver(
            authenticated_x_powers_receiver.len(),
            true,
            self.delta_0,
            vole_receiver,
            channel,
        )?;

        // Verify shuffler proof that each product commitment matches
        // x^pi(i) * (1 / r_{pi(i)}(x_{pi(i)}+k)).
        wolverine_batch_mul_verify(
            authenticated_x_powers_receiver,
            &authenticated_permuted_inverse,
            &authenticated_products,
            &authenticated_products[0],
            channel,
        )?;

        Ok((authenticated_permuted_inverse, authenticated_products))
    }

    pub fn step14_sample_challenges_and_verify_shuffle_product_identity<
        C: AbstractChannel,
        RNG: Rng,
    >(
        &self,
        n: usize,
        rng: &mut RNG,
        product_identity_auth_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut C,
    ) -> Result<()> {
        ensure!(n > 0, "step14 cannot run with n = 0");

        // Inputer samples alpha, beta, gamma and sends them to shuffler.
        let alpha = random_fe_vec_from_rng(rng, 1)?[0];
        let beta = random_fe_vec_from_rng(rng, 1)?[0];
        let gamma = random_fe_vec_from_rng(rng, 1)?[0];
        channel
            .write_bytes(&alpha.to_bytes_le())
            .map_err(|e| anyhow!("step14 failed to send alpha: {}", e))?;
        channel
            .write_bytes(&beta.to_bytes_le())
            .map_err(|e| anyhow!("step14 failed to send beta: {}", e))?;
        channel
            .write_bytes(&gamma.to_bytes_le())
            .map_err(|e| anyhow!("step14 failed to send gamma: {}", e))?;
        channel
            .flush()
            .map_err(|e| anyhow!("step14 failed to flush alpha/beta/gamma: {}", e))?;

        // Receive shuffler-authenticated u_i, v_i, one, and prefix-product chains.
        let authenticated_u_receiver = authenticate_batch_with_peer_key_receiver(
            n,
            true,
            self.delta_0,
            product_identity_auth_vole_receiver,
            channel,
        )?;
        let authenticated_v_receiver = authenticate_batch_with_peer_key_receiver(
            n,
            true,
            self.delta_0,
            product_identity_auth_vole_receiver,
            channel,
        )?;
        let authenticated_one_receiver = authenticate_batch_with_peer_key_receiver(
            1,
            true,
            self.delta_0,
            product_identity_auth_vole_receiver,
            channel,
        )?;
        let authenticated_u_prefix_receiver = authenticate_batch_with_peer_key_receiver(
            n,
            true,
            self.delta_0,
            product_identity_auth_vole_receiver,
            channel,
        )?;
        let authenticated_v_prefix_receiver = authenticate_batch_with_peer_key_receiver(
            n,
            true,
            self.delta_0,
            product_identity_auth_vole_receiver,
            channel,
        )?;

        // Verify multiplication chain for u:
        // p_u[0] = 1 * u_0, p_u[i] = p_u[i-1] * u_i.
        let mut u_chain_left = Vec::with_capacity(n);
        u_chain_left.push(authenticated_one_receiver[0]);
        u_chain_left.extend_from_slice(&authenticated_u_prefix_receiver[..n - 1]);
        wolverine_batch_mul_verify(
            &u_chain_left,
            &authenticated_u_receiver,
            &authenticated_u_prefix_receiver,
            &authenticated_u_prefix_receiver[0],
            channel,
        )?;

        // Verify multiplication chain for v:
        // p_v[0] = 1 * v_0, p_v[i] = p_v[i-1] * v_i.
        let mut v_chain_left = Vec::with_capacity(n);
        v_chain_left.push(authenticated_one_receiver[0]);
        v_chain_left.extend_from_slice(&authenticated_v_prefix_receiver[..n - 1]);
        wolverine_batch_mul_verify(
            &v_chain_left,
            &authenticated_v_receiver,
            &authenticated_v_prefix_receiver,
            &authenticated_v_prefix_receiver[0],
            channel,
        )?;

        // Open final product difference and check it is zero.
        let final_diff_receiver =
            authenticated_u_prefix_receiver[n - 1] - authenticated_v_prefix_receiver[n - 1];
        let opened_diff = receive_open_sender_shares_abstract(&[final_diff_receiver], channel)?[0];
        ensure!(
            opened_diff == FE::zero(),
            "step14 shuffle product identity failed: final product difference is non-zero"
        );

        Ok(())
    }

    pub fn step15_receive_shuffled_oprf_points<C: AbstractChannel>(
        &self,
        expected_count: usize,
        channel: &mut C,
    ) -> Result<Vec<Group>> {
        let _ = self.delta_0;
        ensure!(expected_count > 0, "step15 expected_count must be non-zero");
        let shuffled_oprf = receive_group_elements(channel)
            .map_err(|e| anyhow!("step15 failed to receive shuffled OPRF points: {}", e))?;
        ensure!(
            shuffled_oprf.len() == expected_count,
            "step15 length mismatch: expected {} shuffled OPRF points, got {}",
            expected_count,
            shuffled_oprf.len()
        );
        Ok(shuffled_oprf)
    }

    pub fn step16_receive_and_verify_left_oprf_product<C: AbstractChannel>(
        &self,
        g_ri: &[Group],
        authenticated_inverse_receiver: &[BeDOZaReceiver],
        x: FE,
        channel: &mut C,
    ) -> Result<Group> {
        ensure!(!g_ri.is_empty(), "step16 cannot run on empty g^ri batch");
        ensure!(
            g_ri.len() == authenticated_inverse_receiver.len(),
            "step16 length mismatch: g^ri={} inverse commitments={}",
            g_ri.len(),
            authenticated_inverse_receiver.len()
        );

        // Build authenticated exponents z_i * x^i for MAC verification.
        let x_powers = powers(x, authenticated_inverse_receiver.len());
        let scaled_inverse_receiver: Vec<BeDOZaReceiver> = authenticated_inverse_receiver
            .iter()
            .zip(x_powers.iter())
            .map(|(z_i, &x_i)| *z_i * x_i)
            .collect();

        let delta_0 = scaled_inverse_receiver[0].key();
        ensure!(
            delta_0 == self.delta_0,
            "step16 key mismatch: expected delta_0"
        );
        for (i, share) in scaled_inverse_receiver.iter().enumerate() {
            ensure!(
                share.key() == delta_0,
                "step16 receiver key mismatch at index {}",
                i
            );
        }

        let proof_elems = receive_group_elements(channel).map_err(|e| {
            anyhow!(
                "step16 failed to receive left product proof elements: {}",
                e
            )
        })?;
        ensure!(
            proof_elems.len() == 2,
            "step16 expected exactly 2 proof elements, got {}",
            proof_elems.len()
        );
        let opened_left_product = proof_elems[0].clone();
        let left_pad_product = proof_elems[1].clone();

        let tag_scalars: Vec<FE> = scaled_inverse_receiver.iter().map(|s| s.tag()).collect();
        let left_tag_product = msm_pippenger(g_ri, &tag_scalars)
            .map_err(|e| anyhow!("step16 failed MSM for left tag product: {}", e))?;

        // Check: product^{delta0} * pad_product = tag_product.
        let lhs = opened_left_product.scalar_mul(&delta_0) + left_pad_product;
        ensure!(
            lhs.as_point() == left_tag_product.as_point(),
            "step16 left product MAC check failed"
        );

        Ok(opened_left_product)
    }

    pub fn step17_receive_and_verify_right_oprf_product<C: AbstractChannel>(
        &self,
        shuffled_oprf: &[Group],
        authenticated_x_powers_receiver: &[BeDOZaReceiver],
        channel: &mut C,
    ) -> Result<Group> {
        ensure!(
            !shuffled_oprf.is_empty(),
            "step17 cannot run on empty shuffled OPRF batch"
        );
        ensure!(
            shuffled_oprf.len() == authenticated_x_powers_receiver.len(),
            "step17 length mismatch: shuffled_oprf={} x^pi commitments={}",
            shuffled_oprf.len(),
            authenticated_x_powers_receiver.len()
        );

        let delta_0 = authenticated_x_powers_receiver[0].key();
        ensure!(
            delta_0 == self.delta_0,
            "step17 key mismatch: expected delta_0"
        );
        for (i, share) in authenticated_x_powers_receiver.iter().enumerate() {
            ensure!(
                share.key() == delta_0,
                "step17 receiver key mismatch at index {}",
                i
            );
        }

        let proof_elems = receive_group_elements(channel).map_err(|e| {
            anyhow!(
                "step17 failed to receive right product proof elements: {}",
                e
            )
        })?;
        ensure!(
            proof_elems.len() == 2,
            "step17 expected exactly 2 proof elements, got {}",
            proof_elems.len()
        );
        let opened_right_product = proof_elems[0].clone();
        let right_pad_product = proof_elems[1].clone();

        let tag_scalars: Vec<FE> = authenticated_x_powers_receiver
            .iter()
            .map(|s| s.tag())
            .collect();
        let right_tag_product = msm_pippenger(shuffled_oprf, &tag_scalars)
            .map_err(|e| anyhow!("step17 failed MSM for right tag product: {}", e))?;

        // Check: product^{delta0} * pad_product = tag_product.
        let lhs = opened_right_product.scalar_mul(&delta_0) + right_pad_product;
        ensure!(
            lhs.as_point() == right_tag_product.as_point(),
            "step17 right product MAC check failed"
        );

        Ok(opened_right_product)
    }

    pub fn step18_verify_opened_oprf_products_match(
        &self,
        opened_left_product: &Group,
        opened_right_product: &Group,
    ) -> Result<()> {
        let _ = self.delta_0;
        ensure!(
            opened_left_product.as_point() == opened_right_product.as_point(),
            "step18 failed: opened left OPRF product does not match opened right OPRF product"
        );
        Ok(())
    }

    pub fn run_full_shuffled_oprf<C: AbstractChannel, RNG: Rng>(
        &self,
        x_values: &[FE],
        rng: &mut RNG,
        auth_vole_sender: &mut BufferedVoleSender,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        k1_mul_vole_sender: &mut BufferedVoleSender,
        k1_prime_mul_vole_sender: &mut BufferedVoleSender,
        channel: &mut C,
    ) -> Result<Vec<Group>> {
        ensure!(!x_values.is_empty(), "run_full_shuffled_oprf: empty input");
        let n = x_values.len();

        let (_k0, inputer_key_share) = self.step0_sample_and_authenticate_oprf_key_share(
            rng,
            auth_vole_sender,
            auth_vole_receiver,
            channel,
        )?;
        let authenticated_inputs =
            self.step1_inputer_commits_inputs(x_values, auth_vole_sender, channel)?;
        let (random_values, authenticated_ri_sender) =
            self.step2_inputer_commits_random_values(n, rng, auth_vole_sender, channel)?;
        let authenticated_r_x_plus_k0_sender = self
            .step3_inputer_authenticates_r_times_x_plus_k0_and_proves(
                &authenticated_inputs,
                &random_values,
                &authenticated_ri_sender,
                &inputer_key_share,
                auth_vole_sender,
                channel,
            )?;
        let (_u_values, authenticated_u_sender, authenticated_v_receiver) = self
            .step4_vole_share_x_times_k1_and_authenticate(
                x_values,
                auth_vole_sender,
                auth_vole_receiver,
                k1_mul_vole_sender,
                channel,
            )?;
        self.step5_open_random_linear_combination_for_uv_consistency(
            &authenticated_inputs,
            &authenticated_u_sender,
            channel,
        )?;
        self.step6_verify_authenticated_v_linear_combination_consistency(
            &authenticated_inputs,
            &authenticated_u_sender,
            &authenticated_v_receiver,
            inputer_key_share.bedoza_receiver(),
            auth_vole_sender,
            auth_vole_receiver,
            k1_prime_mul_vole_sender,
            rng,
            channel,
        )?;
        let opened_r_x_plus_k0_plus_u_sender = self.step7_open_ri_x_plus_k0_plus_ui(
            &authenticated_r_x_plus_k0_sender,
            &authenticated_u_sender,
            channel,
        )?;
        let authenticated_r_x_k_receiver = self
            .step8_receive_reauthenticated_ri_x_plus_k_and_verify_consistency(
                &opened_r_x_plus_k0_plus_u_sender,
                &authenticated_v_receiver,
                auth_vole_receiver,
                channel,
            )?;
        let authenticated_inverse_receiver = self.step9_receive_authenticated_inverses_and_verify(
            &authenticated_r_x_k_receiver,
            auth_vole_receiver,
            channel,
        )?;
        let g_ri =
            self.step10_send_g_ri_and_pad_consistency_proof(&authenticated_ri_sender, channel)?;
        let _authenticated_pi_receiver =
            self.step11_receive_authenticated_permutation_values(n, auth_vole_receiver, channel)?;
        let (x, authenticated_x_powers_receiver) = self
            .step12_send_challenge_and_receive_authenticated_x_powers(
                n,
                rng,
                auth_vole_receiver,
                channel,
            )?;
        let (_authenticated_permuted_inverse_receiver, _authenticated_products_receiver) = self
            .step13_receive_authenticated_xpi_times_inverse_and_verify(
                &authenticated_x_powers_receiver,
                auth_vole_receiver,
                channel,
            )?;
        self.step14_sample_challenges_and_verify_shuffle_product_identity(
            n,
            rng,
            auth_vole_receiver,
            channel,
        )?;

        let shuffled_oprf = self.step15_receive_shuffled_oprf_points(n, channel)?;
        let opened_left_product = self.step16_receive_and_verify_left_oprf_product(
            &g_ri,
            &authenticated_inverse_receiver,
            x,
            channel,
        )?;
        let opened_right_product = self.step17_receive_and_verify_right_oprf_product(
            &shuffled_oprf,
            &authenticated_x_powers_receiver,
            channel,
        )?;
        self.step18_verify_opened_oprf_products_match(&opened_left_product, &opened_right_product)?;

        Ok(shuffled_oprf)
    }
}
