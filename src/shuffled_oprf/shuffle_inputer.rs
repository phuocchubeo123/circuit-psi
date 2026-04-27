use crate::{
    bedoza::{
        BeDOZa,
        bedoza_receiver::{BeDOZaReceiver, linear_comb_receiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, linear_comb_sender, send_open_shares},
        comm_util::{random_32bytes_coin, send_fe_vec},
        wolverine::{
            wolverine_batch_mul_prove, wolverine_batch_mul_public_output_verify,
            wolverine_batch_mul_verify,
        },
    },
    math::{
        defines::{FE, powers, random_fe_vec_from_rng},
        group::{Group, msm_pippenger, receive_group_elements, send_group_elements},
    },
    tcp_channel::SwankyChannel,
    vole::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use anyhow::{Result, anyhow, ensure};
use rand::{Rng, SeedableRng, rngs::StdRng};

// Role naming:
// - Inputer (this module, previously "prover"): owns inputs and key delta_0.
// - Shuffler (peer, previously "verifier"): owns permutation and key delta_1.

pub struct InputerOutput {
    pub shuffled_oprf: Vec<Group>,
    pub authenticated_permutation: Vec<BeDOZaReceiver>,
}

#[derive(Clone, Copy, Debug)]
pub struct Inputer {
    delta0: FE,
    k0: FE,
}

impl Inputer {
    pub fn new(delta0: FE, k0: FE) -> Self {
        Self { delta0, k0 }
    }

    pub fn delta_0(&self) -> FE {
        self.delta0
    }

    pub fn vole_key(&self) -> FE {
        self.k0
    }

    pub fn step0_authenticate_oprf_key_and_xi_and_ri_and_receive_pi(
        &self,
        vals: &[FE],
        vole_sender: &mut BufferedVoleSender,
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<(
        BeDOZa,
        Vec<BeDOZaSender>,
        Vec<BeDOZaSender>,
        Vec<BeDOZaReceiver>,
    )> {
        // Inputer authenticates its caller-supplied VOLE key k0 and receives the shuffler's
        // authenticated VOLE key k1 from the peer.
        let inputer_k0_sender = vole_sender
            .commit_auth(channel, &[self.k0])
            .map_err(|e| anyhow!("Failed to authenticate k0: {e}"))?[0];
        let shuffler_k1_receiver = vole_receiver
            .commit_auth(channel, 1)
            .map_err(|e| anyhow!("Failed to receive authenticated k1: {e}"))?[0];

        // Inputer commits its local input values with VOLE under the shuffler's key delta_1.
        let authenticated_xis = vole_sender
            .commit_auth(channel, vals)
            .map_err(|e| anyhow!("Failed to authenticate input values: {e}"))?;

        // Inputer gets authenticated random values without additional network traffic.
        let authenticated_ris = vole_sender
            .random_auth(channel, vals.len())
            .map_err(|e| anyhow!("Failed to authenticate random values: {e}"))?;

        // Inputs receives authenticated permutation pi
        let authenticated_pi = vole_receiver
            .commit_auth(channel, vals.len())
            .map_err(|e| anyhow!("Failed to authenticate the permutation: {e}"))?;

        Ok((
            BeDOZa::new(inputer_k0_sender, shuffler_k1_receiver, false),
            authenticated_xis,
            authenticated_ris,
            authenticated_pi,
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
            "step1 length mismatch: authenticated x values {} vs authenticated r values {}",
            authenticated_xis.len(),
            authenticated_ris.len()
        );

        let authenticated_x_plus_k0: Vec<BeDOZaSender> = authenticated_xis
            .iter()
            .map(|x| x + authenticated_k0)
            .collect();

        let r_times_x_plus_k0_values: Vec<FE> = authenticated_ris
            .iter()
            .zip(authenticated_x_plus_k0.iter())
            .map(|(&r_i, x_plus_k0_i)| r_i.val() * x_plus_k0_i.val())
            .collect();

        let authenticated_r_times_x_plus_k0 = vole_sender
            .commit_auth(channel, &r_times_x_plus_k0_values)
            .map_err(|e| anyhow!("Failed to authenticate ri*(xi + k0): {e}"))?;

        wolverine_batch_mul_prove(
            authenticated_ris,
            &authenticated_x_plus_k0,
            &authenticated_r_times_x_plus_k0,
            vole_sender,
            channel,
        )?;

        Ok(authenticated_r_times_x_plus_k0)
    }

    pub fn step2_vole_share_r_times_k1_and_authenticate(
        &self,
        authenticated_rs: &[BeDOZaSender],
        authenticated_k1: &BeDOZaReceiver,
        vole_sender: &mut BufferedVoleSender,
        vole_receiver: &mut BufferedVoleReceiver,
        k1_vole_sender: &mut BufferedVoleSender,
        channel: &mut SwankyChannel,
    ) -> Result<(Vec<FE>, Vec<BeDOZaSender>, Vec<BeDOZaReceiver>)> {
        // 1) Use VOLE to produce additive shares of r_i * k1:
        //    inputer gets u_i, shuffler gets v_i, with u_i + v_i = r_i * k1.
        let r_values: Vec<FE> = authenticated_rs.iter().map(|r| r.val()).collect();
        let k1_auth_ris = k1_vole_sender
            .commit_auth(channel, &r_values)
            .map_err(|e| anyhow!("Failed to get secret shares of ri * k1: {e}"))?;
        let us: Vec<FE> = k1_auth_ris.iter().map(|share| share.pad()).collect();

        let k1_auth_rand = k1_vole_sender
            .random_auth(channel, 1)
            .map_err(|e| anyhow!("Failed to get secret shares of random r0 * k1: {e}"))?[0];

        // 2) Inputer authenticates u_i under shuffler key delta_1.
        let authenticated_us = vole_sender
            .commit_auth(channel, &us)
            .map_err(|e| anyhow!("Failed to authenticate ui values: {e}"))?;

        let authenticated_r0 = vole_sender
            .commit_auth(channel, &[k1_auth_rand.val()])
            .map_err(|e| anyhow!("Failed to authenticate r0 value: {e}"))?[0];

        let authenticated_u0 = vole_sender
            .commit_auth(channel, &[k1_auth_rand.pad()])
            .map_err(|e| anyhow!("Faile to authenticate u0 value: {e}"))?[0];

        let authenticated_v0 = vole_receiver
            .commit_auth(channel, 1)
            .map_err(|e| anyhow!("Failed to receive authenticated v0 value: {e}"))?[0];

        // 3) Shuffler authenticates v_i under inputer key delta_0 (inputer receives tags).
        let authenticated_vs = vole_receiver
            .commit_auth(channel, r_values.len())
            .map_err(|e| anyhow!("Failed to receive authenticated vi values: {e}"))?;

        // 4) Prove the correctness of authenticated u_i and r_i using a jointly sampled seed.
        let seed = random_32bytes_coin(true, channel)
            .map_err(|e| anyhow!("step2 failed to jointly sample seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, authenticated_rs.len())?;

        let u_linear = linear_comb_sender(&authenticated_us, &coeffs, "step2 u linear comb")?
            + authenticated_u0;
        let r_linear = linear_comb_sender(authenticated_rs, &coeffs, "step2 r linear comb")?
            + authenticated_r0;

        // Open the linear combinations of u_i and r_i to prove that r_i * k1 - u_i = v_i.
        send_open_shares(&[u_linear, r_linear], channel)
            .map_err(|e| anyhow!("Failed to open the linear combinations: {e}"))?;

        // 5) Prove the correctness of authenticated vi
        // Currently I do it by proving auth_k1 * r_linear - u_linear - auth_v_linear = 0.
        let v_linear = linear_comb_receiver(&authenticated_vs, &coeffs, "step2 v linear comb")?
            + authenticated_v0;
        let authenticated_r_times_k1_minus_uv =
            authenticated_k1 * r_linear.val() - u_linear.val() - v_linear;

        let r_times_k1_minus_uv =
            receive_open_shares(&[authenticated_r_times_k1_minus_uv], channel)?[0];
        ensure!(
            r_times_k1_minus_uv == FE::zero(),
            "step2 consistency check failed: r_linear * k1 - u_linear - v_linear != 0"
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

        let authenticated_r_times_x_plus_k: Vec<BeDOZaSender> =
            authenticated_r_times_x_plus_k0_sender
                .iter()
                .zip(authenticated_u_sender.iter())
                .map(|(lhs, rhs)| *lhs + *rhs)
                .collect();

        send_open_shares(&authenticated_r_times_x_plus_k, channel)
            .map_err(|e| anyhow!("Failed to open ri*(xi+k0)+ui: {e}"))?;

        // 2) Receive reauthentication
        // Receive shuffler's reauthentication of y_i := r_i*(x_i+k) under delta_0.
        let reauthenticated_r_x_k_receiver = vole_receiver
            .commit_auth(channel, authenticated_r_times_x_plus_k.len())
            .map_err(|e| anyhow!("Failed to receive reauthentication of ri*(xi+k): {e}"))?;

        // Shuffler chooses seed for batched sacrifice check.
        let mut seed = [0u8; 32];
        let seed_bytes = channel
            .receive()
            .map_err(|e| anyhow!("step8 failed to receive seed: {}", e))?;
        seed.copy_from_slice(&seed_bytes);
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, authenticated_r_times_x_plus_k.len())?;

        let reauth_linear = linear_comb_receiver(
            &reauthenticated_r_x_k_receiver,
            &coeffs,
            "step3 reauthenticated linear comb",
        )
        .map_err(|e| {
            anyhow!("Failed to compute linear combination of reauthenticated ri*(xi+k): {e}")
        })?;
        let v_linear = linear_comb_receiver(
            &authenticated_vs,
            &coeffs,
            "step3 authenticated v linear comb",
        )
        .map_err(|e| anyhow!("Failed to compute linear combination of authenticated vi: {e}"))?;
        let auth_linear = linear_comb_sender(
            &authenticated_r_times_x_plus_k,
            &coeffs,
            "step3 authenticated linear comb",
        )
        .map_err(|e| {
            anyhow!("Failed to compute linear combination of authenticated ri*(xi+k): {e}")
        })?;

        // Simply open the new random linear combination and compare with the old one.
        let opened = receive_open_shares(&[reauth_linear, v_linear], channel)?;
        let opened_reauth_linear = opened[0];
        let opened_v_linear = opened[1];

        ensure!(
            opened_reauth_linear == auth_linear.val() + opened_v_linear,
            "step8 consistency check failed: reauth batch != opened r(x+k0)+u batch + v batch"
        );

        // 3) Also receive and verify inverse
        // Prove y_i * y_i^{-1} = 1 with Wolverine (public-output multiplication).
        let authenticated_r_x_k_inverse = vole_receiver
            .commit_auth(channel, reauthenticated_r_x_k_receiver.len())
            .map_err(|e| anyhow!("Failed to receive authenticated inverses of ri*(xi+k): {e}"))?;
        let public_ones = vec![FE::one(); authenticated_r_x_k_inverse.len()];
        wolverine_batch_mul_public_output_verify(
            &authenticated_r_x_k_inverse,
            &reauthenticated_r_x_k_receiver,
            &public_ones,
            vole_receiver,
            channel,
        )
        .map_err(|e| anyhow!("Failed to verify inverse: {e}"))?;

        Ok(authenticated_r_x_k_inverse)
    }

    pub fn step4_send_g_ri_and_pad_consistency_proof(
        &self,
        authenticated_ri_sender: &[BeDOZaSender],
        channel: &mut SwankyChannel,
    ) -> Result<Vec<Group>> {
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

        // Jointly sample coefficients for the random linear combination.
        let seed = random_32bytes_coin(true, channel)
            .map_err(|e| anyhow!("step4 failed to jointly sample seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
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

    pub fn step5_send_challenge_and_receive_authenticated_xpi_and_xi_times_inverse<RNG: Rng>(
        &self,
        authenticated_pi: &[BeDOZaReceiver],
        authenticated_r_x_k_inverse: &[BeDOZaReceiver],
        rng: &mut RNG,
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<(FE, Vec<BeDOZaReceiver>, Vec<BeDOZaReceiver>)> {
        let n = authenticated_r_x_k_inverse.len();
        ensure!(n > 1, "step5 cannot run with n <= 1");
        // Inputer samples and sends challenge x.
        let x = random_fe_vec_from_rng(rng, 1)?[0];
        channel
            .send(&x.to_bytes_le())
            .map_err(|e| anyhow!("step5 failed to send challenge x: {}", e))?;

        // 2) Receive shuffled authenticated x^{pi(i)}
        let authenticated_permuted_x_powers = vole_receiver
            .commit_auth(channel, n)
            .map_err(|e| anyhow!("step5 failed to receive authenticated x^(pi(i)): {e}"))?;

        // 3) Locally compute authenticated x^i / r_i(x_i+k)
        let x_powers = powers(x, n);
        let authenticated_products: Vec<BeDOZaReceiver> = x_powers
            .iter()
            .zip(authenticated_r_x_k_inverse.iter())
            .map(|(x_p, r_x_k_inverse)| r_x_k_inverse * *x_p)
            .collect();

        // 4) Now verify the permuted things
        // First sample the challenges
        let coeffs = random_fe_vec_from_rng(rng, 3)?;
        let alpha = coeffs[0];
        let beta = coeffs[1];
        let gamma = coeffs[2];
        send_fe_vec(&[alpha, beta, gamma], channel)
            .map_err(|e| anyhow!("Failed to send challenges alpha, beta, gamma: {e}"))?;

        // Now locally compute u_pi(i) = alpha + beta * pi(i) + gamma * x^pi(i)
        let authenticated_shuffled_ui: Vec<BeDOZaReceiver> = authenticated_pi
            .iter()
            .zip(authenticated_permuted_x_powers.iter())
            .map(|(pi, x_p)| ((*pi * beta) + (*x_p * gamma)) + alpha)
            .collect();

        // Now receive authenticated running products: u_pi(1), u_pi(1) * u_pi(2), u_pi(1) * u_pi(2) * u_pi(3), ...
        let authenticated_running_products = vole_receiver
            .commit_auth(channel, n - 1)
            .map_err(|e| anyhow!("Failed to receive running product: {e}"))?;

        // Now prove the running product
        let u_chain_left = [
            vec![authenticated_shuffled_ui[0]],
            authenticated_running_products[..n - 2].to_vec(),
        ]
        .concat();
        let u_chain_right = authenticated_shuffled_ui[1..].to_vec();
        wolverine_batch_mul_verify(
            &u_chain_left,
            &u_chain_right,
            &authenticated_running_products,
            vole_receiver,
            channel,
        )
        .map_err(|e| anyhow!("Verifying the running product failed: {e}"))?;

        let product_to_check =
            receive_open_shares(&[authenticated_running_products[n - 2]], channel)
                .map_err(|e| anyhow!("Failed to receive the product to check: {e}"))?[0];

        let reference_product = (0..n)
            .zip(x_powers.iter())
            .map(|(i, x_p)| alpha + beta * FE::from(i as u64) + gamma * *x_p)
            .product();

        ensure!(
            product_to_check == reference_product,
            "shuffle product identity failed: final product difference is non-zero"
        );

        Ok((x, authenticated_permuted_x_powers, authenticated_products))
    }

    pub fn step6_receive_shuffled_oprf_points_and_verify(
        &self,
        g_ri: &[Group],
        authenticated_permuted_x_powers: &[BeDOZaReceiver],
        authenticated_xi_times_inverse: &[BeDOZaReceiver],
        channel: &mut SwankyChannel,
    ) -> Result<Vec<Group>> {
        let shuffled_oprf = receive_group_elements(channel)
            .map_err(|e| anyhow!("step15 failed to receive shuffled OPRF points: {}", e))?;

        // Precompute both tag/MSM products before reading the proof batches so the peer can keep
        // writing while we spend time on local multi-scalar multiplications.
        let mut tag_scratch = Vec::with_capacity(authenticated_xi_times_inverse.len());
        tag_scratch.extend(
            authenticated_xi_times_inverse
                .iter()
                .map(|bedoza_receiver| bedoza_receiver.tag()),
        );
        let g_xi_times_inverse_tag_product =
            msm_pippenger(g_ri, &tag_scratch).map_err(|e| {
                anyhow!("Failed to get multi-exponentiation for g_xi_times_inverse tags: {e}")
            })?;

        tag_scratch.clear();
        tag_scratch.extend(
            authenticated_permuted_x_powers
                .iter()
                .map(|bedoza_receiver| bedoza_receiver.tag()),
        );
        let shuffled_oprf_x_powers_tag_product =
            msm_pippenger(&shuffled_oprf, &tag_scratch).map_err(|e| {
                anyhow!("Failed to get multi-exponentiation for shuffled_oprf^x_powers tags: {e}")
            })?;

        // 1) Receive and verify the left hand side
        // Shuffler sends [opened_left_product, pad_product] in one batch.
        let left_proof_elems = receive_group_elements(channel)
            .map_err(|e| anyhow!("Failed to receive left proof group elements: {e}"))?;
        ensure!(
            left_proof_elems.len() == 2,
            "step6 expected 2 left proof elements, got {}",
            left_proof_elems.len()
        );
        let mut left_iter = left_proof_elems.into_iter();
        let g_xi_times_inverse_product = left_iter
            .next()
            .ok_or_else(|| anyhow!("step6 missing left opened product"))?;
        let g_xi_times_inverse_pad_product = left_iter
            .next()
            .ok_or_else(|| anyhow!("step6 missing left pad product"))?;

        let lhs = g_xi_times_inverse_pad_product + g_xi_times_inverse_tag_product;
        let rhs = g_xi_times_inverse_product.scalar_mul(&authenticated_xi_times_inverse[0].key());

        ensure!(
            lhs == rhs,
            "Failed to verify left shuffle polynomial product"
        );

        // 2) Receive and verify the right hand side, which is product of
        // (g^{1 / (x_pi(i) + k)})^{committed x^pi(i)}.
        // Shuffler sends [opened_right_product, right_pad_product] in one batch.
        let right_proof_elems = receive_group_elements(channel)
            .map_err(|e| anyhow!("Failed to receive right proof group elements: {e}"))?;
        ensure!(
            right_proof_elems.len() == 2,
            "step6 expected 2 right proof elements, got {}",
            right_proof_elems.len()
        );
        let mut right_iter = right_proof_elems.into_iter();
        let shuffled_oprf_x_powers_product = right_iter
            .next()
            .ok_or_else(|| anyhow!("step6 missing right opened product"))?;
        let shuffled_oprf_x_powers_pad_product = right_iter
            .next()
            .ok_or_else(|| anyhow!("step6 missing right pad product"))?;

        let lhs = shuffled_oprf_x_powers_pad_product + shuffled_oprf_x_powers_tag_product;
        let rhs =
            shuffled_oprf_x_powers_product.scalar_mul(&authenticated_permuted_x_powers[0].key());

        ensure!(
            lhs == rhs,
            "Failed to verify right shuffle polynomial product"
        );

        ensure!(
            g_xi_times_inverse_product == shuffled_oprf_x_powers_product,
            "Shuffled OPRF are inconsistent!"
        );

        Ok(shuffled_oprf)
    }

    pub fn run_full_shuffled_oprf<RNG: Rng>(
        &self,
        x_values: &[FE],
        rng: &mut RNG,
        auth_vole_sender: &mut BufferedVoleSender,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        k1_mul_vole_sender: &mut BufferedVoleSender,
        channel: &mut SwankyChannel,
    ) -> Result<InputerOutput> {
        ensure!(!x_values.is_empty(), "run_full_shuffled_oprf: empty input");
        let (key_shares, authenticated_xi, authenticated_ri, authenticated_pi) = self
            .step0_authenticate_oprf_key_and_xi_and_ri_and_receive_pi(
                x_values,
                auth_vole_sender,
                auth_vole_receiver,
                channel,
            )?;

        let authenticated_r_x_plus_k0 = self
            .step1_inputer_authenticates_r_times_x_plus_k0_and_proves(
                &authenticated_xi,
                &authenticated_ri,
                key_shares.bedoza_sender(),
                auth_vole_sender,
                channel,
            )?;

        let (_u_values, authenticated_u, authenticated_v) = self
            .step2_vole_share_r_times_k1_and_authenticate(
                &authenticated_ri,
                key_shares.bedoza_receiver(),
                auth_vole_sender,
                auth_vole_receiver,
                k1_mul_vole_sender,
                channel,
            )?;

        let authenticated_r_x_k_inverse = self
            .step3_open_ri_x_plus_k0_plus_ui_and_receive_reauthenticate(
                &authenticated_r_x_plus_k0,
                &authenticated_u,
                &authenticated_v,
                auth_vole_receiver,
                channel,
            )?;

        let g_ri = self.step4_send_g_ri_and_pad_consistency_proof(&authenticated_ri, channel)?;

        let (_x, authenticated_permuted_x_powers, authenticated_xi_times_inverse) = self
            .step5_send_challenge_and_receive_authenticated_xpi_and_xi_times_inverse(
                &authenticated_pi,
                &authenticated_r_x_k_inverse,
                rng,
                auth_vole_receiver,
                channel,
            )?;

        let shuffled_oprf = self.step6_receive_shuffled_oprf_points_and_verify(
            &g_ri,
            &authenticated_permuted_x_powers,
            &authenticated_xi_times_inverse,
            channel,
        )?;

        Ok(InputerOutput {
            shuffled_oprf,
            authenticated_permutation: authenticated_pi,
        })
    }
}
