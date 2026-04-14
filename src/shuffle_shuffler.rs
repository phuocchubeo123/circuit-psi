use crate::{
    bedoza::{
        bedoza_receiver::{linear_comb_receiver, receive_open_shares, BeDOZaReceiver},
        bedoza_sender::{linear_comb_sender, send_open_shares, BeDOZaSender},
        comm_util::receive_fe_vec,
        defines::{powers, random_fe_vec_from_rng, FE},
        vole_auth::{
            authenticate_batch_with_peer_key_receiver, authenticate_batch_with_peer_key_sender,
            vole_share_product_receiver,
        },
        wolverine::{
            wolverine_batch_mul_prove, wolverine_batch_mul_public_output_prove,
            wolverine_batch_mul_verify,
        },
        BeDOZa,
    },
    group::{msm_pippenger, receive_group_elements, send_group_elements, Group},
    tcp_channel::SwankyChannel,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use anyhow::{anyhow, ensure, Result};
use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};

// Role naming:
// - Shuffler (this module, previously "verifier"): owns permutation and key delta_1.
// - Inputer (peer, previously "prover"): owns inputs and key delta_0.

fn batch_invert_nonzero(values: &[FE], context: &str) -> Result<Vec<FE>> {
    ensure!(!values.is_empty(), "{}: empty input", context);

    let mut prefix_products = Vec::with_capacity(values.len());
    let mut acc = FE::one();
    for (i, &v) in values.iter().enumerate() {
        ensure!(v != FE::zero(), "{}: zero element at index {}", context, i);
        prefix_products.push(acc);
        acc *= v;
    }

    let mut acc_inv = acc
        .inv()
        .map_err(|e| anyhow!("{}: failed to invert total product: {:?}", context, e))?;
    let mut inverses = vec![FE::zero(); values.len()];

    for i in (0..values.len()).rev() {
        inverses[i] = acc_inv * prefix_products[i];
        acc_inv *= values[i];
    }

    Ok(inverses)
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

fn ensure_receiver_component_key_is(
    receivers: &[BeDOZaReceiver],
    expected_key: FE,
    context: &str,
) -> Result<()> {
    for (i, receiver) in receivers.iter().enumerate() {
        ensure!(
            receiver.key() == expected_key,
            "{}: key mismatch at index {} (expected delta_1)",
            context,
            i
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct Shuffler {
    delta_1: FE,
}

impl Shuffler {
    pub fn new(delta_1: FE) -> Self {
        Self { delta_1 }
    }

    pub fn delta_1(&self) -> FE {
        self.delta_1
    }

    fn validate_permutation(&self, permutation: &[usize], context: &str) -> Result<()> {
        ensure!(
            !permutation.is_empty(),
            "{} permutation cannot be empty",
            context
        );
        let n = permutation.len();
        let mut seen = vec![false; n];
        for (i, &idx) in permutation.iter().enumerate() {
            ensure!(
                idx < n,
                "{} invalid permutation index at position {}: {} not in [0,{})",
                context,
                i,
                idx,
                n
            );
            ensure!(
                !seen[idx],
                "{} duplicate permutation value {} at position {}",
                context,
                idx,
                i
            );
            seen[idx] = true;
        }
        Ok(())
    }

    fn receive_authenticated_batch(
        &self,
        expected_count: usize,
        context: &str,
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<BeDOZaReceiver>> {
        let receiver_commitments = authenticate_batch_with_peer_key_receiver(
            expected_count,
            false,
            self.delta_1,
            vole_receiver,
            channel,
        )?;
        ensure_receiver_component_key_is(&receiver_commitments, self.delta_1, context)?;
        Ok(receiver_commitments)
    }

    pub fn step2_vole_share_x_times_k1_and_authenticate(
        &self,
        authenticated_x_receiver: &[BeDOZaReceiver],
        authenticated_k1_sender: &BeDOZaSender,
        k1: FE,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        auth_vole_sender: &mut BufferedVoleSender,
        k1_mul_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<(Vec<FE>, Vec<BeDOZaReceiver>, Vec<BeDOZaSender>)> {
        ensure!(
            !authenticated_x_receiver.is_empty(),
            "step2 cannot run on empty x commitments"
        );

        // 1) Get additive shares of x_i * k1 from product VOLE.
        let n = authenticated_x_receiver.len();
        let v_values = vole_share_product_receiver(n, k1_mul_vole_receiver, channel)?;
        let v0_value = k1_mul_vole_receiver
            .random_auth(channel, 1)
            .map_err(|e| anyhow!("step2 failed to sample random v0 share: {e}"))?[0]
            .tag();

        // 2) Receive inputer's authenticated u_i, x0 and u0 under delta_1.
        let authenticated_u_receiver = authenticate_batch_with_peer_key_receiver(
            n,
            false,
            self.delta_1,
            auth_vole_receiver,
            channel,
        )?;
        let authenticated_x0_receiver = authenticate_batch_with_peer_key_receiver(
            1,
            false,
            self.delta_1,
            auth_vole_receiver,
            channel,
        )?[0];
        let authenticated_u0_receiver = authenticate_batch_with_peer_key_receiver(
            1,
            false,
            self.delta_1,
            auth_vole_receiver,
            channel,
        )?[0];

        // 3) Send authenticated v0 and v_i under delta_0.
        let authenticated_v0_sender =
            authenticate_batch_with_peer_key_sender(&[v0_value], true, auth_vole_sender, channel)?
                [0];
        let authenticated_v_sender =
            authenticate_batch_with_peer_key_sender(&v_values, true, auth_vole_sender, channel)?;

        // 4) Receive seed, open x/u linear combinations, and check x*k1 = u + v.
        let seed_raw = channel
            .receive()
            .map_err(|e| anyhow!("step2 failed to receive seed: {}", e))?;
        ensure!(
            seed_raw.len() == 32,
            "step2 expected 32-byte seed, got {} bytes",
            seed_raw.len()
        );
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_raw);
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, n)?;

        let u_linear =
            linear_comb_receiver(&authenticated_u_receiver, &coeffs, "step2 u linear comb")?
                + authenticated_u0_receiver;
        let x_linear =
            linear_comb_receiver(authenticated_x_receiver, &coeffs, "step2 x linear comb")?
                + authenticated_x0_receiver;
        let opened = receive_open_shares(&[u_linear, x_linear], channel)?;
        let u_open = opened[0];
        let x_open = opened[1];

        let v_linear_value = coeffs
            .iter()
            .zip(v_values.iter())
            .map(|(&coeff, &v_i)| coeff * v_i)
            .fold(FE::zero(), |acc, term| acc + term)
            + v0_value;
        ensure!(
            u_open + v_linear_value == x_open * k1,
            "step2 consistency check failed: u* + v* != x* * k1"
        );

        // 5) Open authenticated (x*k1 - u - v) so inputer can verify with its MAC.
        let v_linear = linear_comb_sender(&authenticated_v_sender, &coeffs, "step2 v linear comb")?
            + authenticated_v0_sender;
        let authenticated_x_times_k1_minus_uv =
            (*authenticated_k1_sender * x_open) - u_open - v_linear;
        send_open_shares(&[authenticated_x_times_k1_minus_uv], channel)?;

        Ok((v_values, authenticated_u_receiver, authenticated_v_sender))
    }

    pub fn step0_authenticate_oprf_key_and_xi_and_ri_and_send_pi<RNG: Rng>(
        &self,
        permutation: &[usize],
        rng: &mut RNG,
        auth_vole_sender: &mut BufferedVoleSender,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<(
        BeDOZa,
        FE,
        Vec<BeDOZaReceiver>,
        Vec<BeDOZaReceiver>,
        Vec<BeDOZaSender>,
    )> {
        self.validate_permutation(permutation, "step0")?;
        let n = permutation.len();

        // 0.1) Receive inputer's k0 authenticated under delta_1.
        let inputer_k0_receiver = self.receive_authenticated_batch(
            1,
            "shuffler.step0 received k0 share",
            auth_vole_receiver,
            channel,
        )?[0];
        let k1 = random_fe_vec_from_rng(rng, 1)?[0];
        let shuffler_k1_sender =
            authenticate_batch_with_peer_key_sender(&[k1], true, auth_vole_sender, channel)?[0];
        let shuffler_key_share = BeDOZa::new(shuffler_k1_sender, inputer_k0_receiver);

        // 0.2) Receive authenticated x_i and r_i from inputer under delta_1.
        let authenticated_inputs = self.receive_authenticated_batch(
            n,
            "shuffler.step0 received x_i commitments",
            auth_vole_receiver,
            channel,
        )?;
        let authenticated_ri_receiver = self.receive_authenticated_batch(
            n,
            "shuffler.step0 received r_i commitments",
            auth_vole_receiver,
            channel,
        )?;

        // 0.3) Authenticate permutation values under inputer key delta_0.
        let permutation_fe: Vec<FE> = permutation
            .iter()
            .map(|&idx| FE::from(idx as u64))
            .collect();
        let authenticated_pi_sender = authenticate_batch_with_peer_key_sender(
            &permutation_fe,
            true,
            auth_vole_sender,
            channel,
        )?;

        Ok((
            shuffler_key_share,
            k1,
            authenticated_inputs,
            authenticated_ri_receiver,
            authenticated_pi_sender,
        ))
    }

    pub fn step1_inputer_authenticates_r_times_x_plus_k0_and_verifies(
        &self,
        authenticated_inputs: &[BeDOZaReceiver],
        authenticated_ri_receiver: &[BeDOZaReceiver],
        shuffler_key_share: &BeDOZa,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<BeDOZaReceiver>> {
        ensure!(
            authenticated_inputs.len() == authenticated_ri_receiver.len(),
            "step1 length mismatch: input commitments {} vs random commitments {}",
            authenticated_inputs.len(),
            authenticated_ri_receiver.len()
        );

        let k0_receiver = *shuffler_key_share.bedoza_receiver();
        ensure!(
            k0_receiver.key() == self.delta_1,
            "step1 k0 receiver key mismatch: expected delta_1"
        );

        let x_plus_k0_commitments: Vec<BeDOZaReceiver> = authenticated_inputs
            .iter()
            .map(|x| *x + k0_receiver)
            .collect();
        let product_commitments = self.receive_authenticated_batch(
            authenticated_inputs.len(),
            "shuffler.step1 received r_i(x_i+k0) commitments",
            auth_vole_receiver,
            channel,
        )?;

        wolverine_batch_mul_verify(
            authenticated_ri_receiver,
            &x_plus_k0_commitments,
            &product_commitments,
            auth_vole_receiver,
            channel,
        )?;

        Ok(product_commitments)
    }

    pub fn step3_receive_ri_x_plus_k0_plus_ui_and_receive_reauthenticate_and_inverse<RNG: Rng>(
        &self,
        authenticated_r_x_plus_k0_receiver: &[BeDOZaReceiver],
        authenticated_u_receiver: &[BeDOZaReceiver],
        v_values: &[FE],
        authenticated_v_sender: &[BeDOZaSender],
        auth_vole_sender: &mut BufferedVoleSender,
        rng: &mut RNG,
        channel: &mut SwankyChannel,
    ) -> Result<(Vec<FE>, Vec<BeDOZaSender>)> {
        ensure!(
            authenticated_r_x_plus_k0_receiver.len() == authenticated_u_receiver.len(),
            "step3 length mismatch: r(x+k0) commitments {} vs u commitments {}",
            authenticated_r_x_plus_k0_receiver.len(),
            authenticated_u_receiver.len()
        );
        ensure!(
            authenticated_r_x_plus_k0_receiver.len() == v_values.len(),
            "step3 length mismatch: r(x+k0) commitments {} vs v values {}",
            authenticated_r_x_plus_k0_receiver.len(),
            v_values.len()
        );
        ensure!(
            authenticated_r_x_plus_k0_receiver.len() == authenticated_v_sender.len(),
            "step3 length mismatch: r(x+k0) commitments {} vs v commitments {}",
            authenticated_r_x_plus_k0_receiver.len(),
            authenticated_v_sender.len()
        );
        ensure!(
            !authenticated_r_x_plus_k0_receiver.is_empty(),
            "step3 cannot run on empty commitments"
        );

        // 3.1) Receive opened r_i(x_i+k0)+u_i, then reconstruct r_i(x_i+k).
        let opened_receiver_terms: Vec<BeDOZaReceiver> = authenticated_r_x_plus_k0_receiver
            .iter()
            .zip(authenticated_u_receiver.iter())
            .map(|(lhs, rhs)| *lhs + *rhs)
            .collect();
        let opened_r_x_k0_plus_u = receive_open_shares(&opened_receiver_terms, channel)?;
        let r_x_k_values: Vec<FE> = opened_r_x_k0_plus_u
            .iter()
            .zip(v_values.iter())
            .map(|(&opened_term, &v_i)| opened_term + v_i)
            .collect();

        // 3.2) Reauthenticate r_i(x_i+k) under inputer key delta_0, with sacrifice check.
        let authenticated_r_x_k_sender = authenticate_batch_with_peer_key_sender(
            &r_x_k_values,
            true,
            auth_vole_sender,
            channel,
        )?;
        let seed: [u8; 32] = rng.random::<[u8; 32]>();
        channel
            .send(&seed)
            .map_err(|e| anyhow!("step3 failed to send seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, r_x_k_values.len())?;
        let reauth_linear = linear_comb_sender(
            &authenticated_r_x_k_sender,
            &coeffs,
            "step3 reauthenticated linear comb",
        )?;
        let v_linear = linear_comb_sender(authenticated_v_sender, &coeffs, "step3 v linear comb")?;
        send_open_shares(&[reauth_linear, v_linear], channel)?;

        // 3.3) Authenticate inverses and prove r_i(x_i+k) * inv_i = 1 in batch.
        let inverse_values =
            batch_invert_nonzero(&r_x_k_values, "step3 failed to batch-invert r(x+k)")?;
        let authenticated_inverse_sender = authenticate_batch_with_peer_key_sender(
            &inverse_values,
            true,
            auth_vole_sender,
            channel,
        )?;
        let public_ones = vec![FE::one(); authenticated_r_x_k_sender.len()];
        wolverine_batch_mul_public_output_prove(
            &authenticated_r_x_k_sender,
            &authenticated_inverse_sender,
            &public_ones,
            auth_vole_sender,
            channel,
        )?;

        Ok((inverse_values, authenticated_inverse_sender))
    }

    pub fn step4_receive_g_ri_and_verify_pad_consistency_proof(
        &self,
        authenticated_ri_receiver: &[BeDOZaReceiver],
        channel: &mut SwankyChannel,
    ) -> Result<Vec<Group>> {
        ensure!(
            !authenticated_ri_receiver.is_empty(),
            "step4 cannot run on empty ri commitments"
        );

        let g_ri = receive_group_elements(channel)
            .map_err(|e| anyhow!("step4 failed to receive g^ri values: {}", e))?;
        ensure!(
            g_ri.len() == authenticated_ri_receiver.len(),
            "step4 length mismatch: received g^ri {} vs ri commitments {}",
            g_ri.len(),
            authenticated_ri_receiver.len()
        );

        // Sample coefficients for random linear combination and send seed to inputer.
        let mut rng = rand::rng();
        let seed: [u8; 32] = rng.random::<[u8; 32]>();
        channel
            .send(&seed)
            .map_err(|e| anyhow!("step4 failed to send seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let alphas = random_fe_vec_from_rng(&mut seeded_rng, authenticated_ri_receiver.len())?;

        // Receive g^{sum_i alpha_i * pad_i} from inputer.
        let g_pad_linear_vec = receive_group_elements(channel).map_err(|e| {
            anyhow!(
                "step4 failed to receive pad consistency group element: {}",
                e
            )
        })?;
        ensure!(
            g_pad_linear_vec.len() == 1,
            "step4 expected exactly one pad consistency element, got {}",
            g_pad_linear_vec.len()
        );
        let g_pad_linear = g_pad_linear_vec[0].clone();

        // Compute MSM: g^{sum_i alpha_i * r_i}.
        let msm = msm_pippenger(&g_ri, &alphas)
            .map_err(|e| anyhow!("step4 failed MSM computation with Pippenger: {}", e))?;
        let msm_delta = msm.scalar_mul(&self.delta_1);

        // Compute g^{sum_i alpha_i * tag_i}.
        let tag_linear = authenticated_ri_receiver
            .iter()
            .zip(alphas.iter())
            .map(|(ri, &alpha_i)| ri.tag() * alpha_i)
            .fold(FE::zero(), |acc, term| acc + term);
        let g_tag_linear = Group::base_point().scalar_mul(&tag_linear);

        // Check: g^{delta_1 * sum alpha_i r_i} * g^{sum alpha_i pad_i} = g^{sum alpha_i tag_i}.
        let lhs = msm_delta + g_pad_linear;
        ensure!(
            lhs.as_point() == g_tag_linear.as_point(),
            "step4 consistency check failed: MSM/tag relation for r_i commitments did not hold"
        );

        Ok(g_ri)
    }

    pub fn step5_receive_challenge_and_authenticate_xpi_and_prove_running_product(
        &self,
        permutation: &[usize],
        authenticated_pi_sender: &[BeDOZaSender],
        auth_vole_sender: &mut BufferedVoleSender,
        channel: &mut SwankyChannel,
    ) -> Result<(FE, Vec<BeDOZaSender>)> {
        self.validate_permutation(permutation, "step5")?;
        let n = authenticated_pi_sender.len();
        ensure!(n > 1, "step5 cannot run with n <= 1");
        ensure!(
            permutation.len() == n,
            "step5 length mismatch: permutation={} pi commitments={}",
            permutation.len(),
            n
        );

        // 5.1) Receive challenge x and authenticate x^{pi(i)}.
        let mut x_bytes = [0u8; 32];
        let x_raw = channel
            .receive()
            .map_err(|e| anyhow!("step5 failed to receive challenge x: {}", e))?;
        ensure!(
            x_raw.len() == 32,
            "step5 expected 32-byte challenge x, got {} bytes",
            x_raw.len()
        );
        x_bytes.copy_from_slice(&x_raw);
        let x = FE::from_bytes_le(&x_bytes)
            .map_err(|e| anyhow!("step5 failed to parse challenge x: {:?}", e))?;

        let x_powers = powers(x, permutation.len());
        let permuted_x_powers = checked_permute(&x_powers, permutation)?;
        let authenticated_x_powers_sender = authenticate_batch_with_peer_key_sender(
            &permuted_x_powers,
            true,
            auth_vole_sender,
            channel,
        )?;

        // 5.2) Receive alpha/beta/gamma and prove running-product identity.
        let challenges = receive_fe_vec(channel)
            .map_err(|e| anyhow!("step5 failed to receive alpha/beta/gamma: {e}"))?;
        ensure!(
            challenges.len() == 3,
            "step5 expected 3 challenges, got {}",
            challenges.len()
        );
        let alpha = challenges[0];
        let beta = challenges[1];
        let gamma = challenges[2];

        // u_pi(i) = alpha + beta * pi(i) + gamma * x^pi(i).
        let u_values: Vec<FE> = authenticated_pi_sender
            .iter()
            .zip(permuted_x_powers.iter())
            .map(|(pi_i, x_pi_i)| alpha + beta * pi_i.val() + gamma * *x_pi_i)
            .collect();
        let authenticated_u_sender =
            authenticate_batch_with_peer_key_sender(&u_values, true, auth_vole_sender, channel)?;

        // p_0 = u_0 * u_1, p_i = p_{i-1} * u_{i+1}.
        let mut running = u_values[0];
        let running_products: Vec<FE> = u_values
            .iter()
            .skip(1)
            .map(|&u_i| {
                running *= u_i;
                running
            })
            .collect();
        let authenticated_running_products = authenticate_batch_with_peer_key_sender(
            &running_products,
            true,
            auth_vole_sender,
            channel,
        )?;

        let mut u_chain_left = Vec::with_capacity(n - 1);
        u_chain_left.push(authenticated_u_sender[0]);
        u_chain_left.extend_from_slice(&authenticated_running_products[..n - 2]);
        wolverine_batch_mul_prove(
            &u_chain_left,
            &authenticated_u_sender[1..],
            &authenticated_running_products,
            auth_vole_sender,
            channel,
        )?;

        // Open final running product.
        send_open_shares(&[authenticated_running_products[n - 2]], channel)?;

        Ok((x, authenticated_x_powers_sender))
    }

    pub fn step6_send_shuffled_oprf_points_and_open_and_verify_products(
        &self,
        permutation: &[usize],
        g_ri: &[Group],
        inverse_values: &[FE],
        authenticated_inverse_sender: &[BeDOZaSender],
        x: FE,
        authenticated_x_powers_sender: &[BeDOZaSender],
        channel: &mut SwankyChannel,
    ) -> Result<Vec<Group>> {
        self.validate_permutation(permutation, "step6")?;
        ensure!(
            permutation.len() == g_ri.len() && permutation.len() == inverse_values.len(),
            "step6 length mismatch: pi={}, g^ri={}, inverse={}",
            permutation.len(),
            g_ri.len(),
            inverse_values.len()
        );
        ensure!(
            g_ri.len() == authenticated_inverse_sender.len(),
            "step6 length mismatch: g^ri={} inverse commitments={}",
            g_ri.len(),
            authenticated_inverse_sender.len()
        );
        ensure!(!g_ri.is_empty(), "step6 cannot run on empty g^ri batch");
        ensure!(
            g_ri.len() == authenticated_x_powers_sender.len(),
            "step6 length mismatch: g^ri={} x^pi commitments={}",
            g_ri.len(),
            authenticated_x_powers_sender.len()
        );

        // 6.1) Send shuffled OPRF points: (g^{r_{pi(i)}})^{1/(r_{pi(i)}(x_{pi(i)}+k))}.
        let permuted_g_ri = checked_permute(g_ri, permutation)?;
        let permuted_inverse_values = checked_permute(inverse_values, permutation)?;
        let shuffled_oprf: Vec<Group> = permuted_g_ri
            .iter()
            .zip(permuted_inverse_values.iter())
            .map(|(g_r_pi_i, inv_pi_i)| g_r_pi_i.scalar_mul(inv_pi_i))
            .collect();
        send_group_elements(&shuffled_oprf, channel)
            .map_err(|e| anyhow!("step6 failed to send shuffled OPRF points: {}", e))?;

        // 6.2) Open left product and its pad proof.
        let x_powers = powers(x, authenticated_inverse_sender.len());
        let scaled_inverse_sender: Vec<BeDOZaSender> = authenticated_inverse_sender
            .iter()
            .zip(x_powers.iter())
            .map(|(z_i, &x_i)| *z_i * x_i)
            .collect();
        let scaled_values: Vec<FE> = scaled_inverse_sender.iter().map(|s| s.val()).collect();
        let scaled_pads: Vec<FE> = scaled_inverse_sender.iter().map(|s| s.pad()).collect();
        let opened_left_product = msm_pippenger(g_ri, &scaled_values)
            .map_err(|e| anyhow!("step6 failed MSM for opened left product: {}", e))?;
        let left_pad_product = msm_pippenger(g_ri, &scaled_pads)
            .map_err(|e| anyhow!("step6 failed MSM for left pad product: {}", e))?;
        send_group_elements(&[opened_left_product.clone(), left_pad_product], channel)
            .map_err(|e| anyhow!("step6 failed to send left product proof elements: {}", e))?;

        // 6.3) Open right product and its pad proof.
        let x_pi_values: Vec<FE> = authenticated_x_powers_sender
            .iter()
            .map(|s| s.val())
            .collect();
        let x_pi_pads: Vec<FE> = authenticated_x_powers_sender
            .iter()
            .map(|s| s.pad())
            .collect();
        let opened_right_product = msm_pippenger(&shuffled_oprf, &x_pi_values)
            .map_err(|e| anyhow!("step6 failed MSM for opened right product: {}", e))?;
        let right_pad_product = msm_pippenger(&shuffled_oprf, &x_pi_pads)
            .map_err(|e| anyhow!("step6 failed MSM for right pad product: {}", e))?;
        send_group_elements(&[opened_right_product.clone(), right_pad_product], channel)
            .map_err(|e| anyhow!("step6 failed to send right product proof elements: {}", e))?;

        ensure!(
            opened_left_product.as_point() == opened_right_product.as_point(),
            "step6 failed: opened left OPRF product does not match opened right OPRF product"
        );
        Ok(shuffled_oprf)
    }

    pub fn run_full_shuffled_oprf<RNG: Rng>(
        &self,
        permutation: &[usize],
        _k1_prime: FE,
        rng: &mut RNG,
        auth_vole_sender: &mut BufferedVoleSender,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        k1_mul_vole_receiver: &mut BufferedVoleReceiver,
        _k1_prime_mul_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<Vec<Group>> {
        ensure!(
            !permutation.is_empty(),
            "run_full_shuffled_oprf: permutation cannot be empty"
        );
        let (
            shuffler_key_share,
            k1,
            authenticated_inputs,
            authenticated_ri_receiver,
            authenticated_pi_sender,
        ) = self.step0_authenticate_oprf_key_and_xi_and_ri_and_send_pi(
            permutation,
            rng,
            auth_vole_sender,
            auth_vole_receiver,
            channel,
        )?;
        let authenticated_r_x_plus_k0_receiver = self
            .step1_inputer_authenticates_r_times_x_plus_k0_and_verifies(
                &authenticated_inputs,
                &authenticated_ri_receiver,
                &shuffler_key_share,
                auth_vole_receiver,
                channel,
            )?;
        let (v_values, authenticated_u_receiver, authenticated_v_sender) = self
            .step2_vole_share_x_times_k1_and_authenticate(
                &authenticated_inputs,
                shuffler_key_share.bedoza_sender(),
                k1,
                auth_vole_receiver,
                auth_vole_sender,
                k1_mul_vole_receiver,
                channel,
            )?;
        let (inverse_values, authenticated_inverse_sender) = self
            .step3_receive_ri_x_plus_k0_plus_ui_and_receive_reauthenticate_and_inverse(
                &authenticated_r_x_plus_k0_receiver,
                &authenticated_u_receiver,
                &v_values,
                &authenticated_v_sender,
                auth_vole_sender,
                rng,
                channel,
            )?;
        let g_ri = self.step4_receive_g_ri_and_verify_pad_consistency_proof(
            &authenticated_ri_receiver,
            channel,
        )?;
        let (x, authenticated_x_powers_sender) = self
            .step5_receive_challenge_and_authenticate_xpi_and_prove_running_product(
                permutation,
                &authenticated_pi_sender,
                auth_vole_sender,
                channel,
            )?;
        self.step6_send_shuffled_oprf_points_and_open_and_verify_products(
            permutation,
            &g_ri,
            &inverse_values,
            &authenticated_inverse_sender,
            x,
            &authenticated_x_powers_sender,
            channel,
        )
    }
}
