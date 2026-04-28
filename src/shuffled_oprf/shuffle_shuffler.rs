use crate::{
    bedoza::{
        BeDOZa,
        bedoza_receiver::{BeDOZaReceiver, linear_comb_receiver, receive_open_shares},
        bedoza_sender::{BeDOZaSender, linear_comb_sender, send_open_shares},
        comm_util::{random_32bytes_coin, receive_fe_vec},
        wolverine::{
            wolverine_batch_mul_prove, wolverine_batch_mul_public_output_prove,
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
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

// Role naming:
// - Shuffler (this module, previously "verifier"): owns permutation and key delta_1.
// - Inputer (peer, previously "prover"): owns inputs and key delta_0.

pub struct ShufflerOutput {
    pub shuffled_oprf: Vec<Group>,
    pub unshuffled_oprf: Vec<Group>,
    pub authenticated_inputs: Vec<BeDOZaReceiver>,
    pub authenticated_permutation: Vec<BeDOZaSender>,
}

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

#[derive(Clone, Copy, Debug)]
pub struct Shuffler {
    delta_1: FE,
    k1: FE,
}

impl Shuffler {
    pub fn new(delta_1: FE, k1: FE) -> Self {
        Self { delta_1, k1 }
    }

    pub fn delta_1(&self) -> FE {
        self.delta_1
    }

    pub fn vole_key(&self) -> FE {
        self.k1
    }

    pub fn step0_authenticate_oprf_key_and_xi_and_ri_and_send_pi(
        &self,
        permutation: &[usize],
        vole_sender: &mut BufferedVoleSender,
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
        shuffler_key_share_out: &mut Option<BeDOZa>,
        authenticated_xis_out: &mut Vec<BeDOZaReceiver>,
        authenticated_ris_out: &mut Vec<BeDOZaReceiver>,
        authenticated_pi_sender_out: &mut Vec<BeDOZaSender>,
    ) -> Result<()> {
        let n = permutation.len();
        let start = std::time::Instant::now();
        let mut step = 0usize;
        let mut log_step = |description: &str| {
            step += 1;
            println!(
                "[shuffle_shuffler::step0] Step {step}: {description} (elapsed: {:?})",
                start.elapsed()
            );
        };

        // 0.1) Receive the inputer's authenticated VOLE key k0 under delta_1.
        let mut inputer_k0_receiver_buf = Vec::with_capacity(1);
        vole_receiver
            .commit_auth_into(channel, 1, &mut inputer_k0_receiver_buf)
            .map_err(|e| anyhow!("failed to receive authenticated k0: {e}"))?;
        let inputer_k0_receiver = inputer_k0_receiver_buf[0];

        let mut shuffler_k1_sender_buf = Vec::with_capacity(1);
        vole_sender
            .commit_auth_into(channel, &[self.k1], &mut shuffler_k1_sender_buf)
            .map_err(|e| anyhow!("failed to authenticate k1: {e}"))?;
        let shuffler_k1_sender = shuffler_k1_sender_buf[0];
        let shuffler_key_share = BeDOZa::new(shuffler_k1_sender, inputer_k0_receiver, true);
        log_step("received authenticated k0 and authenticated k1");

        // 0.2) Receive authenticated x_i and r_i from inputer under delta_1.
        vole_receiver
            .commit_auth_into(channel, n, authenticated_xis_out)
            .map_err(|e| anyhow!("failed to materialize receiver VOLE outputs: {e}"))?;
        log_step("received authenticated input x_i values");

        let authenticated_ris: Vec<BeDOZaReceiver> = vole_receiver
            .random_auth(channel, n)
            .map_err(|e| anyhow!("failed to receive authenticated r_i values: {e}"))?;
        authenticated_ris_out.extend(authenticated_ris);
        log_step("received authenticated random r_i values");

        // 0.3) Authenticate permutation values under inputer key delta_0.
        let permutation_fe: Vec<FE> = permutation
            .iter()
            .map(|&idx| FE::from(idx as u64))
            .collect();
        vole_sender
            .commit_auth_into(channel, &permutation_fe, authenticated_pi_sender_out)
            .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?;
        log_step("authenticated and sent permutation pi values");

        *shuffler_key_share_out = Some(shuffler_key_share);

        Ok(())
    }

    pub fn step1_inputer_authenticates_r_times_x_plus_k0_and_verifies(
        &self,
        authenticated_inputs: &[BeDOZaReceiver],
        authenticated_ri_receiver: &[BeDOZaReceiver],
        shuffler_key_share: &BeDOZa,
        vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
        product_commitments_out: &mut Vec<BeDOZaReceiver>,
    ) -> Result<()> {
        let start = std::time::Instant::now();
        let mut step = 0usize;
        let mut log_step = |description: &str| {
            step += 1;
            println!(
                "[shuffle_shuffler::step1] Step {step}: {description} (elapsed: {:?})",
                start.elapsed()
            );
        };

        ensure!(
            authenticated_inputs.len() == authenticated_ri_receiver.len(),
            "step1 length mismatch: input commitments {} vs random commitments {}",
            authenticated_inputs.len(),
            authenticated_ri_receiver.len()
        );
        log_step("validated input and r_i commitment lengths");

        let k0_receiver = *shuffler_key_share.bedoza_receiver();
        log_step("loaded authenticated k0 receiver share");

        let x_plus_k0_commitments: Vec<BeDOZaReceiver> = authenticated_inputs
            .iter()
            .map(|x| *x + k0_receiver)
            .collect();
        log_step("computed authenticated (x_i + k0) commitments");

        vole_receiver
            .commit_auth_into(channel, authenticated_inputs.len(), product_commitments_out)
            .map_err(|e| anyhow!("failed to materialize receiver VOLE outputs: {e}"))?;
        log_step("received authenticated r_i * (x_i + k0) commitments");

        wolverine_batch_mul_verify(
            authenticated_ri_receiver,
            &x_plus_k0_commitments,
            product_commitments_out,
            vole_receiver,
            channel,
        )?;
        log_step("verified multiplication relation with Wolverine");

        Ok(())
    }

    pub fn step2_vole_share_r_times_k1_and_authenticate(
        &self,
        authenticated_r_receiver: &[BeDOZaReceiver],
        authenticated_k1_sender: &BeDOZaSender,
        vole_receiver: &mut BufferedVoleReceiver,
        vole_sender: &mut BufferedVoleSender,
        k1_mul_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<(Vec<FE>, Vec<BeDOZaReceiver>, Vec<BeDOZaSender>)> {
        ensure!(
            !authenticated_r_receiver.is_empty(),
            "step2 cannot run on empty r commitments"
        );

        // 1) Get additive shares of r_i * k1 from product VOLE.
        let n = authenticated_r_receiver.len();

        // Should have u_i + v_i = r_i * k1
        let v_values: Vec<FE> = k1_mul_vole_receiver
            .commit_auth(channel, n)
            .map_err(|e| {
                anyhow!("failed to materialize receiver VOLE outputs for product shares: {e}")
            })?
            .into_iter()
            .map(|r| r.tag())
            .collect();

        let mut v0_share_buf = Vec::with_capacity(1);
        k1_mul_vole_receiver
            .random_auth_into(channel, 1, &mut v0_share_buf)
            .map_err(|e| anyhow!("step2 failed to sample random v0 share: {e}"))?;
        let v0_value = v0_share_buf[0].tag();

        // 2) Receive inputer's authenticated u_i, r0 and u0 under delta_1.
        let mut authenticated_u_receiver = Vec::with_capacity(n);
        vole_receiver
            .commit_auth_into(channel, n, &mut authenticated_u_receiver)
            .map_err(|e| anyhow!("failed to materialize receiver VOLE outputs: {e}"))?;

        let authenticated_r0_receiver = vole_receiver
            .commit_auth(channel, 1)
            .map_err(|e| anyhow!("failed to materialize receiver VOLE outputs: {e}"))?[0];

        let authenticated_u0_receiver = vole_receiver
            .commit_auth(channel, 1)
            .map_err(|e| anyhow!("failed to materialize receiver VOLE outputs: {e}"))?[0];

        // 3) Send authenticated v0 and v_i under delta_0.
        let authenticated_v0_sender = vole_sender
            .commit_auth(channel, &[v0_value])
            .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?[0];

        let mut authenticated_v_sender = Vec::with_capacity(v_values.len());
        vole_sender
            .commit_auth_into(channel, &v_values, &mut authenticated_v_sender)
            .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?;

        // 4) Jointly sample a seed, open r/u linear combinations, and check r*k1 = u + v.
        let seed = random_32bytes_coin(false, channel)
            .map_err(|e| anyhow!("step2 failed to jointly sample seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, n)?;

        let u_linear =
            linear_comb_receiver(&authenticated_u_receiver, &coeffs, "step2 u linear comb")?
                + authenticated_u0_receiver;
        let r_linear =
            linear_comb_receiver(authenticated_r_receiver, &coeffs, "step2 r linear comb")?
                + authenticated_r0_receiver;
        let opened = receive_open_shares(&[u_linear, r_linear], channel)?;
        let u_open = opened[0];
        let r_open = opened[1];

        let v_linear_value = coeffs
            .iter()
            .zip(v_values.iter())
            .map(|(&coeff, &v_i)| coeff * v_i)
            .fold(FE::zero(), |acc, term| acc + term)
            + v0_value;
        ensure!(
            u_open + v_linear_value == r_open * self.k1,
            "step2 consistency check failed: u* + v* != r* * k1"
        );

        // 5) Open authenticated (r*k1 - u - v) so inputer can verify with its MAC.
        let v_linear = linear_comb_sender(&authenticated_v_sender, &coeffs, "step2 v linear comb")?
            + authenticated_v0_sender;
        let authenticated_r_times_k1_minus_uv =
            (*authenticated_k1_sender * r_open) - u_open - v_linear;
        send_open_shares(&[authenticated_r_times_k1_minus_uv], channel)?;

        Ok((v_values, authenticated_u_receiver, authenticated_v_sender))
    }

    pub fn step3_receive_ri_x_plus_k0_plus_ui_and_receive_reauthenticate_and_inverse(
        &self,
        authenticated_r_x_plus_k0_receiver: &[BeDOZaReceiver],
        authenticated_u_receiver: &[BeDOZaReceiver],
        v_values: &[FE],
        authenticated_v_sender: &[BeDOZaSender],
        auth_vole_sender: &mut BufferedVoleSender,
        channel: &mut SwankyChannel,
    ) -> Result<(Vec<FE>, Vec<FE>, Vec<BeDOZaSender>)> {
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

        // 3.2) Derive authenticated y_i := r_i*(x_i+k) under inputer key delta_0 without
        // re-authenticating the full vector: y_i = opened(r_i*(x_i+k0)+u_i) + v_i.
        let authenticated_r_x_k_sender: Vec<BeDOZaSender> = authenticated_v_sender
            .iter()
            .zip(opened_r_x_k0_plus_u.iter())
            .map(|(v_i, &opened_term)| *v_i + opened_term)
            .collect();

        // 3.3) Authenticate inverses and prove r_i(x_i+k) * inv_i = 1 in batch.
        let inverse_values =
            batch_invert_nonzero(&r_x_k_values, "step3 failed to batch-invert r(x+k)")?;
        let mut authenticated_inverse_sender = Vec::with_capacity(inverse_values.len());
        auth_vole_sender
            .commit_auth_into(channel, &inverse_values, &mut authenticated_inverse_sender)
            .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?;
        let public_ones = vec![FE::one(); authenticated_r_x_k_sender.len()];
        wolverine_batch_mul_public_output_prove(
            &authenticated_r_x_k_sender,
            &authenticated_inverse_sender,
            &public_ones,
            auth_vole_sender,
            channel,
        )?;

        Ok((r_x_k_values, inverse_values, authenticated_inverse_sender))
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

        // Shuffler samples seed/alphas locally for the random linear combination challenge.
        let mut sampling_rng = rand::rng();
        let seed: [u8; 32] = sampling_rng.random();
        let mut seeded_rng = StdRng::from_seed(seed);
        let alphas = random_fe_vec_from_rng(&mut seeded_rng, authenticated_ri_receiver.len())?;

        // Precompute g^{sum_i alpha_i * tag_i} early while waiting for peer messages.
        let tag_linear = authenticated_ri_receiver
            .iter()
            .zip(alphas.iter())
            .map(|(ri, &alpha_i)| ri.tag() * alpha_i)
            .fold(FE::zero(), |acc, term| acc + term);
        let g_tag_linear = Group::base_point().scalar_mul(&tag_linear);

        let g_ri = receive_group_elements(channel)
            .map_err(|e| anyhow!("step4 failed to receive g^ri values: {}", e))?;
        ensure!(
            g_ri.len() == authenticated_ri_receiver.len(),
            "step4 length mismatch: received g^ri {} vs ri commitments {}",
            g_ri.len(),
            authenticated_ri_receiver.len()
        );

        // Send challenge seed to inputer only after receiving g^ri.
        channel
            .send(&seed)
            .map_err(|e| anyhow!("step4 failed to send seed: {}", e))?;

        // Compute MSM: g^{sum_i alpha_i * r_i}.
        let msm = msm_pippenger(&g_ri, &alphas)
            .map_err(|e| anyhow!("step4 failed MSM computation with Pippenger: {}", e))?;
        let msm_delta = msm.scalar_mul(&self.delta_1);

        // Receive g^{sum_i alpha_i * pad_i} from inputer after finishing local work.
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

        // Check: g^{sum alpha_i tag_i} + g^{sum alpha_i pad_i} = g^{delta_1 * sum alpha_i r_i}.
        let lhs = g_tag_linear + g_pad_linear;
        ensure!(
            lhs.as_point() == msm_delta.as_point(),
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
        let authenticated_x_powers_sender: Vec<BeDOZaSender> = auth_vole_sender
            .commit_auth(channel, &permuted_x_powers)
            .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?;

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
        let authenticated_u_sender: Vec<BeDOZaSender> = authenticated_pi_sender
            .iter()
            .zip(authenticated_x_powers_sender.iter())
            .map(|(pi_i, x_pi_i)| ((*pi_i * beta) + (*x_pi_i * gamma)) + alpha)
            .collect();

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
        let authenticated_running_products: Vec<BeDOZaSender> = auth_vole_sender
            .commit_auth(channel, &running_products)
            .map_err(|e| anyhow!("failed to materialize sender VOLE inputs: {e}"))?;

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
    ) -> Result<(Vec<Group>, Vec<Group>)> {
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

        // 6.1) Build unshuffled OPRF once, then apply permutation.
        // This avoids an extra full pass of scalar multiplications.
        let unshuffled_oprf: Vec<Group> = g_ri
            .iter()
            .zip(inverse_values.iter())
            .map(|(g_ri_i, inverse_i)| g_ri_i.scalar_mul(inverse_i))
            .collect();
        let shuffled_oprf = checked_permute(&unshuffled_oprf, permutation)?;
        send_group_elements(&shuffled_oprf, channel)
            .map_err(|e| anyhow!("step6 failed to send shuffled OPRF points: {}", e))?;

        // 6.2) Open left product and its pad proof.
        // Build scaled values/pads directly to avoid materializing BeDOZaSender and x^i vectors.
        let mut scaled_values = Vec::with_capacity(authenticated_inverse_sender.len());
        let mut scaled_pads = Vec::with_capacity(authenticated_inverse_sender.len());
        let mut x_power = FE::one();
        for share in authenticated_inverse_sender {
            scaled_values.push(share.val() * x_power);
            scaled_pads.push(share.pad() * x_power);
            x_power *= x;
        }
        let opened_left_product = msm_pippenger(g_ri, &scaled_values)
            .map_err(|e| anyhow!("step6 failed MSM for opened left product: {}", e))?;
        let left_pad_product = msm_pippenger(g_ri, &scaled_pads)
            .map_err(|e| anyhow!("step6 failed MSM for left pad product: {}", e))?;
        send_group_elements(&[opened_left_product.clone(), left_pad_product], channel)
            .map_err(|e| anyhow!("step6 failed to send left product proof elements: {}", e))?;

        // 6.3) Open right product and its pad proof.
        let mut x_pi_values = Vec::with_capacity(authenticated_x_powers_sender.len());
        let mut x_pi_pads = Vec::with_capacity(authenticated_x_powers_sender.len());
        for share in authenticated_x_powers_sender {
            x_pi_values.push(share.val());
            x_pi_pads.push(share.pad());
        }
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
        Ok((shuffled_oprf, unshuffled_oprf))
    }

    pub fn run_full_shuffled_oprf<RNG: Rng>(
        &self,
        permutation: &[usize],
        _rng: &mut RNG,
        auth_vole_sender: &mut BufferedVoleSender,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        k1_mul_vole_receiver: &mut BufferedVoleReceiver,
        channel: &mut SwankyChannel,
    ) -> Result<ShufflerOutput> {
        ensure!(
            !permutation.is_empty(),
            "run_full_shuffled_oprf: permutation cannot be empty"
        );
        let total_start = std::time::Instant::now();
        let mut step_idx = 0usize;
        let mut log_step_done = |label: &str, step_start: std::time::Instant| {
            step_idx += 1;
            println!(
                "[shuffle_shuffler::run] Step {step_idx} {label} done in {:?} (total: {:?})",
                step_start.elapsed(),
                total_start.elapsed()
            );
        };

        let mut shuffler_key_share = None;
        let mut authenticated_inputs = Vec::with_capacity(permutation.len());
        let mut authenticated_ri_receiver = Vec::with_capacity(permutation.len());
        let mut authenticated_pi_sender = Vec::with_capacity(permutation.len());
        let step_start = std::time::Instant::now();
        self.step0_authenticate_oprf_key_and_xi_and_ri_and_send_pi(
            permutation,
            auth_vole_sender,
            auth_vole_receiver,
            channel,
            &mut shuffler_key_share,
            &mut authenticated_inputs,
            &mut authenticated_ri_receiver,
            &mut authenticated_pi_sender,
        )?;
        log_step_done(
            "step0 authenticate key/inputs/random/permutation",
            step_start,
        );
        let shuffler_key_share =
            shuffler_key_share.ok_or_else(|| anyhow!("step0 did not produce key share"))?;
        let mut authenticated_r_x_plus_k0_receiver = Vec::with_capacity(permutation.len());
        let step_start = std::time::Instant::now();
        self.step1_inputer_authenticates_r_times_x_plus_k0_and_verifies(
            &authenticated_inputs,
            &authenticated_ri_receiver,
            &shuffler_key_share,
            auth_vole_receiver,
            channel,
            &mut authenticated_r_x_plus_k0_receiver,
        )?;
        log_step_done("step1 verify r*(x+k0)", step_start);
        let step_start = std::time::Instant::now();
        let (v_values, authenticated_u_receiver, authenticated_v_sender) = self
            .step2_vole_share_r_times_k1_and_authenticate(
                &authenticated_ri_receiver,
                shuffler_key_share.bedoza_sender(),
                auth_vole_receiver,
                auth_vole_sender,
                k1_mul_vole_receiver,
                channel,
            )?;
        log_step_done("step2 share r*k1 and authenticate", step_start);
        let step_start = std::time::Instant::now();
        let (_r_x_k_values, inverse_values, authenticated_inverse_sender) = self
            .step3_receive_ri_x_plus_k0_plus_ui_and_receive_reauthenticate_and_inverse(
                &authenticated_r_x_plus_k0_receiver,
                &authenticated_u_receiver,
                &v_values,
                &authenticated_v_sender,
                auth_vole_sender,
                channel,
            )?;
        log_step_done("step3 open/re-auth/inverse", step_start);

        let step_start = std::time::Instant::now();
        let g_ri = self.step4_receive_g_ri_and_verify_pad_consistency_proof(
            &authenticated_ri_receiver,
            channel,
        )?;
        log_step_done("step4 receive g^ri and verify pad proof", step_start);
        let step_start = std::time::Instant::now();
        let (x, authenticated_x_powers_sender) = self
            .step5_receive_challenge_and_authenticate_xpi_and_prove_running_product(
                permutation,
                &authenticated_pi_sender,
                auth_vole_sender,
                channel,
            )?;
        log_step_done("step5 challenge/auth/prove running product", step_start);
        let step_start = std::time::Instant::now();
        let (shuffled_oprf, unshuffled_oprf) = self
            .step6_send_shuffled_oprf_points_and_open_and_verify_products(
                permutation,
                &g_ri,
                &inverse_values,
                &authenticated_inverse_sender,
                x,
                &authenticated_x_powers_sender,
                channel,
            )?;
        log_step_done("step6 send and verify shuffled OPRF points", step_start);

        Ok(ShufflerOutput {
            shuffled_oprf,
            unshuffled_oprf,
            authenticated_inputs,
            authenticated_permutation: authenticated_pi_sender,
        })
    }
}
