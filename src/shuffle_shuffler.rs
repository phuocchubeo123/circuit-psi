use crate::{
    bedoza::{
        BeDOZa,
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        defines::{FE, random_fe_vec_from_rng},
        vole_auth::{
            FourQVoleMac, authenticate_batch_with_peer_key_receiver,
            authenticate_batch_with_peer_key_sender, vole_share_product_receiver,
        },
        wolverine::{
            wolverine_batch_mul_prove, wolverine_batch_mul_public_output_prove,
            wolverine_batch_mul_verify,
        },
    },
    group::{Group, msm_pippenger, receive_group_elements, send_group_elements},
    tcp_channel::TcpChannel,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use anyhow::{Result, anyhow, ensure};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use swanky_channel_legacy::AbstractChannel;

// Role naming:
// - Shuffler (this module, previously "verifier"): owns permutation and key delta_1.
// - Inputer (peer, previously "prover"): owns inputs and key delta_0.

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

fn linear_comb_receiver(
    shares: &[BeDOZaReceiver],
    coeffs: &[FE],
    context: &str,
) -> Result<BeDOZaReceiver> {
    ensure!(!shares.is_empty(), "{}: empty share list", context);
    ensure!(
        shares.len() == coeffs.len(),
        "{}: length mismatch shares={} coeffs={}",
        context,
        shares.len(),
        coeffs.len()
    );

    let mut acc = shares[0] * coeffs[0];
    for (share, &coeff) in shares.iter().skip(1).zip(coeffs.iter().skip(1)) {
        acc = acc + (*share * coeff);
    }
    Ok(acc)
}

fn linear_comb_sender(
    shares: &[BeDOZaSender],
    coeffs: &[FE],
    context: &str,
) -> Result<BeDOZaSender> {
    ensure!(!shares.is_empty(), "{}: empty share list", context);
    ensure!(
        shares.len() == coeffs.len(),
        "{}: length mismatch shares={} coeffs={}",
        context,
        shares.len(),
        coeffs.len()
    );

    let mut acc = shares[0] * coeffs[0];
    for (share, &coeff) in shares.iter().skip(1).zip(coeffs.iter().skip(1)) {
        acc = acc + (*share * coeff);
    }
    Ok(acc)
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

fn send_open_sender_shares_abstract<C: AbstractChannel>(
    shares: &[BeDOZaSender],
    channel: &mut C,
) -> Result<()> {
    for share in shares {
        channel
            .write_bytes(&share.val().to_bytes_le())
            .map_err(|e| anyhow!("failed to send opened sender value: {}", e))?;
    }
    for share in shares {
        channel
            .write_bytes(&share.pad().to_bytes_le())
            .map_err(|e| anyhow!("failed to send opened sender pad: {}", e))?;
    }
    channel
        .flush()
        .map_err(|e| anyhow!("failed to flush opened sender shares: {}", e))?;
    Ok(())
}

fn receive_open_sender_shares_abstract<C: AbstractChannel>(
    receiver_shares: &[BeDOZaReceiver],
    channel: &mut C,
) -> Result<Vec<FE>> {
    ensure!(
        !receiver_shares.is_empty(),
        "receive_open_sender_shares_abstract: empty receiver share list"
    );
    let key = receiver_shares[0].key();
    for (i, share) in receiver_shares.iter().enumerate() {
        ensure!(
            share.key() == key,
            "receive_open_sender_shares_abstract: key mismatch at index {}",
            i
        );
    }

    let mut values = Vec::with_capacity(receiver_shares.len());
    for _ in receiver_shares {
        let mut bytes = [0u8; 32];
        channel
            .read_bytes(&mut bytes)
            .map_err(|e| anyhow!("failed to receive opened sender value: {}", e))?;
        let v = FE::from_bytes_le(&bytes)
            .map_err(|e| anyhow!("failed to parse opened sender value: {:?}", e))?;
        values.push(v);
    }

    let mut pads = Vec::with_capacity(receiver_shares.len());
    for _ in receiver_shares {
        let mut bytes = [0u8; 32];
        channel
            .read_bytes(&mut bytes)
            .map_err(|e| anyhow!("failed to receive opened sender pad: {}", e))?;
        let p = FE::from_bytes_le(&bytes)
            .map_err(|e| anyhow!("failed to parse sender pad: {:?}", e))?;
        pads.push(p);
    }

    for (i, ((&value, &pad), receiver_share)) in values
        .iter()
        .zip(pads.iter())
        .zip(receiver_shares.iter())
        .enumerate()
    {
        ensure!(
            key * value + pad == receiver_share.tag(),
            "receive_open_sender_shares_abstract: tag mismatch at index {}",
            i
        );
    }

    Ok(values)
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

    pub fn step0_sample_and_authenticate_oprf_key_share<C: AbstractChannel, RNG: Rng>(
        &self,
        rng: &mut RNG,
        vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<(FE, BeDOZa)> {
        // Shuffler first receives inputer's k0 authenticated under delta_1, then samples k1
        // and authenticates it under inputer key delta_0.
        let inputer_k0_receiver: BeDOZaReceiver = authenticate_batch_with_peer_key_receiver(
            1,
            false,
            self.delta_1,
            vole_receiver,
            channel,
        )?[0];
        let k1 = random_fe_vec_from_rng(rng, 1)?[0];
        let shuffler_k1_sender: BeDOZaSender =
            authenticate_batch_with_peer_key_sender(&[k1], true, vole_sender, channel)?[0];

        ensure!(
            inputer_k0_receiver.key() == self.delta_1,
            "shuffler.step0 key mismatch for received k0 share"
        );

        Ok((k1, BeDOZa::new(shuffler_k1_sender, inputer_k0_receiver)))
    }

    pub fn step1_inputer_commits_inputs<C: AbstractChannel>(
        &self,
        expected_count: usize,
        vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<Vec<BeDOZaReceiver>> {
        let receiver_commitments = authenticate_batch_with_peer_key_receiver(
            expected_count,
            false,
            self.delta_1,
            vole_receiver,
            channel,
        )?;
        ensure_receiver_component_key_is(
            &receiver_commitments,
            self.delta_1,
            "shuffler.step1_inputer_commits_inputs output",
        )?;
        Ok(receiver_commitments)
    }

    pub fn step2_inputer_commits_random_values<C: AbstractChannel>(
        &self,
        expected_count: usize,
        vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<Vec<BeDOZaReceiver>> {
        let receiver_commitments = authenticate_batch_with_peer_key_receiver(
            expected_count,
            false,
            self.delta_1,
            vole_receiver,
            channel,
        )?;
        ensure_receiver_component_key_is(
            &receiver_commitments,
            self.delta_1,
            "shuffler.inputer_commits_random_values output",
        )?;
        Ok(receiver_commitments)
    }

    pub fn step3_inputer_authenticates_r_times_x_plus_k0_and_proves<C: AbstractChannel>(
        &self,
        input_commitments: &[BeDOZaReceiver],
        random_value_commitments: &[BeDOZaReceiver],
        inputer_k0_share: &BeDOZa,
        vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<Vec<BeDOZaReceiver>> {
        ensure!(
            input_commitments.len() == random_value_commitments.len(),
            "step3 length mismatch: input commitments {} vs random commitments {}",
            input_commitments.len(),
            random_value_commitments.len()
        );

        let k0_receiver = *inputer_k0_share.bedoza_receiver();
        ensure!(
            k0_receiver.key() == self.delta_1,
            "step3 k0 receiver key mismatch: expected delta_1"
        );

        let x_plus_k0_commitments: Vec<BeDOZaReceiver> =
            input_commitments.iter().map(|x| *x + k0_receiver).collect();

        let product_commitments = authenticate_batch_with_peer_key_receiver(
            input_commitments.len(),
            false,
            self.delta_1,
            vole_receiver,
            channel,
        )?;

        wolverine_batch_mul_verify(
            random_value_commitments,
            &x_plus_k0_commitments,
            &product_commitments,
            inputer_k0_share.bedoza_receiver(),
            channel,
        )?;

        Ok(product_commitments)
    }

    pub fn step4_vole_share_x_times_k1_and_authenticate<C: AbstractChannel>(
        &self,
        expected_count: usize,
        auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        k1_mul_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<(Vec<FE>, Vec<BeDOZaReceiver>, Vec<BeDOZaSender>)> {
        // 1) Use VOLE to produce additive shares of x_i * k1:
        //    inputer gets u_i, shuffler gets v_i, with u_i + v_i = x_i * k1.
        let v_values = vole_share_product_receiver(expected_count, k1_mul_vole_receiver, channel)?;

        // 2) Receive inputer's authentication of u_i under delta_1.
        let u_authenticated_receiver = authenticate_batch_with_peer_key_receiver(
            expected_count,
            false,
            self.delta_1,
            auth_vole_receiver,
            channel,
        )?;

        // 3) Shuffler authenticates v_i under inputer key delta_0.
        let v_authenticated_sender =
            authenticate_batch_with_peer_key_sender(&v_values, true, auth_vole_sender, channel)?;

        ensure!(
            v_values.len() == u_authenticated_receiver.len()
                && v_values.len() == v_authenticated_sender.len(),
            "step4 output length mismatch: v={}, u_auth={}, v_auth={}",
            v_values.len(),
            u_authenticated_receiver.len(),
            v_authenticated_sender.len()
        );

        Ok((v_values, u_authenticated_receiver, v_authenticated_sender))
    }

    pub fn step5_verify_random_linear_combination_for_uv_consistency<C: AbstractChannel>(
        &self,
        authenticated_x_receiver: &[BeDOZaReceiver],
        authenticated_u_receiver: &[BeDOZaReceiver],
        v_values: &[FE],
        k1: FE,
        channel: &mut C,
    ) -> Result<()> {
        ensure!(
            authenticated_x_receiver.len() == authenticated_u_receiver.len(),
            "step5 length mismatch: x commitments {} vs u commitments {}",
            authenticated_x_receiver.len(),
            authenticated_u_receiver.len()
        );
        ensure!(
            authenticated_x_receiver.len() == v_values.len(),
            "step5 length mismatch: x commitments {} vs v values {}",
            authenticated_x_receiver.len(),
            v_values.len()
        );
        ensure!(
            !authenticated_x_receiver.is_empty(),
            "step5 cannot run on empty commitments"
        );

        let mut rng = rand::rng();
        let seed: [u8; 32] = rng.random::<[u8; 32]>();
        channel
            .write_bytes(&seed)
            .map_err(|e| anyhow!("step5 failed to send seed: {}", e))?;
        channel
            .flush()
            .map_err(|e| anyhow!("step5 failed to flush seed: {}", e))?;

        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, authenticated_x_receiver.len())?;

        let u_linear =
            linear_comb_receiver(authenticated_u_receiver, &coeffs, "step5 u linear comb")?;
        let x_linear =
            linear_comb_receiver(authenticated_x_receiver, &coeffs, "step5 x linear comb")?;
        let opened = receive_open_sender_shares_abstract(&[u_linear, x_linear], channel)?;
        let u_open = opened[0];
        let x_open = opened[1];

        let v_linear = coeffs
            .iter()
            .zip(v_values.iter())
            .map(|(&coeff, &v_i)| coeff * v_i)
            .fold(FE::zero(), |acc, term| acc + term);

        ensure!(
            u_open + v_linear == x_open * k1,
            "step5 consistency check failed: u* + v* != x* * k1"
        );

        Ok(())
    }

    pub fn step6_prove_authenticated_v_linear_combination_consistency<C: AbstractChannel>(
        &self,
        authenticated_x_receiver: &[BeDOZaReceiver],
        authenticated_u_receiver: &[BeDOZaReceiver],
        authenticated_v_sender: &[BeDOZaSender],
        authenticated_k1_sender: &BeDOZaSender,
        k1_prime: FE,
        auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        k1_prime_mul_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<()> {
        ensure!(
            authenticated_x_receiver.len() == authenticated_u_receiver.len(),
            "step6 length mismatch: x commitments {} vs u commitments {}",
            authenticated_x_receiver.len(),
            authenticated_u_receiver.len()
        );
        ensure!(
            authenticated_x_receiver.len() == authenticated_v_sender.len(),
            "step6 length mismatch: x commitments {} vs v commitments {}",
            authenticated_x_receiver.len(),
            authenticated_v_sender.len()
        );
        ensure!(
            !authenticated_x_receiver.is_empty(),
            "step6 cannot run on empty commitments"
        );

        // Receive inputer's linear-combination seed and derive shared coefficients.
        let mut seed = [0u8; 32];
        channel
            .read_bytes(&mut seed)
            .map_err(|e| anyhow!("step6 failed to receive seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, authenticated_x_receiver.len())?;

        let _x_linear =
            linear_comb_receiver(authenticated_x_receiver, &coeffs, "step6 x linear comb")?;
        let u_linear =
            linear_comb_receiver(authenticated_u_receiver, &coeffs, "step6 u linear comb")?;
        let v_linear = linear_comb_sender(authenticated_v_sender, &coeffs, "step6 v linear comb")?;

        // VOLE-share x* * k1' (receiver side must use delta = k1').
        let v_prime = vole_share_product_receiver(1, k1_prime_mul_vole_receiver, channel)?[0];

        // Authenticate v' and k1' for inputer-side MAC verification.
        let v_prime_sender =
            authenticate_batch_with_peer_key_sender(&[v_prime], true, auth_vole_sender, channel)?
                [0];
        let k1_prime_sender =
            authenticate_batch_with_peer_key_sender(&[k1_prime], true, auth_vole_sender, channel)?
                [0];

        // Receive inputer's authentication of u' under delta_1.
        let u_prime_receiver = authenticate_batch_with_peer_key_receiver(
            1,
            false,
            self.delta_1,
            auth_vole_receiver,
            channel,
        )?[0];

        // Receive random challenge scalars a, b from inputer.
        let mut a_bytes = [0u8; 32];
        channel
            .read_bytes(&mut a_bytes)
            .map_err(|e| anyhow!("step6 failed to receive challenge a: {}", e))?;
        let a = FE::from_bytes_le(&a_bytes)
            .map_err(|e| anyhow!("step6 failed to parse challenge a: {:?}", e))?;
        let mut b_bytes = [0u8; 32];
        channel
            .read_bytes(&mut b_bytes)
            .map_err(|e| anyhow!("step6 failed to receive challenge b: {}", e))?;
        let b = FE::from_bytes_le(&b_bytes)
            .map_err(|e| anyhow!("step6 failed to parse challenge b: {:?}", e))?;

        let _u_check_receiver = u_linear * a + (u_prime_receiver * b);
        let v_check_sender = v_linear * a + (v_prime_sender * b);
        let k_check_sender = (*authenticated_k1_sender * a) + (k1_prime_sender * b);

        // Open k-check and v-check to inputer for verification.
        send_open_sender_shares_abstract(&[k_check_sender, v_check_sender], channel)?;

        Ok(())
    }

    pub fn step7_receive_ri_x_plus_k0_plus_ui_and_reconstruct_ri_x_plus_k<C: AbstractChannel>(
        &self,
        authenticated_r_times_x_plus_k0_receiver: &[BeDOZaReceiver],
        authenticated_u_receiver: &[BeDOZaReceiver],
        v_values: &[FE],
        channel: &mut C,
    ) -> Result<Vec<FE>> {
        ensure!(
            authenticated_r_times_x_plus_k0_receiver.len() == authenticated_u_receiver.len(),
            "step7 length mismatch: r(x+k0) commitments {} vs u commitments {}",
            authenticated_r_times_x_plus_k0_receiver.len(),
            authenticated_u_receiver.len()
        );
        ensure!(
            authenticated_r_times_x_plus_k0_receiver.len() == v_values.len(),
            "step7 length mismatch: r(x+k0) commitments {} vs v values {}",
            authenticated_r_times_x_plus_k0_receiver.len(),
            v_values.len()
        );
        ensure!(
            !authenticated_r_times_x_plus_k0_receiver.is_empty(),
            "step7 cannot run on empty commitments"
        );

        let opened_receiver_terms: Vec<BeDOZaReceiver> = authenticated_r_times_x_plus_k0_receiver
            .iter()
            .zip(authenticated_u_receiver.iter())
            .map(|(lhs, rhs)| *lhs + *rhs)
            .collect();

        // Receive opened ri*(xi+k0)+ui from inputer and verify tags during opening.
        let opened_r_x_k0_plus_u =
            receive_open_sender_shares_abstract(&opened_receiver_terms, channel)?;

        // Compute final term ri*(xi+k) = ri*(xi+k0)+ui+vi.
        let r_x_k: Vec<FE> = opened_r_x_k0_plus_u
            .iter()
            .zip(v_values.iter())
            .map(|(&opened_term, &v_i)| opened_term + v_i)
            .collect();
        Ok(r_x_k)
    }

    pub fn step8_reauthenticate_ri_x_plus_k_and_prove_consistency<C: AbstractChannel, RNG: Rng>(
        &self,
        r_x_k_values: &[FE],
        authenticated_v_sender: &[BeDOZaSender],
        reauth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        rng: &mut RNG,
        channel: &mut C,
    ) -> Result<Vec<BeDOZaSender>> {
        ensure!(
            r_x_k_values.len() == authenticated_v_sender.len(),
            "step8 length mismatch: r(x+k) values {} vs v commitments {}",
            r_x_k_values.len(),
            authenticated_v_sender.len()
        );
        ensure!(
            !r_x_k_values.is_empty(),
            "step8 cannot run on empty commitments"
        );

        // Reauthenticate reconstructed y_i := r_i*(x_i+k) under inputer key delta_0.
        let reauthenticated_r_x_k_sender = authenticate_batch_with_peer_key_sender(
            r_x_k_values,
            true,
            reauth_vole_sender,
            channel,
        )?;

        // Batched sacrifice check using shared random coefficients.
        let seed: [u8; 32] = rng.random::<[u8; 32]>();
        channel
            .write_bytes(&seed)
            .map_err(|e| anyhow!("step8 failed to send seed: {}", e))?;
        channel
            .flush()
            .map_err(|e| anyhow!("step8 failed to flush seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let coeffs = random_fe_vec_from_rng(&mut seeded_rng, r_x_k_values.len())?;

        let reauth_linear = linear_comb_sender(
            &reauthenticated_r_x_k_sender,
            &coeffs,
            "step8 reauthenticated linear comb",
        )?;
        let v_linear = linear_comb_sender(authenticated_v_sender, &coeffs, "step8 v linear comb")?;

        // Open both linear combinations to inputer for consistency check.
        send_open_sender_shares_abstract(&[reauth_linear, v_linear], channel)?;

        Ok(reauthenticated_r_x_k_sender)
    }

    pub fn step9_authenticate_inverses_and_prove<C: AbstractChannel>(
        &self,
        authenticated_r_x_k_sender: &[BeDOZaSender],
        inverse_auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<(Vec<FE>, Vec<BeDOZaSender>)> {
        let _ = self.delta_1;
        ensure!(
            !authenticated_r_x_k_sender.is_empty(),
            "step9 cannot run on empty commitments"
        );

        let r_x_k_values: Vec<FE> = authenticated_r_x_k_sender.iter().map(|s| s.val()).collect();
        let inverse_values =
            batch_invert_nonzero(&r_x_k_values, "step9 failed to batch-invert r(x+k)")?;

        // Shuffler authenticates inverses under inputer key delta_0.
        let authenticated_inverse_sender = authenticate_batch_with_peer_key_sender(
            &inverse_values,
            true,
            inverse_auth_vole_sender,
            channel,
        )?;

        // Prove y_i * y_i^{-1} = 1 with Wolverine (public-output multiplication).
        let public_ones = vec![FE::one(); authenticated_r_x_k_sender.len()];
        wolverine_batch_mul_public_output_prove(
            authenticated_r_x_k_sender,
            &authenticated_inverse_sender,
            &public_ones,
            channel,
        )?;

        Ok((inverse_values, authenticated_inverse_sender))
    }

    pub fn step10_receive_g_ri_and_verify_pad_consistency(
        &self,
        authenticated_ri_receiver: &[BeDOZaReceiver],
        channel: &mut TcpChannel,
    ) -> Result<Vec<Group>> {
        ensure!(
            !authenticated_ri_receiver.is_empty(),
            "step10 cannot run on empty ri commitments"
        );

        let g_ri = receive_group_elements(channel)
            .map_err(|e| anyhow!("step10 failed to receive g^ri values: {}", e))?;
        ensure!(
            g_ri.len() == authenticated_ri_receiver.len(),
            "step10 length mismatch: received g^ri {} vs ri commitments {}",
            g_ri.len(),
            authenticated_ri_receiver.len()
        );

        // Sample coefficients for random linear combination and send seed to inputer.
        let mut rng = rand::rng();
        let seed: [u8; 32] = rng.random::<[u8; 32]>();
        channel
            .send(&seed)
            .map_err(|e| anyhow!("step10 failed to send seed: {}", e))?;
        let mut seeded_rng = StdRng::from_seed(seed);
        let alphas = random_fe_vec_from_rng(&mut seeded_rng, authenticated_ri_receiver.len())?;

        // Receive g^{sum_i alpha_i * pad_i} from inputer.
        let g_pad_linear_vec = receive_group_elements(channel).map_err(|e| {
            anyhow!(
                "step10 failed to receive pad consistency group element: {}",
                e
            )
        })?;
        ensure!(
            g_pad_linear_vec.len() == 1,
            "step10 expected exactly one pad consistency element, got {}",
            g_pad_linear_vec.len()
        );
        let g_pad_linear = g_pad_linear_vec[0].clone();

        // Compute MSM: g^{sum_i alpha_i * r_i}.
        let msm = msm_pippenger(&g_ri, &alphas)
            .map_err(|e| anyhow!("step10 failed MSM computation with Pippenger: {}", e))?;
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
            "step10 consistency check failed: MSM/tag relation for r_i commitments did not hold"
        );

        Ok(g_ri)
    }

    pub fn step11_authenticate_permutation_values<C: AbstractChannel>(
        &self,
        permutation: &[usize],
        permutation_auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<Vec<BeDOZaSender>> {
        let _ = self.delta_1;
        ensure!(
            !permutation.is_empty(),
            "step11 permutation cannot be empty"
        );

        let n = permutation.len();
        let mut seen = vec![false; n];
        for (i, &idx) in permutation.iter().enumerate() {
            ensure!(
                idx < n,
                "step11 invalid permutation index at position {}: {} not in [0,{})",
                i,
                idx,
                n
            );
            ensure!(
                !seen[idx],
                "step11 duplicate permutation value {} at position {}",
                idx,
                i
            );
            seen[idx] = true;
        }

        let permutation_fe: Vec<FE> = permutation
            .iter()
            .map(|&idx| FE::from(idx as u64))
            .collect();
        let authenticated_permutation = authenticate_batch_with_peer_key_sender(
            &permutation_fe,
            true,
            permutation_auth_vole_sender,
            channel,
        )?;
        Ok(authenticated_permutation)
    }

    pub fn step12_receive_challenge_and_authenticate_x_powers<C: AbstractChannel>(
        &self,
        permutation: &[usize],
        x_power_auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<(FE, Vec<FE>, Vec<BeDOZaSender>)> {
        let _ = self.delta_1;
        ensure!(
            !permutation.is_empty(),
            "step12 permutation cannot be empty"
        );

        let n = permutation.len();
        let mut seen = vec![false; n];
        for (i, &idx) in permutation.iter().enumerate() {
            ensure!(
                idx < n,
                "step12 invalid permutation index at position {}: {} not in [0,{})",
                i,
                idx,
                n
            );
            ensure!(
                !seen[idx],
                "step12 duplicate permutation value {} at position {}",
                idx,
                i
            );
            seen[idx] = true;
        }

        // Receive challenge x from inputer.
        let mut x_bytes = [0u8; 32];
        channel
            .read_bytes(&mut x_bytes)
            .map_err(|e| anyhow!("step12 failed to receive challenge x: {}", e))?;
        let x = FE::from_bytes_le(&x_bytes)
            .map_err(|e| anyhow!("step12 failed to parse challenge x: {:?}", e))?;

        // Compute x^{pi(1)}, ..., x^{pi(n)} as a permuted vector of powers.
        let x_powers = powers(x, permutation.len());
        let permuted_x_powers = checked_permute(&x_powers, permutation)?;

        // Authenticate under inputer key delta_0.
        let authenticated_x_powers = authenticate_batch_with_peer_key_sender(
            &permuted_x_powers,
            true,
            x_power_auth_vole_sender,
            channel,
        )?;

        Ok((x, permuted_x_powers, authenticated_x_powers))
    }

    pub fn step13_authenticate_xpi_times_inverse_and_prove<C: AbstractChannel>(
        &self,
        permutation: &[usize],
        authenticated_x_powers_sender: &[BeDOZaSender],
        authenticated_inverse_sender: &[BeDOZaSender],
        vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<(Vec<FE>, Vec<FE>, Vec<BeDOZaSender>, Vec<BeDOZaSender>)> {
        let _ = self.delta_1;
        ensure!(
            authenticated_x_powers_sender.len() == authenticated_inverse_sender.len(),
            "step13 length mismatch: x^pi commitments {} vs inverse commitments {}",
            authenticated_x_powers_sender.len(),
            authenticated_inverse_sender.len()
        );
        ensure!(
            permutation.len() == authenticated_x_powers_sender.len(),
            "step13 length mismatch: permutation {} vs x^pi commitments {}",
            permutation.len(),
            authenticated_x_powers_sender.len()
        );
        ensure!(
            !authenticated_x_powers_sender.is_empty(),
            "step13 cannot run on empty commitments"
        );

        // Build the permuted inverse batch [1 / r_{pi(i)}(x_{pi(i)}+k)]_i.
        let permuted_inverse_values: Vec<FE> = checked_permute(
            &authenticated_inverse_sender
                .iter()
                .map(|inv_i| inv_i.val())
                .collect::<Vec<FE>>(),
            permutation,
        )?;

        let authenticated_permuted_inverse = authenticate_batch_with_peer_key_sender(
            &permuted_inverse_values,
            true,
            vole_sender,
            channel,
        )?;

        let product_values: Vec<FE> = authenticated_x_powers_sender
            .iter()
            .zip(permuted_inverse_values.iter())
            .map(|(x_pi_i, &inv_perm_i)| x_pi_i.val() * inv_perm_i)
            .collect();

        let authenticated_products =
            authenticate_batch_with_peer_key_sender(&product_values, true, vole_sender, channel)?;

        // Prove product consistency against authenticated x^pi(i) and inverse commitments.
        wolverine_batch_mul_prove(
            authenticated_x_powers_sender,
            &authenticated_permuted_inverse,
            &authenticated_products,
            &authenticated_products[0],
            channel,
        )?;

        Ok((
            permuted_inverse_values,
            product_values,
            authenticated_permuted_inverse,
            authenticated_products,
        ))
    }

    pub fn step14_prove_shuffle_product_identity<C: AbstractChannel>(
        &self,
        x: FE,
        authenticated_pi_sender: &[BeDOZaSender],
        authenticated_y_pi_sender: &[BeDOZaSender],
        authenticated_z_sender: &[BeDOZaSender],
        authenticated_x_powers_sender: &[BeDOZaSender],
        product_identity_auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        channel: &mut C,
    ) -> Result<()> {
        let _ = self.delta_1;
        let n = authenticated_pi_sender.len();
        ensure!(n > 0, "step14 cannot run on empty commitments");
        ensure!(
            authenticated_y_pi_sender.len() == n
                && authenticated_z_sender.len() == n
                && authenticated_x_powers_sender.len() == n,
            "step14 length mismatch: pi={}, y_pi={}, z={}, x_pi={}",
            authenticated_pi_sender.len(),
            authenticated_y_pi_sender.len(),
            authenticated_z_sender.len(),
            authenticated_x_powers_sender.len()
        );

        // Receive alpha, beta, gamma from inputer.
        let mut alpha_bytes = [0u8; 32];
        channel
            .read_bytes(&mut alpha_bytes)
            .map_err(|e| anyhow!("step14 failed to receive alpha: {}", e))?;
        let alpha = FE::from_bytes_le(&alpha_bytes)
            .map_err(|e| anyhow!("step14 failed to parse alpha: {:?}", e))?;

        let mut beta_bytes = [0u8; 32];
        channel
            .read_bytes(&mut beta_bytes)
            .map_err(|e| anyhow!("step14 failed to receive beta: {}", e))?;
        let beta = FE::from_bytes_le(&beta_bytes)
            .map_err(|e| anyhow!("step14 failed to parse beta: {:?}", e))?;

        let mut gamma_bytes = [0u8; 32];
        channel
            .read_bytes(&mut gamma_bytes)
            .map_err(|e| anyhow!("step14 failed to receive gamma: {}", e))?;
        let gamma = FE::from_bytes_le(&gamma_bytes)
            .map_err(|e| anyhow!("step14 failed to parse gamma: {:?}", e))?;

        let x_powers = powers(x, n);

        // u_i = alpha * i + beta * x^i * z_i + gamma * x^i.
        let u_values: Vec<FE> = (0..n)
            .map(|i| {
                let i_fe = FE::from(i as u64);
                alpha * i_fe
                    + beta * x_powers[i] * authenticated_z_sender[i].val()
                    + gamma * x_powers[i]
            })
            .collect();

        // v_i = alpha * pi(i) + beta * y_pi(i) + gamma * x^pi(i).
        let v_values: Vec<FE> = (0..n)
            .map(|i| {
                alpha * authenticated_pi_sender[i].val()
                    + beta * authenticated_y_pi_sender[i].val()
                    + gamma * authenticated_x_powers_sender[i].val()
            })
            .collect();

        let authenticated_u_sender = authenticate_batch_with_peer_key_sender(
            &u_values,
            true,
            product_identity_auth_vole_sender,
            channel,
        )?;
        let authenticated_v_sender = authenticate_batch_with_peer_key_sender(
            &v_values,
            true,
            product_identity_auth_vole_sender,
            channel,
        )?;
        let authenticated_one_sender = authenticate_batch_with_peer_key_sender(
            &[FE::one()],
            true,
            product_identity_auth_vole_sender,
            channel,
        )?;

        // Authenticate prefix products p_u[i] = prod_{j<=i} u_j.
        let mut running_u = FE::one();
        let u_prefix_values: Vec<FE> = u_values
            .iter()
            .map(|&u_i| {
                running_u = running_u * u_i;
                running_u
            })
            .collect();
        let authenticated_u_prefix_sender = authenticate_batch_with_peer_key_sender(
            &u_prefix_values,
            true,
            product_identity_auth_vole_sender,
            channel,
        )?;

        // Authenticate prefix products p_v[i] = prod_{j<=i} v_j.
        let mut running_v = FE::one();
        let v_prefix_values: Vec<FE> = v_values
            .iter()
            .map(|&v_i| {
                running_v = running_v * v_i;
                running_v
            })
            .collect();
        let authenticated_v_prefix_sender = authenticate_batch_with_peer_key_sender(
            &v_prefix_values,
            true,
            product_identity_auth_vole_sender,
            channel,
        )?;

        // Prove multiplication chain for u.
        let mut u_chain_left = Vec::with_capacity(n);
        u_chain_left.push(authenticated_one_sender[0]);
        u_chain_left.extend_from_slice(&authenticated_u_prefix_sender[..n - 1]);
        wolverine_batch_mul_prove(
            &u_chain_left,
            &authenticated_u_sender,
            &authenticated_u_prefix_sender,
            &authenticated_u_prefix_sender[0],
            channel,
        )?;

        // Prove multiplication chain for v.
        let mut v_chain_left = Vec::with_capacity(n);
        v_chain_left.push(authenticated_one_sender[0]);
        v_chain_left.extend_from_slice(&authenticated_v_prefix_sender[..n - 1]);
        wolverine_batch_mul_prove(
            &v_chain_left,
            &authenticated_v_sender,
            &authenticated_v_prefix_sender,
            &authenticated_v_prefix_sender[0],
            channel,
        )?;

        // Open final product difference for zero check.
        let final_diff_sender =
            authenticated_u_prefix_sender[n - 1] - authenticated_v_prefix_sender[n - 1];
        send_open_sender_shares_abstract(&[final_diff_sender], channel)?;

        Ok(())
    }

    pub fn step15_send_shuffled_oprf_points(
        &self,
        permutation: &[usize],
        g_ri: &[Group],
        inverse_values: &[FE],
        channel: &mut TcpChannel,
    ) -> Result<Vec<Group>> {
        let _ = self.delta_1;
        ensure!(
            !permutation.is_empty(),
            "step15 permutation cannot be empty"
        );
        ensure!(
            permutation.len() == g_ri.len() && permutation.len() == inverse_values.len(),
            "step15 length mismatch: pi={}, g^ri={}, inverse={}",
            permutation.len(),
            g_ri.len(),
            inverse_values.len()
        );

        let permuted_g_ri = checked_permute(g_ri, permutation)?;
        let permuted_inverse_values = checked_permute(inverse_values, permutation)?;

        // Send (g^{r_{pi(i)}})^{1/(r_{pi(i)}(x_{pi(i)}+k))} = g^{1/(x_{pi(i)}+k)}.
        let shuffled_oprf: Vec<Group> = permuted_g_ri
            .iter()
            .zip(permuted_inverse_values.iter())
            .map(|(g_r_pi_i, inv_pi_i)| g_r_pi_i.scalar_mul(inv_pi_i))
            .collect();

        send_group_elements(&shuffled_oprf, channel)
            .map_err(|e| anyhow!("step15 failed to send shuffled OPRF points: {}", e))?;

        Ok(shuffled_oprf)
    }

    pub fn step16_open_left_oprf_product_and_pad_proof(
        &self,
        g_ri: &[Group],
        authenticated_inverse_sender: &[BeDOZaSender],
        x: FE,
        channel: &mut TcpChannel,
    ) -> Result<Group> {
        let _ = self.delta_1;
        ensure!(!g_ri.is_empty(), "step16 cannot run on empty g^ri batch");
        ensure!(
            g_ri.len() == authenticated_inverse_sender.len(),
            "step16 length mismatch: g^ri={} inverse commitments={}",
            g_ri.len(),
            authenticated_inverse_sender.len()
        );

        // Exponents are authenticated z_i * x^i, where z_i = 1/(r_i(x_i+k)).
        let x_powers = powers(x, authenticated_inverse_sender.len());
        let scaled_inverse_sender: Vec<BeDOZaSender> = authenticated_inverse_sender
            .iter()
            .zip(x_powers.iter())
            .map(|(z_i, &x_i)| *z_i * x_i)
            .collect();

        let scaled_values: Vec<FE> = scaled_inverse_sender.iter().map(|s| s.val()).collect();
        let scaled_pads: Vec<FE> = scaled_inverse_sender.iter().map(|s| s.pad()).collect();

        let opened_left_product = msm_pippenger(g_ri, &scaled_values)
            .map_err(|e| anyhow!("step16 failed MSM for opened left product: {}", e))?;
        let pad_product = msm_pippenger(g_ri, &scaled_pads)
            .map_err(|e| anyhow!("step16 failed MSM for left pad product: {}", e))?;

        // Open product and pad-product proof element to inputer.
        send_group_elements(&[opened_left_product.clone(), pad_product], channel)
            .map_err(|e| anyhow!("step16 failed to send left product proof elements: {}", e))?;

        Ok(opened_left_product)
    }

    pub fn step17_open_right_oprf_product_and_pad_proof(
        &self,
        shuffled_oprf: &[Group],
        authenticated_x_powers_sender: &[BeDOZaSender],
        channel: &mut TcpChannel,
    ) -> Result<Group> {
        let _ = self.delta_1;
        ensure!(
            !shuffled_oprf.is_empty(),
            "step17 cannot run on empty shuffled OPRF batch"
        );
        ensure!(
            shuffled_oprf.len() == authenticated_x_powers_sender.len(),
            "step17 length mismatch: shuffled_oprf={} x^pi commitments={}",
            shuffled_oprf.len(),
            authenticated_x_powers_sender.len()
        );

        let x_pi_values: Vec<FE> = authenticated_x_powers_sender
            .iter()
            .map(|s| s.val())
            .collect();
        let x_pi_pads: Vec<FE> = authenticated_x_powers_sender
            .iter()
            .map(|s| s.pad())
            .collect();

        let opened_right_product = msm_pippenger(shuffled_oprf, &x_pi_values)
            .map_err(|e| anyhow!("step17 failed MSM for opened right product: {}", e))?;
        let right_pad_product = msm_pippenger(shuffled_oprf, &x_pi_pads)
            .map_err(|e| anyhow!("step17 failed MSM for right pad product: {}", e))?;

        // Open product and pad-product proof element to inputer.
        send_group_elements(&[opened_right_product.clone(), right_pad_product], channel)
            .map_err(|e| anyhow!("step17 failed to send right product proof elements: {}", e))?;

        Ok(opened_right_product)
    }

    pub fn step18_verify_opened_oprf_products_match(
        &self,
        opened_left_product: &Group,
        opened_right_product: &Group,
    ) -> Result<()> {
        let _ = self.delta_1;
        ensure!(
            opened_left_product.as_point() == opened_right_product.as_point(),
            "step18 failed: opened left OPRF product does not match opened right OPRF product"
        );
        Ok(())
    }

    pub fn run_full_shuffled_oprf<C: AbstractChannel, RNG: Rng>(
        &self,
        permutation: &[usize],
        k1_prime: FE,
        rng: &mut RNG,
        auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        k1_mul_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        k1_prime_mul_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        channel: &mut C,
        tcp_channel: &mut TcpChannel,
    ) -> Result<Vec<Group>> {
        ensure!(
            !permutation.is_empty(),
            "run_full_shuffled_oprf: permutation cannot be empty"
        );
        let n = permutation.len();

        let (k1, shuffler_key_share) = self.step0_sample_and_authenticate_oprf_key_share(
            rng,
            auth_vole_sender,
            auth_vole_receiver,
            channel,
        )?;
        let authenticated_inputs =
            self.step1_inputer_commits_inputs(n, auth_vole_receiver, channel)?;
        let authenticated_ri_receiver =
            self.step2_inputer_commits_random_values(n, auth_vole_receiver, channel)?;
        let authenticated_r_x_plus_k0_receiver = self
            .step3_inputer_authenticates_r_times_x_plus_k0_and_proves(
                &authenticated_inputs,
                &authenticated_ri_receiver,
                &shuffler_key_share,
                auth_vole_receiver,
                channel,
            )?;
        let (v_values, authenticated_u_receiver, authenticated_v_sender) = self
            .step4_vole_share_x_times_k1_and_authenticate(
                n,
                auth_vole_receiver,
                auth_vole_sender,
                k1_mul_vole_receiver,
                channel,
            )?;
        self.step5_verify_random_linear_combination_for_uv_consistency(
            &authenticated_inputs,
            &authenticated_u_receiver,
            &v_values,
            k1,
            channel,
        )?;
        self.step6_prove_authenticated_v_linear_combination_consistency(
            &authenticated_inputs,
            &authenticated_u_receiver,
            &authenticated_v_sender,
            shuffler_key_share.bedoza_sender(),
            k1_prime,
            auth_vole_receiver,
            auth_vole_sender,
            k1_prime_mul_vole_receiver,
            channel,
        )?;
        let r_x_k_values = self.step7_receive_ri_x_plus_k0_plus_ui_and_reconstruct_ri_x_plus_k(
            &authenticated_r_x_plus_k0_receiver,
            &authenticated_u_receiver,
            &v_values,
            channel,
        )?;
        let authenticated_r_x_k_sender = self
            .step8_reauthenticate_ri_x_plus_k_and_prove_consistency(
                &r_x_k_values,
                &authenticated_v_sender,
                auth_vole_sender,
                rng,
                channel,
            )?;
        let (inverse_values, authenticated_inverse_sender) = self
            .step9_authenticate_inverses_and_prove(
                &authenticated_r_x_k_sender,
                auth_vole_sender,
                channel,
            )?;
        let g_ri = self.step10_receive_g_ri_and_verify_pad_consistency(
            &authenticated_ri_receiver,
            tcp_channel,
        )?;
        let authenticated_pi_sender =
            self.step11_authenticate_permutation_values(permutation, auth_vole_sender, channel)?;
        let (x, _permuted_x_powers, authenticated_x_powers_sender) = self
            .step12_receive_challenge_and_authenticate_x_powers(
                permutation,
                auth_vole_sender,
                channel,
            )?;
        let (
            _permuted_inverse_values,
            _product_values,
            _authenticated_permuted_inverse_sender,
            authenticated_products_sender,
        ) = self.step13_authenticate_xpi_times_inverse_and_prove(
            permutation,
            &authenticated_x_powers_sender,
            &authenticated_inverse_sender,
            auth_vole_sender,
            channel,
        )?;
        self.step14_prove_shuffle_product_identity(
            x,
            &authenticated_pi_sender,
            &authenticated_products_sender,
            &authenticated_inverse_sender,
            &authenticated_x_powers_sender,
            auth_vole_sender,
            channel,
        )?;

        let shuffled_oprf = self.step15_send_shuffled_oprf_points(
            permutation,
            &g_ri,
            &inverse_values,
            tcp_channel,
        )?;
        let opened_left_product = self.step16_open_left_oprf_product_and_pad_proof(
            &g_ri,
            &authenticated_inverse_sender,
            x,
            tcp_channel,
        )?;
        let opened_right_product = self.step17_open_right_oprf_product_and_pad_proof(
            &shuffled_oprf,
            &authenticated_x_powers_sender,
            tcp_channel,
        )?;
        self.step18_verify_opened_oprf_products_match(&opened_left_product, &opened_right_product)?;

        Ok(shuffled_oprf)
    }
}
