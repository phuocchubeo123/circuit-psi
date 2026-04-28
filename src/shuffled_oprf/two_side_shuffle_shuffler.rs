use super::{
    shuffle_inputer::{Inputer, InputerOutput},
    shuffle_shuffler::{Shuffler, ShufflerOutput},
};
use crate::{
    bedoza::{BeDOZa, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::{
        defines::{FE, random_fe_vec_from_rng},
        group::{Group, msm_pippenger, receive_group_elements, send_group_elements},
    },
    tcp_channel::SwankyChannel,
    vole::vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use anyhow::{Result, anyhow, ensure};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

pub struct TwoSideShufflerOutput {
    pub shuffler_output: ShufflerOutput,
    pub inputer_output: InputerOutput,
}

#[derive(Clone, Copy, Debug)]
pub struct TwoSideShuffler {
    shuffler: Shuffler,
    inputer: Inputer,
}

#[derive(Clone)]
struct ShufflerStep6Precomputed {
    shuffled_oprf: Vec<Group>,
    unshuffled_oprf: Vec<Group>,
    opened_left_product: Group,
    left_pad_product: Group,
    opened_right_product: Group,
    right_pad_product: Group,
}

fn run_merged_step4(
    inputer_authenticated_ri_sender: &[BeDOZaSender],
    shuffler_authenticated_ri_receiver: &[BeDOZaReceiver],
    shuffler_delta: FE,
    channel: &mut SwankyChannel,
) -> Result<(Vec<Group>, Vec<Group>)> {
    let start = std::time::Instant::now();
    let mut step = 0usize;
    let mut log_step = |description: &str| {
        step += 1;
        println!(
            "[two_side_shuffle_shuffler::step4_merged] Step {step}: {description} (elapsed: {:?})",
            start.elapsed()
        );
    };

    ensure!(
        !inputer_authenticated_ri_sender.is_empty(),
        "step4 cannot run on empty inputer ri commitments"
    );
    ensure!(
        !shuffler_authenticated_ri_receiver.is_empty(),
        "step4 cannot run on empty shuffler ri commitments"
    );

    // Inputer-role precompute: g^ri for our local sender-side commitments.
    let g_ri_inputer: Vec<Group> = inputer_authenticated_ri_sender
        .iter()
        .map(|ri| Group::base_point().scalar_mul(&ri.val()))
        .collect();

    // Shuffler-role precompute: sample seed/alphas and derive g^{sum alpha_i * tag_i}.
    let mut sampling_rng = rand::rng();
    let mut seed_for_peer_inputer = [0u8; 32];
    sampling_rng.fill(&mut seed_for_peer_inputer);
    let mut shuffler_seeded_rng = StdRng::from_seed(seed_for_peer_inputer);
    let shuffler_alphas = random_fe_vec_from_rng(
        &mut shuffler_seeded_rng,
        shuffler_authenticated_ri_receiver.len(),
    )?;
    let shuffler_tag_linear = shuffler_authenticated_ri_receiver
        .iter()
        .zip(shuffler_alphas.iter())
        .map(|(ri, &alpha_i)| ri.tag() * alpha_i)
        .fold(FE::zero(), |acc, term| acc + term);
    let g_shuffler_tag_linear = Group::base_point().scalar_mul(&shuffler_tag_linear);
    log_step("precomputed local g^ri and shuffler-side challenge state");

    // Mirrored ordering versus two_side_shuffle_inputer:
    // 1) receive peer g^ri (our shuffler role),
    // 2) send local g^ri (our inputer role).
    let g_ri_shuffler = receive_group_elements(channel)
        .map_err(|e| anyhow!("step4 failed to receive peer g^ri values: {}", e))?;
    ensure!(
        g_ri_shuffler.len() == shuffler_authenticated_ri_receiver.len(),
        "step4 length mismatch: received peer g^ri {} vs shuffler commitments {}",
        g_ri_shuffler.len(),
        shuffler_authenticated_ri_receiver.len()
    );
    send_group_elements(&g_ri_inputer, channel)
        .map_err(|e| anyhow!("step4 failed to send local g^ri values: {}", e))?;
    log_step("completed large g^ri exchange");

    // 3) receive peer seed for our inputer-role pad proof, then
    // 4) send our seed for peer's inputer-role pad proof.
    let peer_seed_bytes = channel
        .receive()
        .map_err(|e| anyhow!("step4 failed to receive pad-challenge seed: {}", e))?;
    ensure!(
        peer_seed_bytes.len() == 32,
        "step4 expected 32-byte pad-challenge seed, got {} bytes",
        peer_seed_bytes.len()
    );
    let mut peer_seed = [0u8; 32];
    peer_seed.copy_from_slice(&peer_seed_bytes);
    channel
        .send(&seed_for_peer_inputer)
        .map_err(|e| anyhow!("step4 failed to send peer challenge seed: {}", e))?;
    log_step("exchanged step4 seeds");

    // Compute shuffler-side MSM while deriving inputer-side pad response.
    let shuffler_msm = msm_pippenger(&g_ri_shuffler, &shuffler_alphas)
        .map_err(|e| anyhow!("step4 failed MSM computation with Pippenger: {}", e))?;
    let shuffler_msm_delta = shuffler_msm.scalar_mul(&shuffler_delta);

    let mut inputer_seeded_rng = StdRng::from_seed(peer_seed);
    let inputer_alphas = random_fe_vec_from_rng(
        &mut inputer_seeded_rng,
        inputer_authenticated_ri_sender.len(),
    )?;
    let inputer_pad_linear = inputer_authenticated_ri_sender
        .iter()
        .zip(inputer_alphas.iter())
        .map(|(ri, &alpha_i)| ri.pad() * alpha_i)
        .fold(FE::zero(), |acc, term| acc + term);
    let inputer_pad_group = Group::base_point().scalar_mul(&inputer_pad_linear);
    log_step("finished local MSM/pad computations");

    // 5) Receive peer pad proof for our shuffler verification.
    let peer_pad_group = receive_group_elements(channel).map_err(|e| {
        anyhow!(
            "step4 failed to receive peer pad consistency group element: {}",
            e
        )
    })?;
    ensure!(
        peer_pad_group.len() == 1,
        "step4 expected exactly one peer pad consistency element, got {}",
        peer_pad_group.len()
    );
    let lhs = g_shuffler_tag_linear + peer_pad_group[0].clone();
    ensure!(
        lhs.as_point() == shuffler_msm_delta.as_point(),
        "step4 consistency check failed: MSM/tag relation for peer r_i commitments did not hold"
    );
    log_step("verified peer pad proof");

    // 6) Send our inputer-role pad proof to peer's shuffler.
    send_group_elements(&[inputer_pad_group], channel)
        .map_err(|e| anyhow!("step4 failed to send pad consistency group element: {}", e))?;
    log_step("sent local pad proof and completed merged step4");

    Ok((g_ri_inputer, g_ri_shuffler))
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

fn precompute_shuffler_step6(
    permutation: &[usize],
    g_ri: &[Group],
    authenticated_inverse_sender: &[BeDOZaSender],
    x: FE,
    authenticated_x_powers_sender: &[BeDOZaSender],
) -> Result<ShufflerStep6Precomputed> {
    ensure!(
        permutation.len() == g_ri.len(),
        "step6 length mismatch: permutation={} g^ri={}",
        permutation.len(),
        g_ri.len()
    );
    ensure!(
        g_ri.len() == authenticated_inverse_sender.len(),
        "step6 length mismatch: g^ri={} inverse commitments={}",
        g_ri.len(),
        authenticated_inverse_sender.len()
    );
    ensure!(
        g_ri.len() == authenticated_x_powers_sender.len(),
        "step6 length mismatch: g^ri={} x^pi commitments={}",
        g_ri.len(),
        authenticated_x_powers_sender.len()
    );
    ensure!(!g_ri.is_empty(), "step6 cannot run on empty g^ri batch");

    let unshuffled_oprf: Vec<Group> = g_ri
        .iter()
        .zip(authenticated_inverse_sender.iter())
        .map(|(g_ri_i, inverse_i)| g_ri_i.scalar_mul(&inverse_i.val()))
        .collect();
    let shuffled_oprf = checked_permute(&unshuffled_oprf, permutation)?;

    let mut scaled_values = Vec::with_capacity(authenticated_inverse_sender.len());
    let mut scaled_pads = Vec::with_capacity(authenticated_inverse_sender.len());
    let mut x_power = FE::one();
    for share in authenticated_inverse_sender {
        scaled_values.push(share.val() * x_power);
        scaled_pads.push(share.pad() * x_power);
        x_power *= x;
    }
    let opened_left_product = msm_pippenger(g_ri, &scaled_values)
        .map_err(|e| anyhow!("step6 failed MSM for opened left product: {e}"))?;
    let left_pad_product = msm_pippenger(g_ri, &scaled_pads)
        .map_err(|e| anyhow!("step6 failed MSM for left pad product: {e}"))?;

    let x_pi_values: Vec<FE> = authenticated_x_powers_sender
        .iter()
        .map(BeDOZaSender::val)
        .collect();
    let x_pi_pads: Vec<FE> = authenticated_x_powers_sender
        .iter()
        .map(BeDOZaSender::pad)
        .collect();
    let opened_right_product = msm_pippenger(&shuffled_oprf, &x_pi_values)
        .map_err(|e| anyhow!("step6 failed MSM for opened right product: {e}"))?;
    let right_pad_product = msm_pippenger(&shuffled_oprf, &x_pi_pads)
        .map_err(|e| anyhow!("step6 failed MSM for right pad product: {e}"))?;

    ensure!(
        opened_left_product.as_point() == opened_right_product.as_point(),
        "step6 failed: opened left OPRF product does not match opened right OPRF product"
    );

    Ok(ShufflerStep6Precomputed {
        shuffled_oprf,
        unshuffled_oprf,
        opened_left_product,
        left_pad_product,
        opened_right_product,
        right_pad_product,
    })
}

fn receive_and_verify_inputer_step6(
    g_ri: &[Group],
    authenticated_permuted_x_powers: &[BeDOZaReceiver],
    authenticated_xi_times_inverse: &[BeDOZaReceiver],
    channel: &mut SwankyChannel,
) -> Result<Vec<Group>> {
    ensure!(
        !authenticated_permuted_x_powers.is_empty() && !authenticated_xi_times_inverse.is_empty(),
        "step6 cannot run on empty receiver commitments"
    );
    ensure!(
        g_ri.len() == authenticated_xi_times_inverse.len(),
        "step6 length mismatch: g^ri={} xi_inverse commitments={}",
        g_ri.len(),
        authenticated_xi_times_inverse.len()
    );
    ensure!(
        g_ri.len() == authenticated_permuted_x_powers.len(),
        "step6 length mismatch: g^ri={} x^pi commitments={}",
        g_ri.len(),
        authenticated_permuted_x_powers.len()
    );

    let inverse_tags: Vec<FE> = authenticated_xi_times_inverse
        .iter()
        .map(BeDOZaReceiver::tag)
        .collect();
    let g_xi_times_inverse_tag_product = msm_pippenger(g_ri, &inverse_tags).map_err(|e| {
        anyhow!("Failed to get multi-exponentiation for g_xi_times_inverse tags: {e}")
    })?;

    let x_power_tags: Vec<FE> = authenticated_permuted_x_powers
        .iter()
        .map(BeDOZaReceiver::tag)
        .collect();
    let shuffled_oprf = receive_group_elements(channel)
        .map_err(|e| anyhow!("step6 failed to receive shuffled OPRF points: {}", e))?;
    ensure!(
        shuffled_oprf.len() == authenticated_permuted_x_powers.len(),
        "step6 length mismatch: shuffled OPRF {} vs x^pi commitments {}",
        shuffled_oprf.len(),
        authenticated_permuted_x_powers.len()
    );

    let shuffled_oprf_x_powers_tag_product =
        msm_pippenger(&shuffled_oprf, &x_power_tags).map_err(|e| {
            anyhow!("Failed to get multi-exponentiation for shuffled_oprf^x_powers tags: {e}")
        })?;

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

    let lhs_left = g_xi_times_inverse_pad_product + g_xi_times_inverse_tag_product;
    let rhs_left = g_xi_times_inverse_product.scalar_mul(&authenticated_xi_times_inverse[0].key());
    ensure!(
        lhs_left == rhs_left,
        "Failed to verify left shuffle polynomial product"
    );

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

    let lhs_right = shuffled_oprf_x_powers_pad_product + shuffled_oprf_x_powers_tag_product;
    let rhs_right =
        shuffled_oprf_x_powers_product.scalar_mul(&authenticated_permuted_x_powers[0].key());
    ensure!(
        lhs_right == rhs_right,
        "Failed to verify right shuffle polynomial product"
    );
    ensure!(
        g_xi_times_inverse_product == shuffled_oprf_x_powers_product,
        "Shuffled OPRF are inconsistent!"
    );

    Ok(shuffled_oprf)
}

impl TwoSideShuffler {
    pub fn new(delta1: FE, k1: FE) -> Self {
        Self {
            shuffler: Shuffler::new(delta1, k1),
            inputer: Inputer::new(delta1, k1),
        }
    }

    pub fn run_full_two_side_shuffled_oprf<RNG: Rng>(
        &self,
        shuffler_permutation: &[usize],
        inputer_x_values: &[FE],
        rng: &mut RNG,
        auth_vole_sender: &mut BufferedVoleSender,
        auth_vole_receiver: &mut BufferedVoleReceiver,
        k1_mul_vole_receiver: &mut BufferedVoleReceiver,
        k1_mul_vole_sender: &mut BufferedVoleSender,
        channel: &mut SwankyChannel,
    ) -> Result<TwoSideShufflerOutput> {
        ensure!(
            !shuffler_permutation.is_empty(),
            "run_full_two_side_shuffled_oprf: shuffler permutation cannot be empty"
        );
        ensure!(
            !inputer_x_values.is_empty(),
            "run_full_two_side_shuffled_oprf: inputer input set cannot be empty"
        );

        let mut shuffler_key_share: Option<BeDOZa> = None;
        let mut authenticated_inputs_shuffler = Vec::with_capacity(shuffler_permutation.len());
        let mut authenticated_ri_shuffler = Vec::with_capacity(shuffler_permutation.len());
        let mut authenticated_pi_shuffler = Vec::with_capacity(shuffler_permutation.len());
        self.shuffler
            .step0_authenticate_oprf_key_and_xi_and_ri_and_send_pi(
                shuffler_permutation,
                auth_vole_sender,
                auth_vole_receiver,
                channel,
                &mut shuffler_key_share,
                &mut authenticated_inputs_shuffler,
                &mut authenticated_ri_shuffler,
                &mut authenticated_pi_shuffler,
            )?;
        let shuffler_key_share = shuffler_key_share
            .ok_or_else(|| anyhow!("shuffler step0 did not produce key shares"))?;

        let mut inputer_key_shares: Option<BeDOZa> = None;
        let mut authenticated_xi = Vec::with_capacity(inputer_x_values.len());
        let mut authenticated_ri_inputer = Vec::with_capacity(inputer_x_values.len());
        let mut authenticated_pi_inputer = Vec::with_capacity(inputer_x_values.len());
        self.inputer
            .step0_authenticate_oprf_key_and_xi_and_ri_and_receive_pi(
                inputer_x_values,
                auth_vole_sender,
                auth_vole_receiver,
                channel,
                &mut inputer_key_shares,
                &mut authenticated_xi,
                &mut authenticated_ri_inputer,
                &mut authenticated_pi_inputer,
            )?;
        let inputer_key_shares = inputer_key_shares
            .ok_or_else(|| anyhow!("inputer step0 did not produce key shares"))?;

        let mut authenticated_r_x_plus_k0_shuffler = Vec::with_capacity(shuffler_permutation.len());
        self.shuffler
            .step1_inputer_authenticates_r_times_x_plus_k0_and_verifies(
                &authenticated_inputs_shuffler,
                &authenticated_ri_shuffler,
                &shuffler_key_share,
                auth_vole_receiver,
                channel,
                &mut authenticated_r_x_plus_k0_shuffler,
            )?;

        let mut authenticated_r_x_plus_k0_inputer = Vec::with_capacity(inputer_x_values.len());
        self.inputer
            .step1_inputer_authenticates_r_times_x_plus_k0_and_proves(
                &authenticated_xi,
                &authenticated_ri_inputer,
                inputer_key_shares.bedoza_sender(),
                auth_vole_sender,
                channel,
                &mut authenticated_r_x_plus_k0_inputer,
            )?;

        let (v_values_shuffler, authenticated_u_shuffler, authenticated_v_shuffler) =
            self.shuffler.step2_vole_share_r_times_k1_and_authenticate(
                &authenticated_ri_shuffler,
                shuffler_key_share.bedoza_sender(),
                auth_vole_receiver,
                auth_vole_sender,
                k1_mul_vole_receiver,
                channel,
            )?;
        let (_u_values_inputer, authenticated_u_inputer, authenticated_v_inputer) =
            self.inputer.step2_vole_share_r_times_k1_and_authenticate(
                &authenticated_ri_inputer,
                inputer_key_shares.bedoza_receiver(),
                auth_vole_sender,
                auth_vole_receiver,
                k1_mul_vole_sender,
                channel,
            )?;

        let (_r_x_k_values_shuffler, _inverse_values_shuffler, authenticated_inverse_shuffler) =
            self.shuffler
                .step3_receive_ri_x_plus_k0_plus_ui_and_receive_reauthenticate_and_inverse(
                    &authenticated_r_x_plus_k0_shuffler,
                    &authenticated_u_shuffler,
                    &v_values_shuffler,
                    &authenticated_v_shuffler,
                    auth_vole_sender,
                    channel,
                )?;
        let authenticated_r_x_k_inverse_inputer = self
            .inputer
            .step3_open_ri_x_plus_k0_plus_ui_and_receive_reauthenticate(
                &authenticated_r_x_plus_k0_inputer,
                &authenticated_u_inputer,
                &authenticated_v_inputer,
                auth_vole_receiver,
                channel,
            )?;

        let (g_ri_inputer, g_ri_shuffler) = run_merged_step4(
            &authenticated_ri_inputer,
            &authenticated_ri_shuffler,
            self.shuffler.delta_1(),
            channel,
        )?;

        let (x_shuffler, authenticated_x_powers_shuffler) = self
            .shuffler
            .step5_receive_challenge_and_authenticate_xpi_and_prove_running_product(
                shuffler_permutation,
                &authenticated_pi_shuffler,
                auth_vole_sender,
                channel,
            )?;
        let (_x_inputer, authenticated_permuted_x_powers_inputer, authenticated_xi_times_inverse) =
            self.inputer
                .step5_send_challenge_and_receive_authenticated_xpi_and_xi_times_inverse(
                    &authenticated_pi_inputer,
                    &authenticated_r_x_k_inverse_inputer,
                    rng,
                    auth_vole_receiver,
                    channel,
                )?;

        let shuffler_step6 = precompute_shuffler_step6(
            shuffler_permutation,
            &g_ri_shuffler,
            &authenticated_inverse_shuffler,
            x_shuffler,
            &authenticated_x_powers_shuffler,
        )?;

        // Send local shuffled OPRF proof first (shuffler role), then receive and verify the
        // peer's proof as inputer. The two_side_shuffle_inputer role mirrors this ordering.
        send_group_elements(&shuffler_step6.shuffled_oprf, channel)
            .map_err(|e| anyhow!("step6 failed to send shuffled OPRF points: {}", e))?;
        send_group_elements(
            &[
                shuffler_step6.opened_left_product.clone(),
                shuffler_step6.left_pad_product.clone(),
            ],
            channel,
        )
        .map_err(|e| anyhow!("step6 failed to send left product proof elements: {}", e))?;
        send_group_elements(
            &[
                shuffler_step6.opened_right_product.clone(),
                shuffler_step6.right_pad_product.clone(),
            ],
            channel,
        )
        .map_err(|e| anyhow!("step6 failed to send right product proof elements: {}", e))?;

        let inputer_shuffled_oprf = receive_and_verify_inputer_step6(
            &g_ri_inputer,
            &authenticated_permuted_x_powers_inputer,
            &authenticated_xi_times_inverse,
            channel,
        )?;

        Ok(TwoSideShufflerOutput {
            shuffler_output: ShufflerOutput {
                shuffled_oprf: shuffler_step6.shuffled_oprf,
                unshuffled_oprf: shuffler_step6.unshuffled_oprf,
                authenticated_inputs: authenticated_inputs_shuffler,
                authenticated_permutation: authenticated_pi_shuffler,
            },
            inputer_output: InputerOutput {
                shuffled_oprf: inputer_shuffled_oprf,
                authenticated_inputs: authenticated_xi,
                authenticated_permutation: authenticated_pi_inputer,
            },
        })
    }
}
