use crate::{
    bedoza::{
        bedoza_receiver::BeDOZaReceiver,
        bedoza_sender::BeDOZaSender,
        comm_util::{receive_fe, send_fe},
        defines::{FE, random_fe_vec_from_rng},
    },
    tcp_channel::SwankyChannel,
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use anyhow::{Result, anyhow, ensure};
use rand::{RngExt, SeedableRng, rngs::StdRng};

fn check_lengths<T>(a: &[T], b: &[T], c: &[T], context: &str) -> Result<()> {
    ensure!(!a.is_empty(), "{}: empty input", context);
    ensure!(
        a.len() == b.len() && b.len() == c.len(),
        "{}: length mismatch a={}, b={}, c={}",
        context,
        a.len(),
        b.len(),
        c.len()
    );
    Ok(())
}

fn check_lengths_mixed<T, U, V>(a: &[T], b: &[U], c: &[V], context: &str) -> Result<()> {
    ensure!(!a.is_empty(), "{}: empty input", context);
    ensure!(
        a.len() == b.len() && b.len() == c.len(),
        "{}: length mismatch a={}, b={}, c={}",
        context,
        a.len(),
        b.len(),
        c.len()
    );
    Ok(())
}

pub fn wolverine_batch_mul_prove(
    a: &[BeDOZaSender],
    b: &[BeDOZaSender],
    c: &[BeDOZaSender],
    vole_sender: &mut BufferedVoleSender,
    channel: &mut SwankyChannel,
) -> Result<()> {
    check_lengths(a, b, c, "wolverine_batch_mul_prove")?;
    let dummy_x = vole_sender
        .random_auth(channel, 1)
        .map_err(|e| anyhow!("failed to authenticate Wolverine dummy x: {e}"))?[0];

    // Verifier samples and sends challenge seed.
    let seed_raw = channel
        .receive()
        .map_err(|e| anyhow!("failed to receive Wolverine seed: {}", e))?;
    ensure!(
        seed_raw.len() == 32,
        "failed to receive Wolverine seed: expected 32 bytes, got {}",
        seed_raw.len()
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_raw);
    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len() + 1)?;
    let (mul_coeffs, dummy_coeffs) = coeffs.split_at(a.len());
    let dummy_coeff = dummy_coeffs[0];

    // With t_x = delta * x - pad_x, we have
    // t_a * t_b - delta * t_c = delta * (pad_c - pad_a * b - pad_b * a) + pad_a * pad_b
    // whenever c = a * b.
    let lambda_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()).zip(c.iter()))
        .map(|(&eta_i, ((a_i, b_i), c_i))| {
            let lambda_i = c_i.pad() - a_i.pad() * b_i.val() - b_i.pad() * a_i.val();
            eta_i * lambda_i
        })
        .fold(FE::zero(), |acc, term| acc + term);

    let mu_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()))
        .map(|(&eta_i, (a_i, b_i))| eta_i * (a_i.pad() * b_i.pad()))
        .fold(FE::zero(), |acc, term| acc + term);

    // Dummy linear relation: t = delta * x - pad.
    // This contributes delta * x - pad to the checker, so lambda_dummy = x and mu_dummy = -pad.
    let lambda_batch = lambda_batch_mul + dummy_coeff * dummy_x.val();
    let mu_batch = mu_batch_mul - dummy_coeff * dummy_x.pad();

    send_fe(lambda_batch, channel)
        .map_err(|e| anyhow!("failed to send Wolverine lambda batch: {}", e))?;
    send_fe(mu_batch, channel)
        .map_err(|e| anyhow!("failed to send Wolverine mu batch: {}", e))?;

    Ok(())
}

pub fn wolverine_batch_mul_verify(
    a: &[BeDOZaReceiver],
    b: &[BeDOZaReceiver],
    c: &[BeDOZaReceiver],
    vole_receiver: &mut BufferedVoleReceiver,
    channel: &mut SwankyChannel,
) -> Result<()> {
    check_lengths(a, b, c, "wolverine_batch_mul_verify")?;
    let dummy_v = vole_receiver
        .random_auth(channel, 1)
        .map_err(|e| anyhow!("failed to authenticate Wolverine dummy x: {e}"))?[0];

    let delta_1 = a[0].key();
    for (i, (a_i, b_i, c_i)) in a
        .iter()
        .zip(b.iter())
        .zip(c.iter())
        .map(|((x, y), z)| (x, y, z))
        .enumerate()
    {
        ensure!(
            a_i.key() == delta_1 && b_i.key() == delta_1 && c_i.key() == delta_1,
            "wolverine_batch_mul_verify: key mismatch at gate {} (expected delta_1)",
            i
        );
    }
    ensure!(
        dummy_v.key() == delta_1,
        "wolverine_batch_mul_verify: dummy key mismatch (expected delta_1)"
    );

    let mut rng = rand::rng();
    let seed: [u8; 32] = rng.random::<[u8; 32]>();
    channel
        .send(&seed)
        .map_err(|e| anyhow!("failed to send Wolverine seed: {}", e))?;

    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len() + 1)?;
    let (mul_coeffs, dummy_coeffs) = coeffs.split_at(a.len());
    let dummy_coeff = dummy_coeffs[0];

    let lambda_batch = receive_fe(channel)
        .map_err(|e| anyhow!("failed to receive Wolverine lambda batch: {}", e))?;
    let mu_batch = receive_fe(channel)
        .map_err(|e| anyhow!("failed to receive Wolverine mu batch: {}", e))?;

    let l_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()).zip(c.iter()))
        .map(|(&eta_i, ((a_i, b_i), c_i))| {
            let l_i = a_i.tag() * b_i.tag() - c_i.tag() * delta_1;
            eta_i * l_i
        })
        .fold(FE::zero(), |acc, term| acc + term);
    let l_batch = l_batch_mul + dummy_coeff * dummy_v.tag();

    ensure!(
        l_batch == delta_1 * lambda_batch + mu_batch,
        "Wolverine multiplication proof failed: batched relation mismatch"
    );

    Ok(())
}

pub fn wolverine_batch_mul_public_output_prove(
    a: &[BeDOZaSender],
    b: &[BeDOZaSender],
    public_c: &[FE],
    vole_sender: &mut BufferedVoleSender,
    channel: &mut SwankyChannel,
) -> Result<()> {
    check_lengths_mixed(a, b, public_c, "wolverine_batch_mul_public_output_prove")?;
    let dummy_x = vole_sender
        .random_auth(channel, 1)
        .map_err(|e| anyhow!("failed to authenticate Wolverine public-output dummy x: {e}"))?[0];

    // Verifier samples and sends challenge seed.
    let seed_raw = channel
        .receive()
        .map_err(|e| anyhow!("failed to receive Wolverine public-output seed: {}", e))?;
    ensure!(
        seed_raw.len() == 32,
        "failed to receive Wolverine public-output seed: expected 32 bytes, got {}",
        seed_raw.len()
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_raw);
    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len() + 1)?;
    let (mul_coeffs, dummy_coeffs) = coeffs.split_at(a.len());
    let dummy_coeff = dummy_coeffs[0];

    // For t_a = delta * a - pad_a, t_b = delta * b - pad_b and c public:
    // t_a * t_b - delta^2 * c = delta * (-pad_a * b - pad_b * a) + pad_a * pad_b
    // whenever a*b = c.
    let lambda_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()))
        .map(|(&eta_i, (a_i, b_i))| {
            let lambda_i = -(a_i.pad() * b_i.val() + b_i.pad() * a_i.val());
            eta_i * lambda_i
        })
        .fold(FE::zero(), |acc, term| acc + term);

    let mu_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()))
        .map(|(&eta_i, (a_i, b_i))| eta_i * (a_i.pad() * b_i.pad()))
        .fold(FE::zero(), |acc, term| acc + term);
    let lambda_batch = lambda_batch_mul + dummy_coeff * dummy_x.val();
    let mu_batch = mu_batch_mul - dummy_coeff * dummy_x.pad();

    send_fe(lambda_batch, channel)
        .map_err(|e| anyhow!("failed to send Wolverine public-output lambda batch: {}", e))?;
    send_fe(mu_batch, channel)
        .map_err(|e| anyhow!("failed to send Wolverine public-output mu batch: {}", e))?;

    Ok(())
}

pub fn wolverine_batch_mul_public_output_verify(
    a: &[BeDOZaReceiver],
    b: &[BeDOZaReceiver],
    public_c: &[FE],
    vole_receiver: &mut BufferedVoleReceiver,
    channel: &mut SwankyChannel,
) -> Result<()> {
    check_lengths_mixed(a, b, public_c, "wolverine_batch_mul_public_output_verify")?;
    let dummy_x = vole_receiver
        .random_auth(channel, 1)
        .map_err(|e| anyhow!("failed to authenticate Wolverine public-output dummy x: {e}"))?[0];

    let delta = a[0].key();
    for (i, (a_i, b_i)) in a.iter().zip(b.iter()).enumerate() {
        ensure!(
            a_i.key() == delta && b_i.key() == delta,
            "wolverine_batch_mul_public_output_verify: key mismatch at gate {}",
            i
        );
    }
    ensure!(
        dummy_x.key() == delta,
        "wolverine_batch_mul_public_output_verify: dummy key mismatch"
    );

    let mut rng = rand::rng();
    let seed: [u8; 32] = rng.random::<[u8; 32]>();
    channel
        .send(&seed)
        .map_err(|e| anyhow!("failed to send Wolverine public-output seed: {}", e))?;

    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len() + 1)?;
    let (mul_coeffs, dummy_coeffs) = coeffs.split_at(a.len());
    let dummy_coeff = dummy_coeffs[0];

    let lambda_batch = receive_fe(channel)
        .map_err(|e| anyhow!("failed to receive Wolverine public-output lambda batch: {}", e))?;
    let mu_batch = receive_fe(channel)
        .map_err(|e| anyhow!("failed to receive Wolverine public-output mu batch: {}", e))?;

    let l_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()).zip(public_c.iter()))
        .map(|(&eta_i, ((a_i, b_i), &c_i))| {
            let l_i = a_i.tag() * b_i.tag() - (delta * delta) * c_i;
            eta_i * l_i
        })
        .fold(FE::zero(), |acc, term| acc + term);
    let l_batch = l_batch_mul + dummy_coeff * dummy_x.tag();

    ensure!(
        l_batch == delta * lambda_batch + mu_batch,
        "Wolverine public-output multiplication proof failed: batched relation mismatch"
    );

    Ok(())
}
