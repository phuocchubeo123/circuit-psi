use crate::bedoza::{
    bedoza_receiver::BeDOZaReceiver,
    bedoza_sender::BeDOZaSender,
    defines::{FE, random_fe_vec_from_rng},
};
use anyhow::{Result, anyhow, ensure};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use swanky_channel_legacy::AbstractChannel;

fn send_fe_abstract<C: AbstractChannel>(channel: &mut C, value: FE) -> Result<()> {
    channel
        .write_bytes(&value.to_bytes_le())
        .map_err(|e| anyhow!("failed to send field element: {}", e))?;
    Ok(())
}

fn receive_fe_abstract<C: AbstractChannel>(channel: &mut C) -> Result<FE> {
    let mut bytes = [0u8; 32];
    channel
        .read_bytes(&mut bytes)
        .map_err(|e| anyhow!("failed to receive field element: {}", e))?;
    FE::from_bytes_le(&bytes).map_err(|e| anyhow!("failed to parse field element: {:?}", e))
}

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

pub fn wolverine_batch_mul_prove<C: AbstractChannel>(
    a: &[BeDOZaSender],
    b: &[BeDOZaSender],
    c: &[BeDOZaSender],
    dummy_x: &BeDOZaSender,
    channel: &mut C,
) -> Result<()> {
    check_lengths(a, b, c, "wolverine_batch_mul_prove")?;

    // Verifier samples and sends challenge seed.
    let mut seed = [0u8; 32];
    channel
        .read_bytes(&mut seed)
        .map_err(|e| anyhow!("failed to receive Wolverine seed: {}", e))?;
    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len() + 1)?;
    let (mul_coeffs, dummy_coeffs) = coeffs.split_at(a.len());
    let dummy_coeff = dummy_coeffs[0];

    // With v_x = delta * x + pad_x, set u_x = -pad_x.
    // lambda_i = u_c - u_a * b - u_b * a = -pad_c + pad_a * b + pad_b * a
    // mu_i = u_a * u_b = pad_a * pad_b
    let lambda_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()).zip(c.iter()))
        .map(|(&eta_i, ((a_i, b_i), c_i))| {
            let lambda_i = -c_i.pad() + a_i.pad() * b_i.val() + b_i.pad() * a_i.val();
            eta_i * lambda_i
        })
        .fold(FE::zero(), |acc, term| acc + term);

    let mu_batch_mul = mul_coeffs
        .iter()
        .zip(a.iter().zip(b.iter()))
        .map(|(&eta_i, (a_i, b_i))| eta_i * (a_i.pad() * b_i.pad()))
        .fold(FE::zero(), |acc, term| acc + term);

    // Dummy linear relation: v = x * delta_1 - u.
    // In our representation v = x * delta_1 + pad and u = -pad,
    // so lambda_dummy = x and mu_dummy = -u = pad.
    let lambda_batch = lambda_batch_mul + dummy_coeff * dummy_x.val();
    let mu_batch = mu_batch_mul + dummy_coeff * dummy_x.pad();

    send_fe_abstract(channel, lambda_batch)?;
    send_fe_abstract(channel, mu_batch)?;
    channel
        .flush()
        .map_err(|e| anyhow!("failed to flush Wolverine proof: {}", e))?;

    Ok(())
}

pub fn wolverine_batch_mul_verify<C: AbstractChannel>(
    a: &[BeDOZaReceiver],
    b: &[BeDOZaReceiver],
    c: &[BeDOZaReceiver],
    dummy_v: &BeDOZaReceiver,
    channel: &mut C,
) -> Result<()> {
    check_lengths(a, b, c, "wolverine_batch_mul_verify")?;

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
        .write_bytes(&seed)
        .map_err(|e| anyhow!("failed to send Wolverine seed: {}", e))?;
    channel
        .flush()
        .map_err(|e| anyhow!("failed to flush Wolverine seed: {}", e))?;

    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len() + 1)?;
    let (mul_coeffs, dummy_coeffs) = coeffs.split_at(a.len());
    let dummy_coeff = dummy_coeffs[0];

    let lambda_batch = receive_fe_abstract(channel)?;
    let mu_batch = receive_fe_abstract(channel)?;

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

pub fn wolverine_batch_mul_public_output_prove<C: AbstractChannel>(
    a: &[BeDOZaSender],
    b: &[BeDOZaSender],
    public_c: &[FE],
    channel: &mut C,
) -> Result<()> {
    check_lengths_mixed(a, b, public_c, "wolverine_batch_mul_public_output_prove")?;

    // Verifier samples and sends challenge seed.
    let mut seed = [0u8; 32];
    channel
        .read_bytes(&mut seed)
        .map_err(|e| anyhow!("failed to receive Wolverine public-output seed: {}", e))?;
    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len())?;

    // For v_a = delta*a + pad_a, v_b = delta*b + pad_b and c public:
    // v_a*v_b - delta^2*c = delta*(pad_a*b + pad_b*a) + pad_a*pad_b
    // whenever a*b = c.
    let lambda_batch = coeffs
        .iter()
        .zip(a.iter().zip(b.iter()))
        .map(|(&eta_i, (a_i, b_i))| {
            let lambda_i = a_i.pad() * b_i.val() + b_i.pad() * a_i.val();
            eta_i * lambda_i
        })
        .fold(FE::zero(), |acc, term| acc + term);

    let mu_batch = coeffs
        .iter()
        .zip(a.iter().zip(b.iter()))
        .map(|(&eta_i, (a_i, b_i))| eta_i * (a_i.pad() * b_i.pad()))
        .fold(FE::zero(), |acc, term| acc + term);

    send_fe_abstract(channel, lambda_batch)?;
    send_fe_abstract(channel, mu_batch)?;
    channel
        .flush()
        .map_err(|e| anyhow!("failed to flush Wolverine public-output proof: {}", e))?;

    Ok(())
}

pub fn wolverine_batch_mul_public_output_verify<C: AbstractChannel>(
    a: &[BeDOZaReceiver],
    b: &[BeDOZaReceiver],
    public_c: &[FE],
    channel: &mut C,
) -> Result<()> {
    check_lengths_mixed(a, b, public_c, "wolverine_batch_mul_public_output_verify")?;

    let delta = a[0].key();
    for (i, (a_i, b_i)) in a.iter().zip(b.iter()).enumerate() {
        ensure!(
            a_i.key() == delta && b_i.key() == delta,
            "wolverine_batch_mul_public_output_verify: key mismatch at gate {}",
            i
        );
    }

    let mut rng = rand::rng();
    let seed: [u8; 32] = rng.random::<[u8; 32]>();
    channel
        .write_bytes(&seed)
        .map_err(|e| anyhow!("failed to send Wolverine public-output seed: {}", e))?;
    channel
        .flush()
        .map_err(|e| anyhow!("failed to flush Wolverine public-output seed: {}", e))?;

    let mut seeded_rng = StdRng::from_seed(seed);
    let coeffs = random_fe_vec_from_rng(&mut seeded_rng, a.len())?;

    let lambda_batch = receive_fe_abstract(channel)?;
    let mu_batch = receive_fe_abstract(channel)?;

    let l_batch = coeffs
        .iter()
        .zip(a.iter().zip(b.iter()).zip(public_c.iter()))
        .map(|(&eta_i, ((a_i, b_i), &c_i))| {
            let l_i = a_i.tag() * b_i.tag() - (delta * delta) * c_i;
            eta_i * l_i
        })
        .fold(FE::zero(), |acc, term| acc + term);

    ensure!(
        l_batch == delta * lambda_batch + mu_batch,
        "Wolverine public-output multiplication proof failed: batched relation mismatch"
    );

    Ok(())
}
