use crate::{bedoza::defines::FE, tcp_channel::SwankyChannel};
use anyhow::{Result, anyhow};
use rand::RngExt;
use sha2::{Digest, Sha256};

const FE_BYTES: usize = 32;

pub fn send_fe(value: FE, channel: &mut SwankyChannel) -> Result<()> {
    let bytes = value.to_bytes_le();
    channel.send(bytes.as_ref())
}

pub fn receive_fe(channel: &mut SwankyChannel) -> Result<FE> {
    let raw = channel.receive()?;
    let raw_len = raw.len();
    let arr: [u8; FE_BYTES] = raw
        .try_into()
        .map_err(|_| anyhow!("Expected {} bytes for FE, got {}", FE_BYTES, raw_len))?;

    FE::from_bytes_le(&arr).map_err(|e| anyhow!("Invalid FE encoding: {:?}", e))
}

pub fn send_fe_vec(values: &[FE], channel: &mut SwankyChannel) -> Result<()> {
    let mut buf = Vec::with_capacity(values.len() * FE_BYTES);
    for value in values {
        buf.extend_from_slice(value.to_bytes_le().as_ref());
    }
    channel.send(&buf)
}

pub fn receive_fe_vec(channel: &mut SwankyChannel) -> Result<Vec<FE>> {
    let raw = channel.receive()?;
    let mut chunks = raw.chunks_exact(FE_BYTES);
    if !chunks.remainder().is_empty() {
        return Err(anyhow!(
            "Invalid FE vector payload size: {} is not divisible by {}",
            raw.len(),
            FE_BYTES
        ));
    }

    let mut out = Vec::with_capacity(raw.len() / FE_BYTES);
    for chunk in &mut chunks {
        let arr: [u8; FE_BYTES] = chunk
            .try_into()
            .map_err(|_| anyhow!("Internal chunk conversion failed"))?;
        let fe = FE::from_bytes_le(&arr)
            .map_err(|e| anyhow!("Invalid FE encoding in vector: {:?}", e))?;
        out.push(fe);
    }

    Ok(out)
}

// Jointly sample 32 random bytes with a simple commit-then-reveal coin toss.
// `side = false` acts as the first sender (commit to r0), `side = true` acts as the receiver.
pub fn random_32bytes_coin(side: bool, channel: &mut SwankyChannel) -> Result<[u8; 32]> {
    if !side {
        let mut rng = rand::rng();
        let r0: [u8; 32] = rng.random();
        let r0_hash: [u8; 32] = Sha256::digest(r0).into();
        channel.send(&r0_hash)?;

        let r1_raw = channel.receive()?;
        let r1_len = r1_raw.len();
        let r1: [u8; 32] = r1_raw
            .try_into()
            .map_err(|_| anyhow!("Expected 32 bytes for r1, got {}", r1_len))?;

        channel.send(&r0)?;

        Ok(std::array::from_fn(|i| r0[i] ^ r1[i]))
    } else {
        let r0_hash_raw = channel.receive()?;
        let r0_hash_len = r0_hash_raw.len();
        let r0_hash: [u8; 32] = r0_hash_raw
            .try_into()
            .map_err(|_| anyhow!("Expected 32 bytes for hash(r0), got {}", r0_hash_len))?;

        let mut rng = rand::rng();
        let r1: [u8; 32] = rng.random();
        channel.send(&r1)?;

        let r0_raw = channel.receive()?;
        let r0_len = r0_raw.len();
        let r0: [u8; 32] = r0_raw
            .try_into()
            .map_err(|_| anyhow!("Expected 32 bytes for r0, got {}", r0_len))?;
        let expected_hash: [u8; 32] = Sha256::digest(r0).into();
        if expected_hash != r0_hash {
            return Err(anyhow!("Coin-toss commitment check failed"));
        }

        Ok(std::array::from_fn(|i| r0[i] ^ r1[i]))
    }
}
