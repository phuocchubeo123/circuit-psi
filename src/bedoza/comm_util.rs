use crate::{bedoza::defines::FE, tcp_channel::TcpChannel};
use anyhow::{Result, anyhow};

const FE_BYTES: usize = 32;

pub fn send_fe(value: FE, channel: &mut TcpChannel) -> Result<()> {
    let bytes = value.to_bytes_le();
    channel.send(bytes.as_ref())
}

pub fn receive_fe(channel: &mut TcpChannel) -> Result<FE> {
    let raw = channel.receive()?;
    let raw_len = raw.len();
    let arr: [u8; FE_BYTES] = raw
        .try_into()
        .map_err(|_| anyhow!("Expected {} bytes for FE, got {}", FE_BYTES, raw_len))?;

    FE::from_bytes_le(&arr).map_err(|e| anyhow!("Invalid FE encoding: {:?}", e))
}

pub fn send_fe_vec(values: &[FE], channel: &mut TcpChannel) -> Result<()> {
    let mut buf = Vec::with_capacity(values.len() * FE_BYTES);
    for value in values {
        buf.extend_from_slice(value.to_bytes_le().as_ref());
    }
    channel.send(&buf)
}

pub fn receive_fe_vec(channel: &mut TcpChannel) -> Result<Vec<FE>> {
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
