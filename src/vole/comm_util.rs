use crate::math::defines::FE;
use std::io;
use swanky_channel_legacy::AbstractChannel;

pub fn send_u8(channel: &mut impl AbstractChannel, data: &[u8]) -> io::Result<u64> {
    channel.write_bytes(&(data.len() as u64).to_le_bytes())?;
    if !data.is_empty() {
        channel.write_bytes(data)?;
    }
    channel.flush()?;
    Ok(data.len() as u64)
}

pub fn receive_u8(channel: &mut impl AbstractChannel) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 8];
    channel.read_bytes(&mut len_buf)?;
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut out = vec![0u8; len];
    if !out.is_empty() {
        channel.read_bytes(&mut out)?;
    }
    Ok(out)
}

pub fn send_block<const N: usize>(
    channel: &mut impl AbstractChannel,
    data: &[[u8; N]],
) -> io::Result<u64> {
    channel.write_bytes(&(data.len() as u64).to_le_bytes())?;
    if !data.is_empty() {
        let mut packed = Vec::with_capacity(data.len() * N);
        for block in data {
            packed.extend_from_slice(block);
        }
        channel.write_bytes(&packed)?;
    }
    channel.flush()?;
    Ok((data.len() * N) as u64)
}

pub fn receive_block<const N: usize>(
    channel: &mut impl AbstractChannel,
) -> io::Result<Vec<[u8; N]>> {
    let mut len_buf = [0u8; 8];
    channel.read_bytes(&mut len_buf)?;
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut out = vec![[0u8; N]; len];
    for block in &mut out {
        channel.read_bytes(block)?;
    }
    Ok(out)
}

pub fn send_bits(channel: &mut impl AbstractChannel, bits: &[bool]) -> io::Result<u64> {
    let mut packed = Vec::with_capacity(bits.len().div_ceil(8));
    let mut byte = 0u8;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            byte |= 1 << (i % 8);
        }
        if i % 8 == 7 || i == bits.len() - 1 {
            packed.push(byte);
            byte = 0;
        }
    }

    channel.write_bytes(&(bits.len() as u64).to_le_bytes())?;
    if !packed.is_empty() {
        channel.write_bytes(&packed)?;
    }
    channel.flush()?;
    Ok(packed.len() as u64)
}

pub fn receive_bits(channel: &mut impl AbstractChannel) -> io::Result<Vec<bool>> {
    let mut len_buf = [0u8; 8];
    channel.read_bytes(&mut len_buf)?;
    let bits_len = u64::from_le_bytes(len_buf) as usize;
    let bytes_len = bits_len.div_ceil(8);
    let mut packed = vec![0u8; bytes_len];
    if !packed.is_empty() {
        channel.read_bytes(&mut packed)?;
    }

    let mut bits = Vec::with_capacity(bits_len);
    for i in 0..bits_len {
        bits.push((packed[i / 8] & (1 << (i % 8))) != 0);
    }
    Ok(bits)
}

pub fn send_fe(channel: &mut impl AbstractChannel, elements: &[FE]) -> io::Result<u64> {
    let total_size = (elements.len() * 32) as u64;
    channel.write_bytes(&total_size.to_le_bytes())?;
    if !elements.is_empty() {
        let mut packed = Vec::with_capacity(elements.len() * 32);
        for element in elements {
            packed.extend_from_slice(&element.to_bytes_le());
        }
        channel.write_bytes(&packed)?;
    }
    channel.flush()?;
    Ok(total_size)
}

pub fn receive_fe(channel: &mut impl AbstractChannel) -> io::Result<Vec<FE>> {
    let mut size_buf = [0u8; 8];
    channel.read_bytes(&mut size_buf)?;
    let total_size = u64::from_le_bytes(size_buf) as usize;
    if total_size % 32 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid FE byte length",
        ));
    }

    let mut raw = vec![0u8; total_size];
    if !raw.is_empty() {
        channel.read_bytes(&mut raw)?;
    }

    raw.chunks_exact(32)
        .map(|chunk| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            FE::from_bytes_le(&bytes).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid FE: {e:?}"))
            })
        })
        .collect()
}
