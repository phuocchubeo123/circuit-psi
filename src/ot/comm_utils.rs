use p256::EncodedPoint;
use std::io;
use swanky_channel_legacy::AbstractChannel;

pub fn send_point(channel: &mut impl AbstractChannel, point: &EncodedPoint) -> io::Result<u64> {
    let bytes = point.as_bytes();
    channel.write_bytes(&(bytes.len() as u64).to_le_bytes())?;
    channel.write_bytes(bytes)?;
    channel.flush()?;
    Ok(bytes.len() as u64)
}

pub fn receive_point(channel: &mut impl AbstractChannel) -> io::Result<EncodedPoint> {
    let mut len_buf = [0u8; 8];
    channel.read_bytes(&mut len_buf)?;
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut bytes = vec![0u8; len];
    if !bytes.is_empty() {
        channel.read_bytes(&mut bytes)?;
    }
    EncodedPoint::from_bytes(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid EC point"))
}
