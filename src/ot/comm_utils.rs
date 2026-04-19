use p256::EncodedPoint;
use std::io;
use crate::tcp_channel::SwankyChannel;

pub fn send_point(channel: &mut SwankyChannel, point: &EncodedPoint) -> io::Result<u64> {
    let bytes = point.as_bytes();
    channel
        .send(bytes)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.len() as u64)
}

pub fn receive_point(channel: &mut SwankyChannel) -> io::Result<EncodedPoint> {
    let bytes = channel
        .receive()
        .map_err(|e| io::Error::other(e.to_string()))?;
    EncodedPoint::from_bytes(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid EC point"))
}
