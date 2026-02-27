use p256::EncodedPoint;

pub type FE = crate::fourq_field::FourQScalarField;

pub trait CommunicationChannel {
    /// Sends a slice of u8 data and returns the number of bytes sent.
    fn send_u8(&mut self, data: &[u8]) -> std::io::Result<u64>;

    /// Receives a vector of u8 data.
    fn receive_u8(&mut self) -> std::io::Result<Vec<u8>>;

    /// Sends a fixed-size block of data and returns the number of bytes sent.
    fn send_block<const N: usize>(&mut self, data: &[[u8; N]]) -> std::io::Result<u64>;

    /// Receives a fixed-size block of data.
    fn receive_block<const N: usize>(&mut self) -> std::io::Result<Vec<[u8; N]>>;

    /// Sends an array of bits and returns the number of bytes sent.
    fn send_bits(&mut self, bits: &[bool]) -> std::io::Result<u64>;

    /// Receives an array of bits.
    fn receive_bits(&mut self) -> std::io::Result<Vec<bool>>;

    /// Sends a vector of STARK-252 field elements and returns the number of bytes sent.
    fn send_stark252(&mut self, elements: &[FE]) -> std::io::Result<u64>;

    /// Receives a vector of STARK-252 field elements.
    fn receive_stark252(&mut self) -> std::io::Result<Vec<FE>>;

    /// Sends an elliptic curve point and returns the number of bytes sent.
    fn send_point(&mut self, point: &EncodedPoint) -> std::io::Result<u64>;

    /// Receives an elliptic curve point.
    fn receive_point(&mut self) -> std::io::Result<EncodedPoint>;

    /// Flushes the TCP stream.
    fn flush(&mut self) -> std::io::Result<()>;
}
