use crate::comm_channel::CommunicationChannel;
use std::net::TcpStream;
use p256::EncodedPoint;
use std::io::{Write, Read};

pub type FE = crate::fourq_field::FourQScalarField;

pub struct TcpChannel {
    pub(crate) stream: TcpStream,
}

impl TcpChannel {
    /// Creates a new TcpChannel
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl CommunicationChannel for TcpChannel {
    /// Sends an array of bits over the TCP channel.
    /// This function will return the number of bytes sent.
    fn send_bits(&mut self, bits: &[bool]) -> std::io::Result<u64> {
        // Serialize bits into bytes
        let mut byte_array = Vec::with_capacity((bits.len() + 7) / 8);
        let mut current_byte = 0u8;
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                current_byte |= 1 << (i % 8);
            }
            if i % 8 == 7 || i == bits.len() - 1 {
                byte_array.push(current_byte);
                current_byte = 0;
            }
        }

        // Send the total number of bits (as u64) and the byte array
        let num_bits = bits.len() as u64;
        self.stream.write_all(&num_bits.to_le_bytes())?;
        self.stream.write_all(&byte_array)?;

        Ok((num_bits + 7) / 8)  // Return the number of bits sent
    }

    /// Receives an array of bits over the TCP channel.
    fn receive_bits(&mut self) -> std::io::Result<Vec<bool>> {
        // Read the total number of bits (u64)
        let mut num_bits_buf = [0u8; 8];
        self.stream.read_exact(&mut num_bits_buf)?;
        let num_bits = u64::from_le_bytes(num_bits_buf) as usize;

        // Read the serialized byte array
        let num_bytes = (num_bits + 7) / 8;
        let mut byte_array = vec![0u8; num_bytes];
        self.stream.read_exact(&mut byte_array)?;

        // Deserialize bytes back into bits
        let mut bits = Vec::with_capacity(num_bits);
        for (i, &byte) in byte_array.iter().enumerate() {
            for j in 0..8 {
                if i * 8 + j >= num_bits {
                    break;
                }
                bits.push((byte & (1 << j)) != 0);
            }
        }

        Ok(bits)
    }

    /// Sends a vector of STARK-252 field elements over the TCP channel.
    /// This function will return the number of bytes sent.
    fn send_stark252(&mut self, elements: &[FE]) -> std::io::Result<u64> {
        // Define the chunk size (in bytes). For example, 32 elements (32 bytes each) per chunk.
        const CHUNK_SIZE: usize = 2048; // Adjust this as needed

        // Serialize all elements into a vector
        let mut serialized_data = Vec::with_capacity(elements.len() * 32);
        for element in elements {
            serialized_data.extend_from_slice(&element.to_bytes_le());
        }

        // Calculate the total size of the data
        let total_size = serialized_data.len() as u64;

        // Send the total size
        self.stream.write_all(&total_size.to_le_bytes())?;

        // Send data in chunks
        let mut start = 0;
        while start < serialized_data.len() {
            let end = (start + CHUNK_SIZE).min(serialized_data.len());
            self.stream.write_all(&serialized_data[start..end])?;
            start = end;
        }

        Ok(total_size)  // Return the number of bytes sent
    }

    /// Receives STARK-252 field elements over the TCP channel.
    fn receive_stark252(&mut self) -> std::io::Result<Vec<FE>> {
        // Define the chunk size (in bytes)
        const CHUNK_SIZE: usize = 2048; // Adjust this as needed

        // Read the total size prefix
        let mut size_buf = [0u8; 8];
        self.stream.read_exact(&mut size_buf)?;
        let total_size = u64::from_le_bytes(size_buf);

        // Receive data in chunks
        let mut raw_data = vec![0u8; total_size as usize];
        let mut received = 0;
        while received < total_size as usize {
            let end = (received + CHUNK_SIZE).min(total_size as usize);
            self.stream.read_exact(&mut raw_data[received..end])?;
            received = end;
        }

        // Deserialize the elements
        let elements: Result<Vec<_>, _> = raw_data
            .chunks_exact(32)
            .map(FE::from_bytes_le)
            .collect();

        elements.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize STARK-252 element: {:?}", e),
            )
        })
    }

    /// Sends an elliptic curve point over the TCP channel.
    /// This function will return the number of bytes sent.
    fn send_point(&mut self, point: &EncodedPoint) -> std::io::Result<u64> {
        let point_bytes = point.as_bytes(); // Serialize the point
        let size = point_bytes.len() as u64;

        // Send the size and then the serialized point data
        self.stream
            .write_all(&size.to_le_bytes())?;
        self.stream
            .write_all(point_bytes)?;

        Ok(size)  // Return the number of bytes sent
    }

    /// Receives an elliptic curve point over the TCP channel.
    fn receive_point(&mut self) -> std::io::Result<EncodedPoint> {
        // Read the size of the incoming point
        let mut size_buf = [0u8; 8];
        self.stream
            .read_exact(&mut size_buf)?;
        let size = u64::from_le_bytes(size_buf) as usize;

        // Read the serialized point data
        let mut point_bytes = vec![0u8; size];
        self.stream
            .read_exact(&mut point_bytes)?;

        // Deserialize the point
        EncodedPoint::from_bytes(&point_bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid point received",
            )
        })
    }

    /// Sends a fixed-size block of data over the TCP channel.
    /// This function will return the number of bytes sent.
    fn send_block<const N: usize>(&mut self, data: &[[u8; N]]) -> std::io::Result<u64> {
        let size = data.len() as u64;

        // Send the size of the data array
        self.stream
            .write_all(&size.to_le_bytes())?;

        // Send the blocks of data
        for block in data {
            self.stream
                .write_all(block)?;
        }

        Ok(size * (N as u64))  // Return the number of bytes sent
    }

    /// Receives a fixed-size block of data over the TCP channel.
    fn receive_block<const N: usize>(&mut self) -> std::io::Result<Vec<[u8; N]>> {
        // Receive the size of the data array
        let mut size_buf = [0u8; 8];
        self.stream
            .read_exact(&mut size_buf)?;
        let size = u64::from_le_bytes(size_buf) as usize;

        // Receive the blocks of data into a Vec<[u8; N]>
        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            let mut block = [0u8; N];  // Fixed size array of N bytes
            self.stream
                .read_exact(&mut block)?;
            data.push(block);
        }

        Ok(data)
    }

    /// Sends a slice of u8 data over the TCP channel.
    /// This function will return the number of bytes sent.
    fn send_u8(&mut self, data: &[u8]) -> std::io::Result<u64> {
        const CHUNK_SIZE: usize = 1024; // Define the chunk size in bytes

        // Send the total size first
        let total_size = data.len() as u64;
        self.stream.write_all(&total_size.to_le_bytes())?;

        // Send data in chunks
        let mut start = 0;
        while start < data.len() {
            let end = (start + CHUNK_SIZE).min(data.len());
            self.stream.write_all(&data[start..end])?;
            start = end;
        }

        Ok(total_size)  // Return the number of bytes sent
    }

    /// Receives u8 data over the TCP channel.
    fn receive_u8(&mut self) -> std::io::Result<Vec<u8>> {
        const CHUNK_SIZE: usize = 1024; // Define the chunk size in bytes

        // Read the total size of the data
        let mut size_buf = [0u8; 8];
        self.stream.read_exact(&mut size_buf)?;
        let total_size = u64::from_le_bytes(size_buf) as usize;

        // Receive the data in chunks
        let mut raw_data = vec![0u8; total_size];
        let mut received = 0;
        while received < total_size {
            let end = (received + CHUNK_SIZE).min(total_size);
            self.stream.read_exact(&mut raw_data[received..end])?;
            received = end;
        }

        Ok(raw_data)
    }

    /// Flushes the TCP stream.
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
