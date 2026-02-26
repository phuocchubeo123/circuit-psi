use anyhow::{Result, anyhow};
use std::{
    io::{BufReader, BufWriter, Read, Write},
    net::TcpStream,
    thread::sleep,
    time::Duration,
};
use swanky_channel_legacy::{AbstractChannel, Channel as SwankyChannel};

pub struct TcpChannel {
    stream: TcpStream,
    bytes_sent: u64,
    bytes_received: u64,
}

impl TcpChannel {
    /// Creates a new TcpChannel
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        const CHUNK_SIZE: usize = 8192;

        self.stream.write_all(&(data.len() as u64).to_le_bytes())?;
        self.bytes_sent += 8;

        for chunk in data.chunks(CHUNK_SIZE) {
            self.stream.write_all(chunk)?;
            self.bytes_sent += chunk.len() as u64;
        }

        self.flush()
            .map_err(|e| anyhow!("Failed to flush stream: {}", e))?;

        Ok(())
    }

    pub fn receive(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 8];
        self.stream.read_exact(&mut len_buf)?;
        self.bytes_received += 8;

        let data_len = u64::from_le_bytes(len_buf) as usize;
        let mut data = vec![0u8; data_len];

        let mut total_read = 0;
        while total_read < data_len {
            let bytes_read = self.stream.read(&mut data[total_read..])?;
            if bytes_read == 0 {
                return Err(anyhow!("Connection closed unexpectedly"));
            }
            total_read += bytes_read;
            self.bytes_received += bytes_read as u64;
        }

        Ok(data)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.stream.flush()?;
        Ok(())
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn megabytes_sent(&self) -> f64 {
        self.bytes_sent as f64 / 1_000_000.0
    }

    pub fn megabytes_received(&self) -> f64 {
        self.bytes_received as f64 / 1_000_000.0
    }
}

pub fn connect_with_retry(addr: &str) -> Result<TcpChannel> {
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                return Ok(TcpChannel::new(stream));
            }
            Err(e) => {
                eprintln!("Connection failed: {}. Retrying...", e);
                sleep(Duration::from_millis(50));
            }
        }
    }
}

pub fn listen_to(addr: &str) -> Result<TcpChannel> {
    let listener = std::net::TcpListener::bind(addr)?;
    let (stream, _) = listener.accept()?;
    Ok(TcpChannel::new(stream))
}

pub struct CountingSwankyChannel<C> {
    inner: C,
    bytes_sent: u64,
    bytes_received: u64,
}

impl<C> CountingSwankyChannel<C> {
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn clear_counts(&mut self) {
        self.bytes_sent = 0;
        self.bytes_received = 0;
    }

    pub fn inner(&self) -> &C {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut C {
        &mut self.inner
    }

    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: AbstractChannel> AbstractChannel for CountingSwankyChannel<C> {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_bytes(bytes)?;
        self.bytes_received += bytes.len() as u64;
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write_bytes(bytes)?;
        self.bytes_sent += bytes.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub type SwankyTcpChannel =
    CountingSwankyChannel<SwankyChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>;

pub fn swanky_channel_from_tcp_stream(stream: TcpStream) -> Result<SwankyTcpChannel> {
    let reader = BufReader::new(stream.try_clone()?);
    let writer = BufWriter::new(stream);
    Ok(CountingSwankyChannel::new(SwankyChannel::new(
        reader, writer,
    )))
}

pub fn connect_swanky_with_retry(addr: &str) -> Result<SwankyTcpChannel> {
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                return swanky_channel_from_tcp_stream(stream);
            }
            Err(e) => {
                eprintln!("Connection failed: {}. Retrying...", e);
                sleep(Duration::from_millis(50));
            }
        }
    }
}

pub fn listen_swanky(addr: &str) -> Result<SwankyTcpChannel> {
    let listener = std::net::TcpListener::bind(addr)?;
    let (stream, _) = listener.accept()?;
    swanky_channel_from_tcp_stream(stream)
}
