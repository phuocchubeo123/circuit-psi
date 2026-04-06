use anyhow::Result;
use std::{
    io::{BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    thread::sleep,
    time::Duration,
};
use swanky_channel_legacy::{AbstractChannel, Channel as LegacyChannel};

pub struct SwankyChannel {
    inner: LegacyChannel<BufReader<TcpStream>, BufWriter<TcpStream>>,
    out_bytes: u64,
    in_bytes: u64,
}

impl SwankyChannel {
    pub fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        let reader = BufReader::new(stream.try_clone().expect("failed to clone TcpStream"));
        let writer = BufWriter::new(stream);
        let inner = LegacyChannel::new(reader, writer);
        Self {
            inner,
            out_bytes: 0,
            in_bytes: 0,
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.write_bytes(&(data.len() as u64).to_le_bytes())?;
        self.write_bytes(data)?;
        self.flush()?;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 8];
        self.read_bytes(&mut len_buf)?;
        let data_len = u64::from_le_bytes(len_buf) as usize;
        let mut data = vec![0u8; data_len];
        self.read_bytes(&mut data)?;
        Ok(data)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.out_bytes
    }

    pub fn bytes_received(&self) -> u64 {
        self.in_bytes
    }

    pub fn megabytes_sent(&self) -> f64 {
        self.out_bytes as f64 / 1_000_000.0
    }

    pub fn megabytes_received(&self) -> f64 {
        self.in_bytes as f64 / 1_000_000.0
    }

    pub fn get_bytes_sent(&self) -> u64 {
        self.out_bytes
    }

    pub fn get_bytes_received(&self) -> u64 {
        self.in_bytes
    }
}

impl AbstractChannel for SwankyChannel {
    fn read_bytes(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_bytes(bytes)?;
        self.in_bytes += bytes.len() as u64;
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write_bytes(bytes)?;
        self.out_bytes += bytes.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub fn connect_with_retry(addr: &str) -> Result<SwankyChannel> {
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return Ok(SwankyChannel::new(stream)),
            Err(e) => {
                eprintln!("Connection failed: {e}. Retrying...");
                sleep(Duration::from_millis(50));
            }
        }
    }
}

pub fn listen_to(addr: &str) -> Result<SwankyChannel> {
    let listener = TcpListener::bind(addr)?;
    let (stream, _) = listener.accept()?;
    Ok(SwankyChannel::new(stream))
}

