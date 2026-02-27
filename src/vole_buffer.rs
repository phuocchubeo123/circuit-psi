use crate::scalar_field::FourQScalarField as FE;
use eyre::{Result, ensure};
use mac_n_cheese_vole::mac::{Mac, MacTypes};
use p256::EncodedPoint;
use psi_vole::{
    comm_channel::CommunicationChannel,
    fourq_field::FourQScalarField as PsiFE,
    vole_triple::{LPN17, VoleTriple},
};
use rand08::{CryptoRng, Rng};
use std::{collections::VecDeque, io, marker::PhantomData};
use swanky_channel_legacy::AbstractChannel;
use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier};

fn to_psi(x: FE) -> PsiFE {
    PsiFE::from_bytes_le(&x.to_bytes_le()).expect("valid FourQ bytes")
}

fn to_local(x: PsiFE) -> FE {
    FE::from_bytes_le(&x.to_bytes_le()).expect("valid FourQ bytes")
}

fn exchange_u64(channel: &mut impl AbstractChannel, value: u64) -> Result<u64> {
    channel.write_bytes(&value.to_le_bytes())?;
    channel.flush()?;
    let mut peer = [0u8; 8];
    channel.read_bytes(&mut peer)?;
    Ok(u64::from_le_bytes(peer))
}

struct SwankyCompatChannel<'a, C: AbstractChannel> {
    channel: &'a mut C,
}

impl<'a, C: AbstractChannel> SwankyCompatChannel<'a, C> {
    fn new(channel: &'a mut C) -> Self {
        Self { channel }
    }
}

impl<C: AbstractChannel> CommunicationChannel for SwankyCompatChannel<'_, C> {
    fn send_u8(&mut self, data: &[u8]) -> io::Result<u64> {
        self.channel.write_bytes(&(data.len() as u64).to_le_bytes())?;
        self.channel.write_bytes(data)?;
        self.channel.flush()?;
        Ok(data.len() as u64)
    }

    fn receive_u8(&mut self) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 8];
        self.channel.read_bytes(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;
        let mut out = vec![0u8; len];
        self.channel.read_bytes(&mut out)?;
        Ok(out)
    }

    fn send_block<const N: usize>(&mut self, data: &[[u8; N]]) -> io::Result<u64> {
        self.channel.write_bytes(&(data.len() as u64).to_le_bytes())?;
        if !data.is_empty() {
            let mut packed = Vec::with_capacity(data.len() * N);
            for block in data {
                packed.extend_from_slice(block);
            }
            self.channel.write_bytes(&packed)?;
        }
        self.channel.flush()?;
        Ok((data.len() * N) as u64)
    }

    fn receive_block<const N: usize>(&mut self) -> io::Result<Vec<[u8; N]>> {
        let mut len_buf = [0u8; 8];
        self.channel.read_bytes(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;
        let mut out = vec![[0u8; N]; len];
        for block in &mut out {
            self.channel.read_bytes(block)?;
        }
        Ok(out)
    }

    fn send_bits(&mut self, bits: &[bool]) -> io::Result<u64> {
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
        self.channel.write_bytes(&(bits.len() as u64).to_le_bytes())?;
        self.channel.write_bytes(&packed)?;
        self.channel.flush()?;
        Ok(packed.len() as u64)
    }

    fn receive_bits(&mut self) -> io::Result<Vec<bool>> {
        let mut len_buf = [0u8; 8];
        self.channel.read_bytes(&mut len_buf)?;
        let bits_len = u64::from_le_bytes(len_buf) as usize;
        let bytes_len = bits_len.div_ceil(8);
        let mut packed = vec![0u8; bytes_len];
        self.channel.read_bytes(&mut packed)?;

        let mut bits = Vec::with_capacity(bits_len);
        for i in 0..bits_len {
            bits.push((packed[i / 8] & (1 << (i % 8))) != 0);
        }
        Ok(bits)
    }

    fn send_stark252(&mut self, elements: &[PsiFE]) -> io::Result<u64> {
        let total_size = (elements.len() * 32) as u64;
        self.channel.write_bytes(&total_size.to_le_bytes())?;
        if !elements.is_empty() {
            let mut packed = Vec::with_capacity(elements.len() * 32);
            for element in elements {
                packed.extend_from_slice(&element.to_bytes_le());
            }
            self.channel.write_bytes(&packed)?;
        }
        self.channel.flush()?;
        Ok(total_size)
    }

    fn receive_stark252(&mut self) -> io::Result<Vec<PsiFE>> {
        let mut size_buf = [0u8; 8];
        self.channel.read_bytes(&mut size_buf)?;
        let total_size = u64::from_le_bytes(size_buf) as usize;
        if total_size % 32 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid FE byte length",
            ));
        }
        let mut raw = vec![0u8; total_size];
        self.channel.read_bytes(&mut raw)?;
        raw.chunks_exact(32)
            .map(|chunk| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(chunk);
                PsiFE::from_bytes_le(&bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("invalid FE: {e:?}"))
                })
            })
            .collect()
    }

    fn send_point(&mut self, point: &EncodedPoint) -> io::Result<u64> {
        let bytes = point.as_bytes();
        self.channel.write_bytes(&(bytes.len() as u64).to_le_bytes())?;
        self.channel.write_bytes(bytes)?;
        self.channel.flush()?;
        Ok(bytes.len() as u64)
    }

    fn receive_point(&mut self) -> io::Result<EncodedPoint> {
        let mut len_buf = [0u8; 8];
        self.channel.read_bytes(&mut len_buf)?;
        let len = u64::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        self.channel.read_bytes(&mut bytes)?;
        EncodedPoint::from_bytes(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid EC point"))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.channel.flush()
    }
}

pub struct BufferedVoleSender<T: MacTypes<VF = FE, TF = FE>> {
    vole: VoleTriple,
    key: FE,
    random_buffer: VecDeque<Mac<Prover, T>>,
    _marker: PhantomData<T>,
}

impl<T> BufferedVoleSender<T>
where
    T: MacTypes<VF = FE, TF = FE>,
{
    pub fn init<C: AbstractChannel, RNG: Rng + CryptoRng>(
        channel: &mut C,
        _rng: &mut RNG,
        _base_voles: Vec<Mac<Prover, T>>,
    ) -> Result<Self> {
        let mut key_bytes = [0u8; 32];
        channel.read_bytes(&mut key_bytes)?;
        let key = FE::from_bytes_le(&key_bytes).map_err(|e| eyre::eyre!("{e:?}"))?;

        let mut comm = 0u64;
        let mut io = SwankyCompatChannel::new(channel);
        let mut vole = VoleTriple::new(1, true, &mut io, LPN17, &mut comm);
        vole.setup_receiver(&mut io, &mut comm);
        vole.extend_initialization();

        Ok(Self {
            vole,
            key,
            random_buffer: VecDeque::new(),
            _marker: PhantomData,
        })
    }

    pub fn random_available(&self) -> usize {
        self.random_buffer.len()
    }

    pub fn extend_random<C: AbstractChannel, RNG: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        additional: usize,
    ) -> Result<usize> {
        let peer_requested = exchange_u64(channel, additional as u64)?;
        ensure!(
            peer_requested == additional as u64,
            "extend mismatch: sender wants {}, peer wants {}",
            additional,
            peer_requested
        );

        if additional == 0 {
            return Ok(0);
        }

        let mut y = vec![PsiFE::zero(); additional];
        let mut z = vec![PsiFE::zero(); additional];
        let mut comm = 0u64;
        let mut io = SwankyCompatChannel::new(channel);
        self.vole
            .extend(&mut io, &mut y, &mut z, additional, &mut comm);

        let two_key = self.key + self.key;
        for i in 0..additional {
            let r = to_local(z[i]);
            let y_local = to_local(y[i]);
            let beta = y_local - (two_key * r);
            self.random_buffer
                .push_back(Mac::prover_new(IS_PROVER, r, beta));
        }

        Ok(additional)
    }

    pub fn materialize_inputs<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        inputs: &[FE],
    ) -> Result<Vec<Mac<Prover, T>>> {
        ensure!(
            self.random_buffer.len() >= inputs.len(),
            "not enough random VOLEs in sender buffer: have {}, need {}",
            self.random_buffer.len(),
            inputs.len()
        );
        let mut encoded = Vec::with_capacity(8 + inputs.len() * 32);
        encoded.extend_from_slice(&(inputs.len() as u64).to_le_bytes());

        let mut out = Vec::with_capacity(inputs.len());
        for &x in inputs {
            let random = self.random_buffer.pop_front().expect("checked capacity");
            let (r, beta) = random.prover_extract(IS_PROVER);
            let correction = x - r;
            encoded.extend_from_slice(&correction.to_bytes_le());
            out.push(Mac::prover_new(IS_PROVER, x, beta));
        }

        channel.write_bytes(&encoded)?;
        channel.flush()?;
        Ok(out)
    }
}

pub struct BufferedVoleReceiver<T: MacTypes<VF = FE, TF = FE>> {
    vole: VoleTriple,
    random_buffer: VecDeque<Mac<Verifier, T>>,
    delta: FE,
    _marker: PhantomData<T>,
}

impl<T> BufferedVoleReceiver<T>
where
    T: MacTypes<VF = FE, TF = FE>,
{
    pub fn init<C: AbstractChannel, RNG: Rng + CryptoRng>(
        channel: &mut C,
        _rng: &mut RNG,
        delta: FE,
        _base_voles: Vec<Mac<Verifier, T>>,
    ) -> Result<Self> {
        let key = -delta;
        channel.write_bytes(&key.to_bytes_le())?;
        channel.flush()?;

        let mut comm = 0u64;
        let mut io = SwankyCompatChannel::new(channel);
        let mut vole = VoleTriple::new(0, true, &mut io, LPN17, &mut comm);
        vole.setup_sender(&mut io, to_psi(key), &mut comm);
        vole.extend_initialization();

        Ok(Self {
            vole,
            random_buffer: VecDeque::new(),
            delta,
            _marker: PhantomData,
        })
    }

    pub fn random_available(&self) -> usize {
        self.random_buffer.len()
    }

    pub fn extend_random<C: AbstractChannel, RNG: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        _rng: &mut RNG,
        additional: usize,
    ) -> Result<usize> {
        let peer_requested = exchange_u64(channel, additional as u64)?;
        ensure!(
            peer_requested == additional as u64,
            "extend mismatch: receiver wants {}, peer wants {}",
            additional,
            peer_requested
        );

        if additional == 0 {
            return Ok(0);
        }

        let mut k = vec![PsiFE::zero(); additional];
        let mut dummy = vec![PsiFE::zero(); additional];
        let mut comm = 0u64;
        let mut io = SwankyCompatChannel::new(channel);
        self.vole
            .extend(&mut io, &mut k, &mut dummy, additional, &mut comm);

        for tag in k {
            self.random_buffer
                .push_back(Mac::verifier_new(IS_VERIFIER, to_local(tag)));
        }

        Ok(additional)
    }

    pub fn materialize_next<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        expected_count: usize,
    ) -> Result<Vec<Mac<Verifier, T>>> {
        let mut count_bytes = [0u8; 8];
        channel.read_bytes(&mut count_bytes)?;
        let count = u64::from_le_bytes(count_bytes) as usize;
        ensure!(
            count == expected_count,
            "materialize mismatch: expected {} items, peer sent {}",
            expected_count,
            count
        );
        ensure!(
            self.random_buffer.len() >= count,
            "not enough random VOLEs in receiver buffer: have {}, need {}",
            self.random_buffer.len(),
            count
        );

        let mut correction_bytes = vec![0u8; count * 32];
        channel.read_bytes(&mut correction_bytes)?;

        let mut out = Vec::with_capacity(count);
        for chunk in correction_bytes.chunks_exact(32) {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            let correction = FE::from_bytes_le(&bytes).map_err(|e| eyre::eyre!("{e:?}"))?;

            let random = self.random_buffer.pop_front().expect("checked capacity");
            let updated_tag = random.tag(IS_VERIFIER) - correction * self.delta;
            out.push(Mac::verifier_new(IS_VERIFIER, updated_tag));
        }
        Ok(out)
    }
}
