use crate::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    scalar_field::FourQScalarField as PsiFE,
    scalar_field::FourQScalarField as FE,
    vole_triple::{PrimalLPNParameterFp61, VoleTriple},
};
use eyre::{Result, ensure};
use rand08::{CryptoRng, Rng};
use std::collections::VecDeque;
use swanky_channel_legacy::AesRng;
use swanky_channel_legacy::AbstractChannel;

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

pub struct BufferedVoleSender {
    vole: VoleTriple,
    key: FE,
    random_buffer: VecDeque<BeDOZaSender>,
}

impl BufferedVoleSender {
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        param: PrimalLPNParameterFp61,
    ) -> Result<Self> {
        let mut key_bytes = [0u8; 32];
        channel.read_bytes(&mut key_bytes)?;
        let key = FE::from_bytes_le(&key_bytes).map_err(|e| eyre::eyre!("{e:?}"))?;

        let mut comm = 0u64;
        let mut vole = VoleTriple::new(1, true, channel, param, &mut comm);
        vole.setup_receiver(channel, &mut comm);
        vole.extend_initialization();

        Ok(Self {
            vole,
            key,
            random_buffer: VecDeque::new(),
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
        self.vole
            .extend(channel, &mut y, &mut z, additional, &mut comm);

        let two_key = self.key + self.key;
        for i in 0..additional {
            let r = to_local(z[i]);
            let y_local = to_local(y[i]);
            let beta = y_local - (two_key * r);
            self.random_buffer.push_back(BeDOZaSender::new(r, beta, false));
        }

        Ok(additional)
    }

    fn ensure_random_capacity<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        needed: usize,
    ) -> Result<()> {
        if self.random_buffer.len() >= needed {
            return Ok(());
        }
        let missing = needed - self.random_buffer.len();
        let mut rng = AesRng::new();
        self.extend_random(channel, &mut rng, missing)?;
        Ok(())
    }

    pub fn random_auth<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        count: usize,
    ) -> Result<Vec<BeDOZaSender>> {
        self.ensure_random_capacity(channel, count)?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.random_buffer.pop_front().expect("checked capacity"));
        }
        Ok(out)
    }

    pub fn commit_auth<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        inputs: &[FE],
    ) -> Result<Vec<BeDOZaSender>> {
        self.ensure_random_capacity(channel, inputs.len())?;

        let mut encoded = Vec::with_capacity(8 + inputs.len() * 32);
        encoded.extend_from_slice(&(inputs.len() as u64).to_le_bytes());

        let mut out = Vec::with_capacity(inputs.len());
        for &x in inputs {
            let random = self.random_buffer.pop_front().expect("checked capacity");
            let r = random.val();
            let beta = random.pad();
            let correction = x - r;
            encoded.extend_from_slice(&correction.to_bytes_le());
            out.push(BeDOZaSender::new(x, beta, false));
        }

        channel.write_bytes(&encoded)?;
        channel.flush()?;
        Ok(out)
    }

    pub fn materialize_inputs<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        inputs: &[FE],
    ) -> Result<Vec<BeDOZaSender>> {
        self.commit_auth(channel, inputs)
    }
}

pub struct BufferedVoleReceiver {
    vole: VoleTriple,
    random_buffer: VecDeque<BeDOZaReceiver>,
    delta: FE,
}

impl BufferedVoleReceiver {
    pub fn init<C: AbstractChannel>(
        channel: &mut C,
        delta: FE,
        param: PrimalLPNParameterFp61,
    ) -> Result<Self> {
        let key = -delta;
        channel.write_bytes(&key.to_bytes_le())?;
        channel.flush()?;

        let mut comm = 0u64;
        let mut vole = VoleTriple::new(0, true, channel, param, &mut comm);
        vole.setup_sender(channel, to_psi(key), &mut comm);
        vole.extend_initialization();

        Ok(Self {
            vole,
            random_buffer: VecDeque::new(),
            delta,
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
        self.vole
            .extend(channel, &mut k, &mut dummy, additional, &mut comm);

        for tag in k {
            self.random_buffer
                .push_back(BeDOZaReceiver::new(to_local(tag), -self.delta, false));
        }

        Ok(additional)
    }

    fn ensure_random_capacity<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        needed: usize,
    ) -> Result<()> {
        if self.random_buffer.len() >= needed {
            return Ok(());
        }
        let missing = needed - self.random_buffer.len();
        let mut rng = AesRng::new();
        self.extend_random(channel, &mut rng, missing)?;
        Ok(())
    }

    pub fn random_auth<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        count: usize,
    ) -> Result<Vec<BeDOZaReceiver>> {
        self.ensure_random_capacity(channel, count)?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.random_buffer.pop_front().expect("checked capacity"));
        }
        Ok(out)
    }

    pub fn commit_auth<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        expected_count: usize,
    ) -> Result<Vec<BeDOZaReceiver>> {
        self.ensure_random_capacity(channel, expected_count)?;

        let mut count_bytes = [0u8; 8];
        channel.read_bytes(&mut count_bytes)?;
        let count = u64::from_le_bytes(count_bytes) as usize;
        ensure!(
            count == expected_count,
            "materialize mismatch: expected {} items, peer sent {}",
            expected_count,
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
            let updated_tag = random.tag() - correction * self.delta;
            out.push(BeDOZaReceiver::new(updated_tag, -self.delta, false));
        }
        Ok(out)
    }

    pub fn materialize_next<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        expected_count: usize,
    ) -> Result<Vec<BeDOZaReceiver>> {
        self.commit_auth(channel, expected_count)
    }
}
