use crate::{
    scalar_field::FourQScalarField as PsiFE,
    scalar_field::FourQScalarField as FE,
    vole_triple::{LPN17, VoleTriple},
};
use eyre::{Result, ensure};
use mac_n_cheese_vole::mac::{Mac, MacTypes};
use rand08::{CryptoRng, Rng};
use std::{collections::VecDeque, marker::PhantomData};
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
        let mut vole = VoleTriple::new(1, true, channel, LPN17, &mut comm);
        vole.setup_receiver(channel, &mut comm);
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
        self.vole
            .extend(channel, &mut y, &mut z, additional, &mut comm);

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
        let mut vole = VoleTriple::new(0, true, channel, LPN17, &mut comm);
        vole.setup_sender(channel, to_psi(key), &mut comm);
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
        self.vole
            .extend(channel, &mut k, &mut dummy, additional, &mut comm);

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
