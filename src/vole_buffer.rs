use eyre::{Context, Result, ensure};
use generic_array::typenum::Unsigned;
use keyed_arena::KeyedArena;
use mac_n_cheese_vole::{
    mac::{Mac, MacTypes},
    vole::{VoleReceiver, VoleSender, VoleSizes},
};
use rand08::{CryptoRng, Rng};
use std::{collections::VecDeque, ops::Sub};
use swanky_channel_legacy::AbstractChannel;
use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier};
use swanky_serialization::CanonicalSerialize;

fn exchange_u64(channel: &mut impl AbstractChannel, value: u64) -> Result<u64> {
    channel.write_bytes(&value.to_le_bytes())?;
    channel.flush()?;
    let mut peer = [0u8; 8];
    channel.read_bytes(&mut peer)?;
    Ok(u64::from_le_bytes(peer))
}

fn ceil_div(n: usize, d: usize) -> usize {
    if n == 0 { 0 } else { 1 + (n - 1) / d }
}

pub struct BufferedVoleSender<T: MacTypes> {
    sender: VoleSender<T>,
    base_voles: Vec<Mac<Prover, T>>,
    selector: u64,
    random_buffer: VecDeque<Mac<Prover, T>>,
    sizes: VoleSizes,
}

impl<T> BufferedVoleSender<T>
where
    T: MacTypes,
    T::VF: CanonicalSerialize + Copy + Sub<Output = T::VF>,
{
    pub fn init<C: AbstractChannel, RNG: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut RNG,
        base_voles: Vec<Mac<Prover, T>>,
    ) -> Result<Self> {
        let sizes = VoleSizes::of::<T::VF, T::TF>();
        ensure!(
            base_voles.len() == sizes.base_voles_needed,
            "wrong base VOLE count: expected {}, got {}",
            sizes.base_voles_needed,
            base_voles.len()
        );
        let sender = VoleSender::<T>::init(channel, rng)?;
        channel.flush()?;
        Ok(Self {
            sender,
            base_voles,
            selector: 1,
            random_buffer: VecDeque::new(),
            sizes,
        })
    }

    pub fn random_available(&self) -> usize {
        self.random_buffer.len()
    }

    pub fn extend_random<C: AbstractChannel, RNG: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        additional: usize,
    ) -> Result<usize> {
        let rounds = ceil_div(additional, self.sizes.voles_outputted);
        let peer_rounds = exchange_u64(channel, rounds as u64)?;
        ensure!(
            peer_rounds == rounds as u64,
            "extend mismatch: sender wants {} rounds, peer wants {}",
            rounds,
            peer_rounds
        );

        let mut added = 0usize;
        for _ in 0..rounds {
            let arena = KeyedArena::with_capacity(0, 0);

            let mut comms_1 = vec![0u8; self.sizes.comms_1s];
            let mut comms_2 = vec![0u8; self.sizes.comms_2r];
            let mut comms_3 = vec![0u8; self.sizes.comms_3s];
            let mut comms_4 = vec![0u8; self.sizes.comms_4r];
            let mut comms_5 = vec![0u8; self.sizes.comms_5s];

            let sender_stage2 = self.sender.send(
                &arena,
                self.selector,
                rng,
                &self.base_voles,
                &mut comms_1,
            )?;
            channel.write_bytes(&comms_1)?;
            channel.flush()?;

            channel.read_bytes(&mut comms_2)?;
            let mut sender_output = vec![Mac::zero(); self.sizes.voles_outputted];
            let sender_stage3 = sender_stage2.stage2(
                &self.sender,
                &arena,
                &self.base_voles,
                &mut sender_output,
                &comms_2,
                &mut comms_3,
            )?;
            channel.write_bytes(&comms_3)?;
            channel.flush()?;

            channel.read_bytes(&mut comms_4)?;
            sender_stage3.stage3(
                &self.sender,
                &arena,
                &self.base_voles,
                &mut sender_output,
                &comms_4,
                &mut comms_5,
            )?;
            channel.write_bytes(&comms_5)?;
            channel.flush()?;

            self.random_buffer.extend(sender_output.into_iter());
            self.selector += 1;
            added += self.sizes.voles_outputted;
        }

        Ok(added)
    }

    pub fn materialize_inputs<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        inputs: &[T::VF],
    ) -> Result<Vec<Mac<Prover, T>>> {
        ensure!(
            self.random_buffer.len() >= inputs.len(),
            "not enough random VOLEs in sender buffer: have {}, need {}",
            self.random_buffer.len(),
            inputs.len()
        );
        let elem_len = <T::VF as CanonicalSerialize>::ByteReprLen::USIZE;
        let mut encoded = Vec::with_capacity(8 + inputs.len() * elem_len);
        encoded.extend_from_slice(&(inputs.len() as u64).to_le_bytes());

        let mut out = Vec::with_capacity(inputs.len());
        for &x in inputs {
            let random = self.random_buffer.pop_front().expect("checked capacity");
            let (r, beta) = random.prover_extract(IS_PROVER);
            let correction = x - r;
            encoded.extend_from_slice(correction.to_bytes().as_slice());
            out.push(Mac::prover_new(IS_PROVER, x, beta));
        }

        channel.write_bytes(&encoded)?;
        channel.flush()?;
        Ok(out)
    }
}

pub struct BufferedVoleReceiver<T: MacTypes> {
    receiver: VoleReceiver<T>,
    base_voles: Vec<Mac<Verifier, T>>,
    selector: u64,
    random_buffer: VecDeque<Mac<Verifier, T>>,
    sizes: VoleSizes,
    delta: T::TF,
}

impl<T> BufferedVoleReceiver<T>
where
    T: MacTypes,
    T::VF: CanonicalSerialize + Copy,
    T::TF: Copy + std::ops::Sub<Output = T::TF> + std::ops::Mul<T::VF, Output = T::TF>,
{
    pub fn init<C: AbstractChannel, RNG: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut RNG,
        delta: T::TF,
        base_voles: Vec<Mac<Verifier, T>>,
    ) -> Result<Self> {
        let sizes = VoleSizes::of::<T::VF, T::TF>();
        ensure!(
            base_voles.len() == sizes.base_voles_needed,
            "wrong base VOLE count: expected {}, got {}",
            sizes.base_voles_needed,
            base_voles.len()
        );
        let receiver = VoleReceiver::<T>::init(channel, rng, delta)?;
        channel.flush()?;
        Ok(Self {
            receiver,
            base_voles,
            selector: 1,
            random_buffer: VecDeque::new(),
            sizes,
            delta,
        })
    }

    pub fn random_available(&self) -> usize {
        self.random_buffer.len()
    }

    pub fn extend_random<C: AbstractChannel, RNG: Rng + CryptoRng>(
        &mut self,
        channel: &mut C,
        rng: &mut RNG,
        additional: usize,
    ) -> Result<usize> {
        let rounds = ceil_div(additional, self.sizes.voles_outputted);
        let peer_rounds = exchange_u64(channel, rounds as u64)?;
        ensure!(
            peer_rounds == rounds as u64,
            "extend mismatch: receiver wants {} rounds, peer wants {}",
            rounds,
            peer_rounds
        );

        let mut added = 0usize;
        for _ in 0..rounds {
            let arena = KeyedArena::with_capacity(0, 0);

            let mut comms_1 = vec![0u8; self.sizes.comms_1s];
            let mut comms_2 = vec![0u8; self.sizes.comms_2r];
            let mut comms_3 = vec![0u8; self.sizes.comms_3s];
            let mut comms_4 = vec![0u8; self.sizes.comms_4r];
            let mut comms_5 = vec![0u8; self.sizes.comms_5s];

            channel.read_bytes(&mut comms_1)?;
            let mut receiver_output = vec![Mac::zero(); self.sizes.voles_outputted];
            let receiver_stage2 = self.receiver.receive(
                &arena,
                self.selector,
                rng,
                &self.base_voles,
                &mut receiver_output,
                &comms_1,
                &mut comms_2,
            )?;
            channel.write_bytes(&comms_2)?;
            channel.flush()?;

            channel.read_bytes(&mut comms_3)?;
            let receiver_stage3 = receiver_stage2.stage2(
                &self.receiver,
                &arena,
                &self.base_voles,
                &mut receiver_output,
                &comms_3,
                &mut comms_4,
            )?;
            channel.write_bytes(&comms_4)?;
            channel.flush()?;

            channel.read_bytes(&mut comms_5)?;
            receiver_stage3.stage3(
                &self.receiver,
                &arena,
                &self.base_voles,
                &mut receiver_output,
                &comms_5,
            )?;

            self.random_buffer.extend(receiver_output.into_iter());
            self.selector += 1;
            added += self.sizes.voles_outputted;
        }

        Ok(added)
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

        let elem_len = <T::VF as CanonicalSerialize>::ByteReprLen::USIZE;
        let mut correction_bytes = vec![0u8; count * elem_len];
        channel.read_bytes(&mut correction_bytes)?;

        let mut out = Vec::with_capacity(count);
        for chunk in correction_bytes.chunks_exact(elem_len) {
            let mut bytes: generic_array::GenericArray<
                u8,
                <T::VF as CanonicalSerialize>::ByteReprLen,
            > = Default::default();
            bytes.copy_from_slice(chunk);
            let correction =
                T::VF::from_bytes(&bytes).context("failed to parse VOLE correction element")?;

            let random = self.random_buffer.pop_front().expect("checked capacity");
            let updated_tag = random.tag(IS_VERIFIER) - correction * self.delta;
            out.push(Mac::verifier_new(IS_VERIFIER, updated_tag));
        }
        Ok(out)
    }
}
