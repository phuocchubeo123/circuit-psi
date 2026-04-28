use crate::{
    bedoza::{bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender},
    math::defines::FE,
    tcp_channel::SwankyChannel,
    vole_triple::{PrimalLPNParameterFp61, VoleTriple},
};
use eyre::{Result, ensure};
use std::collections::VecDeque;

pub struct BufferedVoleSender {
    vole: VoleTriple,
    random_buffer: VecDeque<BeDOZaSender>,
}

impl BufferedVoleSender {
    pub fn init(channel: &mut SwankyChannel, param: PrimalLPNParameterFp61) -> Result<Self> {
        let mut comm = 0u64;
        let mut vole = VoleTriple::new(1, true, channel, param, &mut comm);
        vole.setup_receiver(channel, &mut comm);
        vole.extend_initialization();

        Ok(Self {
            vole,
            random_buffer: VecDeque::new(),
        })
    }

    pub fn random_available(&self) -> usize {
        self.random_buffer.len()
    }

    pub fn extend_random(
        &mut self,
        channel: &mut SwankyChannel,
        additional: usize,
    ) -> Result<usize> {
        let mut y = vec![FE::zero(); additional];
        let mut z = vec![FE::zero(); additional];
        let mut comm = 0u64;
        self.vole
            .extend(channel, &mut y, &mut z, additional, &mut comm);

        for i in 0..additional {
            self.random_buffer.push_back(BeDOZaSender::new(z[i], y[i]));
        }
        Ok(additional)
    }

    fn ensure_random_capacity(&mut self, channel: &mut SwankyChannel, needed: usize) -> Result<()> {
        if self.random_buffer.len() >= needed {
            return Ok(());
        }
        let missing = needed - self.random_buffer.len();
        self.extend_random(channel, missing)?;
        Ok(())
    }

    pub fn random_auth(
        &mut self,
        channel: &mut SwankyChannel,
        count: usize,
    ) -> Result<Vec<BeDOZaSender>> {
        self.ensure_random_capacity(channel, count)?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.random_buffer.pop_front().expect("checked capacity"));
        }
        Ok(out)
    }

    pub fn commit_auth(
        &mut self,
        channel: &mut SwankyChannel,
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
            out.push(BeDOZaSender::new(x, beta));
        }

        channel
            .send(&encoded)
            .map_err(|e| eyre::eyre!(e.to_string()))?;
        Ok(out)
    }

    pub fn commit_auth_into(
        &mut self,
        channel: &mut SwankyChannel,
        inputs: &[FE],
        out: &mut Vec<BeDOZaSender>,
    ) -> Result<()> {
        self.ensure_random_capacity(channel, inputs.len())?;

        let mut encoded = Vec::with_capacity(8 + inputs.len() * 32);
        encoded.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
        out.clear();
        out.reserve(inputs.len());
        for &x in inputs {
            let random = self.random_buffer.pop_front().expect("checked capacity");
            let r = random.val();
            let beta = random.pad();
            let correction = x - r;
            encoded.extend_from_slice(&correction.to_bytes_le());
            out.push(BeDOZaSender::new(x, beta));
        }

        channel
            .send(&encoded)
            .map_err(|e| eyre::eyre!(e.to_string()))?;
        Ok(())
    }
}

pub struct BufferedVoleReceiver {
    vole: VoleTriple,
    random_buffer: VecDeque<BeDOZaReceiver>,
    delta: FE,
}

impl BufferedVoleReceiver {
    pub fn init(
        channel: &mut SwankyChannel,
        delta: FE,
        param: PrimalLPNParameterFp61,
    ) -> Result<Self> {
        let mut comm = 0u64;
        let mut vole = VoleTriple::new(0, true, channel, param, &mut comm);
        vole.setup_sender(channel, delta, &mut comm);
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

    pub fn extend_random(
        &mut self,
        channel: &mut SwankyChannel,
        additional: usize,
    ) -> Result<usize> {
        let mut k = vec![FE::zero(); additional];
        let mut dummy = vec![FE::zero(); additional];
        let mut comm = 0u64;
        self.vole
            .extend(channel, &mut k, &mut dummy, additional, &mut comm);

        for tag in k {
            self.random_buffer
                .push_back(BeDOZaReceiver::new(-tag, self.delta));
        }

        Ok(additional)
    }

    fn ensure_random_capacity(&mut self, channel: &mut SwankyChannel, needed: usize) -> Result<()> {
        if self.random_buffer.len() >= needed {
            return Ok(());
        }
        let missing = needed - self.random_buffer.len();
        self.extend_random(channel, missing)?;
        Ok(())
    }

    pub fn random_auth(
        &mut self,
        channel: &mut SwankyChannel,
        count: usize,
    ) -> Result<Vec<BeDOZaReceiver>> {
        // Debug later
        self.ensure_random_capacity(channel, count)?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.random_buffer.pop_front().expect("checked capacity"));
        }
        Ok(out)
    }

    pub fn commit_auth(
        &mut self,
        channel: &mut SwankyChannel,
        expected_count: usize,
    ) -> Result<Vec<BeDOZaReceiver>> {
        self.ensure_random_capacity(channel, expected_count)?;

        let payload = channel.receive().map_err(|e| eyre::eyre!(e.to_string()))?;
        ensure!(payload.len() >= 8, "materialize payload too short");
        let mut count_bytes = [0u8; 8];
        count_bytes.copy_from_slice(&payload[..8]);
        let count = u64::from_le_bytes(count_bytes) as usize;
        ensure!(
            count == expected_count,
            "materialize mismatch: expected {} items, peer sent {}",
            expected_count,
            count
        );

        let correction_bytes = &payload[8..];
        ensure!(
            correction_bytes.len() == count * 32,
            "materialize payload length mismatch: expected {} bytes, got {}",
            count * 32,
            correction_bytes.len()
        );

        let mut out = Vec::with_capacity(count);
        for chunk in correction_bytes.chunks_exact(32) {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            let correction = FE::from_bytes_le(&bytes).map_err(|e| eyre::eyre!("{e:?}"))?;

            let random = self.random_buffer.pop_front().expect("checked capacity");
            let updated_tag = random.tag() + correction * self.delta;
            out.push(BeDOZaReceiver::new(updated_tag, self.delta));
        }
        Ok(out)
    }

    pub fn commit_auth_into(
        &mut self,
        channel: &mut SwankyChannel,
        expected_count: usize,
        out: &mut Vec<BeDOZaReceiver>,
    ) -> Result<()> {
        self.ensure_random_capacity(channel, expected_count)?;

        let payload = channel.receive().map_err(|e| eyre::eyre!(e.to_string()))?;
        ensure!(payload.len() >= 8, "materialize payload too short");
        let mut count_bytes = [0u8; 8];
        count_bytes.copy_from_slice(&payload[..8]);
        let count = u64::from_le_bytes(count_bytes) as usize;
        ensure!(
            count == expected_count,
            "materialize mismatch: expected {} items, peer sent {}",
            expected_count,
            count
        );

        let correction_bytes = &payload[8..];
        ensure!(
            correction_bytes.len() == count * 32,
            "materialize payload length mismatch: expected {} bytes, got {}",
            count * 32,
            correction_bytes.len()
        );

        out.clear();
        out.reserve(count);
        for chunk in correction_bytes.chunks_exact(32) {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            let correction = FE::from_bytes_le(&bytes).map_err(|e| eyre::eyre!("{e:?}"))?;

            let random = self.random_buffer.pop_front().expect("checked capacity");
            let updated_tag = random.tag() + correction * self.delta;
            out.push(BeDOZaReceiver::new(updated_tag, self.delta));
        }
        Ok(())
    }

    pub fn materialize_next(
        &mut self,
        channel: &mut SwankyChannel,
        expected_count: usize,
    ) -> Result<Vec<BeDOZaReceiver>> {
        self.commit_auth(channel, expected_count)
    }
}
