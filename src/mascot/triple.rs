use crate::mascot::cope::MascotCope;
use crate::comm_util::{receive_fe, send_fe};
use crate::pre_ot::OTPre;
use crate::scalar_field::{FOURQ_SCALAR_BITS, random_fourq_elements_from_prg};
use crate::vole::field_config::FE;
use psi_aes::prg::PRG;
use swanky_channel_legacy::AbstractChannel;

const A_PARTS: usize = 4;
const KEY_OT_LIMBS: usize = 1;

#[derive(Clone, Copy, Debug)]
pub struct TripleShare {
    pub a: FE,
    pub b: FE,
    pub c: FE,
}

pub struct MascotTripleSender {
    sender_ot_round: usize,
    receiver_ot_round: usize,
}

pub struct MascotTripleReceiver {
    sender_ot_round: usize,
    receiver_ot_round: usize,
}

impl MascotTripleSender {
    pub fn new() -> Self {
        Self {
            sender_ot_round: 0,
            receiver_ot_round: 0,
        }
    }

    pub fn unauthenticated_triple<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<KEY_OT_LIMBS>,
        ot_when_sender: &mut OTPre<KEY_OT_LIMBS>,
        comm: &mut u64,
    ) -> TripleShare {
        let a_send_parts = random_fe_vec(A_PARTS);
        let b_send = random_fe();
        let a_send = sum_fe(&a_send_parts);

        // COPE #1: sender uses delta = b_send, receiver inputs a_recv_i
        let mut cope_1_sender = MascotCope::new(0);
        cope_1_sender.initialize_sender_pre_ot(
            io,
            b_send,
            ot_when_receiver,
            self.receiver_ot_round,
            comm,
        );
        self.receiver_ot_round += 1;
        let mut x1 = vec![FE::zero(); A_PARTS];
        cope_1_sender.extend_sender_batch(io, &mut x1, A_PARTS, comm);

        // COPE #2 (symmetric): receiver uses delta = b_recv, sender inputs a_send_i
        let mut cope_2_sender_side = MascotCope::new(1);
        cope_2_sender_side.initialize_receiver_pre_ot(
            io,
            ot_when_sender,
            self.sender_ot_round,
            comm,
        );
        self.sender_ot_round += 1;
        let mut y2 = vec![FE::zero(); A_PARTS];
        cope_2_sender_side.extend_receiver_batch(io, &mut y2, &a_send_parts, A_PARTS, comm);

        // Local sender term + sender's shares of cross terms.
        let c_send = a_send * b_send - sum_fe(&x1) + sum_fe(&y2);

        TripleShare {
            a: a_send,
            b: b_send,
            c: c_send,
        }
    }

    pub fn unauthenticated_triples<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<KEY_OT_LIMBS>,
        ot_when_sender: &mut OTPre<KEY_OT_LIMBS>,
        n: usize,
        comm: &mut u64,
    ) -> Vec<TripleShare> {
        if n == 0 {
            return vec![];
        }


        let start = std::time::Instant::now();

        let m = FOURQ_SCALAR_BITS;
        let total_ots = n * m;
        let powers = precompute_powers_of_two(m);

        println!("Precomputation done: {:?}", start.elapsed());

        let mut sample_prg = PRG::new(None, 0);
        let mut a_send_parts = vec![vec![FE::zero(); A_PARTS]; n];
        for parts in &mut a_send_parts {
            random_fourq_elements_from_prg(&mut sample_prg, parts);
        }
        let mut b_send = vec![FE::zero(); n];
        random_fourq_elements_from_prg(&mut sample_prg, &mut b_send);
        let a_send = a_send_parts.iter().map(|v| sum_fe(v)).collect::<Vec<_>>();

        println!("Random generation done: {:?}", start.elapsed());

        // Initialize both directions first to avoid role-switch waiting gaps.
        // COPE #1 init: sender uses delta = b_send_t for all t.
        let receiver_ot_offset = self.receiver_ot_round * m;
        let (delta_bits_1, mut prg_g0_1) = init_sender_pre_ot_batch(
            io,
            &b_send,
            m,
            ot_when_receiver,
            receiver_ot_offset,
            comm,
        );
        self.receiver_ot_round += n;

        println!("COPE #1 init done: {:?}", start.elapsed());

        // COPE #2 init: sender acts as receiver for all a_send_t.
        let sender_ot_offset = self.sender_ot_round * m;
        let (mut prg_g0_2, mut prg_g1_2) =
            init_receiver_pre_ot_batch(io, total_ots, ot_when_sender, sender_ot_offset, comm);
        self.sender_ot_round += n;

        println!("COPE #2 init done: {:?}", start.elapsed());

        // Extension phase in fixed direction order.
        let x1_sum =
            extend_sender_sum_batch(io, &mut prg_g0_1, &delta_bits_1, n, m, A_PARTS, &powers);

        println!("COPE #1 extension done: {:?}", start.elapsed());

        let y2_sum = extend_receiver_sum_batch(
            io,
            &mut prg_g0_2,
            &mut prg_g1_2,
            &a_send_parts,
            m,
            A_PARTS,
            &powers,
            comm,
        );

        println!("Extension done: {:?}", start.elapsed());

        let mut out = Vec::with_capacity(n);
        for t in 0..n {
            out.push(TripleShare {
                a: a_send[t],
                b: b_send[t],
                c: a_send[t] * b_send[t] - x1_sum[t] + y2_sum[t],
            });
        }

        println!("Total time for unauthenticated triples: {:?}", start.elapsed());

        out
    }
}

impl MascotTripleReceiver {
    pub fn new() -> Self {
        Self {
            sender_ot_round: 0,
            receiver_ot_round: 0,
        }
    }

    pub fn unauthenticated_triple<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<KEY_OT_LIMBS>,
        ot_when_sender: &mut OTPre<KEY_OT_LIMBS>,
        comm: &mut u64,
    ) -> TripleShare {
        let a_recv_parts = random_fe_vec(A_PARTS);
        let b_recv = random_fe();
        let a_recv = sum_fe(&a_recv_parts);

        // COPE #1: sender uses delta = b_send, receiver inputs a_recv_i
        let mut cope_1_receiver = MascotCope::new(1);
        cope_1_receiver.initialize_receiver_pre_ot(
            io,
            ot_when_sender,
            self.sender_ot_round,
            comm,
        );
        self.sender_ot_round += 1;
        let mut y1 = vec![FE::zero(); A_PARTS];
        cope_1_receiver.extend_receiver_batch(io, &mut y1, &a_recv_parts, A_PARTS, comm);

        // COPE #2 (symmetric): receiver uses delta = b_recv, sender inputs a_send_i
        let mut cope_2_receiver_side = MascotCope::new(0);
        cope_2_receiver_side.initialize_sender_pre_ot(
            io,
            b_recv,
            ot_when_receiver,
            self.receiver_ot_round,
            comm,
        );
        self.receiver_ot_round += 1;
        let mut x2 = vec![FE::zero(); A_PARTS];
        cope_2_receiver_side.extend_sender_batch(io, &mut x2, A_PARTS, comm);

        // Local receiver term + receiver's shares of cross terms.
        let c_recv = a_recv * b_recv + sum_fe(&y1) - sum_fe(&x2);

        TripleShare {
            a: a_recv,
            b: b_recv,
            c: c_recv,
        }
    }

    pub fn unauthenticated_triples<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<KEY_OT_LIMBS>,
        ot_when_sender: &mut OTPre<KEY_OT_LIMBS>,
        n: usize,
        comm: &mut u64,
    ) -> Vec<TripleShare> {
        if n == 0 {
            return vec![];
        }

        let m = FOURQ_SCALAR_BITS;
        let total_ots = n * m;
        let powers = precompute_powers_of_two(m);

        let mut sample_prg = PRG::new(None, 0);
        let mut a_recv_parts = vec![vec![FE::zero(); A_PARTS]; n];
        for parts in &mut a_recv_parts {
            random_fourq_elements_from_prg(&mut sample_prg, parts);
        }
        let mut b_recv = vec![FE::zero(); n];
        random_fourq_elements_from_prg(&mut sample_prg, &mut b_recv);
        let a_recv = a_recv_parts.iter().map(|v| sum_fe(v)).collect::<Vec<_>>();

        // Initialize both directions first to avoid role-switch waiting gaps.
        // COPE #1 init: receiver inputs a_recv_t for all t.
        let sender_ot_offset = self.sender_ot_round * m;
        let (mut prg_g0_1, mut prg_g1_1) =
            init_receiver_pre_ot_batch(io, total_ots, ot_when_sender, sender_ot_offset, comm);
        self.sender_ot_round += n;
        // COPE #2 init: receiver uses delta = b_recv_t for all t.
        let receiver_ot_offset = self.receiver_ot_round * m;
        let (delta_bits_2, mut prg_g0_2) = init_sender_pre_ot_batch(
            io,
            &b_recv,
            m,
            ot_when_receiver,
            receiver_ot_offset,
            comm,
        );
        self.receiver_ot_round += n;

        // Extension phase in fixed direction order.
        let y1_sum = extend_receiver_sum_batch(
            io,
            &mut prg_g0_1,
            &mut prg_g1_1,
            &a_recv_parts,
            m,
            A_PARTS,
            &powers,
            comm,
        );
        let x2_sum =
            extend_sender_sum_batch(io, &mut prg_g0_2, &delta_bits_2, n, m, A_PARTS, &powers);

        let mut out = Vec::with_capacity(n);
        for t in 0..n {
            out.push(TripleShare {
                a: a_recv[t],
                b: b_recv[t],
                c: a_recv[t] * b_recv[t] + y1_sum[t] - x2_sum[t],
            });
        }
        out
    }
}

fn random_fe() -> FE {
    random_fe_vec(1)[0]
}

fn random_fe_vec(n: usize) -> Vec<FE> {
    let mut out = vec![FE::zero(); n];
    let mut prg = PRG::new(None, 0);
    random_fourq_elements_from_prg(&mut prg, &mut out);
    out
}

fn sum_fe(values: &[FE]) -> FE {
    values.iter().fold(FE::zero(), |acc, v| acc + *v)
}

fn flatten_fe_bits(values: &[FE], m: usize) -> Vec<bool> {
    let mut out = vec![false; values.len() * m];
    for (t, value) in values.iter().enumerate() {
        let bytes = value.to_bytes_le();
        for bit in 0..m {
            let byte_index = bit / 8;
            let bit_index = bit % 8;
            if byte_index < bytes.len() {
                out[t * m + bit] = (bytes[byte_index] & (1 << bit_index)) != 0;
            }
        }
    }
    out
}

fn precompute_powers_of_two(m: usize) -> Vec<FE> {
    let mut powers = vec![FE::one(); m];
    let base = FE::from(2);
    for i in 1..m {
        powers[i] = powers[i - 1] * base;
    }
    powers
}

fn init_sender_pre_ot_batch<IO: AbstractChannel>(
    io: &mut IO,
    deltas: &[FE],
    m: usize,
    pre_ot: &mut OTPre<KEY_OT_LIMBS>,
    ot_offset: usize,
    comm: &mut u64,
) -> (Vec<bool>, Vec<PRG>) {
    let delta_bits = flatten_fe_bits(deltas, m);
    let total_ots = delta_bits.len();

    pre_ot.choices_recver_batch(io, &delta_bits, total_ots, comm);

    let mut k_msg = vec![[0u128; KEY_OT_LIMBS]; total_ots];
    pre_ot.recv_with_offset(io, &mut k_msg, &delta_bits, total_ots, ot_offset, comm);

    let prg_g0 = k_msg
        .iter()
        .map(|msg| PRG::new(Some(&msg[0].to_le_bytes()), 0))
        .collect::<Vec<_>>();
    (delta_bits, prg_g0)
}

fn init_receiver_pre_ot_batch<IO: AbstractChannel>(
    io: &mut IO,
    total_ots: usize,
    pre_ot: &mut OTPre<KEY_OT_LIMBS>,
    ot_offset: usize,
    comm: &mut u64,
) -> (Vec<PRG>, Vec<PRG>) {
    let mut step_start = std::time::Instant::now();
    let mut k0 = vec![[0u8; 16]; total_ots];
    let mut k1 = vec![[0u8; 16]; total_ots];
    let mut key_prg = PRG::new(None, 0);
    key_prg.random_16byte_block(&mut k0);
    key_prg.random_16byte_block(&mut k1);

    let mut k0_msg = vec![[0u128; KEY_OT_LIMBS]; total_ots];
    let mut k1_msg = vec![[0u128; KEY_OT_LIMBS]; total_ots];
    for i in 0..total_ots {
        k0_msg[i] = [u128::from_le_bytes(k0[i])];
        k1_msg[i] = [u128::from_le_bytes(k1[i])];
    }

    println!(
        "Time to create seeds for pre-OT: {:?}",
        step_start.elapsed()
    );
    step_start = std::time::Instant::now();

    pre_ot.choices_sender_batch(io, total_ots, comm);

    println!("Time to send OT choices: {:?}", step_start.elapsed());
    step_start = std::time::Instant::now();

    pre_ot.send_with_offset(io, &k0_msg, &k1_msg, total_ots, ot_offset, comm);

    println!("Time to send OT messages: {:?}", step_start.elapsed());
    step_start = std::time::Instant::now();

    let prg_g0 = k0.iter().map(|key| PRG::new(Some(key), 0)).collect::<Vec<_>>();
    let prg_g1 = k1.iter().map(|key| PRG::new(Some(key), 0)).collect::<Vec<_>>();

    println!("Time to initialize PRGs: {:?}", step_start.elapsed());

    (prg_g0, prg_g1)
}

fn extend_sender_sum_batch<IO: AbstractChannel>(
    io: &mut IO,
    prg_g0: &mut [PRG],
    delta_bits: &[bool],
    n: usize,
    m: usize,
    size: usize,
    powers: &[FE],
) -> Vec<FE> {
    let total_ots = n * m;
    assert_eq!(delta_bits.len(), total_ots, "delta bit length mismatch");
    assert_eq!(prg_g0.len(), total_ots, "sender PRG length mismatch");
    assert_eq!(powers.len(), m, "power length mismatch");

    let received = receive_fe(io).expect("Failed to receive batched tau");
    assert_eq!(
        received.len(),
        total_ots * size,
        "batched tau length mismatch"
    );

    let mut sums = vec![FE::zero(); n];
    let mut w = vec![FE::zero(); size];
    for row in 0..total_ots {
        let triple_idx = row / m;
        let bit_idx = row % m;
        let weight = powers[bit_idx];

        random_fourq_elements_from_prg(&mut prg_g0[row], &mut w);

        let base = row * size;
        let mut v = FE::zero();
        for j in 0..size {
            v += if delta_bits[row] {
                w[j] + received[base + j]
            } else {
                w[j]
            };
        }
        sums[triple_idx] += v * weight;
    }
    sums
}

fn extend_receiver_sum_batch<IO: AbstractChannel>(
    io: &mut IO,
    prg_g0: &mut [PRG],
    prg_g1: &mut [PRG],
    u_parts: &[Vec<FE>],
    m: usize,
    size: usize,
    powers: &[FE],
    comm: &mut u64,
) -> Vec<FE> {
    let n = u_parts.len();
    let total_ots = n * m;
    assert_eq!(prg_g0.len(), total_ots, "receiver PRG0 length mismatch");
    assert_eq!(prg_g1.len(), total_ots, "receiver PRG1 length mismatch");
    assert_eq!(powers.len(), m, "power length mismatch");

    let mut sums = vec![FE::zero(); n];
    let mut tau_flat = Vec::with_capacity(total_ots * size);
    let mut w0 = vec![FE::zero(); size];
    let mut w1 = vec![FE::zero(); size];

    for row in 0..total_ots {
        let triple_idx = row / m;
        let bit_idx = row % m;
        let weight = powers[bit_idx];
        assert_eq!(u_parts[triple_idx].len(), size, "u length mismatch");

        random_fourq_elements_from_prg(&mut prg_g0[row], &mut w0);
        random_fourq_elements_from_prg(&mut prg_g1[row], &mut w1);
        for j in 0..size {
            let adjusted_w1 = w1[j] + u_parts[triple_idx][j];
            tau_flat.push(w0[j] - adjusted_w1);
            sums[triple_idx] += w0[j] * weight;
        }
    }

    *comm += send_fe(io, &tau_flat).expect("Failed to send batched tau");
    sums
}
