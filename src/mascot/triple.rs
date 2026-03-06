use crate::{
    bedoza::{
        BeDOZa, BeDOZaTriple, bedoza_receiver::BeDOZaReceiver, bedoza_sender::BeDOZaSender,
        vole_auth::{
            FourQVoleMac, authenticate_batch_with_peer_key_receiver,
            authenticate_batch_with_peer_key_sender,
        },
    },
    comm_util::{receive_fe, send_fe},
    pre_ot::OTPre,
    scalar_field::{FOURQ_SCALAR_BITS, random_fourq_elements_from_prg},
    vole::field_config::{FE, FE_LIMBS, fe_to_u128_limbs},
    vole_buffer::{BufferedVoleReceiver, BufferedVoleSender},
};
use psi_aes::prg::PRG;
use swanky_channel_legacy::AbstractChannel;

pub const TAU: usize = 4;
pub const TRIPLES_PER_PAIR: usize = 2;
pub const REPETITION: usize = TAU * TRIPLES_PER_PAIR;

#[derive(Clone, Copy, Debug)]
pub struct TripleShare {
    pub a: FE,
    pub b: FE,
    pub c: FE,
}

#[derive(Clone)]
struct AuthTripleShare {
    a: BeDOZa,
    b: BeDOZa,
    c: BeDOZa,
}

pub struct MascotTripleSender {
    sender_ot_used: usize,
    receiver_ot_used: usize,
}

pub struct MascotTripleReceiver {
    sender_ot_used: usize,
    receiver_ot_used: usize,
}

impl MascotTripleSender {
    pub fn new() -> Self {
        Self {
            sender_ot_used: 0,
            receiver_ot_used: 0,
        }
    }

    pub fn triple<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<FE_LIMBS>,
        ot_when_sender: &mut OTPre<FE_LIMBS>,
        auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        local_key: FE,
        comm: &mut u64,
    ) -> BeDOZaTriple {
        self.triples(
            io,
            ot_when_receiver,
            ot_when_sender,
            auth_vole_sender,
            auth_vole_receiver,
            local_key,
            1,
            comm,
        )
        .into_iter()
        .next()
        .expect("single triple exists")
    }

    pub fn triples<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<FE_LIMBS>,
        ot_when_sender: &mut OTPre<FE_LIMBS>,
        auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        local_key: FE,
        n: usize,
        comm: &mut u64,
    ) -> Vec<BeDOZaTriple> {
        if n == 0 {
            return vec![];
        }

        let m = FOURQ_SCALAR_BITS;
        let powers = precompute_powers_of_two(m);
        let total_ots = n * m * REPETITION;

        let (a_send_parts_0, a_send_0) = random_a_parts_and_sum(n, TAU);
        let (a_send_parts_1, a_send_1) = random_a_parts_and_sum(n, TAU);
        let b_send = random_fe_vec(n);

        // COPE #1: sender has delta = b, receives chosen random FE values via OT.
        let (delta_bits_1, selected_1) = init_sender_pre_ot_batch(
            io,
            &b_send,
            m,
            REPETITION,
            ot_when_receiver,
            self.receiver_ot_used,
            comm,
        );
        self.receiver_ot_used += total_ots;

        // COPE #2: sender acts as OT sender and samples both random branches directly.
        let (q0_2, q1_2) = init_receiver_random_ot_batch(
            io,
            total_ots,
            ot_when_sender,
            self.sender_ot_used,
            comm,
        );
        self.sender_ot_used += total_ots;

        let (x1_sum_0, x1_sum_1) =
            extend_sender_sum_batch(io, &selected_1, &delta_bits_1, n, m, TAU, &powers);

        let (y2_sum_0, y2_sum_1) = extend_receiver_sum_batch(
            io,
            &q0_2,
            &q1_2,
            &a_send_parts_0,
            &a_send_parts_1,
            m,
            TAU,
            &powers,
            comm,
        );

        let mut triple_0 = Vec::with_capacity(n);
        let mut triple_1 = Vec::with_capacity(n);
        for t in 0..n {
            triple_0.push(TripleShare {
                a: a_send_0[t],
                b: b_send[t],
                c: a_send_0[t] * b_send[t] - x1_sum_0[t] + y2_sum_0[t],
            });
            triple_1.push(TripleShare {
                a: a_send_1[t],
                b: b_send[t],
                c: a_send_1[t] * b_send[t] - x1_sum_1[t] + y2_sum_1[t],
            });
        }

        authenticate_and_sacrifice_pairs(
            io,
            &triple_0,
            &triple_1,
            auth_vole_sender,
            auth_vole_receiver,
            local_key,
            false,
            true,
            comm,
        )
    }
}

impl MascotTripleReceiver {
    pub fn new() -> Self {
        Self {
            sender_ot_used: 0,
            receiver_ot_used: 0,
        }
    }

    pub fn triple<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<FE_LIMBS>,
        ot_when_sender: &mut OTPre<FE_LIMBS>,
        auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        local_key: FE,
        comm: &mut u64,
    ) -> BeDOZaTriple {
        self.triples(
            io,
            ot_when_receiver,
            ot_when_sender,
            auth_vole_sender,
            auth_vole_receiver,
            local_key,
            1,
            comm,
        )
        .into_iter()
        .next()
        .expect("single triple exists")
    }

    pub fn triples<IO: AbstractChannel>(
        &mut self,
        io: &mut IO,
        ot_when_receiver: &mut OTPre<FE_LIMBS>,
        ot_when_sender: &mut OTPre<FE_LIMBS>,
        auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
        auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
        local_key: FE,
        n: usize,
        comm: &mut u64,
    ) -> Vec<BeDOZaTriple> {
        if n == 0 {
            return vec![];
        }

        let m = FOURQ_SCALAR_BITS;
        let powers = precompute_powers_of_two(m);
        let total_ots = n * m * REPETITION;

        let (a_recv_parts_0, a_recv_0) = random_a_parts_and_sum(n, TAU);
        let (a_recv_parts_1, a_recv_1) = random_a_parts_and_sum(n, TAU);
        let b_recv = random_fe_vec(n);

        // COPE #1: receiver side samples both random branches and sends through OT.
        let (q0_1, q1_1) = init_receiver_random_ot_batch(
            io,
            total_ots,
            ot_when_sender,
            self.sender_ot_used,
            comm,
        );
        self.sender_ot_used += total_ots;

        // COPE #2: receiver has delta = b and receives chosen branch through OT.
        let (delta_bits_2, selected_2) = init_sender_pre_ot_batch(
            io,
            &b_recv,
            m,
            REPETITION,
            ot_when_receiver,
            self.receiver_ot_used,
            comm,
        );
        self.receiver_ot_used += total_ots;

        let (y1_sum_0, y1_sum_1) = extend_receiver_sum_batch(
            io,
            &q0_1,
            &q1_1,
            &a_recv_parts_0,
            &a_recv_parts_1,
            m,
            TAU,
            &powers,
            comm,
        );

        let (x2_sum_0, x2_sum_1) =
            extend_sender_sum_batch(io, &selected_2, &delta_bits_2, n, m, TAU, &powers);

        let mut triple_0 = Vec::with_capacity(n);
        let mut triple_1 = Vec::with_capacity(n);
        for t in 0..n {
            triple_0.push(TripleShare {
                a: a_recv_0[t],
                b: b_recv[t],
                c: a_recv_0[t] * b_recv[t] + y1_sum_0[t] - x2_sum_0[t],
            });
            triple_1.push(TripleShare {
                a: a_recv_1[t],
                b: b_recv[t],
                c: a_recv_1[t] * b_recv[t] + y1_sum_1[t] - x2_sum_1[t],
            });
        }

        authenticate_and_sacrifice_pairs(
            io,
            &triple_0,
            &triple_1,
            auth_vole_sender,
            auth_vole_receiver,
            local_key,
            true,
            false,
            comm,
        )
    }
}

fn random_fe_vec(n: usize) -> Vec<FE> {
    let mut out = vec![FE::zero(); n];
    let mut prg = PRG::new(None, 0);
    random_fourq_elements_from_prg(&mut prg, &mut out);
    out
}

fn random_a_parts_and_sum(n: usize, tau: usize) -> (Vec<Vec<FE>>, Vec<FE>) {
    let mut prg = PRG::new(None, 0);
    let mut parts = vec![vec![FE::zero(); tau]; n];
    for part_vec in &mut parts {
        random_fourq_elements_from_prg(&mut prg, part_vec);
    }
    let summed = parts.iter().map(|v| sum_fe(v)).collect::<Vec<_>>();
    (parts, summed)
}

fn sum_fe(values: &[FE]) -> FE {
    values.iter().fold(FE::zero(), |acc, v| acc + *v)
}

fn flatten_fe_bits(values: &[FE], m: usize, repetition: usize) -> Vec<bool> {
    let mut out = Vec::with_capacity(values.len() * m * repetition);
    for value in values {
        let bytes = value.to_bytes_le();
        let mut bits = vec![false; m];

        // Fixed-width decomposition in MSB->LSB order over the lowest `m` bits.
        for bit in 0..m {
            let bit_from_lsb = m - 1 - bit;
            let byte_index = bit_from_lsb / 8;
            let bit_index = bit_from_lsb % 8;
            bits[bit] = (bytes[byte_index] & (1 << bit_index)) != 0;
        }

        for _ in 0..repetition {
            out.extend_from_slice(&bits);
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
    repetition: usize,
    pre_ot: &mut OTPre<FE_LIMBS>,
    ot_offset: usize,
    comm: &mut u64,
) -> (Vec<bool>, Vec<FE>) {
    let delta_bits = flatten_fe_bits(deltas, m, repetition);
    let total_ots = delta_bits.len();

    pre_ot.choices_recver_batch(io, &delta_bits, total_ots, comm);

    let mut selected_msg = vec![[0u128; FE_LIMBS]; total_ots];
    pre_ot.recv_with_offset(
        io,
        &mut selected_msg,
        &delta_bits,
        total_ots,
        ot_offset,
        comm,
    );

    let selected = selected_msg.iter().map(u128_limbs_to_fe).collect::<Vec<_>>();
    (delta_bits, selected)
}

fn init_receiver_random_ot_batch<IO: AbstractChannel>(
    io: &mut IO,
    total_ots: usize,
    pre_ot: &mut OTPre<FE_LIMBS>,
    ot_offset: usize,
    comm: &mut u64,
) -> (Vec<FE>, Vec<FE>) {
    let mut rot_prg = PRG::new(None, 0);
    let mut q0 = vec![FE::zero(); total_ots];
    let mut q1 = vec![FE::zero(); total_ots];

    random_fourq_elements_from_prg(&mut rot_prg, &mut q0);
    random_fourq_elements_from_prg(&mut rot_prg, &mut q1);

    let k0_msg = q0.iter().map(|x| fe_to_u128_limbs(*x)).collect::<Vec<_>>();
    let k1_msg = q1.iter().map(|x| fe_to_u128_limbs(*x)).collect::<Vec<_>>();

    pre_ot.choices_sender_batch(io, total_ots, comm);
    pre_ot.send_with_offset(io, &k0_msg, &k1_msg, total_ots, ot_offset, comm);

    (q0, q1)
}

fn extend_sender_sum_batch<IO: AbstractChannel>(
    io: &mut IO,
    selected: &[FE],
    delta_bits: &[bool],
    n: usize,
    m: usize,
    tau: usize,
    powers: &[FE],
) -> (Vec<FE>, Vec<FE>) {
    let total_ots = n * m * REPETITION;
    assert_eq!(delta_bits.len(), total_ots, "delta bit length mismatch");
    assert_eq!(selected.len(), total_ots, "selected random length mismatch");
    assert_eq!(powers.len(), m, "power length mismatch");

    let received_tau = receive_fe(io).expect("Failed to receive batched tau");
    assert_eq!(
        received_tau.len(),
        total_ots,
        "batched tau length mismatch"
    );

    let mut sum_0 = vec![FE::zero(); n];
    let mut sum_1 = vec![FE::zero(); n];

    let mut row = 0usize;
    for t in 0..n {
        for rep in 0..REPETITION {
            let triple_idx = rep / tau;
            for bit_msb in 0..m {
                let weight = powers[m - 1 - bit_msb];
                let value = if delta_bits[row] {
                    selected[row] + received_tau[row]
                } else {
                    selected[row]
                };

                if triple_idx == 0 {
                    sum_0[t] += value * weight;
                } else {
                    sum_1[t] += value * weight;
                }

                row += 1;
            }
        }
    }

    (sum_0, sum_1)
}

fn extend_receiver_sum_batch<IO: AbstractChannel>(
    io: &mut IO,
    q0: &[FE],
    q1: &[FE],
    u_parts_0: &[Vec<FE>],
    u_parts_1: &[Vec<FE>],
    m: usize,
    tau: usize,
    powers: &[FE],
    comm: &mut u64,
) -> (Vec<FE>, Vec<FE>) {
    let n = u_parts_0.len();
    let total_ots = n * m * REPETITION;
    assert_eq!(q0.len(), total_ots, "receiver q0 length mismatch");
    assert_eq!(q1.len(), total_ots, "receiver q1 length mismatch");
    assert_eq!(u_parts_1.len(), n, "u parts pair length mismatch");
    assert_eq!(powers.len(), m, "power length mismatch");

    let mut sum_0 = vec![FE::zero(); n];
    let mut sum_1 = vec![FE::zero(); n];
    let mut tau_flat = Vec::with_capacity(total_ots);

    let mut row = 0usize;
    for t in 0..n {
        assert_eq!(u_parts_0[t].len(), tau, "u0 width mismatch");
        assert_eq!(u_parts_1[t].len(), tau, "u1 width mismatch");

        for rep in 0..REPETITION {
            let triple_idx = rep / tau;
            let part_idx = rep % tau;

            for bit_msb in 0..m {
                let u = if triple_idx == 0 {
                    u_parts_0[t][part_idx]
                } else {
                    u_parts_1[t][part_idx]
                };

                let w0 = q0[row];
                let adjusted_w1 = q1[row] + u;
                tau_flat.push(w0 - adjusted_w1);

                let weight = powers[m - 1 - bit_msb];
                if triple_idx == 0 {
                    sum_0[t] += w0 * weight;
                } else {
                    sum_1[t] += w0 * weight;
                }

                row += 1;
            }
        }
    }

    *comm += send_fe(io, &tau_flat).expect("Failed to send batched tau");
    (sum_0, sum_1)
}

fn authenticate_and_sacrifice_pairs<IO: AbstractChannel>(
    io: &mut IO,
    triple_0: &[TripleShare],
    triple_1: &[TripleShare],
    auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
    auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
    local_key: FE,
    local_side: bool,
    sender_first: bool,
    comm: &mut u64,
) -> Vec<BeDOZaTriple> {
    assert_eq!(
        triple_0.len(),
        triple_1.len(),
        "triple pair length mismatch"
    );

    let n = triple_0.len();
    if n == 0 {
        return vec![];
    }

    let (auth_0, auth_1) = authenticate_triples_to_bedoza(
        io,
        triple_0,
        triple_1,
        auth_vole_sender,
        auth_vole_receiver,
        local_key,
        local_side,
        sender_first,
    );

    // Public random challenge s is coin-tossed as s = s_local + s_peer.
    let s_local = random_fe_vec(n);
    let s = open_and_add(io, &s_local, comm);

    let rho_authenticated = (0..n)
        .map(|i| auth_0[i].a * s[i] - auth_1[i].a)
        .collect::<Vec<_>>();
    let rho_open = open_bedoza_values(io, &rho_authenticated, comm);

    let sigma_authenticated = (0..n)
        .map(|i| auth_0[i].c * s[i] - auth_1[i].c - auth_0[i].b * rho_open[i])
        .collect::<Vec<_>>();
    let sigma_open = open_bedoza_values(io, &sigma_authenticated, comm);

    for (i, sigma) in sigma_open.iter().enumerate() {
        assert_eq!(*sigma, FE::zero(), "sacrifice check failed at index {i}");
    }

    auth_0.into_iter().map(|t| (t.a, t.b, t.c)).collect()
}

fn authenticate_triples_to_bedoza<IO: AbstractChannel>(
    io: &mut IO,
    triple_0: &[TripleShare],
    triple_1: &[TripleShare],
    auth_vole_sender: &mut BufferedVoleSender<FourQVoleMac>,
    auth_vole_receiver: &mut BufferedVoleReceiver<FourQVoleMac>,
    local_key: FE,
    local_side: bool,
    sender_first: bool,
) -> (Vec<AuthTripleShare>, Vec<AuthTripleShare>) {
    let n = triple_0.len();
    assert_eq!(n, triple_1.len(), "triple pair length mismatch");
    if n == 0 {
        return (vec![], vec![]);
    }

    let mut values = Vec::with_capacity(5 * n);
    for i in 0..n {
        values.push(triple_0[i].a);
        values.push(triple_0[i].b);
        values.push(triple_0[i].c);
        values.push(triple_1[i].a);
        values.push(triple_1[i].c);
    }

    let sender_owner_side = local_side;
    let receiver_owner_side = !local_side;

    let (sender_shares, receiver_shares): (Vec<BeDOZaSender>, Vec<BeDOZaReceiver>) = if sender_first
    {
        let sender = authenticate_batch_with_peer_key_sender(
            &values,
            sender_owner_side,
            auth_vole_sender,
            io,
        )
        .expect("failed to authenticate local values with VOLE sender");
        let receiver = authenticate_batch_with_peer_key_receiver(
            values.len(),
            receiver_owner_side,
            local_key,
            auth_vole_receiver,
            io,
        )
        .expect("failed to receive authenticated peer values with VOLE receiver");
        (sender, receiver)
    } else {
        let receiver = authenticate_batch_with_peer_key_receiver(
            values.len(),
            receiver_owner_side,
            local_key,
            auth_vole_receiver,
            io,
        )
        .expect("failed to receive authenticated peer values with VOLE receiver");
        let sender = authenticate_batch_with_peer_key_sender(
            &values,
            sender_owner_side,
            auth_vole_sender,
            io,
        )
        .expect("failed to authenticate local values with VOLE sender");
        (sender, receiver)
    };

    assert_eq!(
        sender_shares.len(),
        values.len(),
        "sender authentication length mismatch"
    );
    assert_eq!(
        receiver_shares.len(),
        values.len(),
        "receiver authentication length mismatch"
    );

    let authenticated = sender_shares
        .iter()
        .zip(receiver_shares.iter())
        .map(|(s, r)| BeDOZa::new(*s, *r))
        .collect::<Vec<_>>();

    let mut auth_0 = Vec::with_capacity(n);
    let mut auth_1 = Vec::with_capacity(n);
    for i in 0..n {
        let base = 5 * i;
        auth_0.push(AuthTripleShare {
            a: authenticated[base],
            b: authenticated[base + 1],
            c: authenticated[base + 2],
        });
        auth_1.push(AuthTripleShare {
            a: authenticated[base + 3],
            b: authenticated[base + 1],
            c: authenticated[base + 4],
        });
    }

    (auth_0, auth_1)
}

fn open_and_add<IO: AbstractChannel>(io: &mut IO, local: &[FE], comm: &mut u64) -> Vec<FE> {
    *comm += send_fe(io, local).expect("Failed to send opening share");
    let peer = receive_fe(io).expect("Failed to receive opening share");
    assert_eq!(peer.len(), local.len(), "opening length mismatch");

    local
        .iter()
        .zip(peer.iter())
        .map(|(&l, &r)| l + r)
        .collect()
}

fn open_bedoza_values<IO: AbstractChannel>(
    io: &mut IO,
    shares: &[BeDOZa],
    comm: &mut u64,
) -> Vec<FE> {
    if shares.is_empty() {
        return vec![];
    }

    // Send openings for local sender components.
    for share in shares {
        io.write_bytes(&share.bedoza_sender().val().to_bytes_le())
            .expect("failed to send opened sender value");
    }
    for share in shares {
        io.write_bytes(&share.bedoza_sender().pad().to_bytes_le())
            .expect("failed to send opened sender pad");
    }
    io.flush().expect("failed to flush opened sender shares");
    *comm += (shares.len() as u64) * 64;

    // Receive peer openings and verify with local receiver components.
    let key = shares[0].bedoza_receiver().key();
    for (i, share) in shares.iter().enumerate() {
        assert_eq!(
            share.bedoza_receiver().key(),
            key,
            "BeDOZa opening key mismatch at index {i}"
        );
    }

    let mut peer_values = Vec::with_capacity(shares.len());
    for _ in shares {
        let mut bytes = [0u8; 32];
        io.read_bytes(&mut bytes)
            .expect("failed to receive opened peer value");
        peer_values.push(FE::from_bytes_le(&bytes).expect("failed to parse opened peer value"));
    }

    let mut peer_pads = Vec::with_capacity(shares.len());
    for _ in shares {
        let mut bytes = [0u8; 32];
        io.read_bytes(&mut bytes)
            .expect("failed to receive opened peer pad");
        peer_pads.push(FE::from_bytes_le(&bytes).expect("failed to parse opened peer pad"));
    }

    for (i, ((&value, &pad), share)) in peer_values
        .iter()
        .zip(peer_pads.iter())
        .zip(shares.iter())
        .enumerate()
    {
        assert_eq!(
            key * value + pad,
            share.bedoza_receiver().tag(),
            "BeDOZa opening tag verification failed at index {i}"
        );
    }

    shares
        .iter()
        .zip(peer_values.iter())
        .map(|(share, &peer_value)| share.bedoza_sender().val() + peer_value)
        .collect()
}

fn u128_limbs_to_fe(value: &[u128; FE_LIMBS]) -> FE {
    let mut bytes = [0u8; 32];
    for (i, limb) in value.iter().enumerate() {
        let start = i * 16;
        bytes[start..start + 16].copy_from_slice(&limb.to_le_bytes());
    }
    FE::from_bytes_le(&bytes).expect("OT payload must be canonical FE")
}
