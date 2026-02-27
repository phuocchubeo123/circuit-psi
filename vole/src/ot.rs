use psi_aes::hash::Hash;
use crate::comm_channel::CommunicationChannel;
use p256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use p256::elliptic_curve::{Field, Group}; 
use p256::{Scalar, AffinePoint, ProjectivePoint};

pub struct OTCO {
}

impl OTCO {
    pub fn new() -> Self {
        Self { }
    }

    /// Sender's OT implementation
    pub fn send<IO: CommunicationChannel>(&mut self, io: &mut IO, data0: &[[u8; 16]], data1: &[[u8; 16]], comm: &mut u64) {
        let length = data0.len();
        let mut rng = rand::thread_rng();

        // Generate random scalar `a`
        let a = Scalar::random(&mut rng);

        // Compute A = G * a (G is the generator of the curve)
        let A = ProjectivePoint::generator() * a;
        let A_affine = AffinePoint::from(A);

        // Send A to the receiver
        let A_encoded = A_affine.to_encoded_point(false);
        *comm += io.send_point(&A_encoded).expect("Cannot send encoded A in OTCO");

        // Compute (A * a)^-1
        let mut A_a_inverse = A * a;
        A_a_inverse = A_a_inverse.neg();

        let mut B_points = vec![ProjectivePoint::identity(); length];
        let mut BA_points = vec![ProjectivePoint::identity(); length];

        // Receive B points and compute BA points
        for i in 0..length {
            let b_point = io.receive_point().expect("Cannot receive b_point");
            let b_affine = AffinePoint::from_encoded_point(&b_point).unwrap();
                // .expect("Failed to decode AffinePoint from EncodedPoint");
            let B_projective = ProjectivePoint::from(b_affine);

            // Compute B[i] * a
            let B_a = B_projective * a;
            B_points[i] = B_a;

            // Compute BA[i] = B[i] + (A * a)^-1
            BA_points[i] = B_a + A_a_inverse;
        }

        io.flush();

        // Encrypt and send the data
        for i in 0..length {
            let key_b = Hash::kdf(
                &B_points[i].to_affine().to_encoded_point(false).as_bytes(),
                i as u64,
            );
            let key_ba = Hash::kdf(
                &BA_points[i].to_affine().to_encoded_point(false).as_bytes(),
                i as u64,
            );

            let encrypted0 = xor_blocks(&data0[i], &key_b);
            let encrypted1 = xor_blocks(&data1[i], &key_ba);

            *comm += io.send_block::<16>(&[encrypted0, encrypted1]).expect("Cannot send encrypted data in OTCO sender.");
        }
    }

    /// Receiver's OT implementation
    pub fn recv<IO: CommunicationChannel>(&mut self, io: &mut IO, choices: &[bool], output: &mut Vec<[u8; 16]>, comm: &mut u64) {
        let length = choices.len();
        let mut rng = rand::thread_rng();

        // Generate random scalars `b`
        let b_scalars: Vec<Scalar> = (0..length).map(|_| Scalar::random(&mut rng)).collect();

        let A_encoded = io.receive_point().expect("Cannot receive encoded A");
        let A_affine = AffinePoint::from_encoded_point(&A_encoded).unwrap();
            // .expect("Invalid A point received");
        let A_projective = ProjectivePoint::from(A_affine);

        // Compute and send B points
        for (i, &choice) in choices.iter().enumerate() {
            let mut B_projective = ProjectivePoint::generator() * b_scalars[i];

            // If the choice is true, add A to B[i]
            if choice {
                B_projective += A_projective;
            }

            let B_encoded = B_projective.to_affine().to_encoded_point(false);
            *comm += io.send_point(&B_encoded).expect("Cannot send B encoded");
        }

        io.flush();

        // Compute shared points and decrypt data
        for i in 0..length {
            let B_a = A_projective * b_scalars[i];
            let key_as = Hash::kdf(
                &B_a.to_affine().to_encoded_point(false).as_bytes(),
                i as u64,
            );

            let encrypted = io.receive_block::<16>().expect("Cannot receive encrypted data from sender");
            output.push(if choices[i] {
                xor_blocks(&encrypted[1], &key_as)
            } else {
                xor_blocks(&encrypted[0], &key_as)
            });
        }
    }
}

/// XOR two 128-bit blocks
fn xor_blocks(block1: &[u8; 16], block2: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = block1[i] ^ block2[i];
    }
    result
}
