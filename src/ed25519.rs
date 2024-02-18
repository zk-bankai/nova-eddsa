#![allow(non_snake_case)]

use bellpepper_ed25519::curve::AffinePoint;
use bellpepper_ed25519::curve::Ed25519Curve;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::ops::Rem;

pub fn keygen() -> ((BigUint, [u8; 32]), AffinePoint) {
    let q = Ed25519Curve::order();

    let mut secret: [u8; 32] = [0; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    let hash = Sha512::default().chain_update(secret).finalize();

    let mut scalar_bytes: [u8; 32] = [0u8; 32];
    let mut hash_prefix: [u8; 32] = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[00..32]);
    hash_prefix.copy_from_slice(&hash[32..64]);

    let private_key = BigUint::from_bytes_be(&clamp_integer(scalar_bytes)).rem(q.clone());

    let G = Ed25519Curve::basepoint();
    let P = Ed25519Curve::scalar_multiplication(&G, &private_key);

    ((private_key, hash_prefix), P)
}

pub fn sign(msg: [u8; 32]) -> ((AffinePoint, BigUint), AffinePoint) {
    let q = Ed25519Curve::order();
    let G = Ed25519Curve::basepoint();

    // Generate private_key, hash_prefix and public key P
    let ((private_key, hash_prefix), P) = keygen();

    // Compute r = hash(hash_prefix || msg) mod q
    let mut input = Vec::new();
    input.extend(hash_prefix);
    input.extend(msg);
    let r_hash = Sha512::default().chain_update(input).finalize();
    let r = BigUint::from_bytes_be(&r_hash).rem(q.clone());

    // Compute R = r * G
    let R = Ed25519Curve::scalar_multiplication(&G, &r);

    // Compute h = hash(R || P || msg) mod q
    input = Vec::new();
    input.extend(compress(R.clone()));
    input.extend(compress(P.clone()));
    input.extend(msg);
    assert_eq!(input.len(), 96);
    let mut hash = Sha512::new();
    hash.update(&input);
    let hash_result = hash.finalize();
    let h = BigUint::from_bytes_be(&hash_result).rem(q.clone());

    // Compute s = (r + h * private_key) mod q
    let s = &(r + &(h * private_key).rem(q.clone())).rem(q.clone());

    ((R, s.clone()), P)
}

pub fn verify(msg: [u8; 32], P: AffinePoint, R: AffinePoint, s: BigUint) -> bool {
    let q = Ed25519Curve::order();
    let G = Ed25519Curve::basepoint();

    // Compute h = hash(R || P || msg) mod q
    let mut input = Vec::new();
    input.extend(compress(R.clone()));
    input.extend(compress(P.clone()));
    input.extend(msg);
    assert_eq!(input.len(), 96);
    let mut hash = Sha512::new();
    hash.update(&input);
    let hash_result = hash.finalize();
    let h = BigUint::from_bytes_be(&hash_result).rem(q);

    // P1 = s * G
    let P1 = Ed25519Curve::scalar_multiplication(&G, &s);

    // P2 = R + h * P
    let h_pubkey = Ed25519Curve::scalar_multiplication(&P, &h);
    let P2 = Ed25519Curve::add_points(&h_pubkey, &R);

    // P1 == P2
    Ed25519Curve::check_equality(&P1, &P2)
}

pub fn compress(point: AffinePoint) -> [u8; 32] {
    let x_le_bytes = point.x.to_bytes_le();
    let y_le_bytes = point.y.to_bytes_le();

    let x_is_neg = x_le_bytes[0] & 1;
    let mut s: [u8; 32];
    s = y_le_bytes;
    s[31] ^= x_is_neg << 7;
    s
}

pub fn clamp_integer(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0111_1111;
    bytes[31] |= 0b0100_0000;
    bytes
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify() {
        for _ in 0..20 {
            let mut msg: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut msg);

            let ((R, s), P) = sign(msg);

            let veri_sig = verify(msg, P, R, s);
            assert!(veri_sig)
        }
    }

    #[test]
    fn test_msg() {
        for _ in 0..20 {
            let mut msg: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut msg);

            let ((R, s), P) = sign(msg);

            let mut wrong_msg: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_msg);

            let veri_sig = verify(wrong_msg, P, R, s);
            assert!(!veri_sig)
        }
    }

    #[test]
    fn test_key() {
        let q = Ed25519Curve::order();

        let G = Ed25519Curve::basepoint();

        for _ in 0..20 {
            let mut msg: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut msg);

            let ((R, s), _) = sign(msg);

            let mut wrong_key_scalar_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_key_scalar_bytes);
            let wrong_key_scalar =
                BigUint::from_bytes_le(wrong_key_scalar_bytes.as_ref()).rem(q.clone());
            let wrong_P = Ed25519Curve::scalar_multiplication(&G, &wrong_key_scalar);
            assert!(Ed25519Curve::is_on_curve(&wrong_P));

            let veri_sig = verify(msg, wrong_P, R, s);
            assert!(!veri_sig)
        }
    }

    #[test]
    fn test_sign_r() {
        let q = Ed25519Curve::order();

        let G = Ed25519Curve::basepoint();

        for _ in 0..20 {
            let mut msg: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut msg);

            let ((_, s), P) = sign(msg);

            let mut wrong_r_scalar_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_r_scalar_bytes);
            let wrong_r_scalar =
                BigUint::from_bytes_le(wrong_r_scalar_bytes.as_ref()).rem(q.clone());
            let wrong_R = Ed25519Curve::scalar_multiplication(&G, &wrong_r_scalar);
            assert!(Ed25519Curve::is_on_curve(&wrong_R));

            let veri_sig = verify(msg, P, wrong_R, s);
            assert!(!veri_sig)
        }
    }

    #[test]
    fn test_sign_s() {
        let q = Ed25519Curve::order();

        for _ in 0..20 {
            let mut msg: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut msg);

            let ((R, _), P) = sign(msg);

            let mut wrong_s_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_s_bytes);
            let wrong_s = BigUint::from_bytes_le(wrong_s_bytes.as_ref()).rem(q.clone());

            let veri_sig = verify(msg, P, R, wrong_s);
            assert!(!veri_sig)
        }
    }
}
