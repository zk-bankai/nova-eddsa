use bellpepper_ed25519::curve::AffinePoint;
use bellpepper_ed25519::curve::Ed25519Curve;
use num_bigint::BigUint;
use rand::RngCore;
use std::ops::Rem;

pub fn sign(h: &BigUint, private_key: &BigUint) -> (AffinePoint, BigUint) {
    let q: BigUint = BigUint::parse_bytes(
        b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        16,
    )
    .unwrap();

    let g = Ed25519Curve::basepoint();

    let mut scalar_bytes: [u8; 32] = [0; 32];
    rand::thread_rng().fill_bytes(&mut scalar_bytes);
    let scalar = BigUint::from_bytes_le(scalar_bytes.as_ref()).rem(q.clone());

    let r = Ed25519Curve::scalar_multiplication(&g, &scalar);

    let s = &(scalar + &(h * private_key).rem(q.clone())).rem(q.clone());

    (r, s.clone())
}

pub fn verify(h: &BigUint, pub_key: &AffinePoint, r: &AffinePoint, s: &BigUint) -> bool {
    let g = Ed25519Curve::basepoint();

    let p1 = Ed25519Curve::scalar_multiplication(&g, s);

    let h_pubkey = Ed25519Curve::scalar_multiplication(pub_key, h);
    let p2 = Ed25519Curve::add_points(&h_pubkey, r);

    Ed25519Curve::check_equality(&p1, &p2)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify() {
        let q: BigUint = BigUint::parse_bytes(
            b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16,
        )
        .unwrap();
        let g = Ed25519Curve::basepoint();

        for _ in 0..20 {
            let mut h_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut h_bytes);
            let h = BigUint::from_bytes_le(h_bytes.as_ref()).rem(q.clone());

            let mut priv_key_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut priv_key_bytes);
            let priv_key = BigUint::from_bytes_le(priv_key_bytes.as_ref()).rem(q.clone());

            let pub_key = Ed25519Curve::scalar_multiplication(&g, &priv_key);

            let (r, s) = sign(&h, &priv_key);

            let veri_sig = verify(&h, &pub_key, &r, &s);
            assert!(veri_sig)
        }
    }

    #[test]
    fn test_msg() {
        let q: BigUint = BigUint::parse_bytes(
            b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16,
        )
        .unwrap();
        let g = Ed25519Curve::basepoint();

        for _ in 0..20 {
            let mut h_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut h_bytes);
            let h = BigUint::from_bytes_le(h_bytes.as_ref()).rem(q.clone());

            let mut priv_key_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut priv_key_bytes);
            let priv_key = BigUint::from_bytes_le(priv_key_bytes.as_ref()).rem(q.clone());

            let pub_key = Ed25519Curve::scalar_multiplication(&g, &priv_key);

            let (r, s) = sign(&h, &priv_key);

            let mut wrong_h_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_h_bytes);
            let wrong_h = BigUint::from_bytes_le(wrong_h_bytes.as_ref()).rem(q.clone());

            let veri_sig = verify(&wrong_h, &pub_key, &r, &s);
            assert!(!veri_sig)
        }
    }

    #[test]
    fn test_key() {
        let q: BigUint = BigUint::parse_bytes(
            b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16,
        )
        .unwrap();
        let g = Ed25519Curve::basepoint();

        for _ in 0..20 {
            let mut h_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut h_bytes);
            let h = BigUint::from_bytes_le(h_bytes.as_ref()).rem(q.clone());

            let mut priv_key_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut priv_key_bytes);
            let priv_key = BigUint::from_bytes_le(priv_key_bytes.as_ref()).rem(q.clone());

            let (r, s) = sign(&h, &priv_key);

            let mut wrong_key_scalar_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_key_scalar_bytes);
            let wrong_key_scalar =
                BigUint::from_bytes_le(wrong_key_scalar_bytes.as_ref()).rem(q.clone());
            let wrong_key = Ed25519Curve::scalar_multiplication(&g, &wrong_key_scalar);
            assert!(Ed25519Curve::is_on_curve(&wrong_key));

            let veri_sig = verify(&h, &wrong_key, &r, &s);
            assert!(!veri_sig)
        }
    }

    #[test]
    fn test_sign_r() {
        let q: BigUint = BigUint::parse_bytes(
            b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16,
        )
        .unwrap();
        let g = Ed25519Curve::basepoint();

        for _ in 0..20 {
            let mut h_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut h_bytes);
            let h = BigUint::from_bytes_le(h_bytes.as_ref()).rem(q.clone());

            let mut priv_key_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut priv_key_bytes);
            let priv_key = BigUint::from_bytes_le(priv_key_bytes.as_ref()).rem(q.clone());

            let pub_key = Ed25519Curve::scalar_multiplication(&g, &priv_key);

            let (_, s) = sign(&h, &priv_key);

            let mut wrong_r_scalar_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_r_scalar_bytes);
            let wrong_r_scalar =
                BigUint::from_bytes_le(wrong_r_scalar_bytes.as_ref()).rem(q.clone());
            let wrong_r = Ed25519Curve::scalar_multiplication(&g, &wrong_r_scalar);
            assert!(Ed25519Curve::is_on_curve(&wrong_r));

            let veri_sig = verify(&h, &pub_key, &wrong_r, &s);
            assert!(!veri_sig)
        }
    }

    #[test]
    fn test_sign_s() {
        let q: BigUint = BigUint::parse_bytes(
            b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16,
        )
        .unwrap();
        let g = Ed25519Curve::basepoint();

        for _ in 0..20 {
            let mut h_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut h_bytes);
            let h = BigUint::from_bytes_le(h_bytes.as_ref()).rem(q.clone());

            let mut priv_key_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut priv_key_bytes);
            let priv_key = BigUint::from_bytes_le(priv_key_bytes.as_ref()).rem(q.clone());

            let pub_key = Ed25519Curve::scalar_multiplication(&g, &priv_key);

            let (r, _) = sign(&h, &priv_key);

            let mut wrong_s_bytes: [u8; 32] = [0; 32];
            rand::thread_rng().fill_bytes(&mut wrong_s_bytes);
            let wrong_s = BigUint::from_bytes_le(wrong_s_bytes.as_ref()).rem(q.clone());

            let veri_sig = verify(&h, &pub_key, &r, &wrong_s);
            assert!(!veri_sig)
        }
    }
}
