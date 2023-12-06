use std::marker::PhantomData;
use bellpepper_core::{SynthesisError, ConstraintSystem};
use bellpepper::gadgets::num::AllocatedNum;
use bellpepper_ed25519::{circuit::AllocatedAffinePoint, curve::Ed25519Curve};
use bellpepper_ed25519::curve::AffinePoint;
use ff::{PrimeField, PrimeFieldBits};
use bellpepper_core::boolean::Boolean;
use nova_snark::traits::circuit::StepCircuit;

pub fn verify_circuit<F, CS>(
    cs: &mut CS,
    g: AllocatedAffinePoint<F>,
    pubkey: AllocatedAffinePoint<F>,
    h: Vec<Boolean>,
    sign: (AllocatedAffinePoint<F>, Vec<Boolean>)
) -> Result<(), SynthesisError> 
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    let p1 = g.ed25519_scalar_multiplication(
        &mut cs.namespace(|| "P1 = s * G"), 
        sign.1,
    )?;

    let h_mult_pk = pubkey.ed25519_scalar_multiplication(
        &mut cs.namespace(|| "h * pubkey"), 
        h
    )?;

    let p2 = AllocatedAffinePoint::ed25519_point_addition(
        &mut cs.namespace(|| "R + h * pubkey"), 
        &sign.0, 
        &h_mult_pk
    )?;

    let _ = AllocatedAffinePoint::assert_equality(
        &mut cs.namespace(|| "p1 == p2"), 
        &p1, 
        &p2
    );

    Ok(())
}

#[derive(Clone, Debug)]
pub struct SigIter<F>
where
    F: PrimeField + PrimeFieldBits
{
    pubkey: AffinePoint,
    h: Vec<bool>,
    sign: (AffinePoint, Vec<bool>),
    _phantom: PhantomData<F>
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for SigIter<F> {
    fn arity(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<F>>
    (
        &self,
        cs: &mut CS,
        _z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> 
    {
        let g = Ed25519Curve::basepoint();
        let g_al = AllocatedAffinePoint::alloc_affine_point(
            &mut cs.namespace(|| "alloc base point"), 
            &g
        )?;

        let pubkey_al = AllocatedAffinePoint::alloc_affine_point(
            &mut cs.namespace(|| "alloc pubkey"), 
            &self.pubkey
        )?;

        let h_al: Vec<Boolean> = self.h.clone().into_iter().map(|i| Boolean::constant(i != false)).collect();
        assert_eq!(h_al.len(), 253);

        let r_al = AllocatedAffinePoint::alloc_affine_point(
            &mut cs.namespace(|| "alloc r"), 
            &self.sign.0
        )?;

        let s_al: Vec<Boolean> = self.sign.1.clone().into_iter().map(|i| Boolean::constant(i != false)).collect();
        assert_eq!(s_al.len(), 253);

        verify_circuit(
            &mut cs.namespace(|| "verify signature"), 
            g_al, 
            pubkey_al, 
            h_al, 
            (r_al, s_al)
        )?;

        Ok(vec![])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ops::Rem;
    use pasta_curves::Fp;
    use num_bigint::BigUint;
    use rand::RngCore; 
    use bellpepper_core::test_cs::TestConstraintSystem;
    use bellpepper_ed25519::curve::Ed25519Curve;
    use crate::ed25519::{sign, verify};

    #[test]
    fn test_step_circuit() {
        let q: BigUint = BigUint::parse_bytes(
            b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            16
        ).unwrap();
        let g = Ed25519Curve::basepoint();

        let mut h_bytes: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut h_bytes);
        let h = BigUint::from_bytes_le(h_bytes.as_ref()).rem(q.clone());

        let mut priv_key_bytes: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut priv_key_bytes);
        let priv_key = BigUint::from_bytes_le(priv_key_bytes.as_ref()).rem(q.clone());

        let pub_key = Ed25519Curve::scalar_multiplication(&g, &priv_key);

        let (r, s) = sign(&h, &priv_key);
        
        let veri_sig = verify(&h, &pub_key, &r, &s);
        assert!(veri_sig);

        let mut h_vec = h.to_radix_le(2);
        h_vec.resize(253, 0u8);
        let h_bits: Vec<bool> = h_vec.into_iter().map(|i| i != 0).collect();
        assert_eq!(h_bits.len(), 253);

        let mut s_vec = s.to_radix_le(2);
        s_vec.resize(253, 0u8);
        let s_bits: Vec<bool> = s_vec.into_iter().map(|i| i != 0).collect();
        assert_eq!(s_bits.len(), 253);

        let step = SigIter {
            pubkey: pub_key,
            h: h_bits,
            sign: (r, s_bits),
            _phantom: PhantomData
        };

        let mut cs = TestConstraintSystem::<Fp>::new();

        let _ = step.synthesize(
            &mut cs.namespace(|| "call synth"), 
            &[]
        );

        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 1436175);
        assert_eq!(cs.num_inputs(), 1);
    }
}