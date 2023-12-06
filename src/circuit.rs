use bellpepper_core::{SynthesisError, ConstraintSystem};
use bellpepper_ed25519::circuit::AllocatedAffinePoint;
use ff::{PrimeField, PrimeFieldBits};
use bellpepper_core::boolean::Boolean;

pub fn verify_circuit<F, CS>(
    cs: &mut CS,
    g: AllocatedAffinePoint<F>,
    pubkey: AllocatedAffinePoint<F>,
    h: Vec<Boolean>,
    sign: (AllocatedAffinePoint<F>, Vec<Boolean>)
) -> Result<(), SynthesisError> 
where
    F: PrimeField<Repr = [u8; 32]> + PrimeFieldBits,
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