use ark_ff::*;
use ark_relations::r1cs::*;
use ark_r1cs_std::{alloc::AllocVar, *};
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_std::{borrow::*, *};
use std::ops::AddAssign;
use ark_bls12_377::constraints::G1Var;

use super::{JZRecord, JZKZGCommitmentParams};

type ConstraintF = ark_bls12_377::Fq;

pub struct JZKZGCommitmentParamsVar<const N: usize> {
    pub crs: Vec<G1Var>,
}

pub struct JZRecordVar<const N: usize> {
    pub fields: [Vec<UInt8<ConstraintF>>; N],
    pub blind: Vec<UInt8<ConstraintF>>,
    pub commitment: G1Var,
    pub blinded_commitment: G1Var
}

impl<const N: usize> AllocVar<JZKZGCommitmentParams<N>, ConstraintF> for JZKZGCommitmentParamsVar<N> {
    fn new_variable<T: Borrow<JZKZGCommitmentParams<N>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            let crs: &Vec<ark_bls12_377::G1Projective> = &val.borrow().crs_lagrange;
            let mut crs_vars: Vec<G1Var> = vec![];
            for i in 0..N {
                let crs_i = G1Var::new_variable(
                    cs.clone(),
                    || Ok(crs[i]),
                    mode)?;

                crs_vars.push(crs_i);
            }

            Ok(JZKZGCommitmentParamsVar {
                crs: crs_vars
            })
        })
    }
}

impl<const N: usize> AllocVar<JZRecord<N>, ConstraintF> for JZRecordVar<N> {
    fn new_variable<T: Borrow<JZRecord<N>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            let fields: &[Vec<u8>; N] = &val.borrow().fields;
            let mut constraint_fields: Vec<Vec<UInt8<ConstraintF>>> = vec![];
            for i in 0..N {
                let mut field_byte_vars = Vec::<UInt8<ConstraintF>>::new();
                let field_bytes: &Vec<u8> = &fields[i];

                for byte in field_bytes {
                    field_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                        cs.clone(),
                        || Ok(byte),
                        mode,
                    )?);
                }

                constraint_fields.push(field_byte_vars);
            }

            let mut blind_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            for byte in &val.borrow().blind {
                blind_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            let computed_kzg_com: ark_bls12_377::G1Projective = 
                val.borrow().commitment();

            let kzg_com_var = G1Var::new_variable(
                cs.clone(),
                || Ok(computed_kzg_com),
                mode
            )?;

            let computed_blinded_kzg_com: ark_bls12_377::G1Projective = 
                val.borrow().blinded_commitment();

            let kzg_blinded_com_var = G1Var::new_variable(
                cs.clone(),
                || Ok(computed_blinded_kzg_com),
                mode
            )?;

            Ok(
                JZRecordVar {
                    fields: constraint_fields.try_into().unwrap(),
                    blind: blind_byte_vars,
                    commitment: kzg_com_var,
                    blinded_commitment: kzg_blinded_com_var
                }
            )
        })
    }
}

pub fn generate_constraints<const N: usize>(
    cs: ConstraintSystemRef<ConstraintF>,
    params: &JZKZGCommitmentParamsVar<N>,
    record: &JZRecordVar<N>
) -> Result<()> {

    let mut aggregate_var = G1Var::new_witness(
        ark_relations::ns!(cs, "aggregate_pk"), 
        || Ok(ark_bls12_377::G1Projective::zero())
    )?;

    for i in 0..N {        
        let crs_i: &G1Var = &params.crs[i];
        let elem_i: &Vec<UInt8<ConstraintF>> = &record.fields[i];

        let crs_i_pow_elem_i: G1Var = crs_i.scalar_mul_le(
            elem_i.to_bits_le()?.iter())?;

        aggregate_var.add_assign(crs_i_pow_elem_i);
    }

    record.commitment.enforce_equal(&aggregate_var)?;

    //blinded commitment constraints
    let crs_0 = &params.crs[0];
    let crs_0_pow_blind: G1Var = crs_0.scalar_mul_le(
        record.blind.to_bits_le()?.iter())?;
    
    aggregate_var.add_assign(crs_0_pow_blind);

    record.blinded_commitment.enforce_equal(&aggregate_var)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use rand::RngCore;

    #[test]
    fn test_kzg_com() {
        let mut rng = test_rng();
        let crs = JZKZGCommitmentParams::<4>::trusted_setup(&mut rng);

        let mut entropy = [0u8; 24];
        rng.fill_bytes(&mut entropy);

        let records: [Vec<u8>; 4] = 
            [
                vec![20u8, 30u8],
                vec![
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    254u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    253u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                ],
                vec![
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                ],
                vec![40u8, 50u8, 60u8, 70u8]
            ];

        let coin = JZRecord::<4>::new(&crs, &records, &entropy.to_vec());

        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let crs_var = JZKZGCommitmentParamsVar::<4>::new_constant(cs.clone(), crs).unwrap();
        let coin_var = JZRecordVar::<4>::new_witness(cs.clone(), || Ok(coin)).unwrap();

        generate_constraints(cs.clone(), &crs_var, &coin_var).unwrap();
        assert!(cs.is_satisfied().unwrap(), "constraints not satisfied");
    }
}