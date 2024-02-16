use ark_crypto_primitives::crh::{pedersen, CRHSchemeGadget};
//use ark_ed_on_bls12_377::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
use ark_ed_on_bw6_761::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
#[allow(unused)]
use ark_r1cs_std::prelude::*;
#[allow(unused)]
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_std::borrow::*;
use ark_relations::r1cs::*;
use ark_r1cs_std::{bits::uint8::UInt8, bits::ToBytesGadget, alloc::AllocVar};


use super::*;

type HG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;
//type PRFArgumentVar<ConstraintF> = [UInt8<ConstraintF>];

type ConstraintF = Fq;

pub struct JZPRFParamsVar {
    pub crh_params_var: <HG as CRHSchemeGadget<H, ConstraintF>>::ParametersVar,
}

impl AllocVar<JZPRFParams, ConstraintF> for JZPRFParamsVar {
    fn new_variable<T: Borrow<JZPRFParams>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            let crh_params_var =
                <HG as CRHSchemeGadget<H, _>>::ParametersVar::
                new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().crh_params),
                    mode,
                )?;

            Ok( JZPRFParamsVar { crh_params_var } )
        })
    }
}

pub struct JZPRFInstanceVar {
    pub input_var: Vec<UInt8<ConstraintF>>,
    pub key_var: Vec<UInt8<ConstraintF>>,
    pub output_var: Vec<UInt8<ConstraintF>>,
}

impl AllocVar<JZPRFInstance, ConstraintF> for JZPRFInstanceVar {
    fn new_variable<T: Borrow<JZPRFInstance>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            let prf_instance: &JZPRFInstance = val.borrow();

            let mut input_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            for byte in prf_instance.input.iter() {
                input_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            let mut key_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            for byte in prf_instance.key.iter() {
                key_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            let mut output_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            let prf_output = prf_instance.evaluate();

            for byte in prf_output.iter() {
                output_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            Ok(
                JZPRFInstanceVar {
                    input_var: input_byte_vars,
                    key_var: key_byte_vars,
                    output_var: output_byte_vars,
                }
            )
        })
    }
}


pub fn generate_constraints(
    _cs: ConstraintSystemRef<ConstraintF>,
    params: &JZPRFParamsVar,
    prf_instance: &JZPRFInstanceVar,
) {

    let mut input = vec![];
    input.extend_from_slice(&prf_instance.input_var);
    input.extend_from_slice(&prf_instance.key_var);

    let crh_output_var = HG::evaluate(
        &params.crh_params_var,
        &input
    ).unwrap();

    let len = prf_instance.output_var.len();

    let crh_output_var_bytes = crh_output_var.x.to_bytes().unwrap();

    for (i, byte_var) in crh_output_var_bytes[0..len].iter().enumerate() {
        byte_var.enforce_equal(&prf_instance.output_var[i]).unwrap();
    }
}
