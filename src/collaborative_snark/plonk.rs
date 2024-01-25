use ark_ec::{*, pairing::*};
use ark_std::*;
use ark_std::borrow::*;
use ark_ff::Field;
use std::ops::*;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use ark_serialize::CanonicalSerialize;
use ark_bls12_377::Bls12_377;

use crate::utils;
use crate::record_commitment::*;
use super::kzg;

type Curve = ark_bls12_377::Bls12_377;
type KZG = kzg::KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;
type G2Affine = <Curve as Pairing>::G2Affine;

type ProverFnT = fn(
    &[DensePolynomial<F>],
    &[DensePolynomial<F>]
) -> (Vec<DensePolynomial<F>>, Vec<DensePolynomial<F>>);

type VerifierFnT = fn(
    &F, &PlonkProof
) -> Vec<F>;

pub struct PlonkProof {
    // commitments to input coins data structures
    pub input_coins_com: Vec<G1Affine>,
    // commitments to output coins data structures
    pub output_coins_com: Vec<G1Affine>,
    // commitment to quotient polynomial
    pub quotient_com: G1Affine,
    // commitments to additional polynomials
    pub additional_com: Vec<G1Affine>,

    // openings of input coin polyomials at r
    pub input_coins_opening: Vec<F>,
    // openings of output coin polyomials at r
    pub output_coins_opening: Vec<F>,
    // opening of quotient polynomial at r
    pub quotient_opening: F,
    // openings of additional polynomials at r
    pub additional_opening: Vec<F>,

    pub input_coins_opening_proof: Vec<G1Affine>,
    pub output_coins_opening_proof: Vec<G1Affine>,
    pub quotient_opening_proof: G1Affine,
    pub additional_opening_proof: Vec<G1Affine>,
}

pub fn plonk_prove<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    input_coins: &[JZRecord<N>],
    output_coins: &[JZRecord<N>],
    prover_fn: ProverFnT
) -> PlonkProof {
    let kzg_crs = kzg_crs(crs);

    let input_coins_poly = input_coins
        .iter()
        .map(|x| record_poly::<N>(x))
        .collect::<Vec<DensePolynomial<F>>>();

    let output_coins_poly = output_coins
        .iter()
        .map(|x| record_poly::<N>(x))
        .collect::<Vec<DensePolynomial<F>>>();

    // compute the commitments
    let input_coins_com = input_coins_poly
        .iter()
        .map(|f| KZG::commit_g1(&kzg_crs, f).unwrap())
        .collect::<Vec<G1Affine>>();

    let output_coins_com = output_coins_poly
        .iter()
        .map(|f| KZG::commit_g1(&kzg_crs, f).unwrap())
        .collect::<Vec<G1Affine>>();

    // alpha = H(f,g,h)
    let mut ro_inputs = Vec::new();
    ro_inputs.extend_from_slice(input_coins_com.as_slice());
    ro_inputs.extend_from_slice(output_coins_com.as_slice());
    let alpha = random_oracle(ro_inputs.as_slice());

    //first Z(x)
    let z_poly: DensePolynomial<F> = utils::compute_vanishing_poly(N);

    let (lhs_polynomials, additional_polynomials) = 
        prover_fn(&input_coins_poly[..], &output_coins_poly[..]);

    // random linear combination of the above
    let mut lhs_poly = utils::compute_constant_poly(&F::zero());//DensePolynomial::<F>::zero();
    for (i, poly) in lhs_polynomials.iter().enumerate() {
        lhs_poly.add_assign(
            &utils::poly_eval_mult_const(poly, &alpha.pow([i as u64]))
        );
    }

    let quotient_poly = lhs_poly.div(&z_poly);

    let quotient_com = KZG::commit_g1(&kzg_crs, &quotient_poly).unwrap();

    // r = H(f,g,h,q)
    let mut ro_inputs = Vec::new();
    ro_inputs.extend_from_slice(input_coins_com.as_slice());
    ro_inputs.extend_from_slice(output_coins_com.as_slice());
    ro_inputs.push(quotient_com);
    let r = random_oracle(ro_inputs.as_slice());
    
    PlonkProof {
        input_coins_com,
        output_coins_com,
        quotient_com,
        additional_com: additional_polynomials
            .iter()
            .map(|f| KZG::commit_g1(&kzg_crs, f).unwrap())
            .collect::<Vec<G1Affine>>(),




        input_coins_opening: input_coins_poly
            .iter()
            .map(|f| f.evaluate(&r))
            .collect::<Vec<F>>(),

        output_coins_opening: output_coins_poly
            .iter()
            .map(|f| f.evaluate(&r))
            .collect::<Vec<F>>(),

        quotient_opening: quotient_poly.evaluate(&r),

        additional_opening: additional_polynomials
            .iter()
            .map(|f| f.evaluate(&r))
            .collect::<Vec<F>>(),




        input_coins_opening_proof: input_coins_poly
            .iter()
            .map(|f| KZG::compute_opening_proof(&kzg_crs, f, &r).unwrap())
            .collect::<Vec<G1Affine>>(),

        output_coins_opening_proof: output_coins_poly
            .iter()
            .map(|f| KZG::compute_opening_proof(&kzg_crs, f, &r).unwrap())
            .collect::<Vec<G1Affine>>(),

        quotient_opening_proof: 
            KZG::compute_opening_proof(&kzg_crs, &quotient_poly, &r).unwrap(),

        additional_opening_proof: additional_polynomials
            .iter()
            .map(|f| KZG::compute_opening_proof(&kzg_crs, f, &r).unwrap())
            .collect::<Vec<G1Affine>>(),

    }

}

pub fn plonk_verify<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    proof: &PlonkProof,
    verify_fn: VerifierFnT
) {
    let mut ro_inputs = Vec::new();
    ro_inputs.extend_from_slice(proof.input_coins_com.as_slice());
    ro_inputs.extend_from_slice(proof.output_coins_com.as_slice());

    let alpha = random_oracle(ro_inputs.as_slice());

    ro_inputs.push(proof.quotient_com);

    let r = random_oracle(ro_inputs.as_slice());

    let kzg_crs = kzg_crs(crs);

    for i in 0..proof.input_coins_com.len() {
        assert!(
            KZG::check(
                &kzg_crs,
                &proof.input_coins_com[i],
                r,
                proof.input_coins_opening[i],
                &proof.input_coins_opening_proof[i]
            )
        );
    }

    for i in 0..proof.output_coins_com.len() {
        assert!(
            KZG::check(
                &kzg_crs,
                &proof.output_coins_com[i],
                r,
                proof.output_coins_opening[i],
                &proof.output_coins_opening_proof[i]
            )
        );
    }

    for i in 0..proof.additional_com.len() {
        assert!(
            KZG::check(
                &kzg_crs,
                &proof.additional_com[i],
                r,
                proof.additional_opening[i],
                &proof.additional_opening_proof[i]
            )
        );
    }

    assert!(
        KZG::check(
            &kzg_crs,
            &proof.quotient_com,
            r,
            proof.quotient_opening,
            &proof.quotient_opening_proof
        )
    );
    
    let lhs_evals = verify_fn(&r, &proof);

    let mut lhs = F::zero();
    for (i, eval) in lhs_evals.iter().enumerate() {
        let f = alpha.pow([i as u64]) * eval;
        lhs.add_assign(&f);
    }

    let z_poly: DensePolynomial<F> = utils::compute_vanishing_poly(N);
    let rhs = proof.quotient_opening * z_poly.evaluate(&r);

    assert_eq!(lhs, rhs);
    
}

fn kzg_crs<const N: usize>(
    crs: &JZKZGCommitmentParams<N>
) -> kzg::UniversalParams<Bls12_377> {

    kzg::UniversalParams::<Bls12_377> {
        powers_of_g: crs.crs_coefficient_g1
            .to_owned()
            .iter()
            .map(|x| x.into_affine())
            .collect(),
        powers_of_h: crs.crs_coefficient_g2
            .to_owned()
            .iter()
            .map(|x| x.into_affine())
            .collect(),
    }

}

fn record_poly<const N: usize>(record: &JZRecord<N>) -> DensePolynomial<F> {    
    //powers of nth root of unity
    let domain = Radix2EvaluationDomain::<F>::new(N).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(record.fields().to_vec(), domain);
    //interpolated polynomial over the n points
    eval_form.interpolate()
}

fn random_oracle(
    commitments: &[G1Affine],
) -> F {
    let mut serialized_elements = Vec::new();
    for com in commitments {
        let mut serialized_data = Vec::new();
        com.serialize_uncompressed(&mut serialized_data).unwrap();

        serialized_elements.push(serialized_data);
    }

    utils::fs_hash(&serialized_elements, 1)[0]
}
