use ark_std::*;
use ark_ff::Field;
use std::ops::*;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial,
};

use crate::utils;
use crate::record_commitment::*;
use crate::coin::*;
use super::plonk_utils;
use super::{ProverFnT, VerifierFnT, PlonkProof, KZG, F, G1Affine};

pub fn plonk_prove<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    input_coins: &[Coin<F>],
    output_coins: &[Coin<F>],
    prover_fn: ProverFnT
) -> PlonkProof {
    let kzg_crs = plonk_utils::kzg_crs(crs);

    let input_coins_poly = input_coins
        .iter()
        .map(|coin| plonk_utils::coin_poly::<N>(coin))
        .collect::<Vec<DensePolynomial<F>>>();

    let output_coins_poly = output_coins
        .iter()
        .map(|coin| plonk_utils::coin_poly::<N>(coin))
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
    let alpha = plonk_utils::random_oracle(ro_inputs.as_slice());

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
    let r = plonk_utils::random_oracle(ro_inputs.as_slice());
    
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

    let alpha = plonk_utils::random_oracle(ro_inputs.as_slice());

    ro_inputs.push(proof.quotient_com);

    let r = plonk_utils::random_oracle(ro_inputs.as_slice());

    let kzg_crs = plonk_utils::kzg_crs(crs);

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

