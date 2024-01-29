use ark_std::*;
use ark_poly::univariate::DensePolynomial;
use ark_poly::Polynomial;

use lib_mpc_zexe::utils;
use lib_mpc_zexe::collaborative_snark::plonk::PlonkProof;
use lib_mpc_zexe::coin::*;

type F = ark_bls12_377::Fr;

pub fn verifier<const N: usize>(
    r: &F, proof: &PlonkProof
) -> Vec<F> {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    let app_id_lottery_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::LOTTERY as u64)
    );

    // polynomial identity with Schwartz-Zippel
    let lhs_1 = lagrange_polynomials[AMOUNT].evaluate(&r) * 
        (
            proof.input_coins_opening[0] +
            proof.input_coins_opening[1] -
            proof.output_coins_opening[0]
        );

    let lhs_2 = lagrange_polynomials[ASSET_ID].evaluate(&r) * 
        (
            proof.input_coins_opening[0] -
            proof.output_coins_opening[0]
        );

    let lhs_3 = lagrange_polynomials[ASSET_ID].evaluate(&r) * (
        proof.input_coins_opening[1] -
        proof.output_coins_opening[0]
    );

    let lhs_4 = lagrange_polynomials[APP_ID].evaluate(&r) *
        (   
            proof.input_coins_opening[0] -
            app_id_lottery_poly.evaluate(&r)
        );

    let lhs_5 = lagrange_polynomials[APP_ID].evaluate(&r) *
    (   
        proof.input_coins_opening[1] -
        app_id_lottery_poly.evaluate(&r)
    );

    vec![lhs_1, lhs_2, lhs_3, lhs_4, lhs_5]
}