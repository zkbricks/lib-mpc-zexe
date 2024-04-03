use ark_poly::univariate::DensePolynomial;
use ark_ec::pairing::*;

mod kzg;
mod plonk_utils;

pub mod plonk;
//pub mod distributed_plonk;

type Curve = ark_bls12_377::Bls12_377;
type KZG = kzg::KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;

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

    // proof of openings of input coin polyomials at r
    pub input_coins_opening_proof: Vec<G1Affine>,
    // proof of openings of output coin polyomials at r
    pub output_coins_opening_proof: Vec<G1Affine>,
    // proof of opening of quotient polynomial at r
    pub quotient_opening_proof: G1Affine,
    // proof of openings of additional polynomials at r
    pub additional_opening_proof: Vec<G1Affine>,
}
