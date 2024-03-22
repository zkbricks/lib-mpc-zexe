use ark_ec::{*, pairing::*};
use ark_std::*;
use ark_std::borrow::*;
use ark_poly::{
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use ark_serialize::CanonicalSerialize;
use ark_bls12_377::Bls12_377;

use crate::utils;
use crate::record_commitment::kzg::*;
use crate::coin::*;
use super::kzg;

type Curve = ark_bls12_377::Bls12_377;
type KZG = kzg::KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;
type G2Affine = <Curve as Pairing>::G2Affine;

pub fn kzg_crs<const N: usize>(
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

pub fn coin_poly<const N: usize>(coin: &Coin<F>) -> DensePolynomial<F> {    
    //powers of nth root of unity
    let domain = Radix2EvaluationDomain::<F>::new(N).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(coin.to_vec(), domain);
    //interpolated polynomial over the n points
    eval_form.interpolate()
}

pub fn random_oracle(
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
