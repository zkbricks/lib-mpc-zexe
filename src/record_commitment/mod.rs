pub mod constraints;

use ark_ec::*;
use ark_ff::*;
use ark_std::{*, rand::Rng};
use ark_std::borrow::*;
use ark_ff::{Field, PrimeField, BigInt, BigInteger};
use ark_poly::Polynomial;
use ark_bls12_377::{G1Projective, G2Projective};

use crate::utils;

type F = ark_bls12_377::Fr;

#[derive(Clone)]
pub struct JZKZGCommitmentParams<const N: usize> {
    /// KZG CRS in the coefficient basis
    pub crs_coefficient_g1: Vec<ark_bls12_377::G1Projective>,
    /// KZG CRS in the coefficient basis
    pub crs_coefficient_g2: Vec<ark_bls12_377::G2Projective>,
    /// KZG CRS in the Lagrange basis
    pub crs_lagrange: Vec<ark_bls12_377::G1Projective>,
}

impl<const N: usize> JZKZGCommitmentParams<N> {
    pub fn trusted_setup<R: Rng>(_rng: &mut R) -> Self {
        let tau = F::from(42);

        let g = G1Projective::generator();
        let h = G2Projective::generator();

        let crs_coefficient_g1 = (0..4*N)
            .map(|i| g.mul_bigint(
                tau.pow(
                    &[i as u64]
                ).into_bigint()
            ))
            .collect();

        let crs_coefficient_g2 = (0..4*N)
            .map(|i| h.mul_bigint(
                tau.pow(
                    &[i as u64]
                ).into_bigint()
            ))
            .collect();

        let crs_lagrange = (0..N)
            .map(|i| g.mul_bigint(
                utils::lagrange_poly(N, i)
                .evaluate(&tau)
                .into_bigint()
                ))
            .collect();

        JZKZGCommitmentParams {
            crs_coefficient_g1: crs_coefficient_g1,
            crs_coefficient_g2: crs_coefficient_g2,
            crs_lagrange,
        }
    }
}

#[derive(Clone)]
pub struct JZRecord<const N: usize> {
    pub crs: JZKZGCommitmentParams<N>,
    pub fields: [Vec<u8>; N], //Nth field is the entropy
    pub blind: Vec<u8> //in case we want to reveal a blinded commitment
}

impl<const N: usize> JZRecord<N> {
    pub fn new(
        crs: &JZKZGCommitmentParams<N>,
        fields: &[Vec<u8>; N],
        blind: &Vec<u8>
    ) -> Self {
        JZRecord {
            crs: crs.clone(),
            fields: fields.to_owned(),
            blind: blind.to_owned()
        }
    }

    pub fn commitment(&self) -> ark_bls12_377::G1Projective {
        let mut acc = ark_bls12_377::G1Projective::zero();
        for (i, field) in self.fields.iter().enumerate() {
            if i < N {
                let crs_elem = self.crs.crs_lagrange[i];
                let exp = BigInt::<4>::from_bits_le(
                    utils::bytes_to_bits(&field).as_slice()
                );
                
                acc += crs_elem.clone().mul_bigint(exp);
            }
        }
        acc
    }

    pub fn blinded_commitment(&self) -> ark_bls12_377::G1Projective {
        let com = self.commitment();

        let blind_bi = BigInt::<4>::from_bits_le(
            utils::bytes_to_bits(&self.blind).as_slice()
        );
        let blind_group_elem = self.crs
            .crs_lagrange[0]
            .clone()
            .mul_bigint(blind_bi);

        com + blind_group_elem
    }
}
