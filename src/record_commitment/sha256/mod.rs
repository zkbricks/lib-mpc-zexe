pub mod constraints;

use ark_crypto_primitives::crh::CRHScheme;
use ark_std::*;
use ark_std::borrow::*;

use ark_crypto_primitives::crh::sha256::*;

use crate::utils;

type F = ark_bls12_377::Fr;

#[derive(Clone)]
pub struct JZRecord<const N: usize> {
    pub fields: [Vec<u8>; N], //Nth field is the entropy
    pub blind: Vec<u8> //in case we want to reveal a blinded commitment
}

fn hash_of_fields(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut concatenated = Vec::new();
    for field in fields.iter() {
        concatenated.extend_from_slice(field);
    }

    Sha256::evaluate(&(), concatenated).unwrap()
}

impl<const N: usize> JZRecord<N> {
    pub fn new(
        fields: &[Vec<u8>; N],
        blind: &Vec<u8>
    ) -> Self {
        assert!(
            fields[0].len() == blind.len(), 
            "Blind and entropy field (index 0) must have the same length"
        );
        JZRecord {
            fields: fields.to_owned(),
            blind: blind.to_owned()
        }
    }

    pub fn commitment(&self) -> Vec<u8> {
        hash_of_fields(&self.fields)
    }

    pub fn blinded_commitment(&self) -> Vec<u8> {
        // set the randomness to be the sum of current entropy and blind value
        let new_randomness: Vec<u8> = self.fields[0]
            .iter()
            .zip(self.blind.iter())
            .map(|(&a, &b)| a + b)
            .collect();

        let mut new_fields = self.fields.clone();
        new_fields[0] = new_randomness;

        hash_of_fields(&new_fields)
    }

    pub fn fields(&self) -> [F; N] {
        self.fields
            .iter()
            .map(|field| utils::bytes_to_field(field))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }

    pub fn blinded_fields(&self) -> [F; N] {
        let mut fields = self.fields();
        fields[0] += utils::bytes_to_field::<F, 4>(&self.blind);
        fields
    }
}
