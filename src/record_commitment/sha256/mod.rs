pub mod constraints;

use ark_crypto_primitives::crh::{CRHScheme, sha256::*};
use ark_std::{*, borrow::*};
use ark_ff::*;
use ark_std::marker::PhantomData;

use crate::utils;

fn hash_of_fields(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut concatenated = Vec::new();
    for field in fields.iter() {
        concatenated.extend_from_slice(field);
    }

    Sha256::evaluate(&(), concatenated).unwrap()
}

#[derive(Clone)]
pub struct JZRecord<const N: usize, const M: usize, RecordF: PrimeField + std::convert::From<BigInt<M>>> {
    pub fields: [Vec<u8>; N], //Nth field is the entropy
    pub blind: Vec<u8>, //in case we want to reveal a blinded commitment
    pub _phantom: PhantomData<RecordF>
}

impl<const N: usize, const M: usize, RecordF: PrimeField + std::convert::From<BigInt<M>>> JZRecord<N, M, RecordF> {
    pub fn new(
        fields: &[Vec<u8>; N],
        blind: &Vec<u8>
    ) -> Self {
        assert!(
            fields[0].len() == blind.len(), 
            "Blind and entropy field (index 0) must have the same length"
        );
        JZRecord::<N, M, RecordF> {
            fields: fields.to_owned(),
            blind: blind.to_owned(),
            _phantom: PhantomData
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

    pub fn fields(&self) -> [RecordF; N] {
        self.fields
            .iter()
            .map(|field| utils::bytes_to_field::<RecordF, M>(field))
            .collect::<Vec<RecordF>>()
            .try_into()
            .unwrap()
    }

    pub fn blinded_fields(&self) -> [RecordF; N] {
        let mut fields = self.fields();
        fields[0] += utils::bytes_to_field::<RecordF, M>(&self.blind);
        fields
    }
}
