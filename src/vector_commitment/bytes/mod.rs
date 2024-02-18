mod common;
pub mod constraints;

use common::*;

use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::*,
    merkle_tree::*,
    to_uncompressed_bytes
};
use ark_std::rand::Rng;
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::*;

#[derive(Clone)]
pub struct JZVectorCommitmentParams {
    pub leaf_crh_params: <LeafH as CRHScheme>::Parameters,
    pub two_to_one_params: <CompressH as TwoToOneCRHScheme>::Parameters,
}

impl JZVectorCommitmentParams {
    pub fn trusted_setup<R: Rng>(rng: &mut R) -> Self {
        let leaf_crh_params = <LeafH as CRHScheme>::setup(rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(rng)
            .unwrap()
            .clone();

        JZVectorCommitmentParams {
            leaf_crh_params,
            two_to_one_params,
        }
    }
}

type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

pub type JZVectorCommitment = 
    <JubJubMerkleTreeParams as ark_crypto_primitives::merkle_tree::Config>
    ::InnerDigest;

pub struct JZVectorDB<L: CanonicalSerialize + Clone> {
    pub vc_params: JZVectorCommitmentParams,
    tree: JubJubMerkleTree,
    records: Vec<L>,
    marker: PhantomData<L>
}

#[derive(Clone)]
pub struct JZVectorCommitmentOpeningProof<L: CanonicalSerialize + Clone> {
    pub path: Path<JubJubMerkleTreeParams>,
    pub record: L,
    pub root: JZVectorCommitment
}

impl<L: CanonicalSerialize + Clone> JZVectorDB<L> {

    pub fn new(
        params: &JZVectorCommitmentParams,
        records: &[L]
    ) -> Self {
        // let mut rng = ark_std::test_rng();
        // let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

        let leaves: Vec<_> = records
            .iter()
            .map(|leaf| to_uncompressed_bytes!(leaf).unwrap())
            .collect();

        let tree = JubJubMerkleTree::new(
            &params.leaf_crh_params.clone(),
            &params.two_to_one_params.clone(),
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();

        let root = tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(
                    &params.leaf_crh_params,
                    &params.two_to_one_params,
                    &root,
                    leaf.as_slice()
                ).unwrap()
            );
        }
        
        JZVectorDB {
            vc_params: params.clone(),
            tree,
            records: records.to_vec(),
            marker: PhantomData
        }
    }

    pub fn get_record(&self, index: usize) -> &L {
        if index >= self.records.len() {
            panic!("Index out of bounds");
        }

        &self.records[index]
    }

    pub fn update(&mut self, index: usize, record: &L) {
        if index >= self.records.len() {
            panic!("Index out of bounds");
        }

        self.records[index] = record.clone();
        let new_leaf = to_uncompressed_bytes!(record).unwrap();
        self.tree.update(index, &new_leaf).unwrap();
    }

    pub fn commitment(&self) -> JZVectorCommitment {
        self.tree.root()
    }

    pub fn proof(&self, index: usize) -> Path<JubJubMerkleTreeParams> {
        if index >= self.records.len() {
            panic!("Index out of bounds");
        }

        self.tree.generate_proof(index).unwrap()
    }

}

pub fn verify_proof<L: CanonicalSerialize>(
    params: &JZVectorCommitmentParams,
    commitment: &JZVectorCommitment,
    record: &L,
    proof: &Path<JubJubMerkleTreeParams>
) -> bool {
    let leaf = to_uncompressed_bytes!(record).unwrap();
    proof.verify(
        &params.leaf_crh_params,
        &params.two_to_one_params,
        commitment,
        leaf.as_slice()
    ).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::test_rng;
    use ark_ff::BigInteger256;
    use ark_bls12_377::*;

    #[test]
    fn test_vector_storage_bigint() {
        let mut rng = test_rng();
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

        let mut records = Vec::new();
        for x in 0..16u8 {
            records.push(BigInteger256::from(x));
        }

        let mut db = JZVectorDB::<BigInteger256>::new(&vc_params, &records);
        
        let com = db.commitment();
        let proof = db.proof(0);
        assert!(verify_proof(&vc_params, &com, &records[0], &proof));

        let updated_record = BigInteger256::from(42u8);
        db.update(1, &updated_record);
        let com = db.commitment();
        let proof = db.proof(1);
        assert!(verify_proof(&vc_params, &com, &updated_record, &proof));
    }

    #[test]
    fn test_vector_storage_g1() {
        let mut rng = test_rng();
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

        let mut records = Vec::new();
        // record i is g^i
        for x in 0..16u8 {
            let x_bi = BigInteger256::from(x);
            let g_pow_x_i = G1Affine::generator()
                .mul_bigint(x_bi)
                .into_affine();
            records.push(g_pow_x_i);
        }

        let db = JZVectorDB::<G1Affine>::new(&vc_params, &records);

        let com = db.commitment();
        let some_index = 5; //anything between 0 and 16
        let proof = db.proof(some_index);
        assert!(verify_proof(&vc_params, &com, &records[some_index], &proof));
    }
}