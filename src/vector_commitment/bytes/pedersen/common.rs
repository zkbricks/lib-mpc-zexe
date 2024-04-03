use ark_crypto_primitives::crh::{pedersen, *};
use crate::merkle_tree::*;
//use ark_ed_on_bls12_377::EdwardsProjective as JubJub;
use ark_ed_on_bw6_761::EdwardsProjective as JubJub;

#[derive(Clone)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 384;
}

pub type LeafH = pedersen::CRH<JubJub, Window4x256>;
pub type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x256>;

pub struct JubJubMerkleTreeParams;

impl Config for JubJubMerkleTreeParams {
    type Leaf = [u8];

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}