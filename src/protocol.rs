use ark_bw6_761::BW6_761;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

use ark_std::io::Cursor;
use ark_ec::pairing::*;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_groth16::*;

use crate::coin::*;
use crate::collaborative_snark::*;
use crate::prf::JZPRFParams;
use crate::record_commitment::JZKZGCommitmentParams;
use crate::vector_commitment::bytes::pedersen::{
    JZVectorCommitment as JubJubVectorCommitment,
    JZVectorCommitmentOpeningProof as JubJubVectorCommitmentOpeningProof,
    JZVectorCommitmentParams as JubJubVectorCommitmentParams,
    JZVectorCommitmentPath as JubJubVectorCommitmentPath,
    JZVectorCommitmentLeafDigest as JubJubVectorCommitmentLeafDigest,
    JZVectorCommitmentInnerDigest as JubJubVectorCommitmentInnerDigest
};
use crate::vector_commitment::bytes::sha256::{
    JZVectorCommitment as Sha2VectorCommitment,
    JZVectorCommitmentOpeningProof as Sha2VectorCommitmentOpeningProof,
    JZVectorCommitmentPath as Sha2VectorCommitmentPath,
    JZVectorCommitmentLeafDigest as Sha2VectorCommitmentLeafDigest,
    JZVectorCommitmentInnerDigest as Sha2VectorCommitmentInnerDigest
};

type Curve = ark_bls12_377::Bls12_377;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;
type ConstraintF = ark_bw6_761::Fr;
type ConstraintPairing = ark_bw6_761::BW6_761;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VectorCommitmentOpeningProofBs58 {
    pub path_leaf_sibling_hash: String,
    pub path_auth_path: Vec<String>,
    pub path_leaf_index: usize,
    pub record: String,
    pub root: String
 }

 pub fn jz_vector_commitment_opening_proof_to_bs58(
    proof: &JubJubVectorCommitmentOpeningProof<G1Affine>
 ) -> VectorCommitmentOpeningProofBs58 {
    let mut buffer: Vec<u8> = Vec::new();
    proof.path.leaf_sibling_hash.serialize_compressed(&mut buffer).unwrap();
    let path_leaf_sibling_hash = bs58::encode(buffer).into_string();

    let mut path_auth_path = Vec::new();
    for inner_digest in proof.path.auth_path.iter() {
        let mut buffer: Vec<u8> = Vec::new();
        inner_digest.serialize_compressed(&mut buffer).unwrap();
        let inner_digest_serialized = bs58::encode(buffer).into_string();

        path_auth_path.push(inner_digest_serialized);
    }

    let mut buffer: Vec<u8> = Vec::new();
    proof.record.serialize_compressed(&mut buffer).unwrap();
    let record = bs58::encode(buffer).into_string();

    let mut buffer: Vec<u8> = Vec::new();
    proof.root.serialize_compressed(&mut buffer).unwrap();
    let root = bs58::encode(buffer).into_string();

    VectorCommitmentOpeningProofBs58 {
        path_leaf_sibling_hash,
        path_auth_path,
        path_leaf_index: proof.path.leaf_index,
        record,
        root
    }
}

pub fn sha2_vector_commitment_opening_proof_from_bs58(
    proof: &VectorCommitmentOpeningProofBs58
) -> Sha2VectorCommitmentOpeningProof<Vec<u8>> {

    let buf: Vec<u8> = bs58::decode(proof.path_leaf_sibling_hash.clone()).into_vec().unwrap();
    let leaf_digest = Sha2VectorCommitmentLeafDigest::deserialize_compressed(buf.as_slice()).unwrap();

    let mut nodes: Vec<Sha2VectorCommitmentInnerDigest> = vec![];
    for node in proof.path_auth_path.iter() {
        let buf: Vec<u8> = bs58::decode(node.clone()).into_vec().unwrap();
        let node = Sha2VectorCommitmentInnerDigest::deserialize_compressed(buf.as_slice()).unwrap();

        nodes.push(node);
    }

    let buf: Vec<u8> = bs58::decode(proof.record.clone()).into_vec().unwrap();
    let record = buf;

    let buf: Vec<u8> = bs58::decode(proof.root.clone()).into_vec().unwrap();
    let root = Sha2VectorCommitment::deserialize_compressed(buf.as_slice()).unwrap();

    Sha2VectorCommitmentOpeningProof::<Vec<u8>> {
        path: Sha2VectorCommitmentPath {
            leaf_sibling_hash: leaf_digest,
            auth_path: nodes,
            leaf_index: proof.path_leaf_index,
        },
        record,
        root,
    }
}

pub fn jubjub_vector_commitment_opening_proof_from_bs58(
    proof: &VectorCommitmentOpeningProofBs58
) -> JubJubVectorCommitmentOpeningProof<G1Affine> {

    let buf: Vec<u8> = bs58::decode(proof.path_leaf_sibling_hash.clone()).into_vec().unwrap();
    let leaf_digest = JubJubVectorCommitmentLeafDigest::deserialize_compressed(buf.as_slice()).unwrap();

    let mut nodes: Vec<JubJubVectorCommitmentInnerDigest> = vec![];
    for node in proof.path_auth_path.iter() {
        let buf: Vec<u8> = bs58::decode(node.clone()).into_vec().unwrap();
        let node = JubJubVectorCommitmentInnerDigest::deserialize_compressed(buf.as_slice()).unwrap();

        nodes.push(node);
    }

    let buf: Vec<u8> = bs58::decode(proof.record.clone()).into_vec().unwrap();
    let record = G1Affine::deserialize_compressed(buf.as_slice()).unwrap();

    let buf: Vec<u8> = bs58::decode(proof.root.clone()).into_vec().unwrap();
    let root = JubJubVectorCommitment::deserialize_compressed(buf.as_slice()).unwrap();

    JubJubVectorCommitmentOpeningProof {
        path: JubJubVectorCommitmentPath {
            leaf_sibling_hash: leaf_digest,
            auth_path: nodes,
            leaf_index: proof.path_leaf_index,
        },
        record,
        root,
    }
}

/// LotteryOrder is submitted by the client to the MPC subnet
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LotteryOrder {
    pub input_coin: CoinBs58,
    pub input_coin_local_proof: GrothProofBs58,
    pub placeholder_output_coin: CoinBs58,
}

/// LotteryMatch is the message sent by the matchmaker to the SNARK prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LotteryMatch {
    /// orders entering the lottery
    pub input_orders: Vec<LotteryOrder>,
    /// which of the orders is the winner?
    pub winner_index: u64,
    /// the correction to the placeholder coin
    pub amount_correction: FieldElementBs58,
}

/// LotteryOrder is submitted by the client to the MPC subnet
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SwapOrder {
    pub input_coin: CoinBs58,
    pub input_coin_local_proof: GrothProofBs58,
    pub placeholder_output_coin: CoinBs58,
    pub placeholder_refund_coin: CoinBs58,
}

/// LotteryMatch is the message sent by the matchmaker to the SNARK prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapMatch {
    /// orders entering the swap
    pub input_order_a: SwapOrder,
    pub input_order_b: SwapOrder,
    /// the correction to the placeholder refund coin
    pub amount_correction_a: FieldElementBs58,
    pub amount_correction_b: FieldElementBs58,
}


/// AppTransaction is submitted by the MPC subnet to the L1 contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTransaction {
    /// Groth16 proofs for spent coin and placeholder coin
    pub local_proofs: Vec<GrothProofBs58>,
    /// Collaborative PLONK proof for the relation 
    /// between spent coins and created coins
    pub collaborative_prooof: PlonkProofBs58,
    /// which of the orders
    pub placeholder_selector: Vec<bool>,
    /// the correction to the placeholder coin
    pub amount_correction: Vec<FieldElementBs58>,
}

/// OnRampTransaction is submitted by the client to the L1 contract
/// to deposit L1 assets into wrapped L1 assets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnRampTransaction {
    /// proof attesting to the validity 
    /// of the created coin commitment
    pub proof: GrothProofBs58,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldElementBs58 {
	pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinBs58 {
	pub fields: [String; NUM_FIELDS],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrothProofBs58 {
    pub proof: String,
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlonkProofBs58 {
    // commitments to input coins data structures
    pub input_coins_com: Vec<String>,
    // commitments to output coins data structures
    pub output_coins_com: Vec<String>,
    // commitment to quotient polynomial
    pub quotient_com: String,
    // commitments to additional polynomials
    pub additional_com: Vec<String>,

    // openings of input coin polyomials at r
    pub input_coins_opening: Vec<String>,
    // openings of output coin polyomials at r
    pub output_coins_opening: Vec<String>,
    // opening of quotient polynomial at r
    pub quotient_opening: String,
    // openings of additional polynomials at r
    pub additional_opening: Vec<String>,

    pub input_coins_opening_proof: Vec<String>,
    pub output_coins_opening_proof: Vec<String>,
    pub quotient_opening_proof: String,
    pub additional_opening_proof: Vec<String>,
}


pub fn field_element_to_bs58(field: &F) -> FieldElementBs58 {
    FieldElementBs58 { field: encode_f_as_bs58_str(field) }
}

pub fn field_element_from_bs58(fieldbs58: &FieldElementBs58) -> F {
    decode_bs58_str_as_f(&fieldbs58.field)
}

pub fn coin_to_bs58(coin: &Coin<F>) -> CoinBs58 {
    CoinBs58 { fields: 
        coin
        .iter()
        .map(|f| encode_f_as_bs58_str(f))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }
}

pub fn coin_from_bs58(coin: &CoinBs58) -> Coin<F> {
	coin.fields
		.iter()
		.map(|s| decode_bs58_str_as_f(s))
		.collect::<Vec<_>>()
		.try_into()
		.unwrap()
}

pub fn plonk_proof_from_bs58(proof: &PlonkProofBs58) -> PlonkProof {
    let input_coins_com = proof.input_coins_com
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let output_coins_com = proof.output_coins_com
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let quotient_com = decode_bs58_str_as_g1(&proof.quotient_com);

    let additional_com = proof.additional_com
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let input_coins_opening = proof.input_coins_opening
        .iter()
        .map(|s| decode_bs58_str_as_f(s))
        .collect::<Vec<_>>();

    let output_coins_opening = proof.output_coins_opening
        .iter()
        .map(|s| decode_bs58_str_as_f(s))
        .collect::<Vec<_>>();

    let quotient_opening = decode_bs58_str_as_f(&proof.quotient_opening);

    let additional_opening = proof.additional_opening
        .iter()
        .map(|s| decode_bs58_str_as_f(s))
        .collect::<Vec<_>>();

    let input_coins_opening_proof = proof.input_coins_opening_proof
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let output_coins_opening_proof = proof.output_coins_opening_proof
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    let quotient_opening_proof = decode_bs58_str_as_g1(&proof.quotient_opening_proof);

    let additional_opening_proof = proof.additional_opening_proof
        .iter()
        .map(|s| decode_bs58_str_as_g1(s))
        .collect::<Vec<_>>();

    PlonkProof {
        input_coins_com,
        output_coins_com,
        quotient_com,
        additional_com,

        input_coins_opening,
        output_coins_opening,
        quotient_opening,
        additional_opening,

        input_coins_opening_proof,
        output_coins_opening_proof,
        quotient_opening_proof,
        additional_opening_proof,
    }
}

pub fn plonk_proof_to_bs58(proof: &PlonkProof) -> PlonkProofBs58 {
    let input_coins_com = proof.input_coins_com
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let output_coins_com = proof.output_coins_com
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let quotient_com = encode_g1_as_bs58_str(&proof.quotient_com);

    let additional_com = proof.additional_com
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let input_coins_opening = proof.input_coins_opening
        .iter()
        .map(|c| encode_f_as_bs58_str(c))
        .collect::<Vec<String>>();

    let output_coins_opening = proof.output_coins_opening
        .iter()
        .map(|c| encode_f_as_bs58_str(c))
        .collect::<Vec<String>>();

    let quotient_opening = encode_f_as_bs58_str(&proof.quotient_opening);

    let additional_opening = proof.additional_opening
        .iter()
        .map(|c| encode_f_as_bs58_str(c))
        .collect::<Vec<String>>();

    let input_coins_opening_proof = proof.input_coins_opening_proof
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let output_coins_opening_proof = proof.output_coins_opening_proof
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    let quotient_opening_proof = encode_g1_as_bs58_str(&proof.quotient_opening_proof);

    let additional_opening_proof = proof.additional_opening_proof
        .iter()
        .map(|c| encode_g1_as_bs58_str(c))
        .collect::<Vec<String>>();

    PlonkProofBs58 {
        input_coins_com,
        output_coins_com,
        quotient_com,
        additional_com,

        input_coins_opening,
        output_coins_opening,
        quotient_opening,
        additional_opening,

        input_coins_opening_proof,
        output_coins_opening_proof,
        quotient_opening_proof,
        additional_opening_proof,
    }
}

pub fn groth_proof_to_bs58(
    proof: &Proof<ConstraintPairing>,
    public_inputs: &Vec<ConstraintF>
) -> GrothProofBs58 {
    let public_inputs = public_inputs
        .iter()
        .map(|f| encode_constraintf_as_bs58_str(f))
        .collect::<Vec<String>>();

    let mut buffer: Vec<u8> = Vec::new();
    proof.serialize_compressed(&mut buffer).unwrap();
    let proof = bs58::encode(buffer).into_string();

    GrothProofBs58 {
        proof,
        public_inputs,
    }
}

pub fn groth_proof_from_bs58(proof: &GrothProofBs58) -> 
    (Proof<ConstraintPairing>, Vec<ConstraintF>) {
    let public_inputs = proof.public_inputs
        .iter()
        .map(|s| decode_bs58_str_as_constraintf(s))
        .collect::<Vec<ConstraintF>>();

    let buf: Vec<u8> = bs58::decode(proof.proof.clone()).into_vec().unwrap();
    let proof = Proof::<BW6_761>::deserialize_compressed(buf.as_slice()).unwrap();

    (proof, public_inputs)
}

fn decode_bs58_str_as_constraintf(msg: &String) -> ConstraintF {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    ConstraintF::deserialize_compressed(buf.as_slice()).unwrap()
}

fn decode_bs58_str_as_f(msg: &String) -> F {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    F::deserialize_compressed(buf.as_slice()).unwrap()
}

fn decode_bs58_str_as_g1(msg: &String) -> G1Affine {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    G1Affine::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}

fn encode_constraintf_as_bs58_str(value: &ConstraintF) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
}

fn encode_f_as_bs58_str(value: &F) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
}

fn encode_g1_as_bs58_str(value: &G1Affine) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

pub fn trusted_setup() -> (JZPRFParams, JubJubVectorCommitmentParams, JZKZGCommitmentParams<8>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    // TODO: for now we sample the public parameters directly;
    // we should change this to load from a file produced by a trusted setup
    let prf_params = JZPRFParams::trusted_setup(&mut rng);
    let vc_params = JubJubVectorCommitmentParams::trusted_setup(&mut rng);
    let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

    (prf_params, vc_params, crs)
}