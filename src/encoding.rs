use ark_bw6_761::BW6_761;
use serde::{Deserialize, Serialize};

use ark_std::io::Cursor;
use ark_ec::pairing::*;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_groth16::*;

use crate::coin::*;
use crate::collaborative_snark::plonk::*;


type Curve = ark_bls12_377::Bls12_377;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;
type ConstraintF = ark_bw6_761::Fr;
type ConstraintPairing = ark_bw6_761::BW6_761;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldElementBs58 {
	pub field: String,
}

pub fn field_element_to_bs58(field: &F) -> FieldElementBs58 {
    FieldElementBs58 { field: encode_f_as_bs58_str(field) }
}

pub fn field_element_from_bs58(fieldbs58: &FieldElementBs58) -> F {
    decode_bs58_str_as_f(&fieldbs58.field)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinBs58 {
	pub fields: [String; NUM_FIELDS],
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

pub fn proof_from_bs58(proof: &PlonkProofBs58) -> PlonkProof {
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

pub fn proof_to_bs58(proof: &PlonkProof) -> PlonkProofBs58 {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrothProofBs58 {
    pub proof: String,
    pub public_inputs: Vec<String>,
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
