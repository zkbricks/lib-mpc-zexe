use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use rand_chacha::rand_core::SeedableRng;

use ark_std::io::Cursor;
use ark_ec::pairing::*;
use ark_serialize::CanonicalDeserialize;

use lib_mpc_zexe::record_commitment::JZKZGCommitmentParams;
use lib_mpc_zexe::collaborative_snark::plonk::*;

type Curve = ark_bls12_377::Bls12_377;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;


mod lottery_verifier;

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

type AppStateType = Vec<PlonkProofBs58>;

struct GlobalAppState {
    db: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

fn extract_crs() -> JZKZGCommitmentParams<8> {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    JZKZGCommitmentParams::<8>::trusted_setup(&mut rng)
}


async fn verify_lottery_tx(
    data: web::Data<GlobalAppState>,
    proof: web::Json<PlonkProofBs58>
) -> String {
    let mut db = data.db.lock().unwrap();

    let crs = extract_crs();
    let proof = proof.into_inner();

    plonk_verify(
        &crs,
        &proof_from_bs58(&proof),
        lottery_verifier::verifier::<8>
    );

    println!("Proof verified!");
    
    (*db).push(proof.clone());

    "success".to_string()
}

fn proof_from_bs58(proof: &PlonkProofBs58) -> PlonkProof {
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

fn decode_bs58_str_as_f(msg: &String) -> F {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    F::deserialize_compressed(buf.as_slice()).unwrap()
}

fn decode_bs58_str_as_g1(msg: &String) -> G1Affine {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    G1Affine::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Note: web::Data created _outside_ HttpServer::new closure
    let app_state = web::Data::new(GlobalAppState {
        db: Mutex::new(Vec::new()),
    });

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(app_state.clone()) // <- register the created data
            .route("/lottery", web::post().to(verify_lottery_tx))
    })
    .bind(("127.0.0.1", 8082))?
    .run()
    .await
}