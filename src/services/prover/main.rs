use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use rand_chacha::rand_core::SeedableRng;
use reqwest::Client;

use ark_ec::pairing::*;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::record_commitment::JZKZGCommitmentParams;
use lib_mpc_zexe::collaborative_snark::plonk::*;

type Curve = ark_bls12_377::Bls12_377;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;

mod lottery_prover;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LotteryTransaction {
    input_coins: Vec<CoinBs58>,
    output_coin: CoinBs58,
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

fn proof_to_bs58(proof: &PlonkProof) -> PlonkProofBs58 {
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

type AppStateType = Vec<LotteryTransaction>;

struct GlobalAppState {
    db: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

fn extract_crs() -> JZKZGCommitmentParams<8> {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    JZKZGCommitmentParams::<8>::trusted_setup(&mut rng)
}

fn coin_from_bs58(coin: &CoinBs58) -> Coin<F> {
    let fields: [F; 8] = coin.fields
        .iter()
        .map(|s| decode_bs58_str_as_f(s))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    fields
}

async fn submit_lottery_tx(
    data: web::Data<GlobalAppState>,
    lottery_tx: web::Json<LotteryTransaction>
) -> String {
    let mut _db = data.db.lock().unwrap();
    let tx = lottery_tx.into_inner();

    let crs = extract_crs();

    let f_input_coins: Vec<[F; 8]> = tx.input_coins
        .iter()
        .map(|c| coin_from_bs58(c))
        .collect::<Vec<_>>();

    let f_output_coin = coin_from_bs58(&tx.output_coin);
    
    let proof = plonk_prove(
        &crs, 
        f_input_coins.as_slice(), 
        [f_output_coin].as_slice(),
        lottery_prover::prover::<8>
    );

    let proof_bs58 = proof_to_bs58(&proof);
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8082/lottery")
        .json(&proof_bs58)
        .send()
        .await
        .unwrap();
    
    if response.status().is_success() {
        println!("Lottery executed successfully");
        "success".to_string()
    } else {
        "failure".to_string()
    }

}

fn decode_bs58_str_as_f(msg: &String) -> F {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    F::deserialize_compressed(buf.as_slice()).unwrap()
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
            .route("/lottery", web::post().to(submit_lottery_tx))
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}