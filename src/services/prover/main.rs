use actix_web::{web, App, HttpServer};
use lib_mpc_zexe::coin::AMOUNT;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use rand_chacha::rand_core::SeedableRng;
use reqwest::Client;

use lib_mpc_zexe::record_commitment::JZKZGCommitmentParams;
use lib_mpc_zexe::collaborative_snark::plonk::*;
use lib_mpc_zexe::apps;
use lib_mpc_zexe::encoding::*;

type F = ark_bls12_377::Fr;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Order {
    id: i32,
    input_coin: CoinBs58,
    input_coin_local_proof: GrothProofBs58,
    placeholder_output_coin: CoinBs58,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LotteryTransaction {
    /// orders entering the lottery
    input_orders: Vec<Order>,
    /// which of the orders is the winner?
    winner_index: u64,
    /// the correction to the placeholder coin
    amount_correction: FieldElementBs58,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidityProof {
    /// Groth16 proofs for spent coin and placeholder coin
    local_proofs: Vec<GrothProofBs58>,
    /// Collaborative PLONK proof for the relation 
    /// between spent coins and created coins
    collaborative_prooof: PlonkProofBs58,
    /// which of the orders
    placeholder_selector: Vec<bool>,
    /// the correction to the placeholder coin
    amount_correction: Vec<FieldElementBs58>,
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

async fn submit_lottery_tx(
    data: web::Data<GlobalAppState>,
    lottery_tx: web::Json<LotteryTransaction>
) -> String {
    let mut _db = data.db.lock().unwrap();
    let tx = lottery_tx.into_inner();

    let crs = extract_crs();

    let input_coins: Vec<[F; 8]> = tx.input_orders
        .iter()
        .map(|o| coin_from_bs58(&o.input_coin))
        .collect::<Vec<_>>();

    // let us compute the output coin
    let mut output_coin = coin_from_bs58(
        &tx.input_orders[tx.winner_index as usize].placeholder_output_coin
    );
    
    let amount_correction = field_element_from_bs58(
        &tx.amount_correction
    );
    output_coin[AMOUNT] += amount_correction;

    // input the (blinded) input coins and corrected output coin
    // to the prover algorithm
    let proof = plonk_prove(
        &crs,
        input_coins.as_slice(),
        [output_coin].as_slice(),
        apps::lottery::collaborative_prover::<8>
    );

    // encode proof in base 58
    let collaborative_proof_bs58 = proof_to_bs58(&proof);

    let local_proofs = tx.input_orders
        .iter()
        .map(|o| o.input_coin_local_proof.clone())
        .collect::<Vec<_>>();

    let lottery_proof = ValidityProof {
        local_proofs: local_proofs,
        collaborative_prooof: collaborative_proof_bs58,
        placeholder_selector: (0..tx.input_orders.len())
            .map(|i| i == tx.winner_index as usize)
            .collect::<Vec<_>>(),
        amount_correction: vec![tx.amount_correction.clone()],
    };

    let client = Client::new();
    let response = client.post("http://127.0.0.1:8082/lottery")
        .json(&lottery_proof)
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