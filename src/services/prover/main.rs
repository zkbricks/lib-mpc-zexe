use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use rand_chacha::rand_core::SeedableRng;
use reqwest::Client;

use lib_mpc_zexe::record_commitment::JZKZGCommitmentParams;
use lib_mpc_zexe::collaborative_snark::plonk::*;
use lib_mpc_zexe::encoding::*;

type F = ark_bls12_377::Fr;

mod lottery_prover;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LotteryTransaction {
    input_coins: Vec<CoinBs58>,
    output_coin: CoinBs58,
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