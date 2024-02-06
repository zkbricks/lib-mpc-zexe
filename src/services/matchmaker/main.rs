use actix_web::{web, App, HttpServer};
use reqwest::Client;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::encoding::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Order {
    id: i32,
    input_coin: CoinBs58,
    input_coin_local_proof: GrothProofBs58,
    placeholder_output_coin: CoinBs58,
}

#[derive(Debug, Serialize, Deserialize)]
struct Orders {
    orders: Vec<Order>,
}

/// describes the input from matchmaker to the prover
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LotteryTransaction {
    /// orders entering the lottery
    input_orders: Vec<Order>,
    /// which of the orders is the winner?
    winner_index: u64,
    /// the correction to the placeholder coin
    amount_correction: FieldElementBs58,
}

type AppStateType = Vec<Order>;

// a mutex is necessary to mutate safely across webserver threads
struct GlobalAppState {
    db: Mutex<AppStateType>,
}

async fn debug(data: web::Data<GlobalAppState>) -> String {
    let db = data.db.lock().unwrap();
    let items_response = Orders { orders: (*db).to_owned() };

    serde_json::to_string(&items_response).unwrap()
}

async fn submit_order(data: web::Data<GlobalAppState>, order: web::Json<Order>) -> String {
    let mut db = data.db.lock().unwrap();
    let order = order.into_inner();
    (*db).push(order.clone());

    println!("Added order: {:?}", order);

    "success".to_string()
}

async fn perform_lottery(data: web::Data<GlobalAppState>) -> String {
    let db = data.db.lock().unwrap();

    let orders = (*db).to_owned();

    let input_coin_0 = coin_from_bs58(&orders[0].input_coin);
    let input_coin_1 = coin_from_bs58(&orders[1].input_coin);

    //we will make order 0 the winner, thus rigging the lottery (doesnt matter)
    let placeholder_output_coin = coin_from_bs58(&orders[0].placeholder_output_coin);

    // when added to the placeholder amount, correction yields the desire sum
    let correction = input_coin_0[AMOUNT]
        + input_coin_1[AMOUNT]
        - placeholder_output_coin[AMOUNT];

    // prepare the lottery transaction for the prover
    let lottery_tx = LotteryTransaction {
        input_orders: orders.clone(),
        winner_index: 0,
        amount_correction: field_element_to_bs58(&correction),
    };

    let client = Client::new();
    let response = client.post("http://127.0.0.1:8081/lottery")
        .json(&lottery_tx)
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
            .route("/debug", web::get().to(debug))
            .route("/submit", web::post().to(submit_order))
            .route("/lottery", web::post().to(perform_lottery))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}