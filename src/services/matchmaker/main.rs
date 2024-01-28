use actix_web::{web, App, HttpServer};
use bs58::encode;
use reqwest::{Client, Error, Response};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use lib_mpc_zexe::coin::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

type F = ark_bls12_377::Fr;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Order {
    id: i32,
    coin: CoinBs58,
}

#[derive(Debug, Serialize, Deserialize)]
struct Orders {
    orders: Vec<Order>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LotteryTransaction {
    input_coins: Vec<CoinBs58>,
    output_coin: CoinBs58,
}


type AppStateType = Vec<Order>;

struct GlobalAppState {
    db: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
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

fn decode_bs58_str_as_f(msg: &String) -> F {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    F::deserialize_compressed(buf.as_slice()).unwrap()
}

fn encode_f_as_bs58_str(value: &F) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
}

async fn perform_lottery(data: web::Data<GlobalAppState>) -> String {
    println!("within perform_lottery");

    let mut db = data.db.lock().unwrap();

    let input_coins = (*db).to_owned();
    let mut output_coin = input_coins[0].clone();
    output_coin.coin.fields[AMOUNT] = encode_f_as_bs58_str(
        &(decode_bs58_str_as_f(&input_coins[0].coin.fields[AMOUNT]) +
        decode_bs58_str_as_f(&input_coins[1].coin.fields[AMOUNT]))
    );

    let lottery_tx = LotteryTransaction {
        input_coins: input_coins
            .iter()
            .map(|c| c.coin.clone())
            .collect::<Vec<_>>(),
        output_coin: output_coin.coin.clone(),
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