use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use lib_mpc_zexe::coin::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Order {
    id: i32,
    coin: CoinBs58,
}

#[derive(Debug, Serialize, Deserialize)]
struct Orders {
    orders: Vec<Order>,
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
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}