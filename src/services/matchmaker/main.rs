use actix_web::{web, App, HttpServer};
use lib_mpc_zexe::apps::lottery;
use reqwest::Client;
use rocksdb::DBWithThreadMode;
use rocksdb::SingleThreaded;
use std::collections::HashMap;
use std::sync::Mutex;
use rocksdb::{DB, IteratorMode, Options};

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::protocol as protocol;

struct AppStateType {
    /// stores all pending orders
    db: DBWithThreadMode<SingleThreaded>,
    /// maps asset_id to the number of pending orders for that asset
    asset_id_book: HashMap<String, usize>,
}

// a mutex is necessary to mutate safely across webserver threads
struct GlobalAppState {
    state: Mutex<AppStateType>,
}

/// submit_lottery_order is called by the client to submit a lottery order
async fn submit_lottery_order(
    global_state: web::Data<GlobalAppState>,
    order: web::Json<protocol::LotteryOrder>
) -> String {
    println!("within submit_lottery_order...");

    // let us first parse the incoming lottery order
    let order = order.into_inner();

    // we will use the unspent coin's nullifier as the key for the database
    let unspent_coin_nullifier = order
        .input_coin_local_proof
        .public_inputs[lottery::GrothPublicInput::NULLIFIER as usize]
        .clone();

    // we need the asset id for internal bookkeeping
    let asset_id = order.input_coin.fields[ASSET_ID].clone();

    // we will use the json encoded order as the value for the database
    // TODO: we should just be able to grab this from the request body
    let order_json = serde_json::to_string(&order).unwrap();

    // we now need to mutate state, so let's grab the lock
    let mut state = global_state.state.lock().unwrap();

    // add the order to the db full of pending orders
    (*state).db.put(
        unspent_coin_nullifier.as_bytes(),
        order_json.as_bytes()
    ).unwrap();
    println!("adding order for {:?} to db", unspent_coin_nullifier);

    // update the asset_id_book to reflect the new coin for that asset_id
    let existing_count = (*state)
        .asset_id_book
        .get(&asset_id)
        .unwrap_or(&0)
        .clone();
    (*state).asset_id_book.insert(asset_id, existing_count + 1);
    println!("resulting asset_id_book: {:?}", (*state).asset_id_book);

    // we are done mutating the global state
    drop(state);

    "success".to_string()
}

/// perform_lottery is the event triggering the performing of all possible lotteries
/// each lottery is performed on a pair of available orders in the pending orders db
async fn perform_lottery(global_state: web::Data<GlobalAppState>) -> String {
    println!("within perform_lottery...");

    // we are going to grab as many pairs of orders as we can find the db, and perform the lottery
    // once a pair is identified, both orders are removed from the db

    // let's first grab the lock on the global state, since we need to read and write to it
    let mut state = global_state.state.lock().unwrap();

    for (asset_id, count) in (*state).asset_id_book.iter() {
        if *count < 2 { continue; } // we need at least 2 orders to perform a lottery

        // we have at least 2 orders for this asset_id, let's find them and perform the lottery
        let iter = (*state).db.iterator(IteratorMode::Start);
        let mut orders: Vec<protocol::LotteryOrder> = Vec::new();

        for record in iter {
            let (key, value) = record.unwrap();

            let order: protocol::LotteryOrder = serde_json::from_str(
                std::str::from_utf8(&value).unwrap()
            ).unwrap();

            // only look for coins with the same asset_id as what we are working on now
            if order.input_coin.fields[ASSET_ID] == *asset_id {
                // if we already got 2 orders, let's move past it
                if orders.len() < 2 {
                    orders.push(order); // our working set of size at most 2

                     // remove the order from the db of pending orders, and decrease the count
                    (*state).db.delete(key).unwrap();
                }
            }
        }

        // when we get here, we are guaranteed to have 2 orders
        let input_coin_0 = protocol::coin_from_bs58(&orders[0].input_coin);
        let input_coin_1 = protocol::coin_from_bs58(&orders[1].input_coin);

        // we will make order 0 the winner, thus rigging the lottery (doesnt matter for our purposes here)
        // TODO: at some point, we need to convert this to a weighted lottery
        let placeholder_output_coin = protocol::coin_from_bs58(&orders[0].placeholder_output_coin);

        // when added to the placeholder amount, correction yields the desire sum
        let correction = input_coin_0[AMOUNT]
            + input_coin_1[AMOUNT]
            - placeholder_output_coin[AMOUNT];

        // prepare the lottery transaction for the prover
        let lottery_tx = protocol::LotteryMatch {
            input_orders: orders.clone(),
            winner_index: 0,
            amount_correction: protocol::field_element_to_bs58(&correction),
        };

        println!("submitting lottery order pair to the prover service...");
        let client = Client::new();
        let response = client.post("http://127.0.0.1:8081/lottery")
            .json(&lottery_tx)
            .send()
            .await
            .unwrap();

        if response.status().is_success() {
            println!("lottery executed successfully");
        } else {
            println!("Error encountered in lottery execution");
        }
    }

    // let us now update the asset_id book
    for (_asset_id, count) in (*state).asset_id_book.iter_mut() {
        if *count >= 2 {
            *count -= 2; // reduce by 2
        }
    }
    println!("resulting asset_id_book: {:?}", (*state).asset_id_book);

    drop(state);

    "success".to_string()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Note: web::Data created _outside_ HttpServer::new closure
    let app_state = web::Data::new(
        GlobalAppState { state: Mutex::new(initialize_state()) }
    );

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(app_state.clone()) // <- register the created data
            .route("/submit", web::post().to(submit_lottery_order))
            .route("/lottery", web::post().to(perform_lottery))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn initialize_state() -> AppStateType {
    let path = "/tmp/rocksdb";

    match std::fs::remove_dir_all(path) {
        Ok(_) => println!("removed existing database at '{}'", path),
        Err(e) => eprintln!("failed to remove existing database at '{}': {}", path, e),
    }

    println!("creating new database at '{}'", path);
    let mut opts = Options::default();
    opts.create_if_missing(true);

    let db: DBWithThreadMode<SingleThreaded> = DB::open(&opts, path).unwrap();
    let asset_id_book: HashMap<String, usize> = HashMap::new();

    AppStateType {
        db,
        asset_id_book,
    }
}