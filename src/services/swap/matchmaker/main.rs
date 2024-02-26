use actix_web::{web, App, HttpServer};
use lib_mpc_zexe::apps::swap;
use reqwest::Client;
use rocksdb::DBWithThreadMode;
use rocksdb::SingleThreaded;
use std::collections::HashMap;
use std::sync::Mutex;
use rocksdb::{DB, Options};

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::protocol as protocol;

type F = ark_bls12_377::Fr;

struct AppStateType {
    /// stores all pending orders
    db: DBWithThreadMode<SingleThreaded>,
    /// maps asset_id to the number of pending orders for that asset
    asset_id_book: HashMap<String, Vec<String>>,
}

// a mutex is necessary to mutate safely across webserver threads
struct GlobalAppState {
    state: Mutex<AppStateType>,
}

/// submit_sawp_order is called by the client to submit a swap order
async fn submit_swap_order(
    global_state: web::Data<GlobalAppState>,
    order: web::Json<protocol::SwapOrder>
) -> String {
    println!("within submit_sawp_order...");

    // let us first parse the incoming swap order
    let order = order.into_inner();

    // we will use the unspent coin's nullifier as the key for the database
    let unspent_coin_nullifier = order
        .input_coin_local_proof
        .public_inputs[swap::GrothPublicInput::NULLIFIER as usize]
        .clone();

    // we need the asset id for internal bookkeeping
    let asset_id = order.input_coin.fields[ASSET_ID].clone();

    // we will use the json encoded order as the value for the database
    // TODO: we should just be able to grab this from the request body
    let order_json = serde_json::to_string(&order).unwrap();

    // we now need to mutate state, so let's grab the lock
    let mut state = global_state.state.lock().unwrap();

    // add the order to the db full of pending orders
    println!("adding order for {:?} to db", unspent_coin_nullifier);
    (*state).db.put(
        unspent_coin_nullifier.as_bytes(),
        order_json.as_bytes()
    ).unwrap();
    
    // if asset_id doesn't exist, create an empty list
    if (*state).asset_id_book.get(&asset_id).is_none() {
        (*state).asset_id_book.insert(asset_id.clone(), vec![]);
    }

    // add the coin to the asset_id book
    (*state).asset_id_book
        .get_mut(&asset_id)
        .unwrap()
        .push(unspent_coin_nullifier.clone());

    // we are done mutating the global state
    drop(state);

    "success".to_string()
}

/// perform_swap is the event triggering the performing of all possible swaps
/// each swap is performed on a pair of available orders in the pending orders db
async fn perform_swap(global_state: web::Data<GlobalAppState>) -> String {
    println!("within perform_swap...");

    // let's first grab the lock on the global state, since we need to read and write to it
    let state = global_state.state.lock().unwrap();

    // let us perform as many swaps as we can...
    for token_a_asset_id in (*state).asset_id_book.keys() {

        // iterate over each order with token_a
        for order_a_nullifier in (*state).asset_id_book.get(token_a_asset_id).unwrap() {
            // we need to find a matching order for this one
            let order_json = (*state)
                .db.get(order_a_nullifier.as_bytes())
                .unwrap();

            if order_json.is_none() {
                continue; // didn't find it in the db because it got matched already
            }

            let order_a: protocol::SwapOrder = serde_json::from_str(
                std::str::from_utf8(&order_json.unwrap()).unwrap()
            ).unwrap();

            // this is the desired token type for this order
            let token_b_asset_id = order_a.input_coin.fields[APP_INPUT_0].clone();

            // let us find orders with token_b_asset_id
            let empty = vec![];
            let token_b_order_nullifiers = (*state)
                .asset_id_book
                .get(&token_b_asset_id)
                .unwrap_or(&empty);

            for order_b_nullifier in token_b_order_nullifiers {
                let order_json = (*state)
                    .db.get(order_b_nullifier.as_bytes())
                    .unwrap();

                if order_json.is_none() {
                    continue; // didn't find it in the db because it got matched already
                }

                let order_b: protocol::SwapOrder = serde_json::from_str(
                    std::str::from_utf8(&order_json.unwrap()).unwrap()
                ).unwrap();

                if is_match(
                    &protocol::coin_from_bs58(&order_a.input_coin), 
                    &protocol::coin_from_bs58(&order_b.input_coin)
                ) {
                    let swap_match = create_match_for_prover(&order_a, &order_b);

                    println!("submitting swap order pair to the prover service...");
                    let client = Client::new();
                    let response = client.post("http://127.0.0.1:8081/swap")
                        .json(&swap_match)
                        .send()
                        .await
                        .unwrap();

                    if response.status().is_success() {
                        println!("swap executed successfully");
                        // we need to remove the orders from the db
                        (*state).db.delete(order_a_nullifier.as_bytes()).unwrap();
                        (*state).db.delete(order_b_nullifier.as_bytes()).unwrap();
                    } else {
                        println!("Error encountered in swap execution");
                    }
                }
            }
        }
    }

    drop(state);

    "success".to_string()
}

fn create_match_for_prover(
    order_a: &protocol::SwapOrder,
    order_b: &protocol::SwapOrder
) -> protocol::SwapMatch {

    // parse all 6 coins
    let a_input = protocol::coin_from_bs58(&order_a.input_coin);
    let b_input = protocol::coin_from_bs58(&order_b.input_coin);
    let a_placeholder_refund = protocol::coin_from_bs58(&order_a.placeholder_refund_coin);
    let b_placeholder_refund = protocol::coin_from_bs58(&order_b.placeholder_refund_coin);
    
    let a_placeholder_refund_corr = 
        (a_input[AMOUNT] - b_input[APP_INPUT_1]) - a_placeholder_refund[AMOUNT];
    let b_placeholder_refund_corr = 
        (b_input[AMOUNT] - a_input[APP_INPUT_1]) - b_placeholder_refund[AMOUNT];

    // prepare the swap transaction for the prover
    protocol::SwapMatch {
        input_order_a: order_a.clone(),
        input_order_b: order_b.clone(),
        amount_correction_a: protocol::field_element_to_bs58(&a_placeholder_refund_corr),
        amount_correction_b: protocol::field_element_to_bs58(&b_placeholder_refund_corr),
    }
}

fn is_match(order_a: &Coin<F>, order_b: &Coin<F>) -> bool {
    // we need to check if the orders are a match

    // a's desired asset is b's asset type
    let c1 = order_a[APP_INPUT_0] == order_b[ASSET_ID];

    // b's desired asset is a's asset type
    let c2 = order_b[APP_INPUT_0] == order_a[ASSET_ID];

    // min_b_for_a >= b
    let c3 = order_a[APP_INPUT_1] <= order_b[AMOUNT];
    // min_a_for_b >= a
    let c4 = order_b[APP_INPUT_1] <= order_a[AMOUNT];

    c1 && c2 && c3 && c4
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
            .route("/submit", web::post().to(submit_swap_order))
            .route("/swap", web::post().to(perform_swap))
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
    let asset_id_book: HashMap<String, Vec<String>> = HashMap::new();

    AppStateType {
        db,
        asset_id_book,
    }
}