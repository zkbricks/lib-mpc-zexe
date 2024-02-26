use actix_web::{web, App, HttpServer};
use lib_mpc_zexe::coin::AMOUNT;
use std::sync::Mutex;
use reqwest::Client;

use lib_mpc_zexe::collaborative_snark::plonk::*;
use lib_mpc_zexe::apps;
use lib_mpc_zexe::protocol as protocol;

type AppStateType = Vec<protocol::SwapMatch>;

struct GlobalAppState {
    db: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

async fn submit_swap_tx(
    data: web::Data<GlobalAppState>,
    swap_tx: web::Json<protocol::SwapMatch>
) -> String {
    let mut _db = data.db.lock().unwrap();
    let swap_tx = swap_tx.into_inner();

    let (_, _, crs) = protocol::trusted_setup();

    let a_input = protocol::coin_from_bs58(&swap_tx.input_order_a.input_coin);
    let b_input = protocol::coin_from_bs58(&swap_tx.input_order_b.input_coin);
    let a_placeholder_output = protocol::coin_from_bs58(&swap_tx.input_order_a.placeholder_output_coin);
    let mut a_placeholder_refund = protocol::coin_from_bs58(&swap_tx.input_order_a.placeholder_refund_coin);
    let b_placeholder_output = protocol::coin_from_bs58(&swap_tx.input_order_b.placeholder_output_coin);
    let mut b_placeholder_refund = protocol::coin_from_bs58(&swap_tx.input_order_b.placeholder_refund_coin);
    
    let amount_correction_a = protocol::field_element_from_bs58(&swap_tx.amount_correction_a);
    a_placeholder_refund[AMOUNT] += amount_correction_a;

    let amount_correction_b = protocol::field_element_from_bs58(&swap_tx.amount_correction_b);
    b_placeholder_refund[AMOUNT] += amount_correction_b;

    // input the (blinded) input coins and corrected output coin
    // to the prover algorithm
    let proof = plonk_prove(
        &crs,
        vec![a_input, b_input].as_slice(),
        vec![
                a_placeholder_output,
                a_placeholder_refund,
                b_placeholder_output,
                b_placeholder_refund
            ].as_slice(),
        apps::swap::collaborative_prover::<8>
    );

    let swap_proof = protocol::AppTransaction {
        local_proofs: vec![
            swap_tx.input_order_a.input_coin_local_proof.clone(),
            swap_tx.input_order_b.input_coin_local_proof.clone()
        ],
        collaborative_prooof: protocol::plonk_proof_to_bs58(&proof),
        placeholder_selector: vec![false, true, false, true], //correct only refund coins
        amount_correction: vec![
            swap_tx.amount_correction_a.clone(),
            swap_tx.amount_correction_b.clone()
        ],
    };

    println!("submitting swap transaction to the L1 contract...");
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8082/swap")
        .json(&swap_proof)
        .send()
        .await
        .unwrap();
    
    if response.status().is_success() {
        println!("swap executed successfully!");
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
            .route("/swap", web::post().to(submit_swap_tx))
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}