use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use rand_chacha::rand_core::SeedableRng;

use lib_mpc_zexe::record_commitment::JZKZGCommitmentParams;
use lib_mpc_zexe::collaborative_snark::plonk::*;
use lib_mpc_zexe::encoding::*;

mod lottery_verifier;

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