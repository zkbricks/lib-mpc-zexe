use actix_web::{web, App, HttpServer};
use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use std::sync::Mutex;
use rand_chacha::rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use lib_mpc_zexe::record_commitment::JZKZGCommitmentParams;
use lib_mpc_zexe::collaborative_snark::plonk::*;
use lib_mpc_zexe::apps;
use lib_mpc_zexe::encoding::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LotteryProof {
    local_proofs: Vec<GrothProofBs58>,
    collaborative_prooof: PlonkProofBs58
}

type AppStateType = Vec<LotteryProof>;

struct GlobalAppState {
    db: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

fn extract_crs() -> JZKZGCommitmentParams<8> {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    JZKZGCommitmentParams::<8>::trusted_setup(&mut rng)
}

fn extract_vk() -> VerifyingKey<BW6_761> {
    let (_pk, vk) = apps::lottery::circuit_setup();
    vk
}

async fn verify_lottery_tx(
    data: web::Data<GlobalAppState>,
    proof: web::Json<LotteryProof>
) -> String {
    let mut db = data.db.lock().unwrap();

    let crs = extract_crs();
    let vk = extract_vk();

    let proof = proof.into_inner();

    let now = Instant::now();
    // verify the local proofs
    for p in &proof.local_proofs {
        let (groth_proof, public_inputs) = groth_proof_from_bs58(&p);

        let valid_proof = Groth16::<BW6_761>::verify(
            &vk,
            &public_inputs,
            &groth_proof
        ).unwrap();
        assert!(valid_proof);
    }

    // verify the collaborative proof
    plonk_verify(
        &crs,
        &proof_from_bs58(&proof.collaborative_prooof),
        apps::lottery::verifier::<8>
    );
    
    println!("proof verified in {}.{} secs", 
        now.elapsed().as_secs(),
        now.elapsed().subsec_millis()
    );

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