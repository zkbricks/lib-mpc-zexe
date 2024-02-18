use actix_web::{web, App, HttpServer};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::PrimeField;
use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use lib_mpc_zexe::coin::AMOUNT;
use std::ops::Add;
use std::sync::Mutex;
use std::time::Instant;

use lib_mpc_zexe::collaborative_snark::plonk::*;
use lib_mpc_zexe::apps;
use lib_mpc_zexe::protocol as protocol;

type AppStateType = Vec<protocol::AppTransaction>;

struct GlobalAppState {
    db: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

fn extract_vk() -> VerifyingKey<BW6_761> {
    let (_pk, vk) = apps::lottery::circuit_setup();
    vk
}

async fn verify_lottery_tx(
    data: web::Data<GlobalAppState>,
    proof: web::Json<protocol::AppTransaction>
) -> String {
    let mut db = data.db.lock().unwrap();

    let (_, _, crs) = protocol::trusted_setup();
    let vk = extract_vk();

    let proof = proof.into_inner();
    let plonk_proof = protocol::plonk_proof_from_bs58(&proof.collaborative_prooof);

    let now = Instant::now();

    let mut output_coin_index = 0;
    for i in 0..proof.placeholder_selector.len() {
        let (_, public_inputs) = protocol::groth_proof_from_bs58(&proof.local_proofs[i]);

        // verify that the (commitments of) output coins in collaborative proof are
        // equal to the placeholder coins in local proofs, modulo amount corrections
        if proof.placeholder_selector[i] {
            let amount_correction = protocol::field_element_from_bs58(
                &proof.amount_correction[output_coin_index]
            );
            let correction_group_elem = crs
                .crs_lagrange[AMOUNT]
                .clone()
                .mul_bigint(amount_correction.into_bigint())
                .into_affine();

            let mut placeholder_com = ark_bls12_377::G1Affine::new(public_inputs[0], public_inputs[1]);
            placeholder_com = placeholder_com.add(&correction_group_elem).into_affine();

            // check that the plonk proof is using the commitment we computed here
            assert_eq!(placeholder_com.x(), plonk_proof.output_coins_com[output_coin_index].x());
            assert_eq!(placeholder_com.y(), plonk_proof.output_coins_com[output_coin_index].y());

            output_coin_index += 1;
        }

        // verify that (commitments of) app-input coins match in collaborative and local proofs
        let input_com = ark_bls12_377::G1Affine::new(public_inputs[2], public_inputs[3]);
        assert_eq!(input_com.x(), plonk_proof.input_coins_com[i].x());
        assert_eq!(input_com.y(), plonk_proof.input_coins_com[i].y());
    }


    // verify the local proofs
    for p in &proof.local_proofs {
        let (groth_proof, public_inputs) = protocol::groth_proof_from_bs58(&p);

        let valid_proof = Groth16::<BW6_761>::verify(
            &vk,
            &public_inputs,
            &groth_proof
        ).unwrap();
        assert!(valid_proof);

        println!("verified groth proof");
    }

    // verify the collaborative proof
    plonk_verify(
        &crs,
        &plonk_proof,
        apps::lottery::collaborative_verifier::<8>
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