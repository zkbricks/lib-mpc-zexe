use actix_web::{web, App, HttpServer};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::PrimeField;
use ark_bw6_761::BW6_761;
use ark_groth16::*;
use ark_snark::SNARK;
use std::ops::Add;
use std::sync::Mutex;
use std::time::Instant;

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::record_commitment::JZRecord;
use lib_mpc_zexe::vector_commitment::bytes::{
    JZVectorDB,
    JZVectorCommitmentOpeningProof,
};
use lib_mpc_zexe::collaborative_snark::plonk::*;
use lib_mpc_zexe::apps;
use lib_mpc_zexe::protocol as protocol;

pub struct AppStateType {
    db: JZVectorDB::<ark_bls12_377::G1Affine>,
    num_coins: usize,
}

struct GlobalAppState {
    state: Mutex<AppStateType>, // <- Mutex is necessary to mutate safely across threads
}

async fn get_merkle_proof(
    global_state: web::Data<GlobalAppState>,
    index: web::Json<usize>
) -> String {
    let state = global_state.state.lock().unwrap();
    let index: usize = index.into_inner();

    let merkle_proof = JZVectorCommitmentOpeningProof {
        root: (*state).db.commitment(),
        record: (*state).db.get_record(index).clone(),
        path: (*state).db.proof(index),
    };

    drop(state);

    let merkle_proof_bs58 = protocol::jz_vector_commitment_opening_proof_to_bs58(
        &merkle_proof
    );

    serde_json::to_string(&merkle_proof_bs58).unwrap()
}

async fn on_ramp_tx(
    global_state: web::Data<GlobalAppState>,
    proof: web::Json<protocol::OnRampTransaction>
) -> String {
    let (_, vk) = apps::onramp::circuit_setup();

    let on_ramp_proof = proof.into_inner();
    let (groth_proof, public_inputs) = protocol::groth_proof_from_bs58(
        &on_ramp_proof.proof
    );

    let valid_proof = Groth16::<BW6_761>::verify(
        &vk,
        &public_inputs,
        &groth_proof
    ).unwrap();
    assert!(valid_proof);

    let com = ark_bls12_377::G1Affine::new(
        public_inputs[apps::onramp::GrothPublicInput::COIN_COM_X as usize],
        public_inputs[apps::onramp::GrothPublicInput::COIN_COM_Y as usize]
    );

    // add the coin to the state
    let mut state = global_state.state.lock().unwrap();

    let index = (*state).num_coins;
    (*state).db.update(index, &com);
    (*state).num_coins += 1;
    println!("added coin to state at index {}", index);

    drop(state);
    "success".to_string()
}

async fn verify_lottery_tx(
    global_state: web::Data<GlobalAppState>,
    proof: web::Json<protocol::AppTransaction>
) -> String {

    let (_, _, crs) = protocol::trusted_setup();
    let (_, vk) = apps::lottery::circuit_setup();

    let lottery_proof = proof.into_inner();
    let plonk_proof = protocol::plonk_proof_from_bs58(
        &lottery_proof.collaborative_prooof
    );

    let now = Instant::now();

    let mut output_coin_index = 0;
    let mut output_coin_commitments = Vec::new();

    for i in 0..lottery_proof.placeholder_selector.len() {
        let (groth_proof, public_inputs) = protocol::groth_proof_from_bs58(
            &lottery_proof.local_proofs[i]
        );

        // first verify the groth proof
        let valid_proof = Groth16::<BW6_761>::verify(
            &vk,
            &public_inputs,
            &groth_proof
        ).unwrap();
        assert!(valid_proof);

        // verify that the (commitments of) output coins in collaborative proof are
        // equal to the placeholder coins in local proofs, modulo amount corrections
        if lottery_proof.placeholder_selector[i] {
            let amount_correction = protocol::field_element_from_bs58(
                &lottery_proof.amount_correction[output_coin_index]
            );
            let correction_group_elem = crs
                .crs_lagrange[AMOUNT]
                .clone()
                .mul_bigint(amount_correction.into_bigint())
                .into_affine();

            let mut placeholder_com = ark_bls12_377::G1Affine::new(
                public_inputs[apps::lottery::GrothPublicInput::PLACEHOLDER_OUTPUT_COIN_COM_X as usize], 
                public_inputs[apps::lottery::GrothPublicInput::PLACEHOLDER_OUTPUT_COIN_COM_Y as usize]
            );
            placeholder_com = placeholder_com.add(&correction_group_elem).into_affine();

            // check that the plonk proof is using the commitment for output coins that we computed here
            assert_eq!(placeholder_com.x(), plonk_proof.output_coins_com[output_coin_index].x());
            assert_eq!(placeholder_com.y(), plonk_proof.output_coins_com[output_coin_index].y());

            output_coin_commitments.push(placeholder_com);

            output_coin_index += 1;
        }

        // verify that (commitments of) app-input coins match in collaborative and local proofs
        let input_com = ark_bls12_377::G1Affine::new(
            public_inputs[apps::lottery::GrothPublicInput::BLINDED_INPUT_COIN_COM_X as usize],
            public_inputs[apps::lottery::GrothPublicInput::BLINDED_INPUT_COIN_COM_Y as usize]
        );
        assert_eq!(input_com.x(), plonk_proof.input_coins_com[i].x());
        assert_eq!(input_com.y(), plonk_proof.input_coins_com[i].y());
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

    let mut state = global_state.state.lock().unwrap();
    // let's add all the output coins to the state
    for com in output_coin_commitments {
        let index = (*state).num_coins;
        (*state).db.update(index, &com);
        (*state).num_coins += 1;
    }
    drop(state);

    "success".to_string()
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Note: web::Data created _outside_ HttpServer::new closure
    let app_state = web::Data::new(GlobalAppState {
        state: Mutex::new(AppStateType { db: initialize_state(), num_coins: 0 }),
    });

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(app_state.clone()) // <- register the created data
            .route("/lottery", web::post().to(verify_lottery_tx))
            .route("/onramp", web::post().to(on_ramp_tx))
            .route("/getmerkleproof", web::get().to(get_merkle_proof))
    })
    .bind(("127.0.0.1", 8082))?
    .run()
    .await
}

fn initialize_state() -> JZVectorDB<ark_bls12_377::G1Affine> {
    let (_, vc_params, crs) = protocol::trusted_setup();
    
    let mut records = Vec::new();
    for _ in 0..64u8 {
        let fields: [Vec<u8>; 8] = 
        [
            vec![0u8; 31], //entropy
            vec![0u8; 31], //owner
            vec![0u8; 31], //asset id
            vec![0u8; 31], //amount
            vec![AppId::OWNED as u8], //app id
            vec![0u8; 31],
            vec![0u8; 31],
            vec![0u8; 31],
        ];

        let coin = JZRecord::<8>::new(&crs, &fields, &[0u8; 31].into());
        records.push(coin.commitment().into_affine());
    }

    JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records)
}