use lib_mpc_zexe::protocol::VectorCommitmentOpeningProofBs58;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::JZVectorCommitmentOpeningProof;
use reqwest::Client;
use rand_chacha::rand_core::SeedableRng;
use std::time::Instant;
//use clap::{App, Arg};

use ark_ff::{*};
use ark_std::{*, rand::RngCore};

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::apps::swap;
use lib_mpc_zexe::apps::onramp;
use lib_mpc_zexe::record_commitment::kzg::*;
use lib_mpc_zexe::protocol as protocol;

type MT = lib_mpc_zexe::vector_commitment::bytes::pedersen::config::ed_on_bw6_761::MerkleTreeParams;

async fn get_merkle_proof(index: usize)
-> reqwest::Result<JZVectorCommitmentOpeningProof<MT, ark_bls12_377::G1Affine>> {
    let client = Client::new();
    let response = client.get("http://127.0.0.1:8082/getmerkleproof")
        .json(&index)
        .send()
        .await?
        .text()
        .await?;

    let merkle_proof_bs58: VectorCommitmentOpeningProofBs58 = serde_json::from_str(&response).unwrap();

    Ok(protocol::jubjub_vector_commitment_opening_proof_MTEdOnBw6_761_from_bs58(&merkle_proof_bs58))
}

async fn onramp_order(item: protocol::OnRampTransaction) -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8082/onramp")
        .json(&item)
        .send()
        .await?;

    if response.status().is_success() {
        println!("submitted onramp order to zkBricks L1 contract...");
    } else {
        println!("Failed to create item: {:?}", response.status());
    }

    Ok(())
}

async fn submit_order(item: protocol::SwapOrder) -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8080/submit")
        .json(&item)
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("submitted swap order to zkBricks swap subnet...");
    } else {
        println!("Failed to create item: {:?}", response.status());
    }
    
    Ok(())
}

async fn perform_swap() -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8080/swap")
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("invoking the swap event...");
    } else {
        println!("Failed to execute swap: {:?}", response.status());
    }
    
    Ok(())
}


#[tokio::main]
async fn main() -> reqwest::Result<()> {
    //parse_args();

    let (swap_pk, _) = swap::circuit_setup();
    let (onramp_pk, _) = onramp::circuit_setup();

    onramp_order(
        protocol::OnRampTransaction {
            proof: {
                let groth_proof = onramp::generate_groth_proof(
                    &onramp_pk,
                    &alice_on_ramp_coin()
                );
                protocol::groth_proof_to_bs58(&groth_proof.0, &groth_proof.1)
            }
        }
    ).await?;

    onramp_order(
        protocol::OnRampTransaction {
            proof: {
                let groth_proof = onramp::generate_groth_proof(
                    &onramp_pk,
                    &bob_on_ramp_coin()
                );
                protocol::groth_proof_to_bs58(&groth_proof.0, &groth_proof.1)
            }
        }
    ).await?;


    let now = Instant::now();

    let alice_merkle_proof = get_merkle_proof(0).await?;
    let (alice_proof, alice_public_inputs) = swap::generate_groth_proof(
        &swap_pk,
        &alice_on_ramp_coin(),
        &alice_app_coin(),
        &alice_placeholder_output_coin(),
        &alice_placeholder_refund_coin(),
        &alice_merkle_proof,
        &alice_key().0
    );
    println!("proof generated in {}.{} secs",
        now.elapsed().as_secs(), now.elapsed().subsec_millis()
    );

    let bob_merkle_proof = get_merkle_proof(1).await?;
    let (bob_proof, bob_public_inputs) = swap::generate_groth_proof(
        &swap_pk,
        &bob_on_ramp_coin(),
        &bob_app_coin(),
        &bob_placeholder_output_coin(),
        &bob_placeholder_refund_coin(),
        &bob_merkle_proof,
        &bob_key().0
    );

    // //FgvRhbyZhrB85i3Xui9iB7UjF92zVkREtcw2E1aV2y1R
    // println!("Alice's public key: {:?}", bs58_coins[0].fields[OWNER]);
    // //FfMcCs8a2Bnpo5UxkWX4APHJunSys5SDhmMuV9rfsCf9
    // println!("Bob's public key: {:?}", bs58_coins[1].fields[OWNER]);

    //list_orders().await?;
    submit_order(
        protocol::SwapOrder {
            input_coin:
                protocol::coin_to_bs58(
                    &alice_app_coin().blinded_fields()
                ),
            input_coin_local_proof:
                protocol::groth_proof_to_bs58(
                    &alice_proof, &alice_public_inputs
                ),
            placeholder_output_coin:
                protocol::coin_to_bs58(
                    &alice_placeholder_output_coin().fields()
                ),
            placeholder_refund_coin:
                protocol::coin_to_bs58(
                    &alice_placeholder_refund_coin().fields()
                )
        }
    ).await?;

    submit_order(
        protocol::SwapOrder {
            input_coin:
                protocol::coin_to_bs58(
                    &bob_app_coin().blinded_fields()
                ),
            input_coin_local_proof:
                protocol::groth_proof_to_bs58(
                    &bob_proof, &bob_public_inputs
                ),
            placeholder_output_coin:
                protocol::coin_to_bs58(
                    &bob_placeholder_output_coin().fields()
                ),
            placeholder_refund_coin:
                protocol::coin_to_bs58(
                    &bob_placeholder_refund_coin().fields()
                )
        }
    ).await?;
    
    perform_swap().await?;

    Ok(())
}

fn alice_key() -> ([u8; 32], [u8; 31]) {
    let privkey = [20u8; 32];
    let pubkey =
    [
        218, 61, 173, 102, 17, 186, 176, 174, 
        54, 64, 4, 87, 114, 16, 209, 133, 
        153, 47, 114, 88, 54, 48, 138, 7,
        136, 114, 216, 152, 205, 164, 171
    ];

    (privkey, pubkey)
}

fn bob_key() -> ([u8; 32], [u8; 31]) {
    let privkey = [25u8; 32];
    let pubkey =
    [
        217, 214, 252, 243, 200, 147, 117, 28, 
        142, 219, 58, 120, 65, 180, 251, 74, 
        234, 28, 72, 194, 161, 148, 52, 219, 
        10, 34, 21, 17, 33, 38, 77,
    ];

    (privkey, pubkey)
}

// Anonymous function to generate an array
fn create_array(input: u8) -> [u8; 31] {
    let mut arr = [0; 31];
    arr[0] = input;
    arr
}

fn alice_on_ramp_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let fields: [Vec<u8>; 8] = 
    [
        vec![0u8; 31],
        alice_key().1.to_vec(), //owner
        create_array(1u8).to_vec(), //asset id
        create_array(10u8).to_vec(), //amount
        vec![AppId::OWNED as u8], //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn alice_app_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let fields: [Vec<u8>; 8] = 
    [
        vec![0u8; 31],
        alice_key().1.to_vec(), //owner
        create_array(1u8).to_vec(), //asset id
        create_array(10u8).to_vec(), //amount
        vec![AppId::SWAP as u8], //app id
        create_array(2u8).to_vec(), //desured asset
        create_array(45u8).to_vec(), //desired amount
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn alice_placeholder_output_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let fields: [Vec<u8>; 8] = 
    [
        vec![0u8; 31],
        alice_key().1.to_vec(), //owner
        create_array(2u8).to_vec(), //asset id
        create_array(45u8).to_vec(), //amount
        vec![AppId::OWNED as u8], //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn alice_placeholder_refund_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let mut amount = [0u8; 31];
    rng.fill_bytes(&mut amount);

    let fields: [Vec<u8>; 8] = 
    [
        vec![0u8; 31],
        alice_key().1.to_vec(), //owner
        create_array(1u8).to_vec(), //asset id
        amount.to_vec(), //amount
        vec![AppId::OWNED as u8], //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn bob_on_ramp_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let fields: [Vec<u8>; 8] = 
    [
        vec![0u8; 31],
        bob_key().1.to_vec(), //owner
        create_array(2u8).to_vec(), //asset id
        create_array(50u8).to_vec(), //amount
        vec![AppId::OWNED as u8], //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn bob_app_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let fields: [Vec<u8>; 8] = 
    [
        vec![0u8; 31],
        bob_key().1.to_vec(), //owner
        create_array(2u8).to_vec(), //asset id
        create_array(50u8).to_vec(), //amount
        vec![AppId::SWAP as u8], //app id
        create_array(1u8).to_vec(), //desired asset id
        create_array(9u8).to_vec(), //deired amount
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn bob_placeholder_output_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let fields: [Vec<u8>; 8] =
    [
        vec![0u8; 31],
        bob_key().1.to_vec(), //owner
        create_array(1u8).to_vec(), //asset id
        create_array(9u8).to_vec(), //amount
        vec![AppId::OWNED as u8], //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

fn bob_placeholder_refund_coin() -> JZRecord<8> {
    let (_, _, crs) = protocol::trusted_setup();

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let mut amount = [0u8; 31];
    rng.fill_bytes(&mut amount);

    let fields: [Vec<u8>; 8] = 
    [
        vec![0u8; 31],
        alice_key().1.to_vec(), //owner
        create_array(2u8).to_vec(), //asset id
        amount.to_vec(), //amount
        vec![AppId::OWNED as u8], //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}