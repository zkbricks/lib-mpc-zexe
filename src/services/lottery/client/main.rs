use lib_mpc_zexe::protocol::VectorCommitmentOpeningProofBs58;
use lib_mpc_zexe::vector_commitment::bytes::pedersen::JZVectorCommitmentOpeningProof;
use reqwest::Client;
use rand_chacha::rand_core::SeedableRng;
use std::time::Instant;
//use clap::{App, Arg};

use ark_ff::{*};
use ark_std::{*, rand::RngCore};

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::apps::lottery;
use lib_mpc_zexe::apps::onramp;
use lib_mpc_zexe::record_commitment::*;
use lib_mpc_zexe::protocol as protocol;

async fn get_merkle_proof(index: usize)
-> reqwest::Result<JZVectorCommitmentOpeningProof<ark_bls12_377::G1Affine>> {
    let client = Client::new();
    let response = client.get("http://127.0.0.1:8082/getmerkleproof")
        .json(&index)
        .send()
        .await?
        .text()
        .await?;

    let merkle_proof_bs58: VectorCommitmentOpeningProofBs58 = 
        serde_json::from_str(&response).unwrap();

    Ok(protocol::jubjub_vector_commitment_opening_proof_from_bs58(&merkle_proof_bs58))
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

async fn submit_order(item: protocol::LotteryOrder) -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8080/submit")
        .json(&item)
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("submitted lottery order to zkBricks lottery subnet...");
    } else {
        println!("Failed to create item: {:?}", response.status());
    }
    
    Ok(())
}

async fn perform_lottery() -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8080/lottery")
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("invoking the lottery event...");
    } else {
        println!("Failed to execute lottery: {:?}", response.status());
    }
    
    Ok(())
}

fn airdrop() -> Vec<JZRecord<8>> {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (_, _, crs) = protocol::trusted_setup();

    // Anonymous function to generate an array
    let create_array = |input: u8| -> [u8; 31] {
        let mut arr = [0; 31];
        arr[0] = input;
        arr
    };

    let mut coins = Vec::new();
    for i in 0..64u8 {
        let mut entropy = [0u8; 31];
        rng.fill_bytes(&mut entropy);
    
        let mut blind = [0u8; 31];
        rng.fill_bytes(&mut blind);

        let pubk = if i == 0 { alice_key().1 } else { bob_key().1 };
        let amount = if i == 0 { 15u8 } else { 22u8 };

        let fields: [Vec<u8>; 8] = 
        [
            entropy.to_vec(),
            pubk.to_vec(), //owner
            create_array(1).to_vec(), //asset id
            create_array(amount).to_vec(), //amount
            vec![AppId::OWNED as u8], //app id
            vec![0u8; 31],
            vec![0u8; 31],
            vec![0u8; 31],
        ];

        let coin = JZRecord::<8>::new(&crs, &fields, &blind.to_vec());
        coins.push(coin);
    }

    coins
}


fn create_lottery_app_coin(template: &JZRecord<8>) -> JZRecord<8> {
    let mut coin = template.clone();
    coin.fields[APP_ID] = vec![AppId::LOTTERY as u8];

    coin
}


fn create_placeholder_coin(template: &JZRecord<8>) -> JZRecord<8> {
    
    let (_, _, crs) = protocol::trusted_setup();
    
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let mut entropy = [0u8; 31];
    rng.fill_bytes(&mut entropy);

    let mut amount = [0u8; 31];
    rng.fill_bytes(&mut amount);

    let fields: [Vec<u8>; 8] = 
    [
        entropy.to_vec(),
        template.fields[OWNER].clone(), //owner
        template.fields[ASSET_ID].clone(), //asset id
        amount.to_vec(), //amount
        vec![AppId::OWNED as u8], //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

/*
fn parse_args() {
    let matches = App::new("zkBricks Client")
    .version("1.0")
    .author("zkBricks Inc. <help@zkbricks.com>")
    .about("Submits transactions to zkBricks testnet")
    .arg(
        Arg::with_name("username")
            .short('u') // allows -u
            .long("username") // allows --username
            .takes_value(true)
            .help("Sets the username"),
    )
    .arg(
        Arg::with_name("verbose")
            .short('v')
            .long("verbose")
            .multiple(true) // allows -v, -vv, -vvv, etc.
            .help("Sets the level of verbosity"),
    )
    .get_matches();

    let username = matches.value_of("username").unwrap_or("Guest");
    let verbosity = matches.occurrences_of("verbose");

    println!("Username: {}", username);
    println!("Verbosity level: {}", verbosity);
}
*/

#[tokio::main]
async fn main() -> reqwest::Result<()> {
    //parse_args();

    let (lottery_pk, _) = lottery::circuit_setup();
    let (onramp_pk, _) = onramp::circuit_setup();

    let coins = airdrop();

    // let records = coins
    //     .iter()
    //     .map(|coin| coin.commitment().into_affine())
    //     .collect::<Vec<_>>();
    
    // //let db = JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records);

    onramp_order(
        protocol::OnRampTransaction {
            proof: {
                let groth_proof = onramp::generate_groth_proof(&onramp_pk,&coins[0]);
                protocol::groth_proof_to_bs58(&groth_proof.0, &groth_proof.1)
            }
        }
    ).await?;

    onramp_order(
        protocol::OnRampTransaction {
            proof: {
                let groth_proof = onramp::generate_groth_proof(&onramp_pk,&coins[1]);
                protocol::groth_proof_to_bs58(&groth_proof.0, &groth_proof.1)
            }
        }
    ).await?;


    let now = Instant::now();

    // let alice_merkle_proof = JZVectorCommitmentOpeningProof {
    //     root: db.commitment(),
    //     record: db.get_record(0).clone(),
    //     path: db.proof(0),
    // };
    let alice_merkle_proof = get_merkle_proof(0).await?;
    let (alice_proof, alice_public_inputs) = lottery::generate_groth_proof(
        &lottery_pk,
        &coins[0],
        &create_lottery_app_coin(&coins[0]),
        &create_placeholder_coin(&coins[0]),
        &alice_merkle_proof,
        &alice_key().0
    );
    println!("proof generated in {}.{} secs",
        now.elapsed().as_secs(), now.elapsed().subsec_millis()
    );

    // let bob_merkle_proof = JZVectorCommitmentOpeningProof {
    //     root: db.commitment(),
    //     record: db.get_record(1).clone(),
    //     path: db.proof(1),
    // };
    let bob_merkle_proof = get_merkle_proof(1).await?;
    let (bob_proof, bob_public_inputs) = lottery::generate_groth_proof(
        &lottery_pk,
        &coins[1],
        &create_lottery_app_coin(&coins[1]),
        &create_placeholder_coin(&coins[1]),
        &bob_merkle_proof,
        &bob_key().0
    );

    // //FgvRhbyZhrB85i3Xui9iB7UjF92zVkREtcw2E1aV2y1R
    // println!("Alice's public key: {:?}", bs58_coins[0].fields[OWNER]);
    // //FfMcCs8a2Bnpo5UxkWX4APHJunSys5SDhmMuV9rfsCf9
    // println!("Bob's public key: {:?}", bs58_coins[1].fields[OWNER]);

    //list_orders().await?;
    submit_order(
        protocol::LotteryOrder {
            input_coin:
                protocol::coin_to_bs58(
                    &create_lottery_app_coin(&coins[0]).blinded_fields()
                ),
            input_coin_local_proof:
                protocol::groth_proof_to_bs58(
                    &alice_proof, &alice_public_inputs
                ),
            placeholder_output_coin:
                protocol::coin_to_bs58(
                    &create_placeholder_coin(&coins[0]).fields()
                )
        }
    ).await?;

    //list_orders().await?;
    submit_order(
        protocol::LotteryOrder {
            input_coin:
                protocol::coin_to_bs58(
                    &create_lottery_app_coin(&coins[1]).blinded_fields()
                ),
            input_coin_local_proof:
                protocol::groth_proof_to_bs58(
                    &bob_proof, &bob_public_inputs
                ),
            placeholder_output_coin:
                protocol::coin_to_bs58(
                    &create_placeholder_coin(&coins[1]).fields()
                )
        }
    ).await?;
    //list_orders().await?;
    
    perform_lottery().await?;

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