use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use rand_chacha::rand_core::SeedableRng;
use std::time::Instant;

use ark_ff::{*};
use ark_std::{*, rand::RngCore};

use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::apps::lottery;
use lib_mpc_zexe::record_commitment::*;
use lib_mpc_zexe::encoding::*;


#[derive(Debug, Serialize, Deserialize, Clone)]
struct Order {
    id: i32,
    input_coin: CoinBs58,
    input_coin_local_proof: GrothProofBs58,
    placeholder_output_coin: CoinBs58,
}

#[derive(Debug, Serialize, Deserialize)]
struct Orders {
    orders: Vec<Order>,
}

async fn list_orders() -> reqwest::Result<()> {
    let client = Client::new();
    let response: Response = client.get("http://127.0.0.1:8080/debug").send().await?;
    
    if response.status().is_success() {
        let response_content: String = response.text().await?;
        println!("List of orders: {}", response_content);
    } else {
        println!("Failed to retrieve orders: {:?}", response.status());
    }
    
    Ok(())
}

async fn submit_order(item: Order) -> reqwest::Result<()> {
    let client = Client::new();
    let response = client.post("http://127.0.0.1:8080/submit")
        .json(&item)
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("Item created successfully");
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
        println!("Lottery executed successfully");
    } else {
        println!("Failed to execute lottery: {:?}", response.status());
    }
    
    Ok(())
}

fn airdrop() -> Vec<JZRecord<8>> {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

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
            vec![AppId::LOTTERY as u8], //app id
            vec![0u8; 31],
            vec![0u8; 31],
            vec![0u8; 31],
        ];

        let coin = JZRecord::<8>::new(&crs, &fields, &blind.to_vec());
        coins.push(coin);
    }

    coins
}

fn create_output_coin(template: &JZRecord<8>) -> JZRecord<8> {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

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
        template.fields[APP_ID].clone(), //app id
        vec![0u8; 31],
        vec![0u8; 31],
        vec![0u8; 31],
    ];

    JZRecord::<8>::new(&crs, &fields, &[0u8; 31].to_vec())
}

#[tokio::main]
async fn main() -> reqwest::Result<()> {
    let (pk, _vk) = lottery::circuit_setup();

    let coins = airdrop();

    let now = Instant::now();
    let (alice_proof, alice_public_inputs) = lottery::generate_groth_proof(
        &pk, &coins, 0, &create_output_coin(&coins[0]), &alice_key().0
    );
    println!("proof generated in {}.{} secs",
        now.elapsed().as_secs(), now.elapsed().subsec_millis()
    );

    let (bob_proof, bob_public_inputs) = lottery::generate_groth_proof(
        &pk, &coins, 1, &create_output_coin(&coins[1]), &bob_key().0
    );

    let bs58_coins = coins
        .iter()
        .map(|coin| coin_to_bs58(&coin.blinded_fields()))
        .collect::<Vec<_>>();
    
    list_orders().await?;
    submit_order(
        Order {
            id:
                0,
            input_coin:
                bs58_coins[0].clone(),
            input_coin_local_proof:
                groth_proof_to_bs58(&alice_proof, &alice_public_inputs),
            placeholder_output_coin:
                coin_to_bs58(&create_output_coin(&coins[0]).fields())
        }
    ).await?;
    list_orders().await?;
    submit_order(
        Order {
            id:
                1,
            input_coin:
                bs58_coins[1].clone(),
            input_coin_local_proof:
                groth_proof_to_bs58(&bob_proof, &bob_public_inputs),
            placeholder_output_coin:
                coin_to_bs58(&create_output_coin(&coins[1]).fields())
        }
    ).await?;
    list_orders().await?;
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