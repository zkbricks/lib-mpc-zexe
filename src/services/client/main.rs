use reqwest::{Client, Error, Response};
use serde::{Deserialize, Serialize};
use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::record_commitment::*;
use rand_chacha::rand_core::SeedableRng;
use rand::RngCore;
use ark_serialize::CanonicalSerialize;

type F = ark_bls12_377::Fr;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Order {
    id: i32,
    coin: CoinBs58,
}

#[derive(Debug, Serialize, Deserialize)]
struct Orders {
    orders: Vec<Order>,
}

async fn list_orders() -> Result<(), Error> {
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

async fn submit_order(item: Order) -> Result<(), Error> {
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

    let mut coins = Vec::new();
    for i in 0..2 {
        let mut entropy = [0u8; 24];
        rng.fill_bytes(&mut entropy);
    
        let mut blind = [0u8; 24];
        rng.fill_bytes(&mut blind);

        let pubk = if i == 0 { alice_key().1 } else { bob_key().1 };
        let amount = if i == 0 { 15u8 } else { 22u8 };

        let fields: [Vec<u8>; 8] = 
        [
            entropy.to_vec(),
            pubk.to_vec(), //owner
            vec![1u8], //asset id
            vec![amount], //amount
            vec![AppId::LOTTERY as u8], //app id
            vec![0u8],
            vec![0u8],
            vec![0u8; 32],
        ];

        let coin = JZRecord::<8>::new(&crs, &fields, &blind.to_vec());
        coins.push(coin);
    }

    let bs58_coins = coins
        .iter()
        .map(|c| CoinBs58 { fields :
                c.fields()
                .iter()
                .map(|f| encode_f_as_bs58_str(f))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
            }
        )
        .collect::<Vec<_>>();
    
    list_orders().await?;
    submit_order(Order { id: 0, coin: bs58_coins[0].clone() }).await?;
    list_orders().await?;
    submit_order(Order { id: 1, coin: bs58_coins[1].clone() }).await?;
    list_orders().await?;

    Ok(())
}

fn encode_f_as_bs58_str(value: &F) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
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