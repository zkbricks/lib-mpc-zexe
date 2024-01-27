use serde::{Deserialize, Serialize};

pub const NUM_FIELDS: usize = 8;

pub const ENTROPY: usize = 0;
pub const OWNER: usize = 1;
pub const ASSET_ID: usize = 2;
pub const AMOUNT: usize = 3;
pub const APP_ID: usize = 4;
pub const APP_INPUT_0: usize = 5;
pub const APP_INPUT_1: usize = 6;
pub const RHO: usize = 7;

pub enum AppId {
	PAYMENT = 0,
	LOTTERY = 1,
	SWAP = 2,
	TRADE = 3,
}

type Coin<F> = [F; NUM_FIELDS];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinBs58 {
	pub fields: [String; NUM_FIELDS],
}