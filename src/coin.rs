
// coin data structure: [entropy, owner, asset_id, amount, app (0 = lottery, 1 = swap), app_input: rate]

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
	LOTTERY = 1,
	SWAP = 2,
	TRADE = 3,
}
