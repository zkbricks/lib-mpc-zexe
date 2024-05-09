use ark_crypto_primitives::crh::pedersen;

#[derive(Clone)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

pub type Hash = pedersen::CRH<
    ark_ed_on_bls12_377::EdwardsProjective, Window4x256
>;

pub type HashGadget = pedersen::constraints::CRHGadget<
    ark_ed_on_bls12_377::EdwardsProjective,
    ark_ed_on_bls12_377::constraints::EdwardsVar,
    Window4x256
>;

//pub type HOutput = <ark_ed_on_bls12_377::EdwardsConfig as CurveConfig>::BaseField;