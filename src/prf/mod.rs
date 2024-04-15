pub mod constraints;

use ark_crypto_primitives::crh::{pedersen, *};
use ark_ec::CurveConfig;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_ed_on_bw6_761::{EdwardsProjective as JubJub, EdwardsConfig};
use std::io::Cursor;

#[derive(Clone)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

pub type H = pedersen::CRH<JubJub, Window4x256>;
pub type HOutput = <EdwardsConfig as CurveConfig>::BaseField;

#[derive(Clone)]
pub struct JZPRFParams {
    pub crh_params: <H as CRHScheme>::Parameters,
}

impl JZPRFParams {
    pub fn trusted_setup<R: Rng>(rng: &mut R) -> Self {
        JZPRFParams {
            crh_params: <H as CRHScheme>::setup(rng).unwrap(),
        }
    }
}

pub struct JZPRFInstance {
    pub params: JZPRFParams,
    pub input: Vec<u8>,
    pub key: Vec<u8>,
}

impl JZPRFInstance {
    pub fn new(
        params: &JZPRFParams,
        input: &[u8],
        key: &[u8],
    ) -> Self {
        JZPRFInstance {
            params: params.clone(),
            input: input.to_vec(),
            key: key.to_vec(),
        }
    }

    //output <H as CRHScheme>::Output
    pub fn evaluate(&self) -> Vec<u8> {
        let mut prf_input = vec![];
        prf_input.extend_from_slice(&self.input);
        prf_input.extend_from_slice(&self.key);

        let crh_output: <H as CRHScheme>::Output = 
            <H as CRHScheme>::evaluate(
                &self.params.crh_params,
                prf_input
            )
            .unwrap();

        // we only return the x coordinate
        // crh_output.x: <EdwardsConfig as CurveConfig>::BaseField
        let crh_output = crh_output.x;

        let mut serialized = vec![0; crh_output.serialized_size(ark_serialize::Compress::No)];
        let mut cursor = Cursor::new(&mut serialized[..]);
        crh_output.serialize_uncompressed(&mut cursor).unwrap();

        serialized
    }
}

#[cfg(test)]
mod tests {
    use crate::prf::*;
    use rand::SeedableRng;

    #[test]
    fn test_jzprf() {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        // TODO: for now we sample the public parameters directly;
        // we should change this to load from a file produced by a trusted setup
        let prf_params = JZPRFParams::trusted_setup(&mut rng);
        
        let input = [0u8; 32];
        let key = [25u8; 32];

        let instance = JZPRFInstance::new(&prf_params, &input, &key);
        let _prf_output = instance.evaluate();
    }
}
