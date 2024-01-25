use rand_chacha::rand_core::SeedableRng;
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use lib_mpc_zexe::prf::{*, constraints::*};
use lib_mpc_zexe::prf;

pub type ConstraintF = ark_bw6_761::Fr;

pub struct PRFCircuit {
    pub prf_instance: JZPRFInstance,
}

impl ConstraintSynthesizer<ConstraintF> for PRFCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {
        
        let params_var = JZPRFParamsVar::new_constant(
            cs.clone(),
            &self.prf_instance.params
        ).unwrap();

        let prf_instance_var = JZPRFInstanceVar::new_witness(
            cs.clone(),
            || Ok(self.prf_instance)
        ).unwrap();

        prf::constraints::generate_constraints(
            cs, &params_var, &prf_instance_var
        );
        Ok(())
    }
}

fn setup_witness() -> PRFCircuit {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let params = JZPRFParams::trusted_setup(&mut rng);
    
    let input = [0u8; 32];
    let key = [25u8; 32];
    // let output = vec!
    // [
        // 217, 214, 252, 243, 200, 147, 117, 28, 
        // 142, 219, 58, 120, 65, 180, 251, 74, 
        // 234, 28, 72, 194, 161, 148, 52, 219, 
        // 10, 34, 21, 17, 33, 38, 77, 66,
    // ];

    PRFCircuit {
        prf_instance: JZPRFInstance::new(&params, &input, &key),
    }
}

#[allow(dead_code)]
fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let circuit = setup_witness();

    let (pk, vk) = Groth16::<BW6_761>::
        circuit_specific_setup(circuit, &mut rng)
        .unwrap();

    (pk, vk)
}

#[test]
fn prf() {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (pk, vk) = circuit_setup();
    let circuit = setup_witness();

    let public_input = [];

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();

    let valid_proof = Groth16::<BW6_761>::verify(&vk, &public_input, &proof).unwrap();
    assert!(valid_proof);

}