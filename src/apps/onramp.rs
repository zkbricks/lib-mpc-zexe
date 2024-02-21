use std::cmp::min;
use rand_chacha::rand_core::SeedableRng;
use std::borrow::Borrow;

use ark_ec::*;
use ark_ff::*;
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use crate::{protocol, utils};
use crate::record_commitment;
use crate::record_commitment::{*, constraints::*};
use crate::coin::*;

// Finite Field used to encode the zk circuit
type ConstraintF = ark_bw6_761::Fr;
// Finite Field used to encode the coin data structure
type F = ark_bls12_377::Fr;

// the public inputs in the Groth proof are ordered as follows
#[allow(non_camel_case_types)]
pub enum GrothPublicInput {
    ASSET_ID = 0,
    AMOUNT = 1,
    COIN_COM_X = 2,
    COIN_COM_Y = 3,
}


/// OnRampCircuit is used to prove that the new coin being created
/// during the on-ramp process commits to the amount and asset_id
/// being claimed by the client.
pub struct OnRampCircuit {
    /// public parameters (CRS) for the KZG commitment scheme
    pub crs: JZKZGCommitmentParams<8>,

    /// all fields of the spent coin is a secret witness in the proof generation
    pub unspent_coin_record: JZRecord<8>,
}

/// ConstraintSynthesizer is a trait that is implemented for the OnRampCircuit;
/// it contains the logic for generating the constraints for the SNARK circuit
/// that will be used to generate the local proof encoding a valid coin creation.
impl ConstraintSynthesizer<ConstraintF> for OnRampCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        // let us first allocate constants for all public parameters

        // we need a constant in our spending circuit for the crs,
        // so let's grab it from some coins (all coins use the same crs)
        let crs_var = JZKZGCommitmentParamsVar::<8>::new_constant(
            cs.clone(),
            self.crs
        ).unwrap();

        //----------------- public values for the coin ---------------------

        // we need the asset_id and amount to be public inputs to the circuit
        // so let's create variables for them
        let asset_id = ConstraintF::from(
            BigInt::<6>::from_bits_le(
                utils::bytes_to_bits(
                    &self.unspent_coin_record.fields[ASSET_ID]
                ).as_slice()
            )
        );

        let asset_id_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "asset_id"), 
            || { Ok(asset_id) },
        ).unwrap();

        let amount = ConstraintF::from(
            BigInt::<6>::from_bits_le(
                utils::bytes_to_bits(
                    &self.unspent_coin_record.fields[AMOUNT]
                ).as_slice()
            )
        );

        let amount_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "amount"), 
            || { Ok(amount) },
        ).unwrap();

        //--------------- KZG commitment for unspent coin ------------------
        
        let unspent_coin_record = self.unspent_coin_record.borrow();

        let unspent_coin_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(unspent_coin_record)
        ).unwrap();

        let unspent_coin_commitment = unspent_coin_record
            .commitment()
            .into_affine();

        // a commitment is an (affine) group element so we separately 
        // expose the x and y coordinates, computed below
        let stmt_unspent_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "unspent_com_x"), 
            || { Ok(unspent_coin_commitment.x) },
        ).unwrap();

        let stmt_unspent_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "unspent_com_y"), 
            || { Ok(unspent_coin_commitment.y) },
        ).unwrap();

        // fire off the constraint generation which will include the 
        // circuitry to compute the KZG commitment
        record_commitment::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &unspent_coin_var
        ).unwrap();

        // compute the affine var from the projective var
        let unspent_coin_var_com = unspent_coin_var
            .commitment
            .to_affine()
            .unwrap();

        // does the computed com match the input com?
        unspent_coin_var_com.x.enforce_equal(&stmt_unspent_com_x)?;
        unspent_coin_var_com.y.enforce_equal(&stmt_unspent_com_y)?;

        //--------------- Binding all circuit gadgets together ------------------

        // let's constrain the amount bits to be equal to the amount_var
        let min_len = min(
            unspent_coin_var.fields[AMOUNT].len(),
            amount_var.to_bytes()?.len(),
        );
        for i in 0..min_len {
            unspent_coin_var.fields[AMOUNT][i].enforce_equal(&amount_var.to_bytes()?[i])?;
        }

        // let's constrain the asset_id bits to be equal to the asset_id_var
        let min_len = min(
            unspent_coin_var.fields[ASSET_ID].len(),
            asset_id_var.to_bytes()?.len(),
        );
        for i in 0..min_len {
            unspent_coin_var.fields[ASSET_ID][i].enforce_equal(&asset_id_var.to_bytes()?[i])?;
        }

        Ok(())
    }
}

pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {

    // create a circuit with a dummy witness
    let circuit = {
        let (_, _, crs) = protocol::trusted_setup();
        
        // our dummy witness is a coin with all fields set to zero
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

        // let's create our dummy coin out of the above zeroed fields
        let coin = JZRecord::<8>::new(&crs, &fields, &[0u8; 31].into());
    
        OnRampCircuit {
            crs: crs,
            unspent_coin_record: coin.clone(), // doesn't matter what value the coin has
        }
    };

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (pk, vk) = Groth16::<BW6_761>::
        circuit_specific_setup(circuit, &mut rng)
        .unwrap();

    (pk, vk)
}

pub fn generate_groth_proof(
    pk: &ProvingKey<BW6_761>,
    unspent_coin: &JZRecord<8>,
) -> (Proof<BW6_761>, Vec<ConstraintF>) {

    let (_, _, crs) = protocol::trusted_setup();

    let circuit = OnRampCircuit {
        crs: crs,
        unspent_coin_record: unspent_coin.clone(),
    };

    // native computation of the created coin's commitment
    let unspent_coin_com = circuit.unspent_coin_record
        .commitment()
        .into_affine();

    // construct a BW6_761 field element from the asset_id bits
    let asset_id = ConstraintF::from(
        BigInt::<6>::from_bits_le(
            utils::bytes_to_bits(
                &circuit.unspent_coin_record.fields[ASSET_ID]
            ).as_slice()
        )
    );

    // construct a BW6_761 field element from the amount bits
    let amount = ConstraintF::from(
        BigInt::<6>::from_bits_le(
            utils::bytes_to_bits(
                &circuit.unspent_coin_record.fields[AMOUNT]
            ).as_slice()
        )
    );

    // arrange the public inputs based on the GrothPublicInput enum definition
    // pub enum GrothPublicInput {
    //     ASSET_ID = 0,
    //     AMOUNT = 1,
    //     COIN_COM_X = 2,
    //     COIN_COM_Y = 3,
    // }
    let public_inputs: Vec<ConstraintF> = vec![
        asset_id,
        amount,
        unspent_coin_com.x,
        unspent_coin_com.y,
    ];

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    
    (proof, public_inputs)
}
