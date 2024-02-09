use std::ops::*;
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
use ark_poly::univariate::DensePolynomial;
use ark_poly::Polynomial;

use crate::utils;
use crate::collaborative_snark::plonk::PlonkProof;
use crate::{vector_commitment, record_commitment, prf};
use crate::vector_commitment::bytes::{*, constraints::*};
use crate::record_commitment::{*, constraints::*};
use crate::prf::{*, constraints::*};
use crate::coin::*;


type ConstraintF = ark_bw6_761::Fr;
type F = ark_bls12_377::Fr;

pub fn collaborative_prover<const N: usize>(
    input_coins_poly: &[DensePolynomial<F>],
    output_coins_poly: &[DensePolynomial<F>],
) -> (Vec<DensePolynomial<F>>, Vec<DensePolynomial<F>>) {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    // conservation: input[0].amount + input[1].amount = output[0].amount
    let lhs_poly_1 = lagrange_polynomials[AMOUNT].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .add(input_coins_poly[1].clone())
            .sub(&output_coins_poly[0]))
        );

    // same asset id: input[0].asset_id = output[0].asset_id
    let lhs_poly_2 = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .sub(&output_coins_poly[0]))
        );

    // same asset id: input[1].asset_id = output[0].asset_id
    let lhs_poly_3 = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[1].clone()
            .sub(&output_coins_poly[0]))
        );

    // same asset id: input[0].app_id = output[0].asset_id
    let app_id_lottery_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::LOTTERY as u64)
    );

    let lhs_poly_4 = lagrange_polynomials[APP_ID].clone()
        .mul(
            &input_coins_poly[0].clone()
            .sub(&app_id_lottery_poly)
        );

    let lhs_poly_5 = lagrange_polynomials[APP_ID].clone()
        .mul(
            &input_coins_poly[1].clone()
            .sub(&app_id_lottery_poly)
        );

    (vec![lhs_poly_1, lhs_poly_2, lhs_poly_3, lhs_poly_4, lhs_poly_5], vec![])
}

pub fn collaborative_verifier<const N: usize>(
    r: &F, proof: &PlonkProof
) -> Vec<F> {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    let app_id_lottery_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::LOTTERY as u64)
    );

    // polynomial identity with Schwartz-Zippel
    let lhs_1 = lagrange_polynomials[AMOUNT].evaluate(&r) * 
        (
            proof.input_coins_opening[0] +
            proof.input_coins_opening[1] -
            proof.output_coins_opening[0]
        );

    let lhs_2 = lagrange_polynomials[ASSET_ID].evaluate(&r) * 
        (
            proof.input_coins_opening[0] -
            proof.output_coins_opening[0]
        );

    let lhs_3 = lagrange_polynomials[ASSET_ID].evaluate(&r) * (
        proof.input_coins_opening[1] -
        proof.output_coins_opening[0]
    );

    let lhs_4 = lagrange_polynomials[APP_ID].evaluate(&r) *
        (   
            proof.input_coins_opening[0] -
            app_id_lottery_poly.evaluate(&r)
        );

    let lhs_5 = lagrange_polynomials[APP_ID].evaluate(&r) *
    (   
        proof.input_coins_opening[1] -
        app_id_lottery_poly.evaluate(&r)
    );

    vec![lhs_1, lhs_2, lhs_3, lhs_4, lhs_5]
}

pub struct SpendCircuit {
    pub prf_instance_nullifier: JZPRFInstance,
    pub prf_instance_ownership: JZPRFInstance,
    pub spent_coin_record: JZRecord<8>,
    pub placeholder_output_coin_record: JZRecord<8>,
    pub all_created_coins: Vec<Coin<ark_bls12_377::Fr>>,
    pub db: JZVectorDB<ark_bls12_377::G1Affine>,
    pub index: usize,
}

impl ConstraintSynthesizer<ConstraintF> for SpendCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        let crs_var = JZKZGCommitmentParamsVar::<8>::new_constant(
            cs.clone(),
            self.spent_coin_record.crs.clone()
        ).unwrap();

        //--------------- Private key knowledge ------------------

        let params_var = JZPRFParamsVar::new_constant(
            cs.clone(),
            &self.prf_instance_ownership.params
        ).unwrap();

        let prf_instance_var = JZPRFInstanceVar::new_witness(
            cs.clone(),
            || Ok(self.prf_instance_ownership)
        ).unwrap();

        prf::constraints::generate_constraints(
            cs.clone(), &params_var, &prf_instance_var
        );

        //--------------- KZG proof for placeholder coin ------------------

        let coin_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(self.placeholder_output_coin_record.borrow())
        ).unwrap();

        let record = self.placeholder_output_coin_record.borrow();
        let computed_com = record.commitment().into_affine();

        let placeholder_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "placeholder_com_x"),
            || { Ok(computed_com.x) },
        ).unwrap();

        let placeholder_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "placeholder_com_y"),
            || { Ok(computed_com.y) },
        ).unwrap();

        record_commitment::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &coin_var
        ).unwrap();

        // compute the affine var from the projective var
        let coin_com_affine = coin_var.commitment.to_affine().unwrap();
        // does the computed com match the input com?
        coin_com_affine.x.enforce_equal(&placeholder_com_x)?;
        coin_com_affine.y.enforce_equal(&placeholder_com_y)?;

        //--------------- KZG proof for spent coin ------------------

        let crs_var = JZKZGCommitmentParamsVar::<8>::new_constant(
            cs.clone(),
            self.spent_coin_record.crs.clone()
        ).unwrap();
        
        let coin_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(self.spent_coin_record.borrow())
        ).unwrap();

        let record = self.spent_coin_record.borrow();
        let computed_com = record.blinded_commitment().into_affine();

        // we will publicly release a blinded commitment to hide 
        // which of the existing coins is being spent

        // a commitment is an (affine) group element so we separately 
        // expose the x and y coordinates, computed below
        let input_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_x"), 
            || { Ok(computed_com.x) },
        ).unwrap();

        let input_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_y"), 
            || { Ok(computed_com.y) },
        ).unwrap();

        record_commitment::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &coin_var
        ).unwrap();

        // compute the affine var from the projective var
        let coin_com_affine = coin_var.blinded_commitment.to_affine().unwrap();

        // does the computed com match the input com?
        coin_com_affine.x.enforce_equal(&input_com_x)?;
        coin_com_affine.y.enforce_equal(&input_com_y)?;

        //--------------- Merkle tree proof ------------------

        let proof = JZVectorCommitmentOpeningProof {
            root: self.db.commitment(),
            record: self.db.get_record(self.index).clone(),
            path: self.db.proof(self.index),
        };
        
        let params_var = JZVectorCommitmentParamsVar::new_constant(
            cs.clone(),
            &self.db.vc_params
        ).unwrap();

        let proof_var = JZVectorCommitmentOpeningProofVar::new_witness(
            cs.clone(),
            || Ok(&proof)
        ).unwrap();

        let root_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_root_x"), 
            || { Ok(proof.root.x) },
        ).unwrap();

        let root_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_root_y"), 
            || { Ok(proof.root.y) },
        ).unwrap();

        proof_var.root_var.x.enforce_equal(&root_com_x)?;
        proof_var.root_var.y.enforce_equal(&root_com_y)?;

        vector_commitment::bytes::constraints::generate_constraints(
            cs.clone(), &params_var, &proof_var
        );

        // --------------- Nullifier ------------------

        let nullifier_prf_f = BigInt::<6>::from_bits_le(
            &utils::bytes_to_bits(
                &self.prf_instance_nullifier.evaluate()
            )
        );

        let nullifier_x_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "nullifier_prf"), 
            || { Ok(ark_bls12_377::Fq::from(nullifier_prf_f)) },
        ).unwrap();

        let params_var = JZPRFParamsVar::new_constant(
            cs.clone(),
            &self.prf_instance_nullifier.params
        ).unwrap();

        let nullifier_prf_instance_var = JZPRFInstanceVar::new_witness(
            cs.clone(),
            || Ok(self.prf_instance_nullifier)
        ).unwrap();

        prf::constraints::generate_constraints(
            cs.clone(), &params_var, &nullifier_prf_instance_var
        );

        //--------------- Binding the four ------------------

        let coin_com_affine = coin_var.commitment.to_affine().unwrap();
        // just compare the x-coordinate...that's what compressed mode stores anyways
        // see ark_ec::models::short_weierstrass::GroupAffine::to_bytes
        let mut com_byte_vars: Vec::<UInt8<ConstraintF>> = Vec::new();
        com_byte_vars.extend_from_slice(&coin_com_affine.x.to_bytes()?);

        for (i, byte_var) in com_byte_vars.iter().enumerate() {
            // the serialization impl for CanonicalSerialize does x first
            byte_var.enforce_equal(&proof_var.leaf_var[i])?;
        }

        // prove ownership of the coin. Does sk correspond to coin's pk?
        for (i, byte_var) in coin_var.fields[OWNER].iter().enumerate() {
            byte_var.enforce_equal(&prf_instance_var.output_var[i])?;
        }

        // prove PRF output of nullifier
        let mut prf_byte_vars: Vec::<UInt8<ConstraintF>> = Vec::new();
        prf_byte_vars.extend_from_slice(&nullifier_x_var.to_bytes()?);
        for (i, byte_var) in nullifier_prf_instance_var.output_var.iter().enumerate() {
            byte_var.enforce_equal(&prf_byte_vars[i])?;
        }

        Ok(())
    }
}

pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    // create a circuit with a dummy witness
    let circuit = {
        let prf_params = JZPRFParams::trusted_setup(&mut rng);
        let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);
    
        let mut coins = Vec::new();
        let mut records = Vec::new();
        for _ in 0..2u8 {
            let fields: [Vec<u8>; 8] = 
            [
                vec![0u8; 31],
                vec![0u8; 31], //owner
                vec![0u8; 31], //asset id
                vec![0u8; 31], //amount
                vec![AppId::LOTTERY as u8], //app id
                vec![0u8; 31],
                vec![0u8; 31],
                vec![0u8; 31],
            ];
    
            let coin = JZRecord::<8>::new(&crs, &fields, &[0u8; 31].into());
            records.push(coin.commitment().into_affine());
            coins.push(coin);
        }
    
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);
        let db = JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records);
    
        SpendCircuit {
            prf_instance_ownership: JZPRFInstance::new(
                &prf_params, &[0u8; 32], &[0u8; 32]
            ),
            prf_instance_nullifier: JZPRFInstance::new(
                &prf_params, coins[0].fields[RHO].as_slice(), &[0u8; 32]
            ),
            spent_coin_record: coins[0].clone(), // doesn;t matter what value the coin has
            placeholder_output_coin_record: coins[1].clone(), // doesn't matter what value
            all_created_coins: coins.iter().map(|coin| coin.fields()).collect(),
            db: db,
            index: 0,
        }
    };

    let (pk, vk) = Groth16::<BW6_761>::
        circuit_specific_setup(circuit, &mut rng)
        .unwrap();

    (pk, vk)
}

pub fn generate_groth_proof(
    pk: &ProvingKey<BW6_761>,
    coins: &Vec<JZRecord<8>>,
    coin_index: usize,
    placeholder_coin: &JZRecord<8>,
    sk: &[u8; 32]
) -> (Proof<BW6_761>, Vec<ConstraintF>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let prf_params = JZPRFParams::trusted_setup(&mut rng);
    let _crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

    let records = coins
        .iter()
        .map(|coin| coin.commitment().into_affine())
        .collect::<Vec<_>>();

    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);
    let db = JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records);

    let circuit = SpendCircuit {
        prf_instance_ownership: JZPRFInstance::new(
            &prf_params, &[0u8; 32], sk
        ),
        prf_instance_nullifier: JZPRFInstance::new(
            &prf_params, coins[coin_index].fields[RHO].as_slice(), sk
        ),
        spent_coin_record: coins[coin_index].clone(),
        placeholder_output_coin_record: placeholder_coin.clone(),
        all_created_coins: coins.iter().map(|coin| coin.fields()).collect(),
        db: db,
        index: coin_index,
    };

    let blinded_com = circuit.spent_coin_record.blinded_commitment().into_affine();
    let placeholder_com = circuit.placeholder_output_coin_record.commitment().into_affine();

    let input_root = circuit.db.commitment();
    let nullifier = ConstraintF::from(
            BigInt::<6>::from_bits_le(
            &utils::bytes_to_bits(
                &circuit.prf_instance_nullifier.evaluate()
            )
        )
    );

    let public_inputs = vec![
        placeholder_com.x,
        placeholder_com.y,
        blinded_com.x,
        blinded_com.y,
        input_root.x,
        input_root.y,
        nullifier
    ];

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    
    (proof, public_inputs)
}
