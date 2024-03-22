use std::borrow::Borrow;
use rand_chacha::rand_core::SeedableRng;
use std::ops::*;

use ark_ec::{*};
use ark_ff::{*};
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::{*, rand::RngCore};
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_snark::SNARK;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial
};

use lib_mpc_zexe::utils;
use lib_mpc_zexe::{vector_commitment, record_commitment, prf};
use lib_mpc_zexe::vector_commitment::bytes::pedersen::{*, constraints::*};
use lib_mpc_zexe::record_commitment::kzg::{*, constraints::*};
use lib_mpc_zexe::prf::{*, constraints::*};
use lib_mpc_zexe::coin::*;
use lib_mpc_zexe::collaborative_snark::PlonkProof;

type F = ark_bls12_377::Fr;
pub type ConstraintF = ark_bw6_761::Fr;

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

pub struct PaymentCircuit {
    pub prf_instance_nullifier: JZPRFInstance,
    pub prf_instance_ownership: JZPRFInstance,
    pub record: JZRecord<8>,
    pub db: JZVectorDB<ark_bls12_377::G1Affine>,
    pub index: usize,
}

impl ConstraintSynthesizer<ConstraintF> for PaymentCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        //--------------- Private key ------------------

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

        //--------------- KZG proof ------------------

        let crs_var = JZKZGCommitmentParamsVar::<8>::new_constant(
            cs.clone(),
            self.record.crs.clone()
        ).unwrap();
        
        let coin_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(self.record.borrow())
        ).unwrap();

        let record = self.record.borrow();
        let computed_com = record.blinded_commitment().into_affine();

        let input_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_x"), 
            || { Ok(computed_com.x) },
        ).unwrap();

        let input_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_y"), 
            || { Ok(computed_com.y) },
        ).unwrap();

        record_commitment::kzg::constraints::generate_constraints(
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

        vector_commitment::bytes::pedersen::constraints::generate_constraints(
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

fn generate_local_witness() -> PaymentCircuit {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let prf_params = JZPRFParams::trusted_setup(&mut rng);
    let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

    let mut entropy = [0u8; 24];
    rng.fill_bytes(&mut entropy);

    let mut blind = [0u8; 24];
    rng.fill_bytes(&mut blind);

    let mut coins = Vec::new();
    let mut records = Vec::new();
    for i in 0..16u8 {
        //first coin is owned by alice, the rest by bob
        let pubk = if i == 0 { alice_key().1 } else { bob_key().1 };

        let fields: [Vec<u8>; 8] = 
        [
            entropy.to_vec(),
            pubk.to_vec(), //owner
            vec![1u8], //asset id 1
            vec![10u8], //amount 10
            vec![AppId::OWNED as u8], //app id
            vec![0u8],
            vec![0u8],
            vec![0u8; 32], //rho
        ];

        let coin = JZRecord::<8>::new(&crs, &fields, &blind.to_vec());
        records.push(coin.commitment().into_affine());
        coins.push(coin);
    }

    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);
    let db = JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records);

    PaymentCircuit {
        prf_instance_ownership: JZPRFInstance::new(
            &prf_params, &[0u8; 32], &alice_key().0
        ),
        prf_instance_nullifier: JZPRFInstance::new(
            &prf_params, coins[0].fields[RHO].as_slice(), &alice_key().0
        ),
        record: coins[0].clone(),
        db: db,
        index: 0,
    }
}


pub struct LocalProof {
    pub proof: Proof<BW6_761>,
    pub public_inputs: Vec<ConstraintF>,
    pub spent_coins: Vec<JZRecord<8>>,
}

pub fn local_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let circuit = generate_local_witness();

    let (pk, vk) = Groth16::<BW6_761>::
        circuit_specific_setup(circuit, &mut rng)
        .unwrap();

    (pk, vk)
}

pub fn local_prover(pk: ProvingKey<BW6_761>) -> LocalProof {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let circuit = generate_local_witness();

    let blinded_com = circuit.record.blinded_commitment().into_affine();
    let input_root = circuit.db.commitment();
    let nullifier = ConstraintF::from(
            BigInt::<6>::from_bits_le(
            &utils::bytes_to_bits(
                &circuit.prf_instance_nullifier.evaluate()
            )
        )
    );

    let public_inputs = vec![ 
        blinded_com.x,
        blinded_com.y,
        input_root.x,
        input_root.y,
        nullifier
    ];

    let now = std::time::Instant::now();
    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    let elapsed = now.elapsed();
    println!("Prover time: {:.2?}", elapsed);

    //grab the spent coin
    let circuit = generate_local_witness();
    LocalProof { proof, public_inputs, spent_coins: vec![circuit.record] }
}

pub fn local_verifier(vk: VerifyingKey<BW6_761>, proof: &LocalProof) {
    assert!(
            Groth16::<BW6_761>::verify(
            &vk,
            &proof.public_inputs,
            &proof.proof
        ).unwrap()
    );
}

pub fn mpc_compute<const N: usize>(spent_coin: &JZRecord<N>) -> JZRecord<N> {
    let mut new_coin = spent_coin.clone();
    new_coin.fields[OWNER] = bob_key().1.to_vec();
    new_coin
}

pub fn mpc_prover<const N: usize>(
    input_coins_poly: &[DensePolynomial<F>],
    output_coins_poly: &[DensePolynomial<F>],
) -> (Vec<DensePolynomial<F>>, Vec<DensePolynomial<F>>) {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    // conservation: input[0].amount = output[0].amount
    let lhs_poly_1 = lagrange_polynomials[AMOUNT].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .sub(&output_coins_poly[0]))
        );

    // same asset id: input[0].asset_id = output[0].asset_id
    let lhs_poly_2 = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .sub(&output_coins_poly[0]))
        );

    // same asset id: input[0].app_id = output[0].asset_id
    let app_id_lottery_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::OWNED as u64)
    );

    let lhs_poly_3 = lagrange_polynomials[APP_ID].clone()
        .mul(
            &input_coins_poly[0].clone()
            .sub(&app_id_lottery_poly)
        );

    (vec![lhs_poly_1, lhs_poly_2, lhs_poly_3], vec![])
}


pub fn mpc_verifier<const N: usize>(
    r: &F, proof: &PlonkProof
) -> Vec<F> {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    let app_id_lottery_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::OWNED as u64)
    );

    // polynomial identity with Schwartz-Zippel
    let lhs_1 = lagrange_polynomials[AMOUNT].evaluate(&r) * 
        (
            proof.input_coins_opening[0] -
            proof.output_coins_opening[0]
        );

    let lhs_2 = lagrange_polynomials[ASSET_ID].evaluate(&r) * 
        (
            proof.input_coins_opening[0] -
            proof.output_coins_opening[0]
        );

    let lhs_3 = lagrange_polynomials[APP_ID].evaluate(&r) *
        (   
            proof.input_coins_opening[0] -
            app_id_lottery_poly.evaluate(&r)
        );

    vec![lhs_1, lhs_2, lhs_3]
}



#[cfg(test)]
mod tests {
    use rand_chacha::rand_core::SeedableRng;
    use lib_mpc_zexe::collaborative_snark::plonk::*;

    use super::*;

    #[test]
    fn test_payment() {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

        let (pk, vk) = super::local_setup();
        let local_proof = super::local_prover(pk);
        let new_coin = super::mpc_compute(&local_proof.spent_coins[0]);

        let proof = plonk_prove(
            &crs, 
            vec![local_proof.spent_coins[0].fields().clone()].as_slice(), 
            vec![new_coin.fields()].as_slice(),
            super::mpc_prover::<8>
        );

        super::local_verifier(vk, &local_proof);
        plonk_verify(&crs, &proof, super::mpc_verifier::<8>);
        
    }

}
