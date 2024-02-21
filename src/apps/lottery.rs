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

use crate::{protocol, utils};
use crate::collaborative_snark::plonk::PlonkProof;
use crate::{vector_commitment, record_commitment, prf};
use crate::vector_commitment::bytes::{*, constraints::*};
use crate::record_commitment::{*, constraints::*};
use crate::prf::{*, constraints::*};
use crate::coin::*;

// Finite Field used to encode the zk circuit
type ConstraintF = ark_bw6_761::Fr;
// Finite Field used to encode the coin data structure
type F = ark_bls12_377::Fr;

#[allow(non_camel_case_types)]
pub enum GrothPublicInput {
	PLACEHOLDER_OUTPUT_COIN_COM_X = 0,
	PLACEHOLDER_OUTPUT_COIN_COM_Y = 1,
	BLINDED_INPUT_COIN_COM_X = 2,
	BLINDED_INPUT_COIN_COM_Y = 3,
    INPUT_ROOT_X = 4,
    INPUT_ROOT_Y = 5,
    NULLIFIER = 6,
}

/// collaborative_prover contains the application-specific functionality for
/// collaborative SNARK proof generation. Specifically, it contains the
/// logic for deriving constraints (encoded as polynomial identities) 
/// from the input and output coin polynomials -- these polynomials will 
/// be opened in the generated PLONK proof.
pub fn collaborative_prover<const N: usize>(
    input_coins_poly: &[DensePolynomial<F>],
    output_coins_poly: &[DensePolynomial<F>],
) -> (Vec<DensePolynomial<F>>, Vec<DensePolynomial<F>>) {
    // Each constraint in our app will be encoded as a polynomial equation

    // coin data structure is encoded over the lagrange basis, 
    // so let's compute the lagrange polynomials first
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    // 1) conservation of value: input[0].amount + input[1].amount = output[0].amount
    let lhs_poly_1 = lagrange_polynomials[AMOUNT].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .add(input_coins_poly[1].clone())
            .sub(&output_coins_poly[0]))
        );

    // 2) input and output coins have the same asset id, implied by 2a and 2b below

    // 2a) same asset id: input[0].asset_id = output[0].asset_id
    let lhs_poly_2a = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .sub(&output_coins_poly[0]))
        );

    // 2b) same asset id: input[1].asset_id = output[0].asset_id
    let lhs_poly_2b = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[1].clone()
            .sub(&output_coins_poly[0]))
        );

    // 3) check that the app id is LOTTERY on input[0] and input[1]
    let (lhs_poly_3a, lhs_poly_3b) = {
        let app_id_lottery_poly = utils::poly_eval_mult_const(
            &lagrange_polynomials[APP_ID].clone(),
            &F::from(AppId::LOTTERY as u64)
        );

        let lhs_poly_3a = lagrange_polynomials[APP_ID].clone()
            .mul(
                &input_coins_poly[0].clone()
                .sub(&app_id_lottery_poly)
            );

        let lhs_poly_3b = lagrange_polynomials[APP_ID].clone()
            .mul(
                &input_coins_poly[1].clone()
                .sub(&app_id_lottery_poly)
            );

        (lhs_poly_3a, lhs_poly_3b)
    };

    (vec![lhs_poly_1, lhs_poly_2a, lhs_poly_2b, lhs_poly_3a, lhs_poly_3b], vec![])
}

/// collaborative_verifier contains the application-specific functionality for
/// verifying the collaborative SNARK (PLONK) proof. Specifically, it contains 
/// the logic for checking all the application-specific polynomial identities.
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

    let lhs_2a = lagrange_polynomials[ASSET_ID].evaluate(&r) * 
        (
            proof.input_coins_opening[0] -
            proof.output_coins_opening[0]
        );

    let lhs_2b = lagrange_polynomials[ASSET_ID].evaluate(&r) * (
        proof.input_coins_opening[1] -
        proof.output_coins_opening[0]
    );

    let lhs_3a = lagrange_polynomials[APP_ID].evaluate(&r) *
        (   
            proof.input_coins_opening[0] -
            app_id_lottery_poly.evaluate(&r)
        );

    let lhs_3b = lagrange_polynomials[APP_ID].evaluate(&r) *
    (   
        proof.input_coins_opening[1] -
        app_id_lottery_poly.evaluate(&r)
    );

    vec![lhs_1, lhs_2a, lhs_2b, lhs_3a, lhs_3b]
}

/// SpendCircuit contains all the components that will be used to 
/// generate the constraints a valid spend in lib_mpc_zexe.
/// Specifically, the circuit encodes computation for checking the following properties:
/// 1. The spender knows the secret key corresponding to the coin's public key
/// 2. The computed nullifier encoded in the L1-destined proof is correct
/// 3a. The spender knows the opening for the commitment denoting the spent coin
/// 3b. The spender knows the opening for the commitment denoting the placeholder output coin
/// 4. The commitment to the spent coin exists in the merkle tree of all created coins
/// We use PRF instances for 1 and 2, KZG computation for 3a and 3b, and Merkle tree for 4.
pub struct SpendCircuit {
    /// public parameters (CRS) for the KZG commitment scheme
    pub crs: JZKZGCommitmentParams<8>,

    /// public parameters for the PRF evaluation
    pub prf_params: JZPRFParams,

    /// public parameters for the vector commitment scheme
    pub vc_params: JZVectorCommitmentParams,

    /// secret key for proving ownership of the spent coin
    pub sk: [u8; 32],

    /// all fields of the spent coin is a secret witness in the proof generation
    pub unspent_coin_record: JZRecord<8>,

    /// all fields of the live input coin derived from the above spent coin
    pub input_coin_record: JZRecord<8>,

    /// all fields of the placeholder output coin are also a secret witness
    pub placeholder_output_coin_record: JZRecord<8>,

    /// Merkle opening proof for proving existence of the unspent coin
    pub unspent_coin_existence_proof: JZVectorCommitmentOpeningProof<ark_bls12_377::G1Affine>,
}

/// ConstraintSynthesizer is a trait that is implemented for the SpendCircuit;
/// it contains the logic for generating the constraints for the SNARK circuit
/// that will be used to generate the local proof encoding a valid spend.
impl ConstraintSynthesizer<ConstraintF> for SpendCircuit {
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

        // PRF makes use of public parameters, so we make them constant
        let prf_params_var = JZPRFParamsVar::new_constant(
            cs.clone(),
            &self.prf_params
        ).unwrap();

        // Merkle tree uses Pedersen hashing, so we have public params
        let merkle_params_var = JZVectorCommitmentParamsVar::new_constant(
            cs.clone(),
            &self.vc_params
        ).unwrap();

        //--------------- KZG proof for placeholder coin ------------------
        // Here, we prove that we know the opening for the commitment denoting
        // the placeholder output coin. Note that the placeholder coin's commitment
        // is part of the statement, so it is one of the public inputs to the proof.
        // By including this proof, the verifier is convinced that the party is able
        // to later spend the output coin, as they know the opening.

        let placeholder_coin_record = self.placeholder_output_coin_record.borrow();

        // the entire placeholder output record becomes a secret witness
        let placeholder_coin_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(placeholder_coin_record)
        ).unwrap();

        // we will use its natively computed commitment to set as the public input
        let placeholder_coin_com = placeholder_coin_record
            .commitment()
            .into_affine();

        // we make the commitment to the placeholder coin be part of the statement
        // to that end, we separately enforce equality of the x and y coordinates
        let stmt_placeholder_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "placeholder_com_x"),
            || { Ok(placeholder_coin_com.x) },
        ).unwrap();

        let stmt_placeholder_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "placeholder_com_y"),
            || { Ok(placeholder_coin_com.y) },
        ).unwrap();

        // trigger the constraint generation, which includes the KZG computation;
        // the coin_var includes the variable for the "computed" commitment, so 
        // we will enforce equality of that with the input variable above
        record_commitment::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &placeholder_coin_var
        ).unwrap();

        // compute the affine var from the projective var
        let placeholder_coin_var_com = placeholder_coin_var
            .commitment
            .to_affine()
            .unwrap();

        // does the computed com match the input com?
        placeholder_coin_var_com.x.enforce_equal(&stmt_placeholder_com_x)?;
        placeholder_coin_var_com.y.enforce_equal(&stmt_placeholder_com_y)?;


        //--------------- KZG commitment for input coin ------------------
        // we will now do the same thing for the app-input coin, except
        // we will work with a blinded commitment which re-randomizes the
        // commitment (via the entropy field) to avoid linkage with unspent coin.
        // By including this proof, the verifier is convinced that the party
        // knows the opening for the commitment denoting the input coin.
        // This is a necessary precursor to proving additional properties
        // about the coin, such as its ownership and existence.
        
        let input_coin_record = self.input_coin_record.borrow();

        let input_coin_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(input_coin_record)
        ).unwrap();

        
        // ** NOTE ** that we are using the blinded commitment here 
        // to avoid revealing which of the existing coins is being spent
        let input_coin_commitment = input_coin_record
            .blinded_commitment()
            .into_affine();

        // the statement includes the blinded commitment, so let's
        // create those input variables in the circuit

        // a commitment is an (affine) group element so we separately 
        // expose the x and y coordinates, computed below
        let stmt_input_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_x"), 
            || { Ok(input_coin_commitment.x) },
        ).unwrap();

        let stmt_input_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_y"), 
            || { Ok(input_coin_commitment.y) },
        ).unwrap();

        // fire off the constraint generation which will include the 
        // circuitry to compute the KZG commitment
        record_commitment::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &input_coin_var
        ).unwrap();

        // compute the affine var from the projective var
        let input_coin_var_com = input_coin_var
            .blinded_commitment
            .to_affine()
            .unwrap();

        // does the computed com match the input com?
        input_coin_var_com.x.enforce_equal(&stmt_input_com_x)?;
        input_coin_var_com.y.enforce_equal(&stmt_input_com_y)?;

        //--------------- KZG commitment for unspent coin ------------------
        // we will now do the same thing for the unspent coin.
        // We do this not because we need to reveal the commitment, but
        // because we will prove some properties about the coin, namely
        // that it exists in the merkle tree and that the nullifier is
        // computed correctly. We will also prove that the coin is owned.
        
        let unspent_coin_record = self.unspent_coin_record.borrow();

        let unspent_coin_var = JZRecordVar::<8>::new_witness(
            cs.clone(),
            || Ok(unspent_coin_record)
        ).unwrap();

        // fire off the constraint generation which will include the 
        // circuitry to compute the KZG commitment
        record_commitment::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &unspent_coin_var
        ).unwrap();

        // We will later prove that the input_coin_var_com belongs
        // in the merkle tree.

        //--------------- Merkle tree proof ------------------
        // Here, we will prove that the commitment to the spent coin
        // exists in the merkle tree of all created coins

        let proof_var = JZVectorCommitmentOpeningProofVar::new_witness(
            cs.clone(),
            || Ok(&self.unspent_coin_existence_proof)
        ).unwrap();

        let root_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_root_x"), 
            || { Ok(self.unspent_coin_existence_proof.root.x) },
        ).unwrap();

        let root_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_root_y"), 
            || { Ok(self.unspent_coin_existence_proof.root.y) },
        ).unwrap();

        // generate the merkle proof verification circuitry
        vector_commitment::bytes::constraints::generate_constraints(
            cs.clone(), &merkle_params_var, &proof_var
        );

        proof_var.root_var.x.enforce_equal(&root_com_x)?;
        proof_var.root_var.y.enforce_equal(&root_com_y)?;

        // -------------------- Nullifier -----------------------
        // we now prove that the nullifier within the statement is computed correctly

        // prf_instance nullifier is responsible for proving that the computed
        // nullifier encoded in the L1-destined proof is correct; 
        // we use the same idea as zCash here, where nullifier = PRF(rho; sk)
        let prf_instance_nullifier = JZPRFInstance::new(
            &self.prf_params,
            self.unspent_coin_record.fields[RHO].as_slice(),
            &self.sk
        );

        // allocate the nullifier as an input variable in the statement
        let stmt_nullifier_x_var = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "nullifier_prf"), 
            || { Ok(ark_bls12_377::Fq::from(
                    BigInt::<6>::from_bits_le(
                        &utils::bytes_to_bits(
                            &prf_instance_nullifier.evaluate()
                        )
                    )
                ))
                },
        ).unwrap();

        let nullifier_prf_instance_var = JZPRFInstanceVar::new_witness(
            cs.clone(),
            || Ok(prf_instance_nullifier)
        ).unwrap();

        // trigger the constraint generation for the PRF instance
        prf::constraints::generate_constraints(
            cs.clone(),
            &prf_params_var,
            &nullifier_prf_instance_var
        );

        // constrain the nullifier in the statement to equal the PRF output
        let nullifier_prf_byte_vars: Vec::<UInt8<ConstraintF>> = stmt_nullifier_x_var
            .to_bytes()?
            .to_vec();
        for (i, byte_var) in nullifier_prf_instance_var.output_var.iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_byte_vars[i])?;
        }

        //--------------- Private key knowledge ------------------
        // we will prove that the coin is owned by the spender;
        // we just invoke the constraint generation for the PRF instance

        // prf_instance_ownership is responsible for proving knowledge
        // of the secret key corresponding to the coin's public key;
        // we use the same idea as zCash here, where pk = PRF(0; sk)
        let ownership_prf_instance = JZPRFInstance::new(
            &self.prf_params, &[0u8; 32], &self.sk
        );

        // PRF arguments for the secret witness
        let ownership_prf_instance_var = JZPRFInstanceVar::new_witness(
            cs.clone(),
            || Ok(ownership_prf_instance)
        ).unwrap();

        // trigger the constraint generation for the PRF instance
        prf::constraints::generate_constraints(
            cs.clone(),
            &prf_params_var,
            &ownership_prf_instance_var
        );

        // NOTE: We defer the proof (below) that the PRF output equals the public key of
        // the unspent coin. For now, we are just instantiating the PRF gadgetry.

        //--------------- Binding all circuit gadgets together ------------------

        // 1. constrain the sk variable in both PRFs
        for (i, byte_var) in ownership_prf_instance_var.key_var.iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_instance_var.key_var[i])?;
        }

        // 2. constrain the nullifier PRF input to be the unspent coin's rho value
        for (i, byte_var) in nullifier_prf_instance_var.input_var.iter().enumerate() {
            byte_var.enforce_equal(&unspent_coin_var.fields[RHO][i])?;
        }

        // 1. constrain the unspent coin to have the same value and owner as the input coin
        let matching_fields = vec![OWNER, AMOUNT, ASSET_ID, ENTROPY, RHO]; //let's do others too
        for field in matching_fields {
            for (i, byte_var) in unspent_coin_var.fields[field].iter().enumerate() {
                byte_var.enforce_equal(&input_coin_var.fields[field][i])?;
            }
        }

        // 2. let us first constrain the merkle leaf node to equal the unspent coin's commitment
        let unspent_coin_com_byte_vars: Vec::<UInt8<ConstraintF>> = unspent_coin_var
            .commitment // grab the commitment variable
            .to_affine().unwrap() // we always build constraints over the affine repr
            .x // we build a merkle tree out of the x-coordinates
            .to_bytes()? // let's use arkworks' to_bytes gadget
            .to_vec();
        // constrain equality w.r.t. to the leaf node, byte by byte
        for (i, byte_var) in unspent_coin_com_byte_vars.iter().enumerate() {
            // the serialization impl for CanonicalSerialize does x first
            byte_var.enforce_equal(&proof_var.leaf_var[i])?;
        }

        // 3. prove ownership of the coin. Does sk correspond to coin's pk?
        for (i, byte_var) in unspent_coin_var.fields[OWNER].iter().enumerate() {
            byte_var.enforce_equal(&ownership_prf_instance_var.output_var[i])?;
        }

        Ok(())
    }
}

pub fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {

    // create a circuit with a dummy witness
    let circuit = {
        let (prf_params, vc_params, crs) = protocol::trusted_setup();
    
        // let's create the universe of dummy coins
        let mut coins = Vec::new();
        let mut records = Vec::new();
        for _ in 0..64u8 {
            let fields: [Vec<u8>; 8] = 
            [
                vec![0u8; 31],
                vec![0u8; 31], //owner
                vec![0u8; 31], //asset id
                vec![0u8; 31], //amount
                vec![AppId::OWNED as u8], //app id
                vec![0u8; 31],
                vec![0u8; 31],
                vec![0u8; 31],
            ];
    
            let coin = JZRecord::<8>::new(&crs, &fields, &[0u8; 31].into());
            records.push(coin.commitment().into_affine());
            coins.push(coin);
        }
    
        // let's create a database of coins, and generate a merkle proof
        // we need this in order to create a circuit with appropriate public inputs
        let db = JZVectorDB::<ark_bls12_377::G1Affine>::new(&vc_params, &records);
        let merkle_proof = JZVectorCommitmentOpeningProof {
            root: db.commitment(),
            record: db.get_record(0).clone(),
            path: db.proof(0),
        };

        // note that circuit setup does not care about the values of witness variables
        SpendCircuit {
            crs: crs,
            prf_params: prf_params,
            vc_params: vc_params,
            sk: [0u8; 32],
            unspent_coin_record: coins[0].clone(), // doesn't matter what value the coin has
            input_coin_record: coins[0].clone(), // again, doesn't matter what value
            placeholder_output_coin_record: coins[0].clone(), // doesn't matter what value
            unspent_coin_existence_proof: merkle_proof,
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
    app_input_coin: &JZRecord<8>,
    placeholder_coin: &JZRecord<8>,
    unspent_coin_existence_proof: &JZVectorCommitmentOpeningProof<ark_bls12_377::G1Affine>,
    sk: &[u8; 32]
) -> (Proof<BW6_761>, Vec<ConstraintF>) {

    let (prf_params, vc_params, crs) = protocol::trusted_setup();

    let prf_instance_nullifier = JZPRFInstance::new(
        &prf_params,
        unspent_coin.fields[RHO].as_slice(),
        sk
    );

    let circuit = SpendCircuit {
        crs: crs,
        prf_params: prf_params,
        vc_params: vc_params,
        sk: sk.clone(),
        unspent_coin_record: unspent_coin.clone(),
        input_coin_record: app_input_coin.clone(),
        placeholder_output_coin_record: placeholder_coin.clone(),
        unspent_coin_existence_proof: unspent_coin_existence_proof.clone(),
    };

    // native computation of the input coin's commitment
    // Recall that the input coin is derived from the unspent coin, and blinded
    let blinded_input_coin_com = circuit.input_coin_record
        .blinded_commitment()
        .into_affine();

    // native computation of the placeholder output coin's commitment
    let placeholder_output_coin_com = circuit.placeholder_output_coin_record
        .commitment()
        .into_affine();

    // we already computed the merkle root above
    let input_root = circuit.unspent_coin_existence_proof.root;

    // native computation of the unspent coin's nullifier
    let nullifier = ConstraintF::from(
            BigInt::<6>::from_bits_le(
            &utils::bytes_to_bits(
                &prf_instance_nullifier.evaluate()
            )
        )
    );

    // arrange the public inputs according to the GrothPublicInput definition
    // pub enum GrothPublicInput {
    //     PLACEHOLDER_OUTPUT_COIN_COM_X = 0,
    //     PLACEHOLDER_OUTPUT_COIN_COM_Y = 1,
    //     BLINDED_INPUT_COIN_COM_X = 2,
    //     BLINDED_INPUT_COIN_COM_Y = 3,
    //     INPUT_ROOT_X = 4,
    //     INPUT_ROOT_Y = 5,
    //     NULLIFIER = 6,
    // }

    let public_inputs = vec![
        placeholder_output_coin_com.x,
        placeholder_output_coin_com.y,
        blinded_input_coin_com.x,
        blinded_input_coin_com.y,
        input_root.x,
        input_root.y,
        nullifier
    ];

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    
    (proof, public_inputs)
}
