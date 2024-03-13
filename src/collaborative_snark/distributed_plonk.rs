use ark_ec::*;
use ark_ff::*;
use ark_std::*;
use std::ops::*;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial,
};

use rand_chacha::rand_core::SeedableRng;

use crate::utils;
use crate::record_commitment::*;
use crate::coin::*;
use super::plonk_utils;
use super::{ProverFnT, VerifierFnT, PlonkProof, KZG, F, G1Affine};

struct PlonkProofState {
    pub input_coins_share_poly: Option<Vec<DensePolynomial<F>>>,
    pub output_coins_share_poly: Option<Vec<DensePolynomial<F>>>,
    pub quotient_share_poly: Option<DensePolynomial<F>>,
    pub additional_share_poly: Option<Vec<DensePolynomial<F>>>,

    // aggregated commitments to the input coins
    pub aggregated_input_coins_com: Option<Vec<G1Affine>>,
    // aggregated commitments to the output coins
    pub aggregated_output_coins_com: Option<Vec<G1Affine>>,
    // aggregated commitments to the input coins
    pub aggregated_quotient_com: Option<G1Affine>,
    // aggregated commitments to the output coins
    pub aggregated_additional_com: Option<Vec<G1Affine>>,
    // randomness to use for the opening
}

struct PlonkProofRound0 {
    // commitments to input coins data structures
    pub input_coins_com: Vec<G1Affine>,
    // commitments to output coins data structures
    pub output_coins_com: Vec<G1Affine>,
}

struct PlonkProofRound1 {
    // commitment to quotient polynomial
    pub quotient_com: G1Affine,
    // commitments to additional polynomials
    pub additional_com: Vec<G1Affine>,
}

struct PlonkProofRound2 {
    // openings of input coin polyomials at r
    pub input_coins_opening: Vec<F>,
    // openings of output coin polyomials at r
    pub output_coins_opening: Vec<F>,
    // opening of quotient polynomial at r
    pub quotient_opening: F,
    // openings of additional polynomials at r
    pub additional_opening: Vec<F>,

    // proof of openings of input coin polyomials at r
    pub input_coins_opening_proof: Vec<G1Affine>,
    // proof of openings of output coin polyomials at r
    pub output_coins_opening_proof: Vec<G1Affine>,
    // proof of opening of quotient polynomial at r
    pub quotient_opening_proof: G1Affine,
    // proof of openings of additional polynomials at r
    pub additional_opening_proof: Vec<G1Affine>,
}

// takes as input shares of input and output coins
// and produces an intermediate proof
fn plonk_prove_round0<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    input_coins: &[Coin<F>],
    output_coins: &[Coin<F>],
    _prover_fn: ProverFnT
) -> (PlonkProofRound0, PlonkProofState) {
    let kzg_crs = plonk_utils::kzg_crs(crs);

    let input_coins_poly = input_coins
        .iter()
        .map(|coin| plonk_utils::coin_poly::<N>(coin))
        .collect::<Vec<DensePolynomial<F>>>();

    let output_coins_poly = output_coins
        .iter()
        .map(|coin| plonk_utils::coin_poly::<N>(coin))
        .collect::<Vec<DensePolynomial<F>>>();

    // compute the commitments
    let input_coins_com = input_coins_poly
        .iter()
        .map(|f| KZG::commit_g1(&kzg_crs, f).unwrap())
        .collect::<Vec<G1Affine>>();

    let output_coins_com = output_coins_poly
        .iter()
        .map(|f| KZG::commit_g1(&kzg_crs, f).unwrap())
        .collect::<Vec<G1Affine>>();

    let round0_output = PlonkProofRound0 { input_coins_com, output_coins_com };

    let state = PlonkProofState {
        input_coins_share_poly: Some(input_coins_poly),
        output_coins_share_poly: Some(output_coins_poly),
        quotient_share_poly: None,
        additional_share_poly: None,
        aggregated_input_coins_com: None,
        aggregated_output_coins_com: None,
        aggregated_quotient_com: None,
        aggregated_additional_com: None,
    };

    (round0_output, state)
}

fn plonk_prove_round1<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    input_coins: &[Coin<F>],
    output_coins: &[Coin<F>],
    prover_fn: ProverFnT,
    round0_outputs: &[PlonkProofRound0],
    state: &PlonkProofState,
) -> (PlonkProofRound1, PlonkProofState) {
    let _num_parties = round0_outputs.len();
    let num_input_coins = input_coins.len();
    let num_output_coins = output_coins.len();

    let kzg_crs = plonk_utils::kzg_crs(crs);

    // combine shares of the commitments
    let aggregated_input_coins_com = (0..num_input_coins)
        .map(|i| round0_outputs
                .iter()
                .fold(
                    G1Affine::zero(),
                    |acc, x| (acc + x.input_coins_com[i]).into_affine()
                )
            )
        .collect::<Vec<G1Affine>>();

    let aggregated_output_coins_com = (0..num_output_coins)
        .map(|i| round0_outputs
                .iter()
                .fold(
                    G1Affine::zero(),
                    |acc, x| (acc + x.output_coins_com[i]).into_affine()
                )
            )
        .collect::<Vec<G1Affine>>();

    // lets get some randomness
    let mut ro_inputs = Vec::new();
    ro_inputs.extend_from_slice(aggregated_input_coins_com.as_slice());
    ro_inputs.extend_from_slice(aggregated_output_coins_com.as_slice());
    let alpha = plonk_utils::random_oracle(ro_inputs.as_slice());

    let (lhs_polynomials, additional_polynomials) = 
        prover_fn(
            &state.input_coins_share_poly.clone().unwrap()[..], 
            &state.output_coins_share_poly.clone().unwrap()[..]
        );

    // random linear combination of the above
    let mut lhs_poly = utils::compute_constant_poly(&F::zero());//DensePolynomial::<F>::zero();
    for (i, poly) in lhs_polynomials.iter().enumerate() {
        lhs_poly.add_assign(
            &utils::poly_eval_mult_const(poly, &alpha.pow([i as u64]))
        );
    }

    let z_poly: DensePolynomial<F> = utils::compute_vanishing_poly(N);
    let quotient_poly = lhs_poly.div(&z_poly);

    let quotient_com = KZG::commit_g1(&kzg_crs, &quotient_poly).unwrap();

    let additional_com = additional_polynomials
        .iter()
        .map(|f| KZG::commit_g1(&kzg_crs, f).unwrap())
        .collect::<Vec<G1Affine>>();

    let round1_output = PlonkProofRound1 {
        quotient_com,
        additional_com,
    };

    let state = PlonkProofState {
        input_coins_share_poly: state.input_coins_share_poly.clone(),
        output_coins_share_poly: state.output_coins_share_poly.clone(),
        quotient_share_poly: Some(quotient_poly),
        additional_share_poly: Some(additional_polynomials),
        aggregated_input_coins_com: Some(aggregated_input_coins_com),
        aggregated_output_coins_com: Some(aggregated_output_coins_com),
        aggregated_quotient_com: None,
        aggregated_additional_com: None,
    };

    (round1_output, state)
}


fn plonk_prove_round2<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    _input_coins: &[Coin<F>],
    _output_coins: &[Coin<F>],
    _prover_fn: ProverFnT,
    round1_outputs: &[PlonkProofRound1],
    state: &PlonkProofState,
) -> (PlonkProofRound2, PlonkProofState) {
    let kzg_crs = plonk_utils::kzg_crs(crs);

    let num_additional_polynomials = round1_outputs[0].additional_com.len();

    let aggregated_additional_com = (0..num_additional_polynomials)
    .map(|i| round1_outputs
            .iter()
            .fold(
                G1Affine::zero(),
                |acc, x| (acc + x.additional_com[i]).into_affine()
            )
        )
    .collect::<Vec<G1Affine>>();

    let aggregated_quotient_com = round1_outputs
        .iter()
        .fold(
            G1Affine::zero(),
            |acc, x| (acc + x.quotient_com).into_affine()
        );

    let mut ro_inputs: Vec<G1Affine> = Vec::new();
    ro_inputs.extend_from_slice(state.aggregated_input_coins_com.clone().unwrap().as_slice());
    ro_inputs.extend_from_slice(state.aggregated_output_coins_com.clone().unwrap().as_slice());
    ro_inputs.push(aggregated_quotient_com);
    let r = plonk_utils::random_oracle(ro_inputs.as_slice());

    let round2_output = PlonkProofRound2 {
        input_coins_opening: state.input_coins_share_poly
            .clone()
            .unwrap()
            .iter()
            .map(|f| f.evaluate(&r))
            .collect::<Vec<F>>(),

        output_coins_opening: state.output_coins_share_poly
            .clone()
            .unwrap()
            .iter()
            .map(|f| f.evaluate(&r))
            .collect::<Vec<F>>(),

        quotient_opening: state.quotient_share_poly
            .clone()
            .unwrap()
            .evaluate(&r),

        additional_opening: state.additional_share_poly
            .clone()
            .unwrap()
            .iter()
            .map(|f| f.evaluate(&r))
            .collect::<Vec<F>>(),

        input_coins_opening_proof: state.input_coins_share_poly
            .clone()
            .unwrap()
            .iter()
            .map(|f| KZG::compute_opening_proof(&kzg_crs, f, &r).unwrap())
            .collect::<Vec<G1Affine>>(),

        output_coins_opening_proof: state.output_coins_share_poly
            .clone()
            .unwrap()
            .iter()
            .map(|f| KZG::compute_opening_proof(&kzg_crs, f, &r).unwrap())
            .collect::<Vec<G1Affine>>(),

        quotient_opening_proof: 
            KZG::compute_opening_proof(
                &kzg_crs, &state.quotient_share_poly.clone().unwrap(), &r
            ).unwrap(),

        additional_opening_proof: state.additional_share_poly
            .clone()
            .unwrap()
            .iter()
            .map(|f| KZG::compute_opening_proof(&kzg_crs, f, &r).unwrap())
            .collect::<Vec<G1Affine>>(),
    };

    let state = PlonkProofState {
        input_coins_share_poly: state.input_coins_share_poly.clone(),
        output_coins_share_poly: state.output_coins_share_poly.clone(),
        quotient_share_poly: state.quotient_share_poly.clone(),
        additional_share_poly: state.additional_share_poly.clone(),
        aggregated_input_coins_com: state.aggregated_input_coins_com.clone(),
        aggregated_output_coins_com: state.aggregated_output_coins_com.clone(),
        aggregated_quotient_com: Some(aggregated_quotient_com),
        aggregated_additional_com: Some(aggregated_additional_com),
    };

    (round2_output, state)

}

fn plonk_prove_finish<const N: usize>(
    _crs: &JZKZGCommitmentParams<N>,
    input_coins: &[Coin<F>],
    output_coins: &[Coin<F>],
    _prover_fn: ProverFnT,
    round2_outputs: &[PlonkProofRound2],
    state: &PlonkProofState,
) -> PlonkProof {
    //let kzg_crs = plonk_utils::kzg_crs(crs);

    let num_input_coins = input_coins.len();
    let aggregated_input_coins_opening = (0..num_input_coins)
        .map(|i| round2_outputs
                .iter()
                .fold(
                    F::zero(),
                    |acc, x| (acc + x.input_coins_opening[i])
                )
            )
        .collect::<Vec<F>>();
    let aggregated_input_coins_opening_proof = (0..num_input_coins)
        .map(|i| round2_outputs
                .iter()
                .fold(
                    G1Affine::zero(),
                    |acc, x| (acc + x.input_coins_opening_proof[i]).into_affine()
                )
            )
        .collect::<Vec<G1Affine>>();


    let num_output_coins = output_coins.len();
    let aggregated_output_coins_opening = (0..num_output_coins)
        .map(|i| round2_outputs
                .iter()
                .fold(
                    F::zero(),
                    |acc, x| (acc + x.output_coins_opening[i])
                )
            )
        .collect::<Vec<F>>();

    let aggregated_output_coins_opening_proof = (0..num_output_coins)
        .map(|i| round2_outputs
                .iter()
                .fold(
                    G1Affine::zero(),
                    |acc, x| (acc + x.output_coins_opening_proof[i]).into_affine()
                )
            )
        .collect::<Vec<G1Affine>>();

    let num_additional_polynomials = state.additional_share_poly.as_ref().unwrap().len();
    let aggregated_additional_opening = (0..num_additional_polynomials)
        .map(|i| round2_outputs
                .iter()
                .fold(
                    F::zero(),
                    |acc, x| (acc + x.additional_opening[i])
                )
            )
        .collect::<Vec<F>>();

    let aggregated_additional_opening_proof = (0..num_additional_polynomials)
        .map(|i| round2_outputs
                .iter()
                .fold(
                    G1Affine::zero(),
                    |acc, x| (acc + x.additional_opening_proof[i]).into_affine()
                )
            )
        .collect::<Vec<G1Affine>>();

    let aggregated_quotient_opening = round2_outputs
        .iter()
        .fold(
            F::zero(),
            |acc, x| (acc + x.quotient_opening)
        );

    let aggregated_quotient_opening_proof = round2_outputs
        .iter()
        .fold(
            G1Affine::zero(),
            |acc, x| (acc + x.quotient_opening_proof).into_affine()
        );

    
    PlonkProof {
        input_coins_com: state.aggregated_input_coins_com.clone().unwrap(),
        output_coins_com: state.aggregated_output_coins_com.clone().unwrap(),
        quotient_com: state.aggregated_quotient_com.clone().unwrap(),
        additional_com: state.aggregated_additional_com.clone().unwrap(),

        input_coins_opening: aggregated_input_coins_opening,
        output_coins_opening: aggregated_output_coins_opening,
        quotient_opening: aggregated_quotient_opening,
        additional_opening: aggregated_additional_opening,

        input_coins_opening_proof: aggregated_input_coins_opening_proof,
        output_coins_opening_proof: aggregated_output_coins_opening_proof,
        quotient_opening_proof: aggregated_quotient_opening_proof,
        additional_opening_proof: aggregated_additional_opening_proof,
    }

}

fn plonk_prove<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    input_coins: &[Coin<F>],
    output_coins: &[Coin<F>],
    prover_fn: ProverFnT
) -> PlonkProof {
    // convert the CRS to the affine form that we like.
    //let kzg_crs = plonk_utils::kzg_crs(crs);

    let num_shares = 3;

    let input_coins_shares = input_coins
        .iter()
        .map(|coin| share_record(coin, num_shares))
        .collect::<Vec<Vec<Coin<F>>>>();

    let output_coins_shares = output_coins
        .iter()
        .map(|coin| share_record(coin, num_shares))
        .collect::<Vec<Vec<Coin<F>>>>();

    let (round0_outputs, round0_states): 
        (Vec<PlonkProofRound0>, Vec<PlonkProofState>) = (0..num_shares)
        .map(|i| plonk_prove_round0(
            crs,
            &input_coins_shares[i],
            &output_coins_shares[i],
            prover_fn))
        .collect::<Vec<(PlonkProofRound0,PlonkProofState)>>()
        .into_iter()
        .unzip();

    let (round1_outputs, round1_states): 
        (Vec<PlonkProofRound1>, Vec<PlonkProofState>) = (0..num_shares)
        .map(|i| plonk_prove_round1(
            crs,
            &input_coins_shares[i],
            &output_coins_shares[i],
            prover_fn,
            &round0_outputs,
            &round0_states[i]))
        .collect::<Vec<(PlonkProofRound1,PlonkProofState)>>()
        .into_iter()
        .unzip();

    let (round2_outputs, round2_states): 
        (Vec<PlonkProofRound2>, Vec<PlonkProofState>) = (0..num_shares)
        .map(|i| plonk_prove_round2(
            crs,
            &input_coins_shares[i],
            &output_coins_shares[i],
            prover_fn,
            &round1_outputs,
            &round1_states[i]))
        .collect::<Vec<(PlonkProofRound2,PlonkProofState)>>()
        .into_iter()
        .unzip();
    
    plonk_prove_finish(
        crs,
        &input_coins_shares[0],
        &output_coins_shares[0],
        prover_fn,
        &round2_outputs,
        &round2_states[0]
    )

}

pub fn plonk_verify<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    proof: &PlonkProof,
    verify_fn: VerifierFnT
) {
    let mut ro_inputs = Vec::new();
    ro_inputs.extend_from_slice(proof.input_coins_com.as_slice());
    ro_inputs.extend_from_slice(proof.output_coins_com.as_slice());

    let alpha = plonk_utils::random_oracle(ro_inputs.as_slice());

    ro_inputs.push(proof.quotient_com);

    let r = plonk_utils::random_oracle(ro_inputs.as_slice());

    let kzg_crs = plonk_utils::kzg_crs(crs);

    for i in 0..proof.input_coins_com.len() {
        assert!(
            KZG::check(
                &kzg_crs,
                &proof.input_coins_com[i],
                r,
                proof.input_coins_opening[i],
                &proof.input_coins_opening_proof[i]
            )
        );
    }

    for i in 0..proof.output_coins_com.len() {
        assert!(
            KZG::check(
                &kzg_crs,
                &proof.output_coins_com[i],
                r,
                proof.output_coins_opening[i],
                &proof.output_coins_opening_proof[i]
            )
        );
    }

    for i in 0..proof.additional_com.len() {
        assert!(
            KZG::check(
                &kzg_crs,
                &proof.additional_com[i],
                r,
                proof.additional_opening[i],
                &proof.additional_opening_proof[i]
            )
        );
    }

    assert!(
        KZG::check(
            &kzg_crs,
            &proof.quotient_com,
            r,
            proof.quotient_opening,
            &proof.quotient_opening_proof
        )
    );
    
    let lhs_evals = verify_fn(&r, &proof);

    let mut lhs = F::zero();
    for (i, eval) in lhs_evals.iter().enumerate() {
        let f = alpha.pow([i as u64]) * eval;
        lhs.add_assign(&f);
    }

    let z_poly: DensePolynomial<F> = utils::compute_vanishing_poly(N);
    let rhs = proof.quotient_opening * z_poly.evaluate(&r);

    assert_eq!(lhs, rhs);
}

// implements additive secret sharing for coins
fn share_record(
    record: &Coin<F>, 
    num_shares: usize
) -> Vec<Coin<F>> {
    let num_fields = record.len();
    let mut shares: Vec<Coin<F>> = Vec::new();

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    for party_id in 0..num_shares {
        // first num_shares - 1 parties get random values as shares
        let party_fields = if party_id < num_shares - 1 {
            (0..num_fields)
            .map(|_| F::rand(&mut rng))
            .collect()
        } else { //last party gets the remaining value
            let mut party_fields = Vec::new();
            for i in 0..num_fields {
                let sum = (0..num_shares - 1)
                    .map(|j| shares[j][i])
                    .fold(F::zero(), |acc, x| acc + x);

                party_fields.push(record[i] - sum);
            }

            party_fields
        };

        shares.push(party_fields.try_into().unwrap());
    }

    shares

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_sharing() {
        const N: usize = 8;

        let coin: [F; N] = 
            [
                F::from(0), //entropy
                F::from(0), //owner
                F::from(1), //asset id
                F::from(15), //amount
                F::from(0),
                F::from(0),
                F::from(0),
                F::from(0),
            ];

        let num_shares = 3;
        let shares = share_record(&coin, num_shares);
        for i in 0..N {
            let sum = (0..num_shares)
                .map(|j| shares[j][i])
                .fold(F::zero(), |acc, x| acc + x);

            assert_eq!(coin[i], sum);
        }
    }
}