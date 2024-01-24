use ark_std::*;
use std::ops::*;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial
};

use crate::utils;
use crate::plonk::PlonkProof;
use crate::coin::*;

type F = ark_bls12_377::Fr;

pub fn prover<const N: usize>(
    input_coins_poly: &[DensePolynomial<F>],
    output_coins_poly: &[DensePolynomial<F>],
) -> (Vec<DensePolynomial<F>>, Vec<DensePolynomial<F>>) {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    let shift = APP_INPUT_0 - AMOUNT;
    let input_coin_0_shifted_poly =
        utils::poly_domain_shift::<F,N>(&input_coins_poly[0], shift);

    let input_coin_1_shifted_poly =
        utils::poly_domain_shift::<F,N>(&input_coins_poly[1], shift);

    //output = (input - change) * rate
    let input_minus_change_poly = input_coins_poly[0].clone()
        .sub(&output_coins_poly[2].clone());

    let lhs_poly_0 = lagrange_polynomials[AMOUNT].clone()
    .mul(
        &output_coins_poly[0].clone()
        .sub(&input_minus_change_poly.mul(
            &input_coin_0_shifted_poly.clone()
        ))
    );

    //output * rate = (input - change)
    let input_minus_change_poly = input_coins_poly[1].clone()
        .sub(&output_coins_poly[3].clone());

    let lhs_poly_1 = lagrange_polynomials[AMOUNT].clone()
        .mul(
            &input_minus_change_poly
            .sub(&output_coins_poly[1].clone()
                .mul(&input_coin_1_shifted_poly.clone()))
        );

    // same asset id: input[0].asset_id = output[0].asset_id
    let lhs_poly_2a = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .sub(&output_coins_poly[1]))
        );

    let lhs_poly_2b = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[0].clone()
            .sub(&output_coins_poly[2]))
        );

    // same asset id: input[1].asset_id = output[0].asset_id
    let lhs_poly_3a = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[1].clone()
            .sub(&output_coins_poly[0]))
        );

    // same asset id: input[1].asset_id = output[0].asset_id
    let lhs_poly_3b = lagrange_polynomials[ASSET_ID].clone()
        .mul(
            &(input_coins_poly[1].clone()
            .sub(&output_coins_poly[3]))
        );

    // same asset id: input[0].app_id = output[0].asset_id
    let app_id_trade_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::TRADE as u64)
    );

    let lhs_poly_4 = lagrange_polynomials[APP_ID].clone()
        .mul(
            &input_coins_poly[0].clone()
            .sub(&app_id_trade_poly)
        );

    let lhs_poly_5 = lagrange_polynomials[APP_ID].clone()
        .mul(
            &input_coins_poly[1].clone()
            .sub(&app_id_trade_poly)
        );

    let lhs_poly = vec![
        lhs_poly_0,
        lhs_poly_1,
        lhs_poly_2a,
        lhs_poly_2b,
        lhs_poly_3a,
        lhs_poly_3b,
        lhs_poly_4,
        lhs_poly_5
    ];

    let additional_poly = vec![
        input_coin_0_shifted_poly,
        input_coin_1_shifted_poly
    ];

    (lhs_poly, additional_poly)

}


pub fn verifier<const N: usize>(
    r: &F, proof: &PlonkProof
) -> Vec<F> {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    let app_id_trade_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::TRADE as u64)
    );

    // output = (input - change) * rate
    let lhs_0 = lagrange_polynomials[AMOUNT].evaluate(&r) * 
        (
            proof.output_coins_opening[0] - 
            (proof.input_coins_opening[0] - proof.output_coins_opening[2]) * 
            proof.additional_opening[0]
        );

    //output * rate = (input - change)
    let lhs_1 = lagrange_polynomials[AMOUNT].evaluate(&r) * 
        (
            proof.input_coins_opening[1] - proof.output_coins_opening[3] -
            (proof.output_coins_opening[1] * proof.additional_opening[1])
        );

    let lhs_2a = lagrange_polynomials[ASSET_ID].evaluate(&r) * 
        (
            proof.input_coins_opening[0] -
            proof.output_coins_opening[1]
        );

    let lhs_2b = lagrange_polynomials[ASSET_ID].evaluate(&r) * 
    (
        proof.input_coins_opening[0] -
        proof.output_coins_opening[2]
    );

    let lhs_3a = lagrange_polynomials[ASSET_ID].evaluate(&r) *
        (
            proof.input_coins_opening[1] -
            proof.output_coins_opening[0]
        );

    let lhs_3b = lagrange_polynomials[ASSET_ID].evaluate(&r) *
    (
        proof.input_coins_opening[1] -
        proof.output_coins_opening[3]
    );

    let lhs_4 = lagrange_polynomials[APP_ID].evaluate(&r) *
        (   
            proof.input_coins_opening[0] -
            app_id_trade_poly.evaluate(&r)
        );

    let lhs_5 = lagrange_polynomials[APP_ID].evaluate(&r) *
        (   
            proof.input_coins_opening[1] -
            app_id_trade_poly.evaluate(&r)
        );

    vec![lhs_0, lhs_1, lhs_2a, lhs_2b, lhs_3a, lhs_3b, lhs_4, lhs_5]
}

#[cfg(test)]
mod tests {
    use rand_chacha::rand_core::SeedableRng;
    use rand::RngCore;
    use crate::record_commitment::*;
    use crate::plonk::*;
    use crate::apps::trade;
    use ark_ff::{BigInt, BigInteger};
    use super::*;

    /*
    ---------------------------------------------
    Scenario 1: Bob has leftover change
    ---------------------------------------------

    Alice: 
        2 BTC. —> 20 ETH, 0 change
        output = (input - change) * rate
    Bob: 
        30 ETH —> 2 BTC, 10 ETH change
        output * rate = (input - change)

    ---------------------------------------------
    Scenario 2: Alice has leftover change
    ---------------------------------------------

    Alice: 
        3 BTC -> 20 ETH, 1 BTC change
        output = (input - change) * rate
    Bob:
        20 ETH -> 2 BTC, 0 change
        output * rate = (input - change)

    */

    fn perform_trade(
        coin_rand: [u8; 6],
        coin_owners: [u8; 6],
        coin_asset_ids: [u8; 6],
        coin_amounts: [u8; 6],
        coin_rates: [u8; 6],
    ) {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

        let mut entropy = [0u8; 24];
        rng.fill_bytes(&mut entropy);

        let mut blind = [0u8; 24];
        rng.fill_bytes(&mut blind);


        let mut coins = Vec::new();
        let mut plonk_coins = Vec::new();
        for i in 0..6 {
            let fields: [Vec<u8>; 8] = 
            [
                vec![coin_rand[i]],
                vec![coin_owners[i]], //owner
                vec![coin_asset_ids[i]], //asset id
                vec![coin_amounts[i]], //amount
                vec![AppId::TRADE as u8], //app id
                vec![coin_rates[i]],
                vec![0u8],
                vec![0u8],
            ];

            let coin = JZRecord::<8>::new(&crs, &fields, &blind.to_vec());

            // transform record's fields from byte array to field elements
            let fields: Vec<F> = coin.fields
            .iter()
            .map(|x| F::from(
                BigInt::<4>::from_bits_le(
                    utils::bytes_to_bits(x).as_slice()
                )
            ))
            .collect::<Vec<F>>();

            plonk_coins.push(PlonkDataRecord::<8> {
                fields: [
                    fields[0],
                    fields[1],
                    fields[2],
                    fields[3],
                    fields[4],
                    fields[5],
                    fields[6],
                    fields[7],
                ]
            });

            coins.push(coin);

        }

        let proof = plonk_prove(
            &crs, 
            vec![
                plonk_coins[0].clone(),
                plonk_coins[1].clone()
            ].as_slice(), 
            vec![
                plonk_coins[2].clone(),
                plonk_coins[3].clone(),
                plonk_coins[4].clone(),
                plonk_coins[5].clone(),
            ].as_slice(),
            crate::apps::trade::prover::<8>
        );

        plonk_verify(&crs, &proof, trade::verifier::<8>);

    }

    #[test]
    fn test_plonk_trade_bob_leftover_change() {
        // coin sequence: 
        // 1. Alice's input
        // 2. Bob's input
        // 3. Alice's output
        // 4. Bob's output
        // 5. Alice's output change
        // 6. Bob's output change
        let coin_rand = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8];
        // Alice is 20, Bob is 30
        let coin_owners = [20u8, 30u8, 30u8, 20u8, 20u8, 30u8];
        // asset id 2 is BTC, asset id 3 is ETH
        let coin_asset_ids = [2u8, 3u8, 3u8, 2u8, 2u8, 3u8];
        // Alice has 2 BTC, Bob has 30 ETH
        let coin_amounts = [2u8, 30u8, 20u8, 2u8, 0u8, 10u8];
        let coin_rates = [10u8, 10u8, 0u8, 0u8, 0u8, 0u8];

        perform_trade(
            coin_rand,
            coin_owners,
            coin_asset_ids,
            coin_amounts,
            coin_rates
        );    
    }

    #[test]
    fn test_plonk_trade_alice_leftover_change() {
        // coin sequence: 
        // 1. Alice's input
        // 2. Bob's input
        // 3. Alice's output
        // 4. Bob's output
        // 5. Alice's output change
        // 6. Bob's output change
        let coin_rand = [1u8, 2u8, 3u8, 4u8, 5u8, 6u8];
        // Alice is 20, Bob is 30
        let coin_owners = [20u8, 30u8, 30u8, 20u8, 20u8, 30u8];
        // asset id 2 is BTC, asset id 3 is ETH
        let coin_asset_ids = [2u8, 3u8, 3u8, 2u8, 2u8, 3u8];
        // Alice has 3 BTC, Bob has 20 ETH
        let coin_amounts = [3u8, 20u8, 20u8, 2u8, 1u8, 0u8];
        let coin_rates = [10u8, 10u8, 0u8, 0u8, 0u8, 0u8];

        perform_trade(
            coin_rand,
            coin_owners,
            coin_asset_ids,
            coin_amounts,
            coin_rates
        );    
    }
}
