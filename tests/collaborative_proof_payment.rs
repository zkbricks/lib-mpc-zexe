use ark_std::*;
use std::ops::*;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial
};

use lib_mpc_zexe::utils;
use lib_mpc_zexe::collaborative_snark::plonk::PlonkProof;
use lib_mpc_zexe::coin::*;

type F = ark_bls12_377::Fr;

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
    let app_id_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::PAYMENT as u64)
    );

    let lhs_poly_3 = lagrange_polynomials[APP_ID].clone()
        .mul(
            &input_coins_poly[0].clone()
            .sub(&app_id_poly)
        );

    (vec![lhs_poly_1, lhs_poly_2, lhs_poly_3], vec![])
}


pub fn mpc_verifier<const N: usize>(
    r: &F, proof: &PlonkProof
) -> Vec<F> {
    let lagrange_polynomials = (0..N)
        .map(|i| utils::lagrange_poly(N, i))
        .collect::<Vec<DensePolynomial<F>>>();

    let app_id_poly = utils::poly_eval_mult_const(
        &lagrange_polynomials[APP_ID].clone(),
        &F::from(AppId::PAYMENT as u64)
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
            app_id_poly.evaluate(&r)
        );

    vec![lhs_1, lhs_2, lhs_3]
}


#[cfg(test)]
mod tests {
    use lib_mpc_zexe::record_commitment::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand::RngCore;
    use lib_mpc_zexe::collaborative_snark::plonk::*;
    use super::*;

    #[test]
    fn test_plonk_lottery() {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

        let mut entropy = [0u8; 24];
        rng.fill_bytes(&mut entropy);

        let mut blind = [0u8; 24];
        rng.fill_bytes(&mut blind);

        let mut coins = Vec::new();
        for i in 0..2 {
            let pubk = if i == 0 { alice_key().1 } else { bob_key().1 };
            let fields: [Vec<u8>; 8] = 
            [
                entropy.to_vec(),
                pubk.to_vec(), //owner
                vec![1u8], //asset id
                vec![10u8], //amount
                vec![AppId::PAYMENT as u8], //app id
                vec![0u8],
                vec![0u8],
                vec![0u8; 32],
            ];

            let coin = JZRecord::<8>::new(&crs, &fields, &blind.to_vec());
            coins.push(coin.fields());

        }

        let proof = plonk_prove(
            &crs, 
            vec![coins[0].clone()].as_slice(), 
            vec![coins[1].clone()].as_slice(),
            super::mpc_prover::<8>
        );

        plonk_verify(
            &crs,
            &proof,
            super::mpc_verifier::<8>
        );
        
    }

}