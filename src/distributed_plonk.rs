use ark_ec::{*, pairing::*};
use ark_ff::*;
use ark_std::*;
use ark_std::borrow::*;
use std::ops::*;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use ark_serialize::CanonicalSerialize;
use ark_bls12_377::Bls12_377;

use rand_chacha::rand_core::SeedableRng;

use crate::utils;
use crate::record_commitment::*;
use crate::kzg::*;

type Curve = ark_bls12_377::Bls12_377;
type KZG = crate::kzg::KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
type F = ark_bls12_377::Fr;
type G1Affine = <Curve as Pairing>::G1Affine;
type G2Affine = <Curve as Pairing>::G2Affine;

struct PlonkProof {
    pub f_com: G1Affine,
    pub g_com: G1Affine,
    pub h_com: G1Affine,
    pub q_com: G1Affine,

    pub f_r: F,
    pub g_r: F,
    pub h_r: F,
    pub q_r: F,

    pub f_r_opening_proof: G1Affine,
    pub g_r_opening_proof: G1Affine,
    pub h_r_opening_proof: G1Affine,
    pub q_r_opening_proof: G1Affine,
}

#[derive(Clone)]
struct PlonkProofPhase1Ouptut {
    pub f_com: G1Affine,
    pub g_com: G1Affine,
    pub h_com: G1Affine,
    pub q_com: G1Affine,
}

struct PlonkProofPhase2Ouptut {
    pub f_r: F,
    pub g_r: F,
    pub h_r: F,
    pub q_r: F,

    pub f_r_opening_proof: G1Affine,
    pub g_r_opening_proof: G1Affine,
    pub h_r_opening_proof: G1Affine,
    pub q_r_opening_proof: G1Affine,
}

struct PlonkDataRecord<const N: usize> {
    pub fields: [F; N]
}

fn plonk_prove_phase1<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    f: &PlonkDataRecord<N>,
    g: &PlonkDataRecord<N>,
    h: &PlonkDataRecord<N>
) -> PlonkProofPhase1Ouptut {
    let kzg_crs = kzg_crs(crs);

    // compute all the polynomials
    let f_poly = record_poly::<N>(f);
    let g_poly = record_poly::<N>(g);
    let h_poly = record_poly::<N>(h);

    let l3_poly: DensePolynomial<F> = utils::lagrange_poly(N, 3);

    //compute q(x) in L_2(x) (f(x) + g(x) - h(x)) = q(x) Z(x)
    let z_poly: DensePolynomial<F> = utils::compute_vanishing_poly(N);
    let lhs_poly = l3_poly.clone()
        .mul(
            &(f_poly.clone()
            .add(g_poly.clone())
            .sub(&h_poly))
        );
    let q_poly = lhs_poly.div(&z_poly);

    // compute the commitments
    let f_com = KZG::commit_g1(&kzg_crs, &f_poly).unwrap();
    let g_com = KZG::commit_g1(&kzg_crs, &g_poly).unwrap();
    let h_com = KZG::commit_g1(&kzg_crs, &h_poly).unwrap();
    let q_com = KZG::commit_g1(&kzg_crs, &q_poly).unwrap();

    PlonkProofPhase1Ouptut {
        f_com,
        g_com,
        h_com,
        q_com,
    }

    // r = H(f,g,h,q)
    // let r = random_oracle(&[f_com, g_com, h_com, q_com]);

    // PlonkProof {
    //     f_com,
    //     g_com,
    //     h_com,
    //     q_com,

    //     f_r: f_poly.evaluate(&r),
    //     g_r: g_poly.evaluate(&r),
    //     h_r: h_poly.evaluate(&r),
    //     q_r: q_poly.evaluate(&r),

    //     f_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &f_poly, &r).unwrap(),
    //     g_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &g_poly, &r).unwrap(),
    //     h_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &h_poly, &r).unwrap(),
    //     q_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &q_poly, &r).unwrap(),
    // }

}

fn plonk_prove_phase2<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    f: &PlonkDataRecord<N>,
    g: &PlonkDataRecord<N>,
    h: &PlonkDataRecord<N>,
    phase1_outputs: Vec<PlonkProofPhase1Ouptut>
) -> PlonkProofPhase2Ouptut {
    let kzg_crs = kzg_crs(crs);

    // compute all the polynomials
    let f_poly = record_poly::<N>(f);
    let g_poly = record_poly::<N>(g);
    let h_poly = record_poly::<N>(h);

    let l3_poly: DensePolynomial<F> = utils::lagrange_poly(N, 3);

    //compute q(x) in L_2(x) (f(x) + g(x) - h(x)) = q(x) Z(x)
    let z_poly: DensePolynomial<F> = utils::compute_vanishing_poly(N);
    let lhs_poly = l3_poly.clone()
        .mul(
            &(f_poly.clone()
            .add(g_poly.clone())
            .sub(&h_poly))
        );
    let q_poly = lhs_poly.div(&z_poly);

    // compute the commitments
    let f_com = phase1_outputs
        .iter()
        .fold(G1Affine::zero(), |acc, x| (acc + x.f_com).into_affine());
    
    let g_com = phase1_outputs
        .iter()
        .fold(G1Affine::zero(), |acc, x| (acc + x.g_com).into_affine());

    let h_com = phase1_outputs
        .iter()
        .fold(G1Affine::zero(), |acc, x| (acc + x.h_com).into_affine());

    let q_com = phase1_outputs
        .iter()
        .fold(G1Affine::zero(), |acc, x| (acc + x.q_com).into_affine());
    

    // r = H(f,g,h,q)
    let r = random_oracle(&[f_com, g_com, h_com, q_com]);

    PlonkProofPhase2Ouptut {
        f_r: f_poly.evaluate(&r),
        g_r: g_poly.evaluate(&r),
        h_r: h_poly.evaluate(&r),
        q_r: q_poly.evaluate(&r),

        f_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &f_poly, &r).unwrap(),
        g_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &g_poly, &r).unwrap(),
        h_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &h_poly, &r).unwrap(),
        q_r_opening_proof: KZG::compute_opening_proof(&kzg_crs, &q_poly, &r).unwrap(),
    }

}

fn plonk_prove<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    f: &PlonkDataRecord<N>,
    g: &PlonkDataRecord<N>,
    h: &PlonkDataRecord<N>
) -> PlonkProof {
    let num_shares = 3;

    let f_shares = share_record(f, num_shares);
    let g_shares = share_record(g, num_shares);
    let h_shares = share_record(h, num_shares);

    let phase1_outputs: Vec<PlonkProofPhase1Ouptut> = (0..num_shares)
        .map(|i| plonk_prove_phase1(crs, &f_shares[i], &g_shares[i], &h_shares[i]))
        .collect();

    let phase2_outputs: Vec<PlonkProofPhase2Ouptut> = (0..num_shares)
        .map(|i| plonk_prove_phase2(crs, &f_shares[i], &g_shares[i], &h_shares[i], phase1_outputs.clone()))
        .collect();
    
    let add_all_field = |xs: Vec<F>| xs.iter().fold(F::zero(), |acc, x| acc + x);
    let add_all_g1 = |xs: Vec<G1Affine>| xs.iter().fold(G1Affine::zero(), |acc, x| (acc + x).into_affine());

    PlonkProof {
        f_com: add_all_g1(phase1_outputs.iter().map(|x| x.f_com).collect()),
        g_com: add_all_g1(phase1_outputs.iter().map(|x| x.g_com).collect()),
        h_com: add_all_g1(phase1_outputs.iter().map(|x| x.h_com).collect()),
        q_com: add_all_g1(phase1_outputs.iter().map(|x| x.q_com).collect()),

        f_r: add_all_field(phase2_outputs.iter().map(|x| x.f_r).collect()),
        g_r: add_all_field(phase2_outputs.iter().map(|x| x.g_r).collect()),
        h_r: add_all_field(phase2_outputs.iter().map(|x| x.h_r).collect()),
        q_r: add_all_field(phase2_outputs.iter().map(|x| x.q_r).collect()),

        f_r_opening_proof: add_all_g1(phase2_outputs.iter().map(|x| x.f_r_opening_proof).collect()),
        g_r_opening_proof: add_all_g1(phase2_outputs.iter().map(|x| x.g_r_opening_proof).collect()),
        h_r_opening_proof: add_all_g1(phase2_outputs.iter().map(|x| x.h_r_opening_proof).collect()),
        q_r_opening_proof: add_all_g1(phase2_outputs.iter().map(|x| x.q_r_opening_proof).collect()),
    }
}

fn plonk_verify<const N: usize>(
    crs: &JZKZGCommitmentParams<N>,
    proof: &PlonkProof
) {
    let r = random_oracle(&[
            proof.f_com,
            proof.g_com,
            proof.h_com,
            proof.q_com
        ]
    );

    let kzg_crs = kzg_crs(crs);

    assert!(KZG::check(&kzg_crs, &proof.f_com, r, proof.f_r, &proof.f_r_opening_proof));
    assert!(KZG::check(&kzg_crs, &proof.g_com, r, proof.g_r, &proof.g_r_opening_proof));
    assert!(KZG::check(&kzg_crs, &proof.h_com, r, proof.h_r, &proof.h_r_opening_proof));
    assert!(KZG::check(&kzg_crs, &proof.q_com, r, proof.q_r, &proof.q_r_opening_proof));

    let l3_poly: DensePolynomial<F> = utils::lagrange_poly(N, 3);
    let z_poly: DensePolynomial<F> = utils::compute_vanishing_poly(N);

    let l3_r = l3_poly.evaluate(&r);
    let z_r = z_poly.evaluate(&r);

    // polynomial identity with Schwartz-Zippel
    assert_eq!(l3_r * (proof.f_r + proof.g_r - proof.h_r), proof.q_r * z_r);
}

fn kzg_crs<const N: usize>(
    crs: &JZKZGCommitmentParams<N>
) -> UniversalParams<Bls12_377> {

    UniversalParams::<Bls12_377> {
        powers_of_g: crs.crs_coefficient_g1
            .to_owned()
            .iter()
            .map(|x| x.into_affine())
            .collect(),
        powers_of_h: crs.crs_coefficient_g2
            .to_owned()
            .iter()
            .map(|x| x.into_affine())
            .collect(),
    }

}

// implements additive secret sharing
fn share_record<const N: usize>(
    record: &PlonkDataRecord<N>, 
    num_shares: usize
) -> Vec<PlonkDataRecord<N>> {
    let mut shares: Vec<PlonkDataRecord<N>> = Vec::new();

    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    for party_id in 0..num_shares {
        // first num_shares - 1 parties get random values as shares
        let party_fields = if party_id < num_shares - 1 {
            let party_fields: Vec<F> = (0..N)
                .map(|_| F::rand(&mut rng))
                .collect();

            party_fields
        } else { //last party gets the remaining value
            let mut party_fields = Vec::new();
            for i in 0..N {
                let sum = (0..num_shares - 1)
                    .map(|j| shares[j].fields[i])
                    .fold(F::zero(), |acc, x| acc + x);

                party_fields.push(record.fields[i] - sum);
            }

            party_fields
        };

        shares.push(PlonkDataRecord {
            fields: party_fields.try_into().unwrap(),
        });
    }

    shares

}

fn record_poly<const N: usize>(record: &PlonkDataRecord<N>) -> DensePolynomial<F> {    
    //powers of nth root of unity
    let domain = Radix2EvaluationDomain::<F>::new(N).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(record.fields.to_vec(), domain);
    //interpolated polynomial over the n points
    eval_form.interpolate()
}

fn random_oracle(
    commitments: &[G1Affine],
) -> F {
    let mut serialized_elements = Vec::new();
    for com in commitments {
        let mut serialized_data = Vec::new();
        com.serialize_uncompressed(&mut serialized_data).unwrap();

        serialized_elements.push(serialized_data);
    }

    utils::fs_hash(&serialized_elements, 1)[0]
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_plonk_conservation_of_value() {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        let crs = JZKZGCommitmentParams::<8>::trusted_setup(&mut rng);

        let mut entropy = [0u8; 24];
        rng.fill_bytes(&mut entropy);

        let mut blind = [0u8; 24];
        rng.fill_bytes(&mut blind);

        // some values s.t. [2] = [0] + [1]
        let coin_amounts = [15u8, 22u8, 37u8];

        let mut coins = Vec::new();
        let mut plonk_coins = Vec::new();
        for i in 0..3 {
            let fields: [Vec<u8>; 8] = 
            [
                entropy.to_vec(),
                vec![0u8], //owner
                vec![1u8], //asset id
                vec![coin_amounts[i]], //amount
                vec![0u8],
                vec![0u8],
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

        let proof = plonk_prove(&crs, &plonk_coins[0], &plonk_coins[1], &plonk_coins[2]);
        plonk_verify(&crs, &proof);
        
    }


    #[test]
    fn test_secret_sharing() {
        const N: usize = 8;

        let expected_fields: [F; N] = 
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

        //let coin = JZRecord::<N>::new(&crs, &fields, &blind.to_vec());
        let plonk_coin = PlonkDataRecord::<8> { fields: expected_fields };

        let num_shares = 3;
        let shares = share_record(&plonk_coin, num_shares);
        for i in 0..N {
            let sum = (0..num_shares)
                .map(|j| shares[j].fields[i])
                .fold(F::zero(), |acc, x| acc + x);

            assert_eq!(expected_fields[i], sum);
        }
    }
}