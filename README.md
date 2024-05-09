![example workflow](https://github.com/github/docs/actions/workflows/main.yml/badge.svg)

##  Overview

Cryptography primitives and their R1CS circuit builders for building privacy-preserving apps, such as payments and swaps.

---

##  Module Structure

```
└── /
    ├── src
    │   ├── lib.rs
    │   ├── merkle_tree (generic merkle tree with app-specified CRH)
    │   │   ├── constraints.rs
    │   │   └── mod.rs
    │   ├── prf (keyed prf based on pedersen hashing)
    │   │   ├── config (sample configurations for pedersen hashing)
    │   │   │   ├── ed_on_bls12_377.rs
    │   │   │   └── ed_on_bw6_761.rs
    │   │   ├── constraints.rs
    │   │   └── mod.rs
    │   ├── record_commitment (commitments for record data structures)
    │   │   ├── kzg (generates KZG commitments by interpolating a polynomial over record's fields)
    │   │   │   ├── constraints.rs
    │   │   │   └── mod.rs
    │   │   ├── mod.rs
    │   │   └── sha256 (generates a SHA2 commitment by concatenating all of the record's fields)
    │   │       ├── constraints.rs
    │   │       └── mod.rs
    │   └── vector_commitment (commits to a vector of elements, based on merkle tree accumulators)
    │       ├── bytes (currently only supports leaves that are byte arrays)
    │       │   ├── pedersen (uses pedersen hashing for CRH, both on leaves and intermediate nodes)
    │       │   │   ├── config
    │       │   │   ├── constraints.rs
    │       │   │   └── mod.rs
    │       │   └── sha256 (uses SHA2 hashing for CRH, both on leaves and intermediate nodes)
    │       │       ├── common.rs
    │       │       ├── constraints.rs
    │       │       └── mod.rs
    │       └── mod.rs
    └── tests
```
