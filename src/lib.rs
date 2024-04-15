#![allow(dead_code)]
#![deny(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    // missing_docs
)]
#![forbid(unsafe_code)]

#[allow(unused_imports)]
#[macro_use]
extern crate derivative;

pub mod merkle_tree;
pub mod vector_commitment;
pub mod record_commitment;
pub mod prf;

pub mod collaborative_snark;

pub mod coin;
pub mod utils;
