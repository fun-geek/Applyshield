//! ApplyShield core library.
//!
//! AI prepares. Security validates. The user decides.
//!
//! The binary (`main.rs`) is a thin CLI over this library so that security
//! behaviour can be tested from `tests/` exactly as an outside caller sees it.
//!
//! `unsafe` is denied crate-wide. The single exception is the FFI boundary to
//! the C matching engine in `matching::ffi`; `tests/architecture_tests.rs`
//! fails if `unsafe` appears anywhere else.

#![deny(unsafe_code)]

pub mod approval;
pub mod audit;
pub mod checks;
pub mod cli;
pub mod domain;
pub mod drafting;
pub mod handoff;
pub mod hash;
pub mod inputs;
pub mod matching;
pub mod pipeline;
pub mod security;
pub mod store;
