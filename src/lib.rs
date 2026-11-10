//! ApplyShield core library.
//!
//! AI prepares. Security validates. The user decides.
//!
//! The binary (`main.rs`) is a thin CLI over this library so that security
//! behaviour can be tested from `tests/` exactly as an outside caller sees it.

#![forbid(unsafe_code)]

pub mod security;
