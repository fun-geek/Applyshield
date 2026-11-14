//! Domain layer: the data types the rest of ApplyShield is built on.
//!
//! Named `domain` (not `core`) to avoid clashing with Rust's built-in `core` crate.

pub mod models;
pub mod sensitive;
pub mod untrusted;
