//! Manual benchmark harnesses for the DNS upstream implementations.
//!
//! This module is compiled only with the `bench` feature. The harness lives
//! inside the library because the upstream pool itself is crate-private; the
//! `benches/native_upstream.rs` target is only a thin CLI wrapper around it.

pub mod native_upstream;
