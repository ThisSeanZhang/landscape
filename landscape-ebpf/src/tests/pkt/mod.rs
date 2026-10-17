//! Packet fixtures and builders, grouped by family — separate from
//! `helper` on purpose so every hand-rolled or captured byte blob lives here:
//!
//! - [`v4`] / [`v6`]: parameterized IP-family builders (TCP/UDP/NS/DAD/MSS)
//! - [`pppoe`]: PPPoE session encapsulation
//! - [`frame`]: fixed ethernet-frame samples (fragments, ICMP errors, ...)
//! - [`capture`]: bare-hex fixtures taken from real captures
// Consumers are topic tests that may be compiled out in a partial build;
// the full `bpf-test` build enforces dead-code hygiene.
#![cfg_attr(not(feature = "bpf-test"), allow(dead_code, unused_imports))]

pub(crate) mod capture;
pub(crate) mod frame;
pub(crate) mod pppoe;
pub(crate) mod v4;
pub(crate) mod v6;

pub(crate) use capture::*;
pub(crate) use frame::*;
pub(crate) use pppoe::*;
pub(crate) use v4::*;
pub(crate) use v6::*;
