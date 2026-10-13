//! Kernel data-plane micro-benchmarks. Kept separate from the correctness
//! suites in `crate::tests` so "does it work" and "how fast is it" cannot
//! quietly entangle again.
//!
//! # Layout rules
//!
//! - One Rust file per benchmark topic under `src/bench/`; the matching BPF
//!   programs live in `src/bpf/bench/bench_*.bpf.c` (built — and skeletons
//!   generated — only under the `bpf-test` feature, exactly like
//!   `src/bpf/tests/`).
//! - Shared correctness-test infrastructure (packet builders, netns/veth
//!   helpers) is reused from `crate::tests::*`; those modules stay
//!   `pub(crate)`. Bench-local helpers (e.g. trie `publish_entries`) live
//!   next to the bench that needs them.
//! - Every bench is a `#[test] #[ignore = "..."]` function: benchmarks need
//!   root and `bpf-test`, so they must never run as part of a plain
//!   `cargo test`.
//!
//! # Methodology rules
//!
//! `BPF_PROG_TEST_RUN` syscall overhead (~µs) dwarfs a single lookup (~ns),
//! so each program loops `BENCH_ITERS` times in one invocation (verifier cap
//! 1M instructions keeps the loop count honest) and we report
//! `(variant - baseline) / BENCH_ITERS` per lookup. Results are only
//! meaningful when the sink counters prove every iteration actually hit the
//! lookup under test.
//!
//! Run with: `cargo test -p landscape-ebpf --lib bench:: -- --ignored --nocapture`

pub(crate) mod bench_wan_dispatch {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/bench_wan_dispatch.skel.rs"));
}

mod wan_dispatch;
