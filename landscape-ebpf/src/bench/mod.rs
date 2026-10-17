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
//! `bench_skb_read` batches at the kernel level instead
//! (`ProgramInput::repeat`): one syscall runs the program N times and the
//! kernel reports the per-run average, keeping the loop out of the BPF
//! program entirely (the scanner twins blow the 1M-insn verifier budget
//! as in-program loops). Same baseline-subtraction and sink rules apply.
//!
//! Run with: `cargo test -p landscape-ebpf --lib --features bpf-test bench:: -- --ignored --nocapture`

pub(crate) mod bench_skb_read {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/bench_skb_read.skel.rs"));
}

pub(crate) mod bench_wan_dispatch {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/bench_wan_dispatch.skel.rs"));
}

pub(crate) mod bench_nat4_lookup {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/bench_nat4_lookup.skel.rs"));
}

mod nat4_lookup;
mod skb_read;
mod wan_dispatch;
