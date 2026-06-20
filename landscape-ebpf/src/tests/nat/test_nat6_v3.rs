pub(crate) mod skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_nat6_v3.skel.rs"));
}

pub(crate) use skel::*;
