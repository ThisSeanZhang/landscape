pub mod ns_proxy {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/ns_proxy.skel.rs"));
}
