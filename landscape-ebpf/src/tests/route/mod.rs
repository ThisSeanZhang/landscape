#[allow(clippy::module_inception)]
pub(crate) mod test_route {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_route.skel.rs"));
}

mod packet;

#[cfg(test)]
mod pppoe_skb_fallback;
#[cfg(test)]
mod tc_lan_ingress;
#[cfg(test)]
mod tc_lan_ingress_v6;
#[cfg(test)]
mod tc_wan_egress;
mod tc_wan_egress_host_direct;
#[cfg(test)]
mod tc_wan_egress_v6;
#[cfg(test)]
mod tc_wan_ingress;
// Uses the `test_wan_trie_probe` skeleton owned by the misc topic, so these
// two only compile when both topics are enabled.
#[cfg(all(test, feature = "test-misc"))]
mod tc_wan_ingress_intro;
#[cfg(test)]
mod tc_wan_ingress_v6;
#[cfg(test)]
mod test_lan_redirect_check;
#[cfg(test)]
mod test_route_docker;
#[cfg(test)]
mod test_route_search;
#[cfg(test)]
mod test_route_slot;
#[cfg(test)]
mod test_route_wan_cache;
#[cfg(all(test, feature = "test-misc"))]
mod xdp_wan_intro;
