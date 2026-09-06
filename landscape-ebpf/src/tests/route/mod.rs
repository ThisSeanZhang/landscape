#[allow(clippy::module_inception)]
pub(crate) mod test_route {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_route.skel.rs"));
}

pub(crate) mod map_helper;
pub(crate) mod packet_builder;

mod packet;

#[cfg(test)]
mod tc_lan_ingress;
#[cfg(test)]
mod tc_lan_ingress_v6;
#[cfg(test)]
mod tc_wan_egress;
#[cfg(test)]
mod tc_wan_egress_v6;
#[cfg(test)]
mod tc_wan_ingress;
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
