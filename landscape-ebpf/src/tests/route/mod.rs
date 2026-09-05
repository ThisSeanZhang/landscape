#[allow(clippy::module_inception)]
pub(crate) mod test_route {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_route.skel.rs"));
}

pub(crate) mod map_helper;
pub(crate) mod packet_builder;

mod packet;

#[cfg(test)]
mod test_route_docker;
#[cfg(test)]
mod test_route_search;
#[cfg(test)]
mod test_route_slot;
#[cfg(test)]
mod test_route_wan_cache;
