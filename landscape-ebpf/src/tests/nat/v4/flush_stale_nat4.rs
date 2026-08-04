use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
};

use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};

use crate::{
    map_setting::{add_wan_ip, flush_nat4_dyn_maps_by_old_ip, nat::NatMappingKeyV4},
    stages::nat::tc_nat_skel::{types, TcNatSkelBuilder},
    NAT_MAPPING_EGRESS, NAT_MAPPING_INGRESS,
};

const OLD_WAN_IP: Ipv4Addr = Ipv4Addr::new(100, 71, 54, 57);
const NEW_WAN_IP: Ipv4Addr = Ipv4Addr::new(100, 72, 176, 49);
const LAN_HOST_A: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 16);
const LAN_HOST_B: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 20);
const REMOTE_WG: Ipv4Addr = Ipv4Addr::new(193, 112, 55, 37);
const REMOTE_TS: Ipv4Addr = Ipv4Addr::new(81, 71, 155, 152);
const REMOTE_HTTP: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const IFINDEX: u32 = 6;

fn insert_egress_ingress_pair<M1: MapCore, M2: MapCore>(
    egress_map: &M1,
    ingress_map: &M2,
    l4proto: u8,
    lan_addr: Ipv4Addr,
    lan_port: u16,
    nat_addr: Ipv4Addr,
    nat_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
) {
    let egress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_EGRESS,
        l4proto,
        from_port: lan_port.to_be(),
        from_addr: lan_addr.to_bits().to_be(),
    };
    let mut egress_val = types::nat4_egress_mapping_value_v3::default();
    egress_val.addr = nat_addr.to_bits().to_be();
    egress_val.trigger_addr = remote_addr.to_bits().to_be();
    egress_val.port = nat_port.to_be();
    egress_val.trigger_port = remote_port.to_be();
    egress_val.is_allow_reuse = 1;

    let ingress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto,
        from_port: nat_port.to_be(),
        from_addr: nat_addr.to_bits().to_be(),
    };
    let ingress_val = types::nat4_mapping_value_v3 {
        state_ref: ((1u64) << 56) | 1,
        addr: lan_addr.to_bits().to_be(),
        trigger_addr: remote_addr.to_bits().to_be(),
        port: lan_port.to_be(),
        trigger_port: remote_port.to_be(),
        generation: 1,
        _pad: 0,
        is_allow_reuse: 1,
    };

    egress_map
        .update(
            unsafe { plain::as_bytes(&egress_key) },
            unsafe { plain::as_bytes(&egress_val) },
            MapFlags::ANY,
        )
        .expect("insert egress mapping");
    ingress_map
        .update(
            unsafe { plain::as_bytes(&ingress_key) },
            unsafe { plain::as_bytes(&ingress_val) },
            MapFlags::ANY,
        )
        .expect("insert ingress mapping");
}

fn egress_exists<M: MapCore>(map: &M, l4proto: u8, lan_addr: Ipv4Addr, lan_port: u16) -> bool {
    let key = NatMappingKeyV4 {
        gress: NAT_MAPPING_EGRESS,
        l4proto,
        from_port: lan_port.to_be(),
        from_addr: lan_addr.to_bits().to_be(),
    };
    map.lookup(unsafe { plain::as_bytes(&key) }, MapFlags::ANY).ok().flatten().is_some()
}

fn ingress_exists<M: MapCore>(map: &M, l4proto: u8, nat_addr: Ipv4Addr, nat_port: u16) -> bool {
    let key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto,
        from_port: nat_port.to_be(),
        from_addr: nat_addr.to_bits().to_be(),
    };
    map.lookup(unsafe { plain::as_bytes(&key) }, MapFlags::ANY).ok().flatten().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::nat::NAT_V3_TEST_LOCK;

    #[test]
    fn flush_removes_only_stale_mappings() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-flush-stale");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(OLD_WAN_IP),
            None,
            32,
            Some(MacAddr::broadcast()),
        );

        // Insert mappings with OLD WAN IP (stale after redial):
        // WireGuard flow: LAN_HOST_A:58648 -> OLD_WAN_IP:32787 -> REMOTE_WG:51820 (UDP)
        insert_egress_ingress_pair(
            &skel.maps.nat4_egress_dyn_map,
            &skel.maps.nat4_ingress_dyn_map,
            17, // UDP
            LAN_HOST_A,
            58648,
            OLD_WAN_IP,
            32787,
            REMOTE_WG,
            51820,
        );
        // Tailscale flow: LAN_HOST_A:60133 -> OLD_WAN_IP:32775 -> REMOTE_TS:41641 (UDP)
        insert_egress_ingress_pair(
            &skel.maps.nat4_egress_dyn_map,
            &skel.maps.nat4_ingress_dyn_map,
            17,
            LAN_HOST_A,
            60133,
            OLD_WAN_IP,
            32775,
            REMOTE_TS,
            41641,
        );

        // Insert mappings with NEW WAN IP (should survive flush):
        // HTTP flow: LAN_HOST_B:44000 -> NEW_WAN_IP:40000 -> REMOTE_HTTP:443 (TCP)
        insert_egress_ingress_pair(
            &skel.maps.nat4_egress_dyn_map,
            &skel.maps.nat4_ingress_dyn_map,
            6, // TCP
            LAN_HOST_B,
            44000,
            NEW_WAN_IP,
            40000,
            REMOTE_HTTP,
            443,
        );
        // DNS flow: LAN_HOST_B:55555 -> NEW_WAN_IP:40001 -> REMOTE_HTTP:53 (UDP)
        insert_egress_ingress_pair(
            &skel.maps.nat4_egress_dyn_map,
            &skel.maps.nat4_ingress_dyn_map,
            17,
            LAN_HOST_B,
            55555,
            NEW_WAN_IP,
            40001,
            REMOTE_HTTP,
            53,
        );

        // Verify all 4 mappings exist before flush.
        assert!(egress_exists(&skel.maps.nat4_egress_dyn_map, 17, LAN_HOST_A, 58648));
        assert!(egress_exists(&skel.maps.nat4_egress_dyn_map, 17, LAN_HOST_A, 60133));
        assert!(egress_exists(&skel.maps.nat4_egress_dyn_map, 6, LAN_HOST_B, 44000));
        assert!(egress_exists(&skel.maps.nat4_egress_dyn_map, 17, LAN_HOST_B, 55555));
        assert!(ingress_exists(&skel.maps.nat4_ingress_dyn_map, 17, OLD_WAN_IP, 32787));
        assert!(ingress_exists(&skel.maps.nat4_ingress_dyn_map, 17, OLD_WAN_IP, 32775));
        assert!(ingress_exists(&skel.maps.nat4_ingress_dyn_map, 6, NEW_WAN_IP, 40000));
        assert!(ingress_exists(&skel.maps.nat4_ingress_dyn_map, 17, NEW_WAN_IP, 40001));

        // Flush mappings for OLD_WAN_IP.
        let flushed = flush_nat4_dyn_maps_by_old_ip(
            &skel.maps.nat4_egress_dyn_map,
            &skel.maps.nat4_ingress_dyn_map,
            OLD_WAN_IP,
        );

        // Should have flushed exactly 2 stale mappings.
        assert_eq!(flushed, 2, "expected 2 stale mappings flushed");

        // Stale mappings (old WAN IP) should be gone.
        assert!(
            !egress_exists(&skel.maps.nat4_egress_dyn_map, 17, LAN_HOST_A, 58648),
            "WG egress mapping should be deleted"
        );
        assert!(
            !egress_exists(&skel.maps.nat4_egress_dyn_map, 17, LAN_HOST_A, 60133),
            "TS egress mapping should be deleted"
        );
        assert!(
            !ingress_exists(&skel.maps.nat4_ingress_dyn_map, 17, OLD_WAN_IP, 32787),
            "WG ingress mapping should be deleted"
        );
        assert!(
            !ingress_exists(&skel.maps.nat4_ingress_dyn_map, 17, OLD_WAN_IP, 32775),
            "TS ingress mapping should be deleted"
        );

        // Fresh mappings (new WAN IP) should still exist.
        assert!(
            egress_exists(&skel.maps.nat4_egress_dyn_map, 6, LAN_HOST_B, 44000),
            "HTTP egress mapping should survive"
        );
        assert!(
            egress_exists(&skel.maps.nat4_egress_dyn_map, 17, LAN_HOST_B, 55555),
            "DNS egress mapping should survive"
        );
        assert!(
            ingress_exists(&skel.maps.nat4_ingress_dyn_map, 6, NEW_WAN_IP, 40000),
            "HTTP ingress mapping should survive"
        );
        assert!(
            ingress_exists(&skel.maps.nat4_ingress_dyn_map, 17, NEW_WAN_IP, 40001),
            "DNS ingress mapping should survive"
        );
    }

    #[test]
    fn flush_noop_when_no_stale_entries() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-flush-noop");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        // Only insert mappings with NEW_WAN_IP.
        insert_egress_ingress_pair(
            &skel.maps.nat4_egress_dyn_map,
            &skel.maps.nat4_ingress_dyn_map,
            17,
            LAN_HOST_A,
            58648,
            NEW_WAN_IP,
            32787,
            REMOTE_WG,
            51820,
        );

        // Flush for an IP that has no entries.
        let flushed = flush_nat4_dyn_maps_by_old_ip(
            &skel.maps.nat4_egress_dyn_map,
            &skel.maps.nat4_ingress_dyn_map,
            OLD_WAN_IP,
        );

        assert_eq!(flushed, 0, "should flush nothing");
        assert!(
            egress_exists(&skel.maps.nat4_egress_dyn_map, 17, LAN_HOST_A, 58648),
            "existing mapping should be untouched"
        );
    }
}
