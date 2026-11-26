use std::{
    fs::File,
    io::{IoSlice, Write},
    mem::MaybeUninit,
    os::fd::AsRawFd,
    process::Command,
    time::Duration,
};

use etherparse::{Ethernet2Header, Icmpv6Type, Ipv6Header, PacketBuilder, ip_number};
use libbpf_rs::{
    MapCore,
    skel::{OpenSkel, SkelBuilder},
};
use nix::net::if_::if_nametoindex;

use super::{LAN_CLIENT, REMOTE, ROUTER, TC_ACT_UNSPEC, WAN_CLIENT, WAN_PREFIX, icmp6_error};
use crate::{
    maps::nat::{StaticNatMappingV6Item, add_static_nat6_mapping},
    tests::{
        helper::{
            map::read_unaligned,
            net::{NetNsGuard, TCAttach, wait_for},
        },
        isolated_pin_root,
        nat::test_nat6_v3::{TestNat6V3SkelBuilder, types::ptb_sample},
    },
};

const TAP_NAME: &str = "npt-tap";

fn open_tap() -> File {
    let tap = File::options().read(true).write(true).open("/dev/net/tun").expect("open TUN/TAP");
    // SAFETY: ifreq is a C struct whose fields may be zero-initialized.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(TAP_NAME.bytes()) {
        *dst = src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags =
        (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_NAPI | libc::IFF_NAPI_FRAGS) as libc::c_short;
    // SAFETY: TUNSETIFF takes a writable ifreq for this open TUN/TAP fd.
    let rc = unsafe { libc::ioctl(tap.as_raw_fd(), libc::TUNSETIFF, &mut ifr) };
    assert_eq!(rc, 0, "TUNSETIFF: {}", std::io::Error::last_os_error());
    let up = Command::new("ip")
        .args(["link", "set", "dev", TAP_NAME, "address", "04:04:04:04:04:04", "up"])
        .output()
        .expect("bring up TAP");
    assert!(up.status.success(), "ip link set: {}", String::from_utf8_lossy(&up.stderr));
    tap
}

#[test]
#[ignore = "requires root, /dev/net/tun and network namespaces"]
fn tc_packet_too_big_tap() {
    let ns = NetNsGuard::create("ptb");
    let _entered = ns.enter();
    let mut tap = open_tap();
    let pin_root = isolated_pin_root("nat6-tap");
    let mut builder = TestNat6V3SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = MaybeUninit::uninit();
    let mut open = builder.open(&mut obj).unwrap();
    let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
    rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(WAN_PREFIX));
    rodata.wan_ro_npt_mask = crate::stages::nat6::compute_npt_mask(60);
    let skel = open.load().unwrap();
    add_static_nat6_mapping(
        &skel.maps.nat6_static_map,
        [StaticNatMappingV6Item {
            lan_ip: LAN_CLIENT,
            port: 12345,
            l4_protocol: ip_number::TCP.0,
        }],
    );
    let _hook = TCAttach::attach_ingress(
        &skel.progs.capture_ptb_ingress,
        if_nametoindex(TAP_NAME).unwrap() as i32,
    );

    let [wan, lan] = [WAN_CLIENT, LAN_CLIENT].map(|src| {
        let mut packet = Vec::new();
        PacketBuilder::ipv6(src.octets(), REMOTE.octets(), 64)
            .tcp(12345, 443, 100, 4096)
            .write(&mut packet, &[0x55; 1400])
            .unwrap();
        packet
    });
    let checksum = Ipv6Header::LEN + 16;
    assert_ne!(wan[checksum], lan[checksum]);
    let tcp_offset = Ethernet2Header::LEN + 2 * Ipv6Header::LEN + 8;
    // The first iovec ends after 8, 17 or 18 TCP bytes. TAP puts the rest in page fragments.
    for (quoted, linear, after) in
        [(17, 8, 8), (18, 8, 18), (18, 17, 18), (18, 18, 18), (20, 17, 18)]
    {
        let end = Ipv6Header::LEN + quoted;
        let mut translated = lan[..end].to_vec();
        if quoted == 17 {
            translated[checksum] = wan[checksum];
        }
        let ptb = Icmpv6Type::PacketTooBig { mtu: 1280 };
        let input = icmp6_error(ROUTER, WAN_CLIENT, ptb.clone(), &wan[..end]);
        let expected = icmp6_error(ROUTER, LAN_CLIENT, ptb, &translated);
        let (head, tail) = input.split_at(tcp_offset + linear);
        let iov = [IoSlice::new(head), IoSlice::new(tail)];
        let segments = if tail.is_empty() { &iov[..1] } else { &iov[..] };
        assert_eq!(tap.write_vectored(segments).unwrap(), input.len());

        let key = (input.len() as u32).to_ne_bytes();
        let mut bytes = None;
        wait_for("TC Packet Too Big sample", Duration::from_secs(2), || {
            bytes = skel.maps.ptb_samples.lookup_and_delete(&key).unwrap();
            bytes.is_some()
        });
        let bytes = bytes.unwrap();
        assert_eq!(bytes.len(), size_of::<ptb_sample>());
        let sample = read_unaligned::<ptb_sample>(&bytes);
        assert_eq!(
            sample.head_before_rewrite as usize,
            head.len(),
            "quoted={quoted}, linear={linear}"
        );
        assert_eq!(
            sample.head_after_rewrite as usize,
            tcp_offset + after,
            "quoted={quoted}, linear={linear}"
        );
        assert_eq!(sample.verdict, TC_ACT_UNSPEC);
        assert_eq!(&sample.frame[..expected.len()], expected, "quoted={quoted}, linear={linear}");
    }
}
