use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

use crate::tests::{
    test_scanner::{types::packet_info, TestScannerSkelBuilder},
    TestSkb,
};

use zerocopy::FromBytes;
use zerocopy::IntoBytes;
use zerocopy::{byteorder::*, Immutable};

pub(crate) mod package;
mod performance;
mod xdp_scanner;

#[repr(C, packed)]
#[derive(IntoBytes, FromBytes, Immutable, Clone, Debug, Copy, Default)]
pub struct PacketOffsetInfo {
    status: U16<LittleEndian>,

    icmp_error_l3_protocol: u8,
    icmp_error_l4_protocol: u8,

    fragment_type: u8,
    l4_protocol: u8,
    l3_protocol: u8,
    pkt_type: u8,

    fragment_id: U16<LittleEndian>,
    fragment_off: U16<LittleEndian>,

    l3_offset_when_scan: U16<LittleEndian>,
    l4_offset: U16<LittleEndian>,

    icmp_error_inner_l4_offset: U16<LittleEndian>,
    icmp_error_l3_offset: U16<LittleEndian>,
}

pub fn replace_offset(bytes: &mut [u8], offset: &PacketOffsetInfo) {
    bytes[48..68].copy_from_slice(offset.as_bytes());
}

pub fn read_offset(bytes: &[u8], offset: &mut PacketOffsetInfo) {
    offset.as_mut_bytes().copy_from_slice(&bytes[48..68]);
}

const MAP_KEY: u32 = 0;

pub fn test_scanner(
    mut payload: Vec<u8>,
    has_mac: bool,
    skb_ctx: Option<TestSkb>,
    offset: &mut PacketOffsetInfo,
) -> Option<packet_info> {
    let builder = TestScannerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();

    let rodata_data = open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");

    if !has_mac {
        rodata_data.current_l3_offset = 0;
    }

    let skel = open.load().unwrap();

    let test_scanner = skel.progs.test_scanner;

    let mut ctx = skb_ctx.unwrap_or_default();

    let ctx_size = std::mem::size_of::<TestSkb>();
    let mut ctx_slice =
        unsafe { std::slice::from_raw_parts_mut(&mut ctx as *mut TestSkb as *mut u8, ctx_size) };
    replace_offset(&mut ctx_slice, &offset);
    let input = ProgramInput {
        data_in: Some(&mut payload),
        context_in: None,
        context_out: Some(ctx_slice),
        ..Default::default()
    };
    let result = test_scanner.test_run(input).expect("test_run failed");

    println!("return_value = {}", result.return_value as i32);
    println!("duration = {:?}", result.duration);
    println!("ctx_slice = {:?}", ctx_slice);
    println!("offset bytes = {:?}", &ctx_slice[48..68]);
    let offset_info = PacketOffsetInfo::read_from_bytes(&ctx_slice[48..68]).unwrap();
    println!("offset info = {:?}", offset_info);
    read_offset(&ctx_slice, offset);
    let result = skel.maps.scanner_test_result_map.lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY);
    result
        .ok()
        .flatten()
        .map(|bytes| plain::from_bytes::<packet_info>(&bytes).ok().cloned())
        .flatten()
}

pub mod tests {
    use crate::tests::scanner::{package::*, test_scanner, PacketOffsetInfo};

    #[test]
    fn test_ipv4_without_l2() {
        let mut offset_info = PacketOffsetInfo::default();
        let bytes = crate::tests::dummpy_tcp_pkg();
        let packet_info = test_scanner(bytes[14..].to_vec(), false, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn test_ipv4() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info =
            test_scanner(crate::tests::dummpy_tcp_pkg(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn test_ipv6() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info =
            test_scanner(crate::tests::dummpy_ipv6_tcp_pkg(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn test_tcp() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info = test_scanner(build_ipv4_tcp_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn test_udp() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info = test_scanner(build_ipv4_udp_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn test_ipv4_frag() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info = test_scanner(build_ipv4_frag_first_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn test_ipv4_frag_nonfirst() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info =
            test_scanner(build_ipv4_frag_nonfirst_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn icmpv4_echo_eth() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info = test_scanner(build_icmpv4_echo_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn icmpv4_error_with_inner_ipv4_eth() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info =
            test_scanner(build_icmpv4_error_with_inner_ipv4_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn ipv6_tcp_eth() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info = test_scanner(build_ipv6_tcp_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn ipv6_frag_eth() {
        let mut offset_info = PacketOffsetInfo::default();
        let bytes: Vec<u8> = build_ipv6_frag_eth();
        println!("{:?}", bytes);
        let packet_info = test_scanner(bytes, true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }

    #[test]
    fn ipv6_frag_nonfirst_eth() {
        let mut offset_info = PacketOffsetInfo::default();
        let packet_info =
            test_scanner(build_ipv6_frag_nonfirst_eth(), true, None, &mut offset_info);
        println!("{}", packet_info.unwrap());
    }
}
