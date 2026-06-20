use std::io;

use futures::stream::TryStreamExt;
use netlink_packet_core::{
    DefaultNla, Emitable, NetlinkHeader, NetlinkMessage, NetlinkPayload, ParseableParametrized,
    NLA_F_NESTED, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_generic::{GenlFamily, GenlHeader, GenlMessage};
use tracing::{error, info, warn};

// ─── Netlink Attribute IDs from linux/ethtool_netlink.h ───
const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;
const ETHTOOL_A_HEADER_FLAGS: u16 = 3;

const ETHTOOL_A_FEATURES_HEADER: u16 = 1;
const ETHTOOL_A_FEATURES_WANTED: u16 = 3;
const ETHTOOL_A_FEATURES_ACTIVE: u16 = 4;

#[allow(dead_code)]
const ETHTOOL_A_BITSET_NOMASK: u16 = 1;
const ETHTOOL_A_BITSET_SIZE: u16 = 2;
const ETHTOOL_A_BITSET_BITS: u16 = 3;
const ETHTOOL_A_BITSET_VALUE: u16 = 4;

const ETHTOOL_A_BITSET_BITS_BIT: u16 = 1;

const ETHTOOL_A_BITSET_BIT_INDEX: u16 = 1;
const ETHTOOL_A_BITSET_BIT_VALUE: u16 = 3;

// ─── Netlink kernel constants ───
const ETHTOOL_MSG_FEATURES_GET: u8 = 13;
const ETHTOOL_MSG_FEATURES_SET: u8 = 14;
const ETHTOOL_GENL_NAME: &str = "ethtool";
const ETHTOOL_GENL_VERSION: u8 = 1;

/// ETHTOOL_FLAG_COMPACT_BITSETS from linux/ethtool_netlink.h
const ETHTOOL_FLAG_COMPACT_BITSETS: u32 = 1;

/// NETIF_F_GRO_BIT from include/linux/netdev_features.h:30
pub const NETIF_F_GRO_BIT: u32 = 14;
/// NETDEV_FEATURE_COUNT from include/linux/netdev_features.h:101
const NETDEV_FEATURE_COUNT: u32 = 64;

// ─── ioctl constants from linux/ethtool.h ───
/// ETHTOOL_GGRO — get GRO enable (ethtool_value)
const ETHTOOL_GGRO: u32 = 0x0000002b;
/// ETHTOOL_SGRO — set GRO enable (ethtool_value)
const ETHTOOL_SGRO: u32 = 0x0000002c;

#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

// ─── Payload type ───

#[derive(Debug, Clone)]
struct EthtoolPayload {
    cmd: u8,
    data: Vec<u8>,
}

impl GenlFamily for EthtoolPayload {
    fn family_name() -> &'static str {
        ETHTOOL_GENL_NAME
    }
    fn command(&self) -> u8 {
        self.cmd
    }
    fn version(&self) -> u8 {
        ETHTOOL_GENL_VERSION
    }
}

impl Emitable for EthtoolPayload {
    fn buffer_len(&self) -> usize {
        self.data.len()
    }
    fn emit(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.data);
    }
}

impl ParseableParametrized<[u8], GenlHeader> for EthtoolPayload {
    fn parse_with_param(
        buf: &[u8],
        _params: GenlHeader,
    ) -> Result<Self, netlink_packet_core::DecodeError> {
        Ok(EthtoolPayload { cmd: 0, data: buf.to_vec() })
    }
}

// ─── NLA builders ───

fn emit_u32_bytes(v: u32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn nla_flag(kind: u16) -> DefaultNla {
    DefaultNla::new(kind, vec![])
}

fn nla_u32(kind: u16, value: u32) -> DefaultNla {
    DefaultNla::new(kind, emit_u32_bytes(value))
}

fn nla_nest(kind: u16, inner: Vec<u8>) -> DefaultNla {
    DefaultNla::new(kind | NLA_F_NESTED, inner)
}

fn emit_nla(nla: &DefaultNla) -> Vec<u8> {
    let mut buf = vec![0u8; nla.buffer_len()];
    nla.emit(&mut buf);
    buf
}

fn emit_nlas(nlas: &[DefaultNla]) -> Vec<u8> {
    let mut buf = vec![0u8; nlas.buffer_len()];
    nlas.emit(&mut buf);
    buf
}

// ─── Message builders ───

fn build_header_nest(dev_name: &str, header_flags: u32) -> Vec<u8> {
    let mut attrs: Vec<DefaultNla> =
        vec![DefaultNla::new(ETHTOOL_A_HEADER_DEV_NAME, dev_name.as_bytes().to_vec())];
    if header_flags != 0 {
        attrs.push(nla_u32(ETHTOOL_A_HEADER_FLAGS, header_flags));
    }
    emit_nla(&nla_nest(ETHTOOL_A_FEATURES_HEADER, emit_nlas(&attrs)))
}

fn build_bit_nest(bit_index: u32, set: bool) -> Vec<u8> {
    let idx = emit_nla(&nla_u32(ETHTOOL_A_BITSET_BIT_INDEX, bit_index));
    let inner = if set {
        let val = emit_nla(&nla_flag(ETHTOOL_A_BITSET_BIT_VALUE));
        [idx, val].concat()
    } else {
        idx
    };
    emit_nla(&nla_nest(ETHTOOL_A_BITSET_BITS_BIT, inner))
}

fn build_bitset_nest(bit_indices: &[(u32, bool)]) -> Vec<u8> {
    let mut bits_content = Vec::new();
    for &(idx, set) in bit_indices {
        bits_content.extend(build_bit_nest(idx, set));
    }

    emit_nlas(&[
        nla_u32(ETHTOOL_A_BITSET_SIZE, NETDEV_FEATURE_COUNT),
        nla_nest(ETHTOOL_A_BITSET_BITS, bits_content),
    ])
}

fn build_features_set_payload(dev_name: &str, bits: &[(u32, bool)]) -> EthtoolPayload {
    let header = build_header_nest(dev_name, 0);
    let wanted = nla_nest(ETHTOOL_A_FEATURES_WANTED, build_bitset_nest(bits));
    let data = [header, emit_nla(&wanted)].concat();
    EthtoolPayload { cmd: ETHTOOL_MSG_FEATURES_SET, data }
}

fn build_features_get_payload(dev_name: &str) -> EthtoolPayload {
    EthtoolPayload {
        cmd: ETHTOOL_MSG_FEATURES_GET,
        data: build_header_nest(dev_name, ETHTOOL_FLAG_COMPACT_BITSETS),
    }
}

// ─── Connection & send helpers ───

fn make_features_msg(payload: EthtoolPayload) -> NetlinkMessage<GenlMessage<EthtoolPayload>> {
    let genl_msg = GenlMessage::from_payload(payload);
    let mut msg = NetlinkMessage::new(NetlinkHeader::default(), genl_msg.into());
    msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.finalize();
    msg
}

async fn ethtool_request(payload: EthtoolPayload) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, mut handle, _) = genetlink::new_connection()?;
    tokio::spawn(connection);

    let msg = make_features_msg(payload);
    let mut stream = handle.request(msg).await?;
    while let Some(msg) = stream.try_next().await? {
        if let NetlinkPayload::Error(err) = msg.payload {
            return Err(err.to_io().into());
        }
    }
    Ok(())
}

async fn ethtool_request_with_reply(
    payload: EthtoolPayload,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (connection, mut handle, _) = genetlink::new_connection()?;
    tokio::spawn(connection);

    let msg = make_features_msg(payload);
    let mut stream = handle.request(msg).await?;
    let mut reply_data = None;
    while let Some(msg) = stream.try_next().await? {
        match &msg.payload {
            NetlinkPayload::Error(err) => return Err(err.to_io().into()),
            NetlinkPayload::InnerMessage(genl_msg) => {
                reply_data = Some(genl_msg.payload.data.clone());
            }
            _ => {}
        }
    }
    reply_data.ok_or_else(|| "no reply from kernel".into())
}

// ─── Response parsing ───

use netlink_packet_core::NlasIterator;

/// Parse a specific NLA attribute from raw bytes by attribute kind.
fn parse_nla_at(kind: u16, buf: &[u8]) -> Option<Vec<u8>> {
    let iter: NlasIterator<&[u8]> = NlasIterator::new(buf);
    for nla_res in iter {
        let nla = nla_res.ok()?;
        if nla.kind() == kind {
            return Some(nla.value().to_vec());
        }
    }
    None
}

/// Parse a compact bitset VALUE field and check if a given bit is set.
fn parse_compact_bitset_bit(value_bytes: &[u8], bit_index: u32) -> Result<bool, &'static str> {
    let word_idx = (bit_index / 32) as usize;
    let bit_off = bit_index % 32;
    if (word_idx + 1) * 4 > value_bytes.len() {
        return Err("bitset VALUE too short");
    }
    let word = u32::from_ne_bytes([
        value_bytes[word_idx * 4],
        value_bytes[word_idx * 4 + 1],
        value_bytes[word_idx * 4 + 2],
        value_bytes[word_idx * 4 + 3],
    ]);
    Ok((word & (1u32 << bit_off)) != 0)
}

// ─── Netlink API ───

pub async fn set_gro_nl(dev_name: &str, enable: bool) -> Result<(), Box<dyn std::error::Error>> {
    let payload = build_features_set_payload(dev_name, &[(NETIF_F_GRO_BIT, enable)]);
    ethtool_request(payload).await
}

pub async fn get_gro_nl(dev_name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let payload = build_features_get_payload(dev_name);
    let reply = ethtool_request_with_reply(payload).await?;

    let active_nest = parse_nla_at(ETHTOOL_A_FEATURES_ACTIVE, &reply)
        .ok_or("reply missing ETHTOOL_A_FEATURES_ACTIVE")?;
    let value_bytes =
        parse_nla_at(ETHTOOL_A_BITSET_VALUE, &active_nest).ok_or("reply bitset missing VALUE")?;

    parse_compact_bitset_bit(&value_bytes, NETIF_F_GRO_BIT).map_err(|e| e.into())
}

// ─── ioctl helpers ───

/// Call ETHTOOL_GGRO / ETHTOOL_SGRO via SIOCETHTOOL ioctl.
/// Returns `Ok(data)` on success, where `data` reflects the `ethtool_value.data` field.
unsafe fn ethtool_ioctl(ifname: &str, cmd: u32, data: u32) -> Result<u32, io::Error> {
    let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: libc::ifreq = std::mem::zeroed();
    let name_bytes = ifname.as_bytes();
    let max_len = (libc::IFNAMSIZ - 1) as usize;
    let copy_len = name_bytes.len().min(max_len);
    std::ptr::copy_nonoverlapping(
        name_bytes.as_ptr(),
        ifr.ifr_name.as_mut_ptr() as *mut u8,
        copy_len,
    );

    let mut eval = EthtoolValue { cmd, data };
    ifr.ifr_ifru.ifru_data = &mut eval as *mut EthtoolValue as *mut libc::c_char;

    let ret = libc::ioctl(sock, libc::SIOCETHTOOL as libc::Ioctl, &ifr);
    libc::close(sock);

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(eval.data)
    }
}

// ─── ioctl API ───

pub fn set_gro_ioctl(dev_name: &str, enable: bool) -> Result<(), io::Error> {
    let data = if enable { 1 } else { 0 };
    unsafe { ethtool_ioctl(dev_name, ETHTOOL_SGRO, data) }?;
    Ok(())
}

pub fn get_gro_ioctl(dev_name: &str) -> Result<bool, io::Error> {
    let data = unsafe { ethtool_ioctl(dev_name, ETHTOOL_GGRO, 0) }?;
    Ok(data != 0)
}

// ─── Unified public API ───

/// Set GRO state: try netlink first, fallback to ioctl.
pub async fn set_gro(dev_name: &str, enable: bool) -> Result<(), Box<dyn std::error::Error>> {
    match set_gro_nl(dev_name, enable).await {
        Ok(()) => return Ok(()),
        Err(e) => warn!("set_gro netlink failed for {dev_name}: {e}, trying ioctl"),
    }
    set_gro_ioctl(dev_name, enable)?;
    Ok(())
}

/// Get GRO state: try netlink first, fallback to ioctl.
pub async fn get_gro(dev_name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match get_gro_nl(dev_name).await {
        Ok(v) => return Ok(v),
        Err(e) => warn!("get_gro netlink failed for {dev_name}: {e}, trying ioctl"),
    }
    get_gro_ioctl(dev_name).map_err(|e| e.into())
}

pub async fn disable_gro(dev_name: &str) {
    match set_gro_nl(dev_name, false).await {
        Ok(()) => {
            info!("disabled GRO on {dev_name} (netlink)");
            return;
        }
        Err(e) => warn!("disable_gro netlink failed for {dev_name}: {e}, trying ioctl"),
    }
    match set_gro_ioctl(dev_name, false) {
        Ok(()) => info!("disabled GRO on {dev_name} (ioctl)"),
        Err(e) => error!("disable_gro ioctl failed for {dev_name}: {e}"),
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{parse_u32, NlasIterator};

    /// Netlink header (16 bytes) + Generic netlink header (4 bytes) = 20
    const GENL_PAYLOAD_OFFSET: usize = 20;

    fn parse_payload(data: &[u8]) -> EthtoolPayload {
        EthtoolPayload::parse_with_param(data, GenlHeader { cmd: 0, version: 1 })
            .expect("failed to parse")
    }

    /// Round-trip: build a message, serialize, then re-parse individual NLA
    /// fields to confirm structural correctness.
    fn roundtrip_set_test(dev_name: &str, bits: &[(u32, bool)]) {
        let payload = build_features_set_payload(dev_name, bits);
        let msg = make_features_msg(payload);
        let mut buf = vec![0u8; msg.buffer_len()];
        msg.emit(&mut buf);

        let genl_payload = &buf[GENL_PAYLOAD_OFFSET..];
        let reparse = parse_payload(genl_payload);

        let header_nest = parse_nla_at(ETHTOOL_A_FEATURES_HEADER, &reparse.data)
            .expect("missing ETHTOOL_A_FEATURES_HEADER");
        let name_bytes = parse_nla_at(ETHTOOL_A_HEADER_DEV_NAME, &header_nest)
            .expect("missing ETHTOOL_A_HEADER_DEV_NAME");
        assert_eq!(std::str::from_utf8(&name_bytes).unwrap().trim_matches('\0'), dev_name);

        let wanted_nest = parse_nla_at(ETHTOOL_A_FEATURES_WANTED, &reparse.data)
            .expect("missing ETHTOOL_A_FEATURES_WANTED");

        assert!(
            parse_nla_at(ETHTOOL_A_BITSET_NOMASK, &wanted_nest).is_none(),
            "NOMASK flag should NOT be present"
        );

        let size_bytes = parse_nla_at(ETHTOOL_A_BITSET_SIZE, &wanted_nest).expect("missing SIZE");
        assert_eq!(parse_u32(&size_bytes).unwrap(), NETDEV_FEATURE_COUNT);

        let bits_nest = parse_nla_at(ETHTOOL_A_BITSET_BITS, &wanted_nest).expect("missing BITS");

        let mut found_bits = Vec::new();
        let iter: NlasIterator<&[u8]> = NlasIterator::new(&bits_nest);
        for nla_res in iter {
            let nla = nla_res.unwrap();
            if nla.kind() == ETHTOOL_A_BITSET_BITS_BIT {
                let bit_nest = nla.value().to_vec();
                let idx = parse_nla_at(ETHTOOL_A_BITSET_BIT_INDEX, &bit_nest).unwrap();
                let has_value = parse_nla_at(ETHTOOL_A_BITSET_BIT_VALUE, &bit_nest).is_some();
                found_bits.push((parse_u32(&idx).unwrap(), has_value));
            }
        }
        assert_eq!(found_bits.len(), bits.len(), "unexpected number of bit entries");
        for &(idx, expected_set) in bits {
            assert!(
                found_bits.contains(&(idx, expected_set)),
                "expected bit {idx} set={expected_set} not found in {found_bits:?}",
            );
        }
    }

    #[test]
    fn test_disable_gro_message() {
        roundtrip_set_test("eth0", &[(NETIF_F_GRO_BIT, false)]);
    }

    #[test]
    fn test_enable_gro_message() {
        roundtrip_set_test("ens6", &[(NETIF_F_GRO_BIT, true)]);
    }

    #[test]
    fn test_multiple_features_message() {
        roundtrip_set_test("lan0", &[(NETIF_F_GRO_BIT, false), (NETIF_F_GRO_BIT + 1, true)]);
    }

    #[test]
    fn test_get_message_structure() {
        let payload = build_features_get_payload("wan0");
        assert_eq!(payload.cmd, ETHTOOL_MSG_FEATURES_GET);

        let header_nest = parse_nla_at(ETHTOOL_A_FEATURES_HEADER, &payload.data)
            .expect("missing FEATURES_HEADER");
        let flags_val = parse_nla_at(ETHTOOL_A_HEADER_FLAGS, &header_nest)
            .expect("FEATURES_HEADER should have FLAGS for compact bitsets");
        let flags = u32::from_ne_bytes(flags_val[..4].try_into().unwrap());
        assert_eq!(flags, ETHTOOL_FLAG_COMPACT_BITSETS);
    }

    #[test]
    fn test_parse_compact_bitset() {
        let value_bytes: Vec<u8> = [
            0x00u8, 0x40, 0x00, 0x00, // word 0: bit 14 set
            0x00, 0x00, 0x00, 0x00,
        ] // word 1: all zero
        .to_vec();
        assert!(parse_compact_bitset_bit(&value_bytes, 14).unwrap());
        assert!(!parse_compact_bitset_bit(&value_bytes, 15).unwrap());
        assert!(!parse_compact_bitset_bit(&value_bytes, 35).unwrap());

        let mut word1 = 0u32;
        word1 |= 1 << 4;
        let mut bytes = vec![0u8; 8];
        bytes[4..].copy_from_slice(&word1.to_ne_bytes());
        assert!(parse_compact_bitset_bit(&bytes, 36).unwrap());
        assert!(!parse_compact_bitset_bit(&bytes, 35).unwrap());
    }

    /// Integration test: full get/set/get roundtrip using ioctl path.
    /// Needs root + a real NIC.
    #[tokio::test]
    async fn test_gro_roundtrip() {
        let ifname = std::env::var("TEST_IFACE").unwrap_or_else(|_| "ens6".to_string());

        // 1. read original via ioctl
        let was_on = get_gro_ioctl(&ifname).expect("ioctl GET failed");
        eprintln!("[test] ioctl GET initial: GRO={was_on} on {ifname}");

        // 2. disable via ioctl
        set_gro_ioctl(&ifname, false).expect("ioctl SET false failed");
        let state_off = get_gro_ioctl(&ifname).expect("ioctl GET after disable failed");
        assert!(!state_off, "GRO should be OFF after disable, but ioctl says ON");

        // 3. enable via ioctl
        set_gro_ioctl(&ifname, true).expect("ioctl SET true failed");
        let state_on = get_gro_ioctl(&ifname).expect("ioctl GET after enable failed");
        assert!(state_on, "GRO should be ON after enable, but ioctl says OFF");

        // 4. restore
        set_gro_ioctl(&ifname, was_on).ok();
        eprintln!("[test] ioctl roundtrip PASSED, restored GRO={was_on}");
    }
}
