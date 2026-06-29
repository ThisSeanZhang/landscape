use std::net::Ipv6Addr;

/// A delegable PD prefix range.
/// Produced by resolving group config + IAPrefixMap.
pub struct PdRange {
    pub group_id: String,
    pub parent: Ipv6Addr,
    pub parent_len: u8,
    pub pool_len: u8,
    pub start_idx: u32,
    pub end_idx: u32,
}

/// PD lease index — stores group + sub-range offset, not the full prefix.
/// The full prefix is computed on demand via `resolve_pd_prefix`.
pub struct PdSlotKey {
    pub group_id: String,
    pub sub_index: u32,
}

/// Normalize a prefix by masking host bits beyond `prefix_len`.
pub fn normalize_prefix(prefix: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    if prefix_len >= 128 {
        return prefix;
    }
    let val = u128::from_be_bytes(prefix.octets());
    let masked = val & (!0u128 << (128 - prefix_len as u32));
    Ipv6Addr::from(masked.to_be_bytes())
}

/// Carve a delegated sub-prefix block from a parent prefix.
pub fn compute_delegated_prefix(
    base: Ipv6Addr,
    base_len: u8,
    delegate_len: u8,
    sub_index: u32,
) -> Ipv6Addr {
    let val = u128::from(base);
    let mask = if base_len >= 128 { !0u128 } else { !0u128 << (128 - base_len as u32) };
    let network = val & mask;
    let shift = 128 - delegate_len as u32;
    Ipv6Addr::from(network | ((sub_index as u128) << shift))
}

/// Resolve a PdSlotKey to a full delegated prefix `(prefix, prefix_len)`.
pub fn resolve_pd_prefix(ranges: &[PdRange], key: &PdSlotKey) -> Option<(Ipv6Addr, u8)> {
    let range = ranges.iter().find(|r| r.group_id == key.group_id)?;
    if key.sub_index < range.start_idx || key.sub_index > range.end_idx {
        return None;
    }
    let max_blocks = if range.parent_len >= 128 {
        0u128
    } else {
        1u128 << (128u32.saturating_sub(range.parent_len as u32))
    };
    if (key.sub_index as u128) >= max_blocks {
        return None;
    }
    let delegated =
        compute_delegated_prefix(range.parent, range.parent_len, range.pool_len, key.sub_index);
    Some((delegated, range.pool_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // ── normalize_prefix ──

    #[test]
    fn normalize_64_prefix() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0xffff, 0, 0, 1);
        let result = normalize_prefix(addr, 64);
        assert_eq!(result.segments(), [0x2001, 0x0db8, 0x0000, 0x0001, 0, 0, 0, 0]);
    }

    #[test]
    fn normalize_128_prefix_is_id() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0xabcd);
        assert_eq!(normalize_prefix(addr, 128), addr);
    }

    #[test]
    fn normalize_0_prefix_is_zero() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
        assert_eq!(normalize_prefix(addr, 0), Ipv6Addr::UNSPECIFIED);
    }

    // ── compute_delegated_prefix ──

    #[test]
    fn compute_slot_0_yields_network_address() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
        let delegated = compute_delegated_prefix(base, 56, 64, 0);
        assert_eq!(delegated.segments(), [0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn compute_slot_5_yields_correct_subnet() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);
        let delegated = compute_delegated_prefix(base, 56, 64, 5);
        assert_eq!(delegated.segments(), [0x2001, 0x0db8, 0x0001, 0x0005, 0, 0, 0, 0]);
    }

    #[test]
    fn compute_with_base_len_64_pool_len_64_is_identity() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let result = compute_delegated_prefix(base, 64, 64, 0);
        assert_eq!(result, base);
    }

    #[test]
    fn compute_ignores_host_bits_in_base() {
        let base = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0xabcd, 0, 0, 0, 0);
        let delegated = compute_delegated_prefix(base, 56, 64, 1);
        assert_eq!(delegated.segments(), [0x2001, 0x0db8, 0x0001, 0xab01, 0, 0, 0, 0]);
    }

    // ── resolve_pd_prefix ──

    fn make_range(
        group_id: &str,
        parent: Ipv6Addr,
        parent_len: u8,
        pool_len: u8,
        start: u32,
        end: u32,
    ) -> PdRange {
        PdRange {
            group_id: group_id.to_string(),
            parent,
            parent_len,
            pool_len,
            start_idx: start,
            end_idx: end,
        }
    }

    #[test]
    fn resolve_valid_slot() {
        let ranges = vec![make_range(
            "g1",
            Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0),
            56,
            64,
            0,
            255,
        )];
        let key = PdSlotKey { group_id: "g1".into(), sub_index: 5 };
        let (prefix, len) = resolve_pd_prefix(&ranges, &key).unwrap();
        assert_eq!(len, 64);
        assert_eq!(prefix.segments(), [0x2001, 0x0db8, 0x0001, 0x0005, 0, 0, 0, 0]);
    }

    #[test]
    fn resolve_out_of_range_is_none() {
        let ranges =
            vec![make_range("g1", Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0), 56, 64, 0, 3)];
        let key = PdSlotKey { group_id: "g1".into(), sub_index: 5 };
        assert!(resolve_pd_prefix(&ranges, &key).is_none());
    }

    #[test]
    fn resolve_wrong_group_is_none() {
        let ranges = vec![make_range(
            "g1",
            Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0),
            56,
            64,
            0,
            255,
        )];
        let key = PdSlotKey { group_id: "g2".into(), sub_index: 0 };
        assert!(resolve_pd_prefix(&ranges, &key).is_none());
    }

    #[test]
    fn resolve_empty_ranges_is_none() {
        let key = PdSlotKey { group_id: "g1".into(), sub_index: 0 };
        assert!(resolve_pd_prefix(&[], &key).is_none());
    }
}
