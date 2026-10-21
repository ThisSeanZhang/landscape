use std::net::IpAddr;

use landscape_common::flow::ip_mark::IpConfig;
use sha2::{Digest, Sha256};

/// Content hash over the deduplicated, sorted, host-bit-masked CIDR set.
pub(crate) fn geo_ip_content_hash(values: &[IpConfig]) -> String {
    fn masked(ip: IpAddr, prefix_len: u32) -> Vec<u8> {
        match ip {
            IpAddr::V4(addr) => {
                let mask = if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len.min(32)) };
                (u32::from(addr) & mask).to_be_bytes().to_vec()
            }
            IpAddr::V6(addr) => {
                let mask =
                    if prefix_len == 0 { 0 } else { u128::MAX << (128 - prefix_len.min(128)) };
                (u128::from(addr) & mask).to_be_bytes().to_vec()
            }
        }
    }

    let mut canonical: Vec<(u8, u32, Vec<u8>)> = values
        .iter()
        .map(|config| {
            let family = match config.ip {
                IpAddr::V4(_) => 4u8,
                IpAddr::V6(_) => 6u8,
            };
            (family, config.prefix, masked(config.ip, config.prefix))
        })
        .collect();
    canonical.sort_unstable();
    canonical.dedup();

    let mut hasher = Sha256::new();
    hasher.update((canonical.len() as u64).to_be_bytes());
    for (family, prefix, network) in canonical {
        hasher.update([family]);
        hasher.update(prefix.to_be_bytes());
        hasher.update((network.len() as u64).to_be_bytes());
        hasher.update(&network);
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use landscape_common::flow::ip_mark::IpConfig;

    use super::geo_ip_content_hash;

    #[test]
    fn content_hash_is_masked_and_dedup_stable() {
        let config = |network: &str, prefix: u32| IpConfig {
            ip: IpAddr::from_str(network).unwrap(),
            prefix,
        };
        let masked_variants = vec![config("10.1.2.3", 8), config("10.200.0.9", 8)];
        let canonical = vec![config("10.0.0.0", 8)];

        assert_eq!(geo_ip_content_hash(&masked_variants), geo_ip_content_hash(&canonical));
        assert_ne!(
            geo_ip_content_hash(&masked_variants),
            geo_ip_content_hash(&[config("11.0.0.0", 8)])
        );
    }
}
