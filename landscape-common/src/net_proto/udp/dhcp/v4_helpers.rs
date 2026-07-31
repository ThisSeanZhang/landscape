use std::collections::HashSet;

use crate::lan_service::lan_dhcpv4::config::is_server_managed;
use crate::net_proto::udp::dhcp::v4::{OptionCode, UnknownOption};
use crate::net_proto::udp::dhcp::{DhcpV4Message, DhcpV4Option};

/// Default parameter request list (option 55) used when a client omits it.
///
/// Mirrors the legacy default list: 1, 3, 6, 15, 26, 28, 12, 42, 51, 119.
pub fn get_default_request_list() -> DhcpV4Option {
    DhcpV4Option::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::DomainName,
        OptionCode::InterfaceMtu,
        OptionCode::BroadcastAddr,
        OptionCode::Hostname,
        OptionCode::NtpServers,
        OptionCode::AddressLeaseTime,
        OptionCode::DomainSearch,
    ])
}

/// Look up a DHCP option by raw option code.
pub fn has_option(msg: &DhcpV4Message, code: u8) -> Option<DhcpV4Option> {
    msg.opts().get(OptionCode::from(code)).cloned()
}

/// Extract the hostname (option 12) if present.
pub fn get_hostname(msg: &DhcpV4Message) -> Option<String> {
    match msg.opts().get(OptionCode::Hostname) {
        Some(DhcpV4Option::Hostname(name)) => Some(name.clone()),
        _ => None,
    }
}

/// Renew (T1, option 58), rebinding (T2, option 59) and lease time (option 51).
pub fn get_renew_time(msg: &DhcpV4Message) -> Option<(u64, u64, u64)> {
    let Some(DhcpV4Option::AddressLeaseTime(lease_time)) =
        msg.opts().get(OptionCode::AddressLeaseTime)
    else {
        return None;
    };
    let renew_time = match msg.opts().get(OptionCode::Renewal) {
        Some(DhcpV4Option::Renewal(time)) => *time,
        _ => lease_time / 2,
    };
    let rebinding_time = match msg.opts().get(OptionCode::Rebinding) {
        Some(DhcpV4Option::Rebinding(time)) => *time,
        _ => lease_time * 7 / 8,
    };
    Some((renew_time as u64, rebinding_time as u64, *lease_time as u64))
}

/// Extract raw (code, data) pairs carried as unknown options.
pub fn custom_raw_options(msg: &DhcpV4Message) -> Vec<(u8, Vec<u8>)> {
    msg.opts()
        .iter()
        .filter_map(|(_, opt)| match opt {
            DhcpV4Option::Unknown(unknown) => {
                Some((u8::from(unknown.code()), unknown.data().to_vec()))
            }
            _ => None,
        })
        .collect()
}

/// Filter standard options by blocklist, keeping server-managed ones unconditionally.
/// Then merge custom raw options, excluding any that appear in the blocklist.
pub fn apply_custom_and_filter(
    msg: &mut DhcpV4Message,
    custom_opts: Vec<(u8, Vec<u8>)>,
    filter_set: &HashSet<u8>,
) {
    msg.opts_mut().retain(|code, _| {
        let idx = u8::from(*code);
        !filter_set.contains(&idx) || is_server_managed(idx)
    });
    for (code, data) in custom_opts.into_iter().filter(|(code, _)| !filter_set.contains(code)) {
        msg.opts_mut()
            .insert(DhcpV4Option::Unknown(UnknownOption::new(OptionCode::from(code), data)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_proto::udp::dhcp::v4::MessageType;
    use crate::net_proto::udp::dhcp::{Decodable, Decoder, Encodable, Encoder};

    fn encode_msg(msg: &DhcpV4Message) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e).expect("encode dhcp v4 message");
        buf
    }

    fn decode_msg(bytes: &[u8]) -> DhcpV4Message {
        DhcpV4Message::decode(&mut Decoder::new(bytes)).expect("decode dhcp v4 message")
    }

    #[test]
    fn default_request_list_has_expected_codes() {
        let DhcpV4Option::ParameterRequestList(codes) = get_default_request_list() else {
            panic!("expected ParameterRequestList");
        };
        let codes: Vec<u8> = codes.iter().map(|c| u8::from(*c)).collect();
        assert_eq!(codes, vec![1, 3, 6, 15, 26, 28, 12, 42, 51, 119]);
    }

    #[test]
    fn has_option_and_hostname() {
        let mut msg = DhcpV4Message::default();
        msg.opts_mut().insert(DhcpV4Option::Hostname("pc2".into()));
        msg.opts_mut().insert(DhcpV4Option::SubnetMask([255, 255, 255, 0].into()));

        assert_eq!(get_hostname(&msg).as_deref(), Some("pc2"));
        assert!(matches!(has_option(&msg, 1), Some(DhcpV4Option::SubnetMask(_))));
        assert!(has_option(&msg, 12).is_some());
        assert!(has_option(&msg, 50).is_none());
    }

    #[test]
    fn renew_time_derives_defaults() {
        let mut msg = DhcpV4Message::default();
        msg.opts_mut().insert(DhcpV4Option::AddressLeaseTime(40));
        assert_eq!(get_renew_time(&msg), Some((20, 35, 40)));

        msg.opts_mut().insert(DhcpV4Option::Renewal(30));
        msg.opts_mut().insert(DhcpV4Option::Rebinding(35));
        assert_eq!(get_renew_time(&msg), Some((30, 35, 40)));
    }

    #[test]
    fn unknown_option_round_trips() {
        let data = vec![0x00, 0x01, 0x02, 0xAA];
        let mut msg = DhcpV4Message::default();
        msg.opts_mut()
            .insert(DhcpV4Option::Unknown(UnknownOption::new(OptionCode::from(162), data.clone())));

        assert_eq!(custom_raw_options(&msg), vec![(162, data.clone())]);

        let decoded = decode_msg(&encode_msg(&msg));
        assert_eq!(custom_raw_options(&decoded), vec![(162, data)]);
    }

    #[test]
    fn apply_custom_and_filter_behavior() {
        let mut msg = DhcpV4Message::default();
        msg.opts_mut().insert(DhcpV4Option::MessageType(MessageType::Offer));
        msg.opts_mut().insert(DhcpV4Option::Hostname("pc2".into()));
        msg.opts_mut().insert(DhcpV4Option::DomainName("lan".into()));
        msg.opts_mut().insert(DhcpV4Option::ServerIdentifier([10, 255, 255, 1].into()));

        let mut filter = HashSet::new();
        filter.insert(15); // DomainName -> filtered
        filter.insert(12); // Hostname -> filtered
        filter.insert(54); // ServerIdentifier -> server managed, kept

        let custom = vec![(162, vec![1, 2, 3]), (15, vec![9])];
        apply_custom_and_filter(&mut msg, custom, &filter);

        assert!(msg.opts().get(OptionCode::Hostname).is_none());
        assert!(msg.opts().get(OptionCode::DomainName).is_none());
        assert!(msg.opts().get(OptionCode::ServerIdentifier).is_some());
        assert!(matches!(msg.opts().get(OptionCode::from(162)), Some(DhcpV4Option::Unknown(_))));
        assert_eq!(custom_raw_options(&msg), vec![(162, vec![1, 2, 3])]);
    }
}
