use std::net::Ipv4Addr;

use landscape_common::net::MacAddr;

use super::auth::Authenticator;

#[derive(Debug)]
pub(crate) enum PPPoEConnectState {
    Discovering,
    ReuqestSession { server_mac_addr: Vec<u8>, ac_cookie: Option<Vec<u8>> },
    SessionConfirm { server_mac_addr: Vec<u8>, session_id: u16 },
}

pub(crate) struct LcpBaseConfig {
    pub(crate) mru: u16,
    pub(crate) magic_number: u32,
}

impl LcpBaseConfig {
    pub(crate) fn new_client(requested_mru: u16) -> Self {
        let now =
            std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap();
        let magic_number = now.as_secs() as u32;
        LcpBaseConfig { mru: requested_mru, magic_number }
    }
}

pub(crate) struct LCPStatus {
    pub(crate) lcp_echo_times: u16,
    pub(crate) echo_req_id: u8,
    pub(crate) client_config: TagValue<LcpBaseConfig>,
    pub(crate) server_config: TagValue<LcpBaseConfig>,
    pub(crate) cfg_req_id: u8,
    pub(crate) auth_type: TagValue<u16>,
    pub(crate) authenticator: Option<Box<dyn Authenticator>>,
    pub(crate) ipcp_server_ipaddr: TagValue<Ipv4Addr>,
    pub(crate) ipcp_client_ipaddr: TagValue<Ipv4Addr>,
    pub(crate) ipcp_req_id: u8,
    pub(crate) ip6cp_server_id: TagValue<Vec<u8>>,
    pub(crate) ip6cp_client_id: TagValue<Vec<u8>>,
    pub(crate) ip6cp_req_id: u8,
    pub(crate) termination: (bool, TagValue<()>),
}

impl LCPStatus {
    pub(crate) fn new(client_mac: MacAddr, requested_mru: u16) -> Self {
        let mut ipv6_interface_id = [0_u8; 8];
        let mac_addr = client_mac.octets();
        ipv6_interface_id[0] = mac_addr[0];
        ipv6_interface_id[1] = mac_addr[1];
        ipv6_interface_id[2] = mac_addr[2];
        ipv6_interface_id[3] = 0xff;
        ipv6_interface_id[4] = 0xfe;
        ipv6_interface_id[5] = mac_addr[3];
        ipv6_interface_id[6] = mac_addr[4];
        ipv6_interface_id[7] = mac_addr[5];
        LCPStatus {
            lcp_echo_times: 0,
            echo_req_id: 0,
            client_config: TagValue::Nak(LcpBaseConfig::new_client(requested_mru)),
            server_config: TagValue::Nak(LcpBaseConfig::new_client(requested_mru)),
            cfg_req_id: 1,
            auth_type: TagValue::Nak(0),
            authenticator: None,
            ipcp_server_ipaddr: TagValue::Nak(Ipv4Addr::UNSPECIFIED),
            ipcp_client_ipaddr: TagValue::Nak(Ipv4Addr::UNSPECIFIED),
            ipcp_req_id: 1,
            ip6cp_server_id: TagValue::Nak(vec![]),
            ip6cp_client_id: TagValue::Nak(ipv6_interface_id.to_vec()),
            ip6cp_req_id: 1,
            termination: (false, TagValue::Nak(())),
        }
    }

    pub(crate) fn connect_base_cfg_redy(&self) -> bool {
        self.client_config.is_confirm() && self.server_config.is_confirm()
    }
}

pub(crate) enum TagValue<T> {
    Nak(T),
    Ack(T),
    Reject,
}

impl<T> TagValue<T> {
    pub(crate) fn is_confirm(&self) -> bool {
        match self {
            TagValue::Nak(_) => false,
            TagValue::Ack(_) | TagValue::Reject => true,
        }
    }
}

impl<T: Clone> TagValue<T> {
    pub(crate) fn get_value(&self) -> Option<T> {
        match self {
            TagValue::Ack(v) => Some(v.clone()),
            TagValue::Nak(_) | TagValue::Reject => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LCPStatus, TagValue};
    use landscape_common::net::MacAddr;

    #[test]
    fn tag_value_reports_confirm_and_value() {
        let ack = TagValue::Ack(42_u16);
        assert!(ack.is_confirm());
        assert_eq!(ack.get_value(), Some(42));

        let nak = TagValue::Nak(7_u16);
        assert!(!nak.is_confirm());
        assert_eq!(nak.get_value(), None);

        let reject: TagValue<u16> = TagValue::Reject;
        assert!(reject.is_confirm());
        assert_eq!(reject.get_value(), None);
    }

    #[test]
    fn lcp_status_new_uses_requested_mru_and_ipv6_id() {
        let mac = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
        let status = LCPStatus::new(mac, 1480);

        match &status.client_config {
            TagValue::Nak(cfg) => assert_eq!(cfg.mru, 1480),
            _ => panic!("client config should start as NAK"),
        }

        match &status.ip6cp_client_id {
            TagValue::Nak(id) => {
                assert_eq!(id, &vec![0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55])
            }
            _ => panic!("ipv6cp client id should start as NAK"),
        }

        assert!(!status.connect_base_cfg_redy());
    }
}
