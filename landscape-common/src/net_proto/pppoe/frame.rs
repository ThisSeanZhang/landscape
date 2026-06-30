use std::{net::Ipv4Addr, time::SystemTime};

use serde::{Deserialize, Serialize};

use super::tags::PPPoETag;
use crate::net_proto::ppp::PointToPoint;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PPPoEFrame {
    pub ver: u8,
    pub t: u8,
    pub code: u8,
    pub sid: u16,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl PPPoEFrame {
    pub fn new(data: &[u8]) -> Option<PPPoEFrame> {
        if data.len() < 6 {
            return None;
        }
        let ver = data[0] >> 4;
        let t = data[0] & 0x0f;
        let sid = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        Some(PPPoEFrame {
            ver,
            t,
            code: data[1],
            sid,
            length,
            payload: data[6..].to_vec(),
        })
    }

    pub fn is_offer(&self) -> bool {
        self.code == 0x07
    }

    pub fn is_terminate(&self) -> bool {
        self.code == 0xa7
    }

    pub fn is_confirm(&self) -> bool {
        self.code == 0x65
    }

    pub fn is_session_data(&self) -> bool {
        self.code == 0x00
    }

    pub fn convert_to_payload(self) -> Vec<u8> {
        let mut result = vec![(self.ver << 4) | (self.t & 0x0f), self.code];
        result.extend(self.sid.to_be_bytes());
        result.extend((self.payload.len() as u16).to_be_bytes());
        result.extend(self.payload);
        result
    }

    pub fn get_discover(multi_modem: bool) -> (u32, PPPoEFrame) {
        let mut result = PPPoEFrame::new(&[17, 9, 0, 0, 0, 4, 1, 1, 0, 0]).unwrap();
        let mut host_uniq = 0;
        if multi_modem {
            host_uniq =
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32;
            result.payload.extend(PPPoETag::HostUniq(host_uniq).decode_options());
        }
        (host_uniq, result)
    }

    pub fn get_discover_with_host_uniq(host_uniq: u32) -> PPPoEFrame {
        let mut result = PPPoEFrame::new(&[17, 9, 0, 0, 0, 4, 1, 1, 0, 0]).unwrap();
        result.payload.extend(PPPoETag::HostUniq(host_uniq).decode_options());
        result
    }

    pub fn get_offer_with_host_uniq(host_uniq: u32) -> PPPoEFrame {
        let mut result = PPPoEFrame::new(&[17, 7, 0, 0, 0, 0]).unwrap();
        result.payload.extend(PPPoETag::HostUniq(host_uniq).decode_options());
        result.length = result.payload.len() as u16;
        result
    }

    pub fn get_request(host_uniq_id: u32, ac_cookie: Option<Vec<u8>>) -> PPPoEFrame {
        let mut result = PPPoEFrame::new(&[17, 25, 0, 0, 0, 12, 1, 1, 0, 0]).unwrap();
        if host_uniq_id != 0 {
            result.payload.extend(PPPoETag::HostUniq(host_uniq_id).decode_options());
            if let Some(ac_cookie) = ac_cookie {
                result.payload.extend(PPPoETag::AcCookie(ac_cookie).decode_options());
            }
        }
        result.length = result.payload.len() as u16;
        result
    }

    pub fn conversion_payload_to_ppp(&self) -> Option<PointToPoint> {
        PointToPoint::new(&self.payload)
    }

    pub fn get_ppp_mru_config_request(
        sid: u16,
        request_id: u8,
        mru: u16,
        magic_number: u32,
    ) -> PPPoEFrame {
        let data = PointToPoint::request_mru(request_id, mru, magic_number);
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: data.len() as u16,
            payload: data,
        }
    }

    pub fn get_ppp_lcp_pap(sid: u16, peer_id: &str, password: &str) -> PPPoEFrame {
        let payload = PointToPoint::gen_pap(peer_id, password).convert_to_payload();
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }

    pub fn get_ppp_auth_response(sid: u16, payload: Vec<u8>) -> PPPoEFrame {
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }

    pub fn gen_echo_request_with_magic(sid: u16, req_id: u8, magic_number: u32) -> PPPoEFrame {
        let payload = PointToPoint::gen_echo_request_with_magic(req_id, magic_number);
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }

    pub fn get_ipcp_request(sid: u16, req_id: u8) -> PPPoEFrame {
        let payload = PointToPoint::get_ipcp_request(
            req_id,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        )
        .convert_to_payload();
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }

    pub fn get_ipcp_request_only_client_ip(sid: u16, req_id: u8, ip: Ipv4Addr) -> PPPoEFrame {
        let payload =
            PointToPoint::get_ipcp_request_only_client_ip(req_id, ip).convert_to_payload();
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }

    pub fn get_ipcp_request_with_ip(
        sid: u16,
        req_id: u8,
        ip: Ipv4Addr,
        dns1: Ipv4Addr,
        dns2: Ipv4Addr,
    ) -> PPPoEFrame {
        let payload = PointToPoint::get_ipcp_request(req_id, ip, dns1, dns2).convert_to_payload();
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }

    pub fn get_ipv6cp_request(sid: u16, ipv6_interface_id: Vec<u8>, req_id: u8) -> PPPoEFrame {
        let payload =
            PointToPoint::get_ipv6cp_request(ipv6_interface_id, req_id).convert_to_payload();
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }

    pub fn get_termination_request(sid: u16, req_id: u8) -> PPPoEFrame {
        let payload = PointToPoint::get_termination_request(req_id).convert_to_payload();
        PPPoEFrame {
            ver: 1,
            t: 1,
            code: 0,
            sid,
            length: payload.len() as u16,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PPPoEFrame;

    #[test]
    fn discover() {
        let data = [17, 9, 0, 0, 0, 4, 1, 1, 0, 0];
        let p1 = PPPoEFrame::new(&data).unwrap();
        assert_eq!(p1.clone().convert_to_payload(), data);

        let data2 = [17, 9, 0, 0, 0, 12, 1, 1, 0, 0, 1, 3, 0, 4, 34, 30, 2, 0];
        let p2 = PPPoEFrame::new(&data2).unwrap();
        assert_eq!(p2.convert_to_payload(), data2);
    }

    #[test]
    fn offer_includes_host_uniq_tag() {
        let f = PPPoEFrame::get_offer_with_host_uniq(0x1234_5678);
        assert_eq!(f.ver, 1);
        assert_eq!(f.t, 1);
        assert_eq!(f.code, 0x07, "PADO");
        assert_eq!(f.sid, 0);

        use super::super::tags::PPPoETag;
        let tags = PPPoETag::from_bytes(&f.payload);
        assert_eq!(tags.len(), 1);
        if let PPPoETag::HostUniq(id) = &tags[0] {
            assert_eq!(*id, 0x1234_5678);
        } else {
            panic!("expected HostUniq tag");
        }
    }
}
