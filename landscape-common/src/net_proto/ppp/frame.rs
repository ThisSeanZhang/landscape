use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PointToPoint {
    /// 0xc021 LCP, 0xc023 PAP, 0x8021 IPCP, 0x8057 IPV6CP
    pub protocol: u16,
    pub code: u8,
    pub id: u8,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl PointToPoint {
    pub fn new(data: &[u8]) -> Option<PointToPoint> {
        if data.len() < 6 {
            return None;
        }
        let protocol = u16::from_be_bytes([data[0], data[1]]);
        let code = data[2];
        let id = data[3];
        let length = u16::from_be_bytes([data[4], data[5]]);
        if length < 4 {
            return None;
        }

        let data_end = length as usize + 2;
        if data_end > data.len() {
            return None;
        }

        Some(PointToPoint {
            protocol,
            code,
            id,
            length,
            payload: data[6..data_end].to_vec(),
        })
    }

    pub fn is_lcp_config(&self) -> bool {
        self.protocol == 0xc021
    }

    pub fn is_pap_auth(&self) -> bool {
        self.protocol == 0xc023
    }

    pub fn is_ipcp(&self) -> bool {
        self.protocol == 0x8021
    }

    pub fn is_ipv6cp(&self) -> bool {
        self.protocol == 0x8057
    }

    pub fn is_chap(&self) -> bool {
        self.protocol == 0xc223
    }

    pub fn is_request(&self) -> bool {
        self.code == 1
    }

    pub fn is_ack(&self) -> bool {
        self.code == 2
    }

    pub fn is_nak(&self) -> bool {
        self.code == 3
    }

    pub fn is_reject(&self) -> bool {
        self.code == 4
    }

    pub fn is_termination(&self) -> bool {
        self.code == 5
    }

    pub fn is_termination_ack(&self) -> bool {
        self.code == 6
    }

    pub fn is_proto_reject(&self) -> bool {
        self.code == 8
    }

    pub fn is_echo_request(&self) -> bool {
        self.code == 9
    }

    pub fn is_echo_reply(&self) -> bool {
        self.code == 10
    }

    pub fn is_challenge(&self) -> bool {
        self.code == 1
    }

    pub fn is_chap_success(&self) -> bool {
        self.code == 3
    }

    pub fn is_chap_failure(&self) -> bool {
        self.code == 4
    }

    pub fn request_mru(request_id: u8, mru: u16, magic_number: u32) -> Vec<u8> {
        let len = 14_u16;
        [
            [0xc0, 0x21, 1, request_id].to_vec(),
            len.to_be_bytes().to_vec(),
            [1, 4].to_vec(),
            mru.to_be_bytes().to_vec(),
            [5, 6].to_vec(),
            magic_number.to_be_bytes().to_vec(),
        ]
        .concat()
    }

    pub fn request_mru_with_auth(
        request_id: u8,
        mru: u16,
        magic_number: u32,
        auth_type: u16,
    ) -> Vec<u8> {
        let len = 18_u16;
        [
            [0xc0, 0x21, 1, request_id].to_vec(),
            len.to_be_bytes().to_vec(),
            [1, 4].to_vec(),
            mru.to_be_bytes().to_vec(),
            [3, 4].to_vec(),
            auth_type.to_be_bytes().to_vec(),
            [5, 6].to_vec(),
            magic_number.to_be_bytes().to_vec(),
        ]
        .concat()
    }

    pub fn ack_mru(request_id: u8, mru: u16, magic_number: u32) -> Vec<u8> {
        let len = 14_u16;
        [
            [0xc0, 0x21, 2, request_id].to_vec(),
            len.to_be_bytes().to_vec(),
            [1, 4].to_vec(),
            mru.to_be_bytes().to_vec(),
            [5, 6].to_vec(),
            magic_number.to_be_bytes().to_vec(),
        ]
        .concat()
    }

    pub fn nak_mru(request_id: u8, mru: u16, magic_number: u32) -> Vec<u8> {
        let len = 14_u16;
        [
            [0xc0, 0x21, 3, request_id].to_vec(),
            len.to_be_bytes().to_vec(),
            [1, 4].to_vec(),
            mru.to_be_bytes().to_vec(),
            [5, 6].to_vec(),
            magic_number.to_be_bytes().to_vec(),
        ]
        .concat()
    }

    pub fn gen_reject(&self, reject_option: Vec<u8>) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.protocol.to_be_bytes());
        result.push(4);
        result.push(self.id);
        result.extend((reject_option.len() as u16 + 4_u16).to_be_bytes());
        result.extend(reject_option);
        result
    }

    pub fn gen_ack(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.protocol.to_be_bytes());
        result.push(2);
        result.push(self.id);
        result.extend(self.length.to_be_bytes());
        result.extend(self.payload.clone());
        result
    }

    pub fn gen_reply(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.protocol.to_be_bytes());
        result.push(10);
        result.push(self.id);
        result.extend(self.length.to_be_bytes());
        result.extend(self.payload.clone());
        result
    }

    pub fn gen_reply_with_magic(&self, magic_number: u32) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.protocol.to_be_bytes());
        result.push(10);
        result.push(self.id);
        result.extend(8_u16.to_be_bytes());
        result.extend(magic_number.to_be_bytes());
        result
    }

    pub fn gen_echo_request_with_magic(id: u8, magic_number: u32) -> Vec<u8> {
        let mut result = vec![0xc0, 0x21];
        result.push(9);
        result.push(id);
        result.extend(8_u16.to_be_bytes());
        result.extend(magic_number.to_be_bytes());
        result
    }

    pub fn gen_pap(peer_id: &str, password: &str) -> PointToPoint {
        let mut payload = vec![peer_id.len() as u8];
        payload.extend(peer_id.as_bytes());
        payload.push(password.len() as u8);
        payload.extend(password.as_bytes());
        PointToPoint {
            protocol: 0xc023,
            code: 1,
            id: 1,
            length: payload.len() as u16 + 4,
            payload,
        }
    }

    pub fn gen_chap_response(id: u8, peer_id: &str, password: &str, challenge: &[u8]) -> Vec<u8> {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(&[id]);
        hasher.update(password.as_bytes());
        hasher.update(challenge);
        let hash = hasher.finalize();
        let mut payload = vec![16u8];
        payload.extend(hash.as_slice());
        payload.extend(peer_id.as_bytes());
        let length = (payload.len() + 4) as u16;
        let mut result = vec![0xc2, 0x23, 2, id];
        result.extend(length.to_be_bytes());
        result.extend(payload);
        result
    }

    pub fn get_ipcp_request_only_client_ip(id: u8, ip: Ipv4Addr) -> PointToPoint {
        let ip = ip.octets();
        let options: Vec<u8> = [3, 6, ip[0], ip[1], ip[2], ip[3]].to_vec();

        PointToPoint {
            protocol: 0x8021,
            code: 1,
            id,
            length: 10,
            payload: options,
        }
    }

    pub fn get_ipcp_request(id: u8, ip: Ipv4Addr, dns1: Ipv4Addr, dns2: Ipv4Addr) -> PointToPoint {
        let ip = ip.octets();
        let dns1 = dns1.octets();
        let dns2 = dns2.octets();
        let options: Vec<u8> = [
            3, 6, ip[0], ip[1], ip[2], ip[3], 0x81, 6, dns1[0], dns1[1], dns1[2], dns1[3], 0x83, 6,
            dns2[0], dns2[1], dns2[2], dns2[3],
        ]
        .to_vec();

        PointToPoint {
            protocol: 0x8021,
            code: 1,
            id,
            length: 22,
            payload: options,
        }
    }

    pub fn get_ipv6cp_request(ipv6_interface_id: Vec<u8>, id: u8) -> PointToPoint {
        let mut options: Vec<u8> = [1, 0x0a].to_vec();
        options.extend(ipv6_interface_id);
        let length = options.len() as u16 + 4;
        PointToPoint {
            protocol: 0x8057,
            code: 1,
            id,
            length,
            payload: options,
        }
    }

    pub fn get_termination_request(id: u8) -> PointToPoint {
        let options: Vec<u8> =
            [0x55, 0x73, 0x65, 0x72, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74].to_vec();
        let length = options.len() as u16 + 4;
        PointToPoint {
            protocol: 0xc021,
            code: 5,
            id,
            length,
            payload: options,
        }
    }

    pub fn get_termination_ack(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.protocol.to_be_bytes());
        result.push(6);
        result.push(self.id);
        result.extend(self.length.to_be_bytes());
        result.extend(self.payload.clone());
        result
    }

    pub fn convert_to_payload(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(self.protocol.to_be_bytes());
        result.push(self.code);
        result.push(self.id);
        result.extend(self.length.to_be_bytes());
        result.extend(self.payload.clone());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_chap_response_packet_structure() {
        let id = 0x02;
        let peer_id = "client";
        let password = "secret";
        let challenge = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let pkt = PointToPoint::gen_chap_response(id, peer_id, password, &challenge);

        assert_eq!(pkt[0], 0xc2, "protocol byte 0");
        assert_eq!(pkt[1], 0x23, "protocol byte 1");
        assert_eq!(pkt[2], 2, "code = Response");
        assert_eq!(pkt[3], id, "id preserved");

        let length = u16::from_be_bytes([pkt[4], pkt[5]]);
        assert_eq!(pkt.len(), length as usize + 2, "length field consistent");

        assert_eq!(pkt[6], 16, "value-size = 16 (MD5 digest)");

        let hash_bytes = &pkt[7..23];
        assert_eq!(hash_bytes.len(), 16, "hash is 16 bytes");

        let name_bytes = &pkt[23..];
        assert_eq!(name_bytes, peer_id.as_bytes(), "name follows hash");
    }

    #[test]
    fn gen_chap_response_hash_is_correct() {
        use md5::{Digest, Md5};

        let id = 0x01;
        let password = "clientPass";
        let challenge = [0x5eu8, 0x47, 0xb9, 0xc2, 0x7e, 0x34, 0x55, 0xc2];

        let pkt = PointToPoint::gen_chap_response(id, "peer", password, &challenge);

        let mut hasher = Md5::new();
        hasher.update(&[id]);
        hasher.update(password.as_bytes());
        hasher.update(&challenge);
        let expected = hasher.finalize();

        let hash_from_pkt = &pkt[7..23];
        assert_eq!(hash_from_pkt, expected.as_slice(), "MD5 hash matches independent computation");
    }

    #[test]
    fn gen_chap_response_different_inputs_different_outputs() {
        let challenge1 = [1u8, 2, 3, 4];
        let challenge2 = [5u8, 6, 7, 8];

        let pkt1 = PointToPoint::gen_chap_response(1, "peer", "pass", &challenge1);
        let pkt2 = PointToPoint::gen_chap_response(1, "peer", "pass", &challenge2);

        let hash1 = &pkt1[7..23];
        let hash2 = &pkt2[7..23];
        assert_ne!(hash1, hash2, "different challenges produce different hashes");
    }

    // ── encoding cross-checks ────────────────────────────────────────

    fn ppp_u16_at(d: &[u8], o: usize) -> u16 {
        u16::from_be_bytes([d[o], d[o + 1]])
    }
    fn ppp_u32_at(d: &[u8], o: usize) -> u32 {
        u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
    }

    #[test]
    fn request_mru_encodes_mru_and_magic() {
        let pkt = PointToPoint::request_mru(0x42, 1400, 0xCAFE_BEEF);
        assert_eq!(ppp_u16_at(&pkt, 0), 0xc021, "protocol LCP");
        assert_eq!(pkt[2], 1, "code Request");
        assert_eq!(pkt[3], 0x42, "id");
        // option MRU
        assert_eq!(pkt[6], 1);
        assert_eq!(pkt[7], 4);
        assert_eq!(ppp_u16_at(&pkt, 8), 1400);
        // option magic
        assert_eq!(pkt[10], 5);
        assert_eq!(pkt[11], 6);
        assert_eq!(ppp_u32_at(&pkt, 12), 0xCAFE_BEEF);
    }

    #[test]
    fn request_mru_with_auth_includes_3_options() {
        let pkt = PointToPoint::request_mru_with_auth(1, 1492, 0xDEAD, 0xc023);
        assert_eq!(pkt[2], 1, "code Request");
        // PPP total length = 4 + (4 + 4 + 6) = 18
        assert_eq!(ppp_u16_at(&pkt, 4), 18);
        // option 1: MRU=1492
        assert_eq!(pkt[6], 1);
        assert_eq!(pkt[7], 4);
        assert_eq!(ppp_u16_at(&pkt, 8), 1492);
        // option 2: auth=PAP
        assert_eq!(pkt[10], 3);
        assert_eq!(pkt[11], 4);
        assert_eq!(ppp_u16_at(&pkt, 12), 0xc023);
        // option 3: magic
        assert_eq!(pkt[14], 5);
        assert_eq!(pkt[15], 6);
        assert_eq!(ppp_u32_at(&pkt, 16), 0xDEAD);
    }

    #[test]
    fn ack_mru_has_code_2() {
        let pkt = PointToPoint::ack_mru(7, 1492, 0xBEEF);
        assert_eq!(pkt[2], 2, "code Ack");
        assert_eq!(pkt[3], 7, "id");
    }

    #[test]
    fn nak_mru_has_code_3() {
        let pkt = PointToPoint::nak_mru(5, 1400, 0xCAFE);
        assert_eq!(pkt[2], 3, "code Nak");
        assert_eq!(pkt[3], 5, "id");
    }
}
