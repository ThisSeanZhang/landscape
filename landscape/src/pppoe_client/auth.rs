use landscape_common::net_proto::ppp::PointToPoint;

pub(crate) struct AuthResult {
    pub(crate) response: Option<Vec<u8>>,
    pub(crate) done: bool,
    pub(crate) failed: bool,
}

impl AuthResult {
    fn noop() -> Self {
        AuthResult { response: None, done: false, failed: false }
    }
}

pub(crate) trait Authenticator: std::fmt::Debug + Send + Sync {
    fn handle_incoming(&mut self, pkt: &PointToPoint) -> AuthResult;

    fn outgoing_packet(&self) -> Option<Vec<u8>>;

    #[allow(dead_code)]
    fn protocol(&self) -> u16;

    fn is_done(&self) -> bool;
}

#[derive(Debug)]
pub(crate) struct PapAuthenticator {
    done: bool,
    peer_id: String,
    password: String,
}

impl PapAuthenticator {
    pub(crate) fn new(peer_id: &str, password: &str) -> Self {
        PapAuthenticator {
            done: false,
            peer_id: peer_id.into(),
            password: password.into(),
        }
    }
}

impl Authenticator for PapAuthenticator {
    fn handle_incoming(&mut self, pkt: &PointToPoint) -> AuthResult {
        if pkt.is_ack() {
            self.done = true;
            AuthResult { response: None, done: true, failed: false }
        } else {
            AuthResult { response: None, done: true, failed: true }
        }
    }

    fn outgoing_packet(&self) -> Option<Vec<u8>> {
        if self.done {
            return None;
        }
        Some(PointToPoint::gen_pap(&self.peer_id, &self.password).convert_to_payload())
    }

    fn protocol(&self) -> u16 {
        0xc023
    }

    fn is_done(&self) -> bool {
        self.done
    }
}

#[derive(Debug)]
pub(crate) struct ChapAuthenticator {
    done: bool,
    peer_id: String,
    password: String,
    challenge: Option<Vec<u8>>,
    challenge_id: u8,
}

impl ChapAuthenticator {
    pub(crate) fn new(peer_id: &str, password: &str) -> Self {
        ChapAuthenticator {
            done: false,
            peer_id: peer_id.into(),
            password: password.into(),
            challenge: None,
            challenge_id: 0,
        }
    }
}

impl Authenticator for ChapAuthenticator {
    fn handle_incoming(&mut self, pkt: &PointToPoint) -> AuthResult {
        if pkt.is_challenge() {
            let value_size = pkt.payload[0] as usize;
            let challenge = &pkt.payload[1..1 + value_size];
            self.challenge = Some(challenge.to_vec());
            self.challenge_id = pkt.id;
            let response =
                PointToPoint::gen_chap_response(pkt.id, &self.peer_id, &self.password, challenge);
            AuthResult {
                response: Some(response),
                done: false,
                failed: false,
            }
        } else if pkt.is_chap_success() {
            self.done = true;
            AuthResult { response: None, done: true, failed: false }
        } else if pkt.is_chap_failure() {
            AuthResult { response: None, done: true, failed: true }
        } else {
            AuthResult::noop()
        }
    }

    fn outgoing_packet(&self) -> Option<Vec<u8>> {
        None
    }

    fn protocol(&self) -> u16 {
        0xc223
    }

    fn is_done(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pap_pkt(code: u8) -> PointToPoint {
        PointToPoint {
            protocol: 0xc023,
            code,
            id: 1,
            length: 4,
            payload: vec![],
        }
    }

    fn make_chap_challenge(id: u8, value: &[u8]) -> PointToPoint {
        let mut payload = vec![value.len() as u8];
        payload.extend(value);
        payload.extend(b"server");
        let length = payload.len() as u16 + 4;
        PointToPoint { protocol: 0xc223, code: 1, id, length, payload }
    }

    fn make_chap_success(id: u8) -> PointToPoint {
        PointToPoint {
            protocol: 0xc223,
            code: 3,
            id,
            length: 9,
            payload: vec![7, b'W', b'e', b'l', b'c', b'o', b'm', b'e'],
        }
    }

    fn make_chap_failure(id: u8) -> PointToPoint {
        PointToPoint {
            protocol: 0xc223,
            code: 4,
            id,
            length: 4,
            payload: vec![],
        }
    }

    mod pap {
        use super::*;

        #[test]
        fn ack_sets_done() {
            let mut auth = PapAuthenticator::new("user", "pass");
            assert!(!auth.is_done());
            let result = auth.handle_incoming(&make_pap_pkt(2));
            assert!(result.done);
            assert!(!result.failed);
            assert!(result.response.is_none());
            assert!(auth.is_done());
        }

        #[test]
        fn nak_sets_failed() {
            let mut auth = PapAuthenticator::new("user", "pass");
            let result = auth.handle_incoming(&make_pap_pkt(3));
            assert!(result.done);
            assert!(result.failed);
        }

        #[test]
        fn outgoing_returns_request_then_none_after_done() {
            let mut auth = PapAuthenticator::new("user", "pass");
            let req = auth.outgoing_packet();
            assert!(req.is_some(), "should return PAP request when not done");
            let req = req.unwrap();
            assert_eq!(req[0], 0xc0);
            assert_eq!(req[1], 0x23);
            assert_eq!(req[2], 1);

            auth.handle_incoming(&make_pap_pkt(2));
            assert!(auth.outgoing_packet().is_none(), "should return None after ack");
        }
    }

    mod chap {
        use super::*;

        #[test]
        fn challenge_generates_correct_response() {
            let mut auth = ChapAuthenticator::new("peer", "secret");
            let challenge_bytes = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
            let pkt = make_chap_challenge(0x02, &challenge_bytes);
            let result = auth.handle_incoming(&pkt);

            assert!(!result.done, "not done after challenge");
            assert!(!result.failed);
            assert!(!auth.is_done());
            assert!(result.response.is_some(), "must produce a response");

            let resp = result.response.unwrap();
            assert_eq!(resp[0], 0xc2, "protocol CHAP");
            assert_eq!(resp[1], 0x23);
            assert_eq!(resp[2], 2, "code=Response");
            assert_eq!(resp[3], 0x02, "id matches challenge");
            assert_eq!(resp[6], 16, "value-size=16");
            let hash = &resp[7..23];
            let name = &resp[23..];
            assert_eq!(name, b"peer", "name in response");
            assert_eq!(hash.len(), 16);

            use md5::{Digest, Md5};
            let mut hasher = Md5::new();
            hasher.update(&[0x02u8]);
            hasher.update(b"secret");
            hasher.update(&challenge_bytes);
            let expected = hasher.finalize();
            assert_eq!(hash, expected.as_slice(), "MD5 hash is correct");
        }

        #[test]
        fn success_after_challenge() {
            let mut auth = ChapAuthenticator::new("peer", "secret");
            auth.handle_incoming(&make_chap_challenge(1, &[1, 2, 3]));
            assert!(!auth.is_done(), "still not done after challenge");

            let result = auth.handle_incoming(&make_chap_success(1));
            assert!(result.done);
            assert!(!result.failed);
            assert!(auth.is_done());
        }

        #[test]
        fn failure_sets_failed() {
            let mut auth = ChapAuthenticator::new("peer", "secret");
            auth.handle_incoming(&make_chap_challenge(1, &[1, 2, 3]));

            let result = auth.handle_incoming(&make_chap_failure(1));
            assert!(result.done);
            assert!(result.failed);
            assert!(!auth.is_done());
        }

        #[test]
        fn outgoing_always_none() {
            let mut auth = ChapAuthenticator::new("peer", "secret");
            assert!(auth.outgoing_packet().is_none());
            auth.handle_incoming(&make_chap_challenge(1, &[1, 2, 3]));
            assert!(auth.outgoing_packet().is_none());
            auth.handle_incoming(&make_chap_success(1));
            assert!(auth.outgoing_packet().is_none());
        }

        #[test]
        fn unknown_code_is_noop() {
            let mut auth = ChapAuthenticator::new("peer", "secret");
            let pkt = PointToPoint {
                protocol: 0xc223,
                code: 99,
                id: 1,
                length: 4,
                payload: vec![],
            };
            let result = auth.handle_incoming(&pkt);
            assert!(!result.done);
            assert!(!result.failed);
            assert!(result.response.is_none());
        }
    }
}
