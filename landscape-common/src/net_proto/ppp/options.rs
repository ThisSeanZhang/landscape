use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PPPOption {
    pub t: u8,
    pub length: u8,
    pub data: Vec<u8>,
}

impl PPPOption {
    pub fn from_bytes(data: &[u8]) -> Vec<PPPOption> {
        let mut result = vec![];
        let mut index = 0;
        loop {
            if index + 2 > data.len() {
                break;
            }
            let t = data[index];
            if t == 0 {
                break;
            }
            let length = data[index + 1];
            if length < 2 {
                break;
            }
            let data_end = index + length as usize;
            if data_end > data.len() {
                break;
            }
            result.push(PPPOption {
                t,
                length,
                data: data[index + 2..data_end].to_vec(),
            });
            index = data_end;
        }
        result
    }

    pub fn is_mru(&self) -> bool {
        self.t == 0x01
    }

    pub fn is_auth_type(&self) -> bool {
        self.t == 0x03
    }

    pub fn is_magic_number(&self) -> bool {
        self.t == 0x05
    }

    pub fn convert_to_payload(&self) -> Vec<u8> {
        let mut result = vec![self.t, self.length];
        result.extend(&self.data);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::PPPOption;

    #[test]
    fn test_option() {
        let data: Vec<u8> = [
            0x01, 0x04, 0x05, 0xd4, 0x03, 0x04, 0xc0, 0x23, 0x05, 0x06, 0xe1, 0xe3, 0xfb, 0x26,
            0x00, 0x00,
        ]
        .to_vec();
        let data = PPPOption::from_bytes(&data);
        assert_eq!(data.len(), 3);
    }

    #[test]
    fn parse_chap_auth_option_with_algorithm() {
        let data: Vec<u8> = [0x03, 0x05, 0xc2, 0x23, 0x05].to_vec();
        let options = PPPOption::from_bytes(&data);
        assert_eq!(options.len(), 1);
        assert!(options[0].is_auth_type());
        assert_eq!(options[0].length, 5);
        assert_eq!(options[0].data, vec![0xc2, 0x23, 0x05]);
    }
}
