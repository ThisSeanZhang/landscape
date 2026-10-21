use std::io::{self, BufRead, BufReader, Read};

use landscape_common::{config_service::geo::GeoError, flow::ip_mark::IpConfig};
use quick_protobuf::{BytesReader, MessageRead};

use crate::ip_utils::mask_ip;
use crate::protobuf_stream::{
    read_counted_bytes, read_counted_bytes_into, read_counted_u64, read_optional_varint,
    read_varint, skip_field,
};
use crate::protos::geo::CIDR;

const MAX_COUNTRY_CODE_BYTES: usize = 64 * 1024;
const MAX_CIDR_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoIpStreamEvent {
    EntryStart { country_code: String },
    Cidr(IpConfig),
    EntryEnd,
}

/// Streaming decoder for `GeoIPList` protobuf files.
///
/// Only one encoded `CIDR` message is materialized at a time. The canonical
/// geoip.dat layout writes `country_code` before `cidr`.
pub struct GeoIpDatStream<R: Read> {
    reader: BufReader<R>,
    state: DatStreamState,
    message_buf: Vec<u8>,
    finished: bool,
}

#[derive(Debug)]
enum DatStreamState {
    TopLevel,
    Entry { remaining: u64, country_code_seen: bool },
}

impl<R: Read> GeoIpDatStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            state: DatStreamState::TopLevel,
            message_buf: Vec::new(),
            finished: false,
        }
    }

    fn next_event_inner(&mut self) -> Result<Option<GeoIpStreamEvent>, GeoError> {
        loop {
            match &mut self.state {
                DatStreamState::TopLevel => {
                    let Some(tag) =
                        read_optional_varint(&mut self.reader).map_err(dat_stream_io_error)?
                    else {
                        self.finished = true;
                        return Ok(None);
                    };
                    if tag == 0 {
                        return Err(GeoError::IpDatDecodeError);
                    }
                    let field_number = tag >> 3;
                    let wire_type = (tag & 0x07) as u8;
                    if field_number == 1 {
                        if wire_type != 2 {
                            return Err(GeoError::IpDatDecodeError);
                        }
                        let length = read_varint(&mut self.reader).map_err(dat_stream_io_error)?;
                        self.state =
                            DatStreamState::Entry { remaining: length, country_code_seen: false };
                    } else {
                        skip_field(&mut self.reader, wire_type, None)
                            .map_err(dat_stream_io_error)?;
                    }
                }
                DatStreamState::Entry { remaining, country_code_seen } => {
                    if *remaining == 0 {
                        if *country_code_seen {
                            self.state = DatStreamState::TopLevel;
                            return Ok(Some(GeoIpStreamEvent::EntryEnd));
                        }
                        *country_code_seen = true;
                        return Ok(Some(GeoIpStreamEvent::EntryStart {
                            country_code: String::new(),
                        }));
                    }

                    let tag = read_counted_u64(&mut self.reader, remaining)
                        .map_err(dat_stream_io_error)?;
                    if tag == 0 {
                        return Err(GeoError::IpDatDecodeError);
                    }
                    let field_number = tag >> 3;
                    let wire_type = (tag & 0x07) as u8;

                    match (field_number, wire_type) {
                        (1, 2) => {
                            if *country_code_seen {
                                return Err(GeoError::IpDatDecodeError);
                            }
                            let length = read_counted_u64(&mut self.reader, remaining)
                                .map_err(dat_stream_io_error)?;
                            let length =
                                usize::try_from(length).map_err(|_| GeoError::IpDatDecodeError)?;
                            if length > MAX_COUNTRY_CODE_BYTES {
                                return Err(GeoError::IpDatDecodeError);
                            }
                            let bytes = read_counted_bytes(&mut self.reader, remaining, length)
                                .map_err(dat_stream_io_error)?;
                            let country_code =
                                String::from_utf8(bytes).map_err(|_| GeoError::IpDatDecodeError)?;
                            *country_code_seen = true;
                            return Ok(Some(GeoIpStreamEvent::EntryStart { country_code }));
                        }
                        (2, 2) => {
                            if !*country_code_seen {
                                return Err(GeoError::IpDatDecodeError);
                            }
                            let length = read_counted_u64(&mut self.reader, remaining)
                                .map_err(dat_stream_io_error)?;
                            let length =
                                usize::try_from(length).map_err(|_| GeoError::IpDatDecodeError)?;
                            if length > MAX_CIDR_MESSAGE_BYTES {
                                return Err(GeoError::IpDatDecodeError);
                            }
                            read_counted_bytes_into(
                                &mut self.reader,
                                remaining,
                                length,
                                &mut self.message_buf,
                            )
                            .map_err(dat_stream_io_error)?;
                            if let Some(cidr) = decode_cidr(&self.message_buf)? {
                                return Ok(Some(GeoIpStreamEvent::Cidr(cidr)));
                            }
                        }
                        _ => {
                            skip_field(&mut self.reader, wire_type, Some(remaining))
                                .map_err(dat_stream_io_error)?;
                        }
                    }
                }
            }
        }
    }
}

impl<R: Read> Iterator for GeoIpDatStream<R> {
    type Item = Result<GeoIpStreamEvent, GeoError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.next_event_inner() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

/// Streaming decoder for one-CIDR-per-line text files.
pub struct GeoIpTxtStream<R: Read> {
    reader: BufReader<R>,
    key: String,
    started: bool,
    finished: bool,
    line: Vec<u8>,
    valid_lines: usize,
    skipped_lines: usize,
}

impl<R: Read> GeoIpTxtStream<R> {
    pub fn new(reader: R, txt_key: Option<&str>) -> Self {
        let key = txt_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(crate::DEFAULT_TXT_GEO_KEY)
            .to_ascii_uppercase();
        Self {
            reader: BufReader::new(reader),
            key,
            started: false,
            finished: false,
            line: Vec::new(),
            valid_lines: 0,
            skipped_lines: 0,
        }
    }

    pub fn valid_lines(&self) -> usize {
        self.valid_lines
    }

    pub fn skipped_lines(&self) -> usize {
        self.skipped_lines
    }

    fn next_event_inner(&mut self) -> Result<Option<GeoIpStreamEvent>, GeoError> {
        if !self.started {
            self.started = true;
            return Ok(Some(GeoIpStreamEvent::EntryStart { country_code: self.key.clone() }));
        }

        loop {
            self.line.clear();
            let read =
                self.reader.read_until(b'\n', &mut self.line).map_err(txt_stream_io_error)?;
            if read == 0 {
                self.finished = true;
                if self.valid_lines == 0 {
                    return Err(GeoError::IpNoValidCidrFound);
                }
                return Ok(Some(GeoIpStreamEvent::EntryEnd));
            }

            let line = String::from_utf8_lossy(&self.line);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(cidr) = crate::parse_txt_cidr_line(line) {
                self.valid_lines += 1;
                return Ok(Some(GeoIpStreamEvent::Cidr(cidr)));
            }
            self.skipped_lines += 1;
        }
    }
}

impl<R: Read> Iterator for GeoIpTxtStream<R> {
    type Item = Result<GeoIpStreamEvent, GeoError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.next_event_inner() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

fn decode_cidr(bytes: &[u8]) -> Result<Option<IpConfig>, GeoError> {
    let mut reader = BytesReader::from_bytes(bytes);
    let cidr = CIDR::from_reader(&mut reader, bytes).map_err(|_| GeoError::IpDatDecodeError)?;
    Ok(crate::convert_ipconfig_from_proto(&cidr).map(|cidr| IpConfig {
        ip: mask_ip(cidr.ip, cidr.prefix),
        prefix: cidr.prefix,
    }))
}

fn dat_stream_io_error(error: io::Error) -> GeoError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData => GeoError::IpDatDecodeError,
        _ => GeoError::RawDatReadFailed(format!("geoip stream read failed: {error}")),
    }
}

fn txt_stream_io_error(error: io::Error) -> GeoError {
    GeoError::RawDatReadFailed(format!("geoip txt stream read failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Cursor, net::IpAddr};

    use landscape_common::{config_service::geo::GeoError, flow::ip_mark::IpConfig};

    use super::{GeoIpDatStream, GeoIpStreamEvent, GeoIpTxtStream};
    use crate::ip_utils::mask_ip;

    fn push_varint(output: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn push_len_field(output: &mut Vec<u8>, field: u8, bytes: &[u8]) {
        push_varint(output, u64::from(field << 3 | 2));
        push_varint(output, bytes.len() as u64);
        output.extend_from_slice(bytes);
    }

    fn encode_cidr(ip: IpAddr, prefix: u32) -> Vec<u8> {
        let mut cidr = Vec::new();
        let ip_bytes = match ip {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        push_len_field(&mut cidr, 1, &ip_bytes);
        push_varint(&mut cidr, 2 << 3);
        push_varint(&mut cidr, u64::from(prefix));
        cidr
    }

    fn encode_entry(country_code: &str, cidrs: &[(IpAddr, u32)]) -> Vec<u8> {
        let mut entry = Vec::new();
        push_len_field(&mut entry, 1, country_code.as_bytes());
        for (ip, prefix) in cidrs {
            let cidr = encode_cidr(*ip, *prefix);
            push_len_field(&mut entry, 2, &cidr);
        }
        entry
    }

    fn encode_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut list = Vec::new();
        for entry in entries {
            push_len_field(&mut list, 1, entry);
        }
        list
    }

    fn cidr(ip: &str, prefix: u32) -> IpConfig {
        IpConfig { ip: ip.parse().unwrap(), prefix }
    }

    #[test]
    fn dat_stream_decodes_entries_and_cidrs_incrementally() {
        let bytes = encode_list(&[
            encode_entry("CN", &[("10.0.0.0".parse().unwrap(), 8)]),
            encode_entry("US", &[("2001:db8::".parse().unwrap(), 32)]),
        ]);

        let events: Vec<GeoIpStreamEvent> =
            GeoIpDatStream::new(Cursor::new(bytes)).collect::<Result<_, _>>().unwrap();
        assert_eq!(
            events,
            vec![
                GeoIpStreamEvent::EntryStart { country_code: "CN".to_string() },
                GeoIpStreamEvent::Cidr(cidr("10.0.0.0", 8)),
                GeoIpStreamEvent::EntryEnd,
                GeoIpStreamEvent::EntryStart { country_code: "US".to_string() },
                GeoIpStreamEvent::Cidr(cidr("2001:db8::", 32)),
                GeoIpStreamEvent::EntryEnd,
            ]
        );
    }

    #[test]
    fn dat_stream_matches_buffered_parser() {
        let bytes = encode_list(&[encode_entry(
            "CN",
            &[("10.1.2.3".parse().unwrap(), 8), ("2001:db8::1".parse().unwrap(), 32)],
        )]);
        let expected = crate::read_geo_ips_from_bytes_dat(bytes.clone()).unwrap();

        let mut actual: HashMap<String, Vec<IpConfig>> = HashMap::new();
        let mut current = None;
        for event in GeoIpDatStream::new(Cursor::new(bytes)) {
            match event.unwrap() {
                GeoIpStreamEvent::EntryStart { country_code } => current = Some(country_code),
                GeoIpStreamEvent::Cidr(cidr) => {
                    actual.entry(current.clone().unwrap()).or_default().push(cidr)
                }
                GeoIpStreamEvent::EntryEnd => {}
            }
        }

        assert_eq!(actual["CN"].len(), expected["CN"].len());
        assert_eq!(actual["CN"][0].ip, mask_ip(expected["CN"][0].ip, expected["CN"][0].prefix));
        assert_eq!(actual["CN"][0].prefix, expected["CN"][0].prefix);
    }

    #[test]
    fn txt_stream_matches_buffered_parser() {
        let text = b"# comment\n10.1.2.3/8\ninvalid\n2001:db8::1/32\n";
        let expected = crate::read_geo_ips_from_bytes_txt(text, Some("cn"), &|| false).unwrap();
        let mut stream = GeoIpTxtStream::new(Cursor::new(text), Some("cn"));
        let events: Vec<GeoIpStreamEvent> = stream.by_ref().collect::<Result<_, _>>().unwrap();
        assert_eq!(
            events,
            vec![
                GeoIpStreamEvent::EntryStart { country_code: "CN".to_string() },
                GeoIpStreamEvent::Cidr(cidr("10.1.2.3", 8)),
                GeoIpStreamEvent::Cidr(cidr("2001:db8::1", 32)),
                GeoIpStreamEvent::EntryEnd,
            ]
        );
        assert_eq!(stream.valid_lines(), expected.valid_lines);
        assert_eq!(stream.skipped_lines(), expected.skipped_lines);
    }

    #[test]
    fn txt_stream_rejects_file_without_valid_cidrs() {
        let result: Result<Vec<_>, _> =
            GeoIpTxtStream::new(Cursor::new(b"# only comments\ninvalid\n"), None).collect();
        assert!(matches!(result, Err(GeoError::IpNoValidCidrFound)));
    }

    #[test]
    fn truncated_dat_stream_is_rejected() {
        let bytes = encode_list(&[encode_entry("CN", &[("10.0.0.0".parse().unwrap(), 8)])]);
        let result: Result<Vec<_>, _> =
            GeoIpDatStream::new(Cursor::new(&bytes[..bytes.len() - 1])).collect();
        assert!(result.is_err());
    }
}
