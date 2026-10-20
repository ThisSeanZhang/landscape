use std::io::{self, BufReader, Read};

use landscape_common::{config_service::geo::GeoError, dns::rule::DomainMatchType};
use quick_protobuf::{BytesReader, MessageRead};

use crate::protos::geo::Domain;

pub const MAX_DOMAIN_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_COUNTRY_CODE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoSiteStreamEvent {
    EntryStart { country_code: String },
    Domain { match_type: DomainMatchType, value: String, attributes: Vec<String> },
    EntryEnd,
}

/// Streaming decoder for `GeoSiteList` files.
///
/// The top-level list and each `GeoSite` entry are parsed incrementally. Only
/// one encoded `Domain` message is materialized at a time. The canonical
/// geosite.dat layout writes `country_code` before `domain`, so a domain that
/// appears before its country code is treated as malformed input.
pub struct GeoSiteStream<R: Read> {
    reader: BufReader<R>,
    state: StreamState,
    finished: bool,
}

#[derive(Debug)]
enum StreamState {
    TopLevel,
    Entry { remaining: u64, country_code_seen: bool },
}

impl<R: Read> GeoSiteStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            state: StreamState::TopLevel,
            finished: false,
        }
    }

    fn next_event_inner(&mut self) -> Result<Option<GeoSiteStreamEvent>, GeoError> {
        loop {
            match &mut self.state {
                StreamState::TopLevel => {
                    let Some(tag) =
                        read_optional_varint(&mut self.reader).map_err(stream_io_error)?
                    else {
                        self.finished = true;
                        return Ok(None);
                    };
                    if tag == 0 {
                        return Err(GeoError::SiteDatDecodeError);
                    }
                    let field_number = tag >> 3;
                    let wire_type = (tag & 0x07) as u8;
                    if field_number == 1 {
                        if wire_type != 2 {
                            return Err(GeoError::SiteDatDecodeError);
                        }
                        let length = read_varint(&mut self.reader).map_err(stream_io_error)?;
                        self.state =
                            StreamState::Entry { remaining: length, country_code_seen: false };
                    } else {
                        skip_field(&mut self.reader, wire_type, None).map_err(stream_io_error)?;
                    }
                }
                StreamState::Entry { remaining, country_code_seen } => {
                    if *remaining == 0 {
                        if *country_code_seen {
                            self.state = StreamState::TopLevel;
                            return Ok(Some(GeoSiteStreamEvent::EntryEnd));
                        }
                        *country_code_seen = true;
                        return Ok(Some(GeoSiteStreamEvent::EntryStart {
                            country_code: String::new(),
                        }));
                    }

                    let tag = read_counted_u64(&mut self.reader, remaining)?;
                    if tag == 0 {
                        return Err(GeoError::SiteDatDecodeError);
                    }
                    let field_number = tag >> 3;
                    let wire_type = (tag & 0x07) as u8;

                    match (field_number, wire_type) {
                        (1, 2) => {
                            if *country_code_seen {
                                return Err(GeoError::SiteDatDecodeError);
                            }
                            let length = read_counted_u64(&mut self.reader, remaining)?;
                            let length = usize::try_from(length)
                                .map_err(|_| GeoError::SiteDatDecodeError)?;
                            if length > MAX_COUNTRY_CODE_BYTES {
                                return Err(GeoError::SiteDatDecodeError);
                            }
                            let bytes = read_counted_bytes(&mut self.reader, remaining, length)?;
                            let country_code = String::from_utf8(bytes)
                                .map_err(|_| GeoError::SiteDatDecodeError)?;
                            *country_code_seen = true;
                            return Ok(Some(GeoSiteStreamEvent::EntryStart { country_code }));
                        }
                        (2, 2) => {
                            if !*country_code_seen {
                                return Err(GeoError::SiteDatDecodeError);
                            }
                            let length = read_counted_u64(&mut self.reader, remaining)?;
                            let length = usize::try_from(length)
                                .map_err(|_| GeoError::SiteDatDecodeError)?;
                            if length > MAX_DOMAIN_MESSAGE_BYTES {
                                return Err(GeoError::SiteDatDecodeError);
                            }
                            let bytes = read_counted_bytes(&mut self.reader, remaining, length)?;
                            let domain = decode_domain(&bytes)?;
                            return Ok(Some(domain));
                        }
                        _ => {
                            skip_field(&mut self.reader, wire_type, Some(remaining))
                                .map_err(stream_io_error)?;
                        }
                    }
                }
            }
        }
    }
}

impl<R: Read> Iterator for GeoSiteStream<R> {
    type Item = Result<GeoSiteStreamEvent, GeoError>;

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

fn decode_domain(bytes: &[u8]) -> Result<GeoSiteStreamEvent, GeoError> {
    let mut reader = BytesReader::from_bytes(bytes);
    let domain =
        Domain::from_reader(&mut reader, bytes).map_err(|_| GeoError::SiteDatDecodeError)?;
    let match_type = crate::convert_match_type_from_proto(domain.type_pb);
    let value = domain.value.to_lowercase();
    let attributes = domain.attribute.iter().map(|attribute| attribute.key.to_string()).collect();
    Ok(GeoSiteStreamEvent::Domain { match_type, value, attributes })
}

fn read_optional_varint<R: Read>(reader: &mut R) -> io::Result<Option<u64>> {
    let mut first = [0u8; 1];
    if reader.read(&mut first)? == 0 {
        return Ok(None);
    }
    let mut result = u64::from(first[0] & 0x7f);
    let mut byte = first[0];
    let mut shift = 7u32;
    while byte & 0x80 != 0 {
        if shift >= 64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"));
        }
        reader.read_exact(&mut first)?;
        byte = first[0];
        result |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }
    Ok(Some(result))
}

fn read_varint<R: Read>(reader: &mut R) -> io::Result<u64> {
    read_optional_varint(reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated varint"))
}

fn read_counted_u64<R: Read>(reader: &mut R, remaining: &mut u64) -> Result<u64, GeoError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).map_err(stream_io_error)?;
        *remaining = remaining.checked_sub(1).ok_or(GeoError::SiteDatDecodeError)?;
        if shift >= 64 {
            return Err(GeoError::SiteDatDecodeError);
        }
        result |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

fn read_counted_bytes<R: Read>(
    reader: &mut R,
    remaining: &mut u64,
    length: usize,
) -> Result<Vec<u8>, GeoError> {
    let length_u64 = u64::try_from(length).map_err(|_| GeoError::SiteDatDecodeError)?;
    if *remaining < length_u64 {
        return Err(GeoError::SiteDatDecodeError);
    }
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes).map_err(stream_io_error)?;
    *remaining -= length_u64;
    Ok(bytes)
}

fn skip_field<R: Read>(
    reader: &mut R,
    wire_type: u8,
    mut remaining: Option<&mut u64>,
) -> io::Result<()> {
    match wire_type {
        0 => {
            skip_varint(reader, remaining.as_deref_mut())?;
        }
        1 => {
            skip_exact(reader, 8, remaining.as_deref_mut())?;
        }
        2 => {
            let length = match remaining.as_deref_mut() {
                Some(remaining) => read_counted_u64_io(reader, remaining)?,
                None => read_varint(reader)?,
            };
            let length = usize::try_from(length)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "length too large"))?;
            skip_exact(reader, length, remaining.as_deref_mut())?;
        }
        5 => {
            skip_exact(reader, 4, remaining)?;
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported wire type"));
        }
    }
    Ok(())
}

fn skip_varint<R: Read>(reader: &mut R, remaining: Option<&mut u64>) -> io::Result<()> {
    let mut remaining = remaining;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        if let Some(remaining) = remaining.as_deref_mut() {
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry underflow"))?;
        }
        if byte[0] & 0x80 == 0 {
            return Ok(());
        }
    }
}

fn skip_exact<R: Read>(
    reader: &mut R,
    mut length: usize,
    mut remaining: Option<&mut u64>,
) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    while length > 0 {
        let chunk = length.min(buffer.len());
        reader.read_exact(&mut buffer[..chunk])?;
        length -= chunk;
        if let Some(remaining) = remaining.as_deref_mut() {
            *remaining = remaining
                .checked_sub(chunk as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry underflow"))?;
        }
    }
    Ok(())
}

fn read_counted_u64_io<R: Read>(reader: &mut R, remaining: &mut u64) -> io::Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry underflow"))?;
        if shift >= 64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"));
        }
        result |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

fn stream_io_error(error: io::Error) -> GeoError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData => GeoError::SiteDatDecodeError,
        _ => GeoError::RawDatReadFailed(format!("geosite stream read failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use landscape_common::dns::rule::DomainMatchType;

    use super::{GeoSiteStream, GeoSiteStreamEvent};

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

    fn encode_domain(match_type: DomainMatchType, value: &str, attributes: &[&str]) -> Vec<u8> {
        let mut domain = Vec::new();
        push_varint(&mut domain, 1 << 3);
        push_varint(
            &mut domain,
            match match_type {
                DomainMatchType::Plain => 0,
                DomainMatchType::Regex => 1,
                DomainMatchType::Domain => 2,
                DomainMatchType::Full => 3,
            },
        );
        push_len_field(&mut domain, 2, value.as_bytes());
        for attribute in attributes {
            let mut encoded_attribute = Vec::new();
            push_len_field(&mut encoded_attribute, 1, attribute.as_bytes());
            push_len_field(&mut domain, 3, &encoded_attribute);
        }
        domain
    }

    fn encode_geosite(country_code: &str, domains: &[(DomainMatchType, &str, &[&str])]) -> Vec<u8> {
        let mut entry = Vec::new();
        push_len_field(&mut entry, 1, country_code.as_bytes());
        for (match_type, value, attributes) in domains {
            let domain = encode_domain(match_type.clone(), value, attributes);
            push_len_field(&mut entry, 2, &domain);
        }
        entry
    }

    fn encode_geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut list = Vec::new();
        for entry in entries {
            push_len_field(&mut list, 1, entry);
        }
        list
    }

    #[test]
    fn stream_decodes_entries_and_domains_incrementally() {
        let bytes = encode_geosite_list(&[
            encode_geosite(
                "CN",
                &[
                    (DomainMatchType::Domain, "Example.COM", &["cn"]),
                    (DomainMatchType::Full, "www.example.com", &[]),
                ],
            ),
            encode_geosite("ADS", &[]),
        ]);

        let events: Vec<GeoSiteStreamEvent> =
            GeoSiteStream::new(Cursor::new(bytes)).collect::<Result<_, _>>().unwrap();
        assert_eq!(
            events,
            vec![
                GeoSiteStreamEvent::EntryStart { country_code: "CN".to_string() },
                GeoSiteStreamEvent::Domain {
                    match_type: DomainMatchType::Domain,
                    value: "example.com".to_string(),
                    attributes: vec!["cn".to_string()],
                },
                GeoSiteStreamEvent::Domain {
                    match_type: DomainMatchType::Full,
                    value: "www.example.com".to_string(),
                    attributes: Vec::new(),
                },
                GeoSiteStreamEvent::EntryEnd,
                GeoSiteStreamEvent::EntryStart { country_code: "ADS".to_string() },
                GeoSiteStreamEvent::EntryEnd,
            ]
        );
    }

    #[test]
    fn truncated_stream_returns_an_error() {
        let bytes = encode_geosite_list(&[encode_geosite("CN", &[])]);
        let result: Result<Vec<_>, _> =
            GeoSiteStream::new(Cursor::new(&bytes[..bytes.len() - 1])).collect();
        assert!(result.is_err());
    }
    #[test]
    fn stream_matches_buffered_geosite_parser() {
        let bytes = encode_geosite_list(&[
            encode_geosite(
                "CN",
                &[
                    (DomainMatchType::Domain, "Example.COM", &["cn"]),
                    (DomainMatchType::Regex, "^ads\\.Example\\.com$", &[]),
                ],
            ),
            encode_geosite("ADS", &[(DomainMatchType::Plain, "Tracker", &[])]),
        ]);
        let expected = crate::read_geo_sites_from_bytes(bytes.clone()).unwrap();

        let mut current = None;
        let mut actual = std::collections::HashMap::new();
        for event in GeoSiteStream::new(Cursor::new(bytes)) {
            match event.unwrap() {
                GeoSiteStreamEvent::EntryStart { country_code } => current = Some(country_code),
                GeoSiteStreamEvent::Domain { match_type, value, attributes } => {
                    actual
                        .entry(current.clone().unwrap())
                        .or_insert_with(Vec::new)
                        .push((match_type, value, attributes));
                }
                GeoSiteStreamEvent::EntryEnd => {
                    current = None;
                }
            }
        }

        let expected = expected
            .into_iter()
            .map(|(key, values)| {
                (
                    key,
                    values
                        .into_iter()
                        .map(|value| (value.match_type, value.value, value.attributes))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let actual = actual
            .into_iter()
            .map(|(key, values)| {
                (
                    key,
                    values
                        .into_iter()
                        .map(|(match_type, value, attributes)| {
                            (
                                match_type,
                                value,
                                attributes.into_iter().collect::<std::collections::HashSet<_>>(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(actual, expected);
    }
}
