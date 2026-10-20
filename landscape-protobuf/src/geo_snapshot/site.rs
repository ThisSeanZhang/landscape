use std::{io::Read, path::PathBuf};

use landscape_common::dns::{domain::normalize_domain_string, rule::DomainMatchType};

use super::{
    GeoSnapshotError, GeoSnapshotIndex, GeoSnapshotMetadata, GeoSnapshotPayloadReader,
    GeoSnapshotReader, GeoSnapshotSourceKind, GeoSnapshotWriter,
};

const MAX_RULE_VALUE_BYTES: u32 = 1024 * 1024;
const MAX_ATTRIBUTES: u32 = 4096;
const MAX_ATTRIBUTE_BYTES: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoSnapshotRule {
    pub match_type: DomainMatchType,
    pub value: String,
    pub attributes: Vec<String>,
}

pub struct SiteSnapshotWriter {
    inner: GeoSnapshotWriter,
}

impl SiteSnapshotWriter {
    pub fn create(
        final_path: impl Into<PathBuf>,
        source_id: uuid::Uuid,
    ) -> Result<Self, GeoSnapshotError> {
        Ok(Self {
            inner: GeoSnapshotWriter::create(final_path, GeoSnapshotSourceKind::Site, source_id)?,
        })
    }

    pub fn start_key(&mut self, key: &str) -> Result<(), GeoSnapshotError> {
        self.inner.start_key(key)
    }

    pub fn write_rule(
        &mut self,
        match_type: DomainMatchType,
        value: &str,
        attributes: &[String],
    ) -> Result<(), GeoSnapshotError> {
        self.write_rule_iter(match_type, value, attributes.iter().map(String::as_str))
    }

    pub fn write_rule_iter<'a, I>(
        &mut self,
        match_type: DomainMatchType,
        value: &str,
        attributes: I,
    ) -> Result<(), GeoSnapshotError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let value = match match_type {
            DomainMatchType::Regex => value.to_string(),
            _ => normalize_domain_string(value.to_string()),
        };
        if value.len() > MAX_RULE_VALUE_BYTES as usize {
            return Err(GeoSnapshotError::InvalidPayload("site rule value is too large"));
        }

        let mut attributes: Vec<String> = attributes.into_iter().map(str::to_string).collect();
        attributes.sort_unstable();
        attributes.dedup();
        if attributes.len() > MAX_ATTRIBUTES as usize {
            return Err(GeoSnapshotError::InvalidPayload("site rule has too many attributes"));
        }
        for attribute in &attributes {
            if attribute.len() > MAX_ATTRIBUTE_BYTES as usize {
                return Err(GeoSnapshotError::InvalidPayload("site attribute is too large"));
            }
        }

        let mut item = Vec::new();
        item.push(match_type_tag(match_type));
        push_u32(&mut item, value.len())?;
        item.extend_from_slice(value.as_bytes());
        push_u32(&mut item, attributes.len())?;
        for attribute in &attributes {
            push_u32(&mut item, attribute.len())?;
            item.extend_from_slice(attribute.as_bytes());
        }
        self.inner.write_item(&item)
    }

    pub fn end_key(&mut self) -> Result<(), GeoSnapshotError> {
        self.inner.end_key()
    }

    pub fn finish(self) -> Result<(), GeoSnapshotError> {
        self.inner.finish()
    }
}

pub struct SiteSnapshotReader {
    inner: GeoSnapshotReader,
}

impl SiteSnapshotReader {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GeoSnapshotError> {
        let inner = GeoSnapshotReader::open(path)?;
        if inner.metadata().source_kind != GeoSnapshotSourceKind::Site {
            return Err(GeoSnapshotError::UnsupportedSourceKind(
                inner.metadata().source_kind as u8,
            ));
        }
        Ok(Self { inner })
    }

    pub fn metadata(&self) -> &GeoSnapshotMetadata {
        self.inner.metadata()
    }

    pub fn index(&self) -> &GeoSnapshotIndex {
        self.inner.index()
    }

    pub fn open_key(&self, key: &str) -> Result<SiteSnapshotKeyReader, GeoSnapshotError> {
        Ok(SiteSnapshotKeyReader {
            payload: self.inner.open_key(key)?,
            finished: false,
        })
    }
}

pub struct SiteSnapshotKeyReader {
    payload: GeoSnapshotPayloadReader,
    finished: bool,
}

impl SiteSnapshotKeyReader {
    pub fn next_rule(&mut self) -> Result<Option<GeoSnapshotRule>, GeoSnapshotError> {
        if self.finished {
            return Ok(None);
        }
        if self.payload.remaining_len() == 0 {
            self.payload.finish()?;
            self.finished = true;
            return Ok(None);
        }

        let match_type = read_match_type(&mut self.payload)?;
        let value_len = read_u32(&mut self.payload)?;
        if value_len > MAX_RULE_VALUE_BYTES {
            return Err(GeoSnapshotError::InvalidPayload("site rule value is too large"));
        }
        let value = read_string(&mut self.payload, value_len as usize, "rule value")?;

        let attribute_count = read_u32(&mut self.payload)?;
        if attribute_count > MAX_ATTRIBUTES {
            return Err(GeoSnapshotError::InvalidPayload("site rule has too many attributes"));
        }
        let mut attributes = Vec::with_capacity(attribute_count as usize);
        for _ in 0..attribute_count {
            let attribute_len = read_u32(&mut self.payload)?;
            if attribute_len > MAX_ATTRIBUTE_BYTES {
                return Err(GeoSnapshotError::InvalidPayload("site attribute is too large"));
            }
            attributes.push(read_string(&mut self.payload, attribute_len as usize, "attribute")?);
        }

        self.payload.record_item();
        Ok(Some(GeoSnapshotRule { match_type, value, attributes }))
    }
}

fn push_u32(output: &mut Vec<u8>, value: usize) -> Result<(), GeoSnapshotError> {
    let value = u32::try_from(value).map_err(|_| GeoSnapshotError::LengthOverflow)?;
    output.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_match_type<R: Read>(reader: &mut R) -> Result<DomainMatchType, GeoSnapshotError> {
    let mut tag = [0u8; 1];
    map_payload_read(reader.read_exact(&mut tag))?;
    match tag[0] {
        0 => Ok(DomainMatchType::Plain),
        1 => Ok(DomainMatchType::Regex),
        2 => Ok(DomainMatchType::Domain),
        3 => Ok(DomainMatchType::Full),
        _ => Err(GeoSnapshotError::InvalidPayload("invalid site match type")),
    }
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, GeoSnapshotError> {
    let mut bytes = [0u8; 4];
    map_payload_read(reader.read_exact(&mut bytes))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_string<R: Read>(
    reader: &mut R,
    len: usize,
    field: &'static str,
) -> Result<String, GeoSnapshotError> {
    let mut bytes = vec![0u8; len];
    map_payload_read(reader.read_exact(&mut bytes))?;
    String::from_utf8(bytes).map_err(|_| GeoSnapshotError::InvalidUtf8(field))
}

fn map_payload_read(result: std::io::Result<()>) -> Result<(), GeoSnapshotError> {
    result.map_err(|error| match error.kind() {
        std::io::ErrorKind::UnexpectedEof => GeoSnapshotError::TruncatedPayload,
        _ => GeoSnapshotError::Io(error),
    })
}

fn match_type_tag(match_type: DomainMatchType) -> u8 {
    match match_type {
        DomainMatchType::Plain => 0,
        DomainMatchType::Regex => 1,
        DomainMatchType::Domain => 2,
        DomainMatchType::Full => 3,
    }
}
