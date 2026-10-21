use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use uuid::Uuid;

use super::{
    GeoSnapshotError, GeoSnapshotIndex, GeoSnapshotMetadata, GeoSnapshotPayloadReader,
    GeoSnapshotReader, GeoSnapshotSourceKind, GeoSnapshotWriter,
};
use crate::ip_utils::mask_ip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpSnapshotCidr {
    pub ip: IpAddr,
    pub prefix: u32,
}

pub struct IpSnapshotWriter {
    inner: GeoSnapshotWriter,
}

impl IpSnapshotWriter {
    pub fn create(
        final_path: impl Into<PathBuf>,
        source_id: Uuid,
    ) -> Result<Self, GeoSnapshotError> {
        Ok(Self {
            inner: GeoSnapshotWriter::create(final_path, GeoSnapshotSourceKind::Ip, source_id)?,
        })
    }

    pub fn start_key(&mut self, key: &str) -> Result<(), GeoSnapshotError> {
        self.inner.start_key(key)
    }

    pub fn write_cidr(&mut self, ip: IpAddr, prefix: u32) -> Result<(), GeoSnapshotError> {
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(GeoSnapshotError::InvalidPayload("invalid IP prefix length"));
        }

        let ip = mask_ip(ip, prefix);
        let bytes = match ip {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        let mut item = Vec::with_capacity(1 + bytes.len() + 4);
        item.push(bytes.len() as u8);
        item.extend_from_slice(&bytes);
        item.extend_from_slice(&prefix.to_le_bytes());
        self.inner.write_item(&item)
    }

    pub fn end_key(&mut self) -> Result<(), GeoSnapshotError> {
        self.inner.end_key()
    }

    pub fn finish(self) -> Result<(), GeoSnapshotError> {
        self.inner.finish()
    }
}

pub struct IpSnapshotReader {
    inner: GeoSnapshotReader,
}

impl IpSnapshotReader {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GeoSnapshotError> {
        let inner = GeoSnapshotReader::open(path)?;
        if inner.metadata().source_kind != GeoSnapshotSourceKind::Ip {
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

    pub fn open_key(&self, key: &str) -> Result<IpSnapshotKeyReader, GeoSnapshotError> {
        Ok(IpSnapshotKeyReader {
            payload: self.inner.open_key(key)?,
            finished: false,
        })
    }
}

pub struct IpSnapshotKeyReader {
    payload: GeoSnapshotPayloadReader,
    finished: bool,
}

impl IpSnapshotKeyReader {
    pub fn next_cidr(&mut self) -> Result<Option<IpSnapshotCidr>, GeoSnapshotError> {
        if self.finished {
            return Ok(None);
        }
        if self.payload.remaining_len() == 0 {
            self.payload.finish()?;
            self.finished = true;
            return Ok(None);
        }

        let mut ip_len = [0u8; 1];
        read_payload_exact(&mut self.payload, &mut ip_len)?;
        let ip = match ip_len[0] {
            4 => {
                let mut octets = [0u8; 4];
                read_payload_exact(&mut self.payload, &mut octets)?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            16 => {
                let mut octets = [0u8; 16];
                read_payload_exact(&mut self.payload, &mut octets)?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(GeoSnapshotError::InvalidPayload("invalid IP address length")),
        };
        let mut prefix_bytes = [0u8; 4];
        read_payload_exact(&mut self.payload, &mut prefix_bytes)?;
        let prefix = u32::from_le_bytes(prefix_bytes);
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(GeoSnapshotError::InvalidPayload("invalid IP prefix length"));
        }

        self.payload.record_item();
        Ok(Some(IpSnapshotCidr { ip, prefix }))
    }
}

fn read_payload_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), GeoSnapshotError> {
    reader.read_exact(buffer).map_err(|error| match error.kind() {
        std::io::ErrorKind::UnexpectedEof => GeoSnapshotError::TruncatedPayload,
        _ => GeoSnapshotError::Io(error),
    })
}
