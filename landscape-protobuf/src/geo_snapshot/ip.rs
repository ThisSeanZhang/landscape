use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use uuid::Uuid;

use super::{
    GeoSnapshotError, GeoSnapshotIndex, GeoSnapshotMetadata, GeoSnapshotPayloadReader,
    GeoSnapshotReader, GeoSnapshotSourceKind, GeoSnapshotWriter, SnapshotLayout,
};
use crate::ip_utils::mask_ip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpSnapshotCidr {
    pub ip: IpAddr,
    pub prefix: u32,
}

/// A CIDR already shaped like a cache row: masked network bytes and a prefix
/// that fits the stored `u8` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpSnapshotPreparedCidr {
    pub family: u8,
    pub prefix_len: u8,
    pub network: [u8; 16],
}

impl IpSnapshotPreparedCidr {
    pub fn from_ip(ip: IpAddr, prefix: u32) -> Self {
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = prefix.min(max_prefix) as u8;
        let (family, network) = pack_network(mask_ip(ip, prefix_len as u32));
        Self { family, prefix_len, network }
    }

    pub fn ip(&self) -> IpAddr {
        unpack_network(self.family, &self.network)
    }
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

        let (family, network) = pack_network(mask_ip(ip, prefix));
        let network_len = network_len(family);
        let mut item = [0u8; 18];
        item[0] = family;
        item[1] = prefix as u8;
        item[2..2 + network_len].copy_from_slice(&network[..network_len]);
        self.inner.write_item(&item[..2 + network_len])
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
    layout: SnapshotLayout,
}

impl IpSnapshotReader {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GeoSnapshotError> {
        let inner = GeoSnapshotReader::open(path)?;
        if inner.metadata().source_kind != GeoSnapshotSourceKind::Ip {
            return Err(GeoSnapshotError::UnsupportedSourceKind(
                inner.metadata().source_kind as u8,
            ));
        }
        let layout = SnapshotLayout::from_version(inner.metadata().format_version)?;
        Ok(Self { inner, layout })
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
            layout: self.layout,
            finished: false,
        })
    }
}

pub struct IpSnapshotKeyReader {
    payload: GeoSnapshotPayloadReader,
    layout: SnapshotLayout,
    finished: bool,
}

impl IpSnapshotKeyReader {
    /// Cache-ready form: the build stage already masked the network bytes, so
    /// apply binds them without another conversion or allocation.
    pub fn next_prepared(&mut self) -> Result<Option<IpSnapshotPreparedCidr>, GeoSnapshotError> {
        match self.layout {
            SnapshotLayout::V1 => Ok(self
                .next_cidr_v1()?
                .map(|cidr| IpSnapshotPreparedCidr::from_ip(cidr.ip, cidr.prefix))),
            SnapshotLayout::V2 => self.next_prepared_v2(),
        }
    }

    pub fn next_cidr(&mut self) -> Result<Option<IpSnapshotCidr>, GeoSnapshotError> {
        match self.layout {
            SnapshotLayout::V1 => self.next_cidr_v1(),
            SnapshotLayout::V2 => {
                let Some(prepared) = self.next_prepared_v2()? else {
                    return Ok(None);
                };
                Ok(Some(IpSnapshotCidr {
                    ip: prepared.ip(),
                    prefix: prepared.prefix_len as u32,
                }))
            }
        }
    }

    fn next_prepared_v2(&mut self) -> Result<Option<IpSnapshotPreparedCidr>, GeoSnapshotError> {
        if self.is_done()? {
            return Ok(None);
        }

        let family = read_u8(&mut self.payload)?;
        if family != 4 && family != 6 {
            return Err(GeoSnapshotError::InvalidPayload("invalid IP family"));
        }
        let prefix_len = read_u8(&mut self.payload)?;
        if prefix_len as u32 > max_prefix(family) {
            return Err(GeoSnapshotError::InvalidPayload("invalid IP prefix length"));
        }
        let mut network = [0u8; 16];
        read_payload_exact(&mut self.payload, &mut network[..network_len(family)])?;
        if !network_is_masked(family, prefix_len, &network) {
            return Err(GeoSnapshotError::InvalidPayload("IP network has host bits set"));
        }

        self.payload.record_item();
        Ok(Some(IpSnapshotPreparedCidr { family, prefix_len, network }))
    }

    fn next_cidr_v1(&mut self) -> Result<Option<IpSnapshotCidr>, GeoSnapshotError> {
        if self.is_done()? {
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
        if prefix > max_prefix(ip_len[0]) {
            return Err(GeoSnapshotError::InvalidPayload("invalid IP prefix length"));
        }

        self.payload.record_item();
        Ok(Some(IpSnapshotCidr { ip, prefix }))
    }

    fn is_done(&mut self) -> Result<bool, GeoSnapshotError> {
        if self.finished {
            return Ok(true);
        }
        if self.payload.remaining_len() == 0 {
            self.payload.finish()?;
            self.finished = true;
            return Ok(true);
        }
        Ok(false)
    }
}

fn max_prefix(family: u8) -> u32 {
    match family {
        4 => 32,
        _ => 128,
    }
}

fn network_len(family: u8) -> usize {
    if family == 4 { 4 } else { 16 }
}

fn network_is_masked(family: u8, prefix_len: u8, network: &[u8; 16]) -> bool {
    let prefix = prefix_len as u32;
    if family == 4 {
        let value = u32::from_be_bytes([network[0], network[1], network[2], network[3]]);
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        value & !mask == 0
    } else {
        let value = u128::from_be_bytes(*network);
        let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
        value & !mask == 0
    }
}

fn pack_network(ip: IpAddr) -> (u8, [u8; 16]) {
    let mut network = [0u8; 16];
    match ip {
        IpAddr::V4(addr) => {
            network[..4].copy_from_slice(&addr.octets());
            (4, network)
        }
        IpAddr::V6(addr) => {
            network.copy_from_slice(&addr.octets());
            (6, network)
        }
    }
}

fn unpack_network(family: u8, network: &[u8; 16]) -> IpAddr {
    match family {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&network[..4]).expect("v4 prefix"))),
        _ => IpAddr::V6(Ipv6Addr::from(*network)),
    }
}

fn read_u8<R: Read>(reader: &mut R) -> Result<u8, GeoSnapshotError> {
    let mut byte = [0u8; 1];
    read_payload_exact(reader, &mut byte)?;
    Ok(byte[0])
}

fn read_payload_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), GeoSnapshotError> {
    reader.read_exact(buffer).map_err(|error| match error.kind() {
        std::io::ErrorKind::UnexpectedEof => GeoSnapshotError::TruncatedPayload,
        _ => GeoSnapshotError::Io(error),
    })
}
