use std::io::{self, Read};

pub(crate) fn read_optional_varint<R: Read>(reader: &mut R) -> io::Result<Option<u64>> {
    let mut first = [0u8; 1];
    if reader.read(&mut first)? == 0 {
        return Ok(None);
    }
    read_varint_from_first(reader, first[0]).map(Some)
}

pub(crate) fn read_varint<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    read_varint_from_first(reader, first[0])
}

pub(crate) fn read_counted_u64<R: Read>(reader: &mut R, remaining: &mut u64) -> io::Result<u64> {
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

pub(crate) fn read_counted_bytes<R: Read>(
    reader: &mut R,
    remaining: &mut u64,
    length: usize,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    read_counted_bytes_into(reader, remaining, length, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn read_counted_bytes_into<R: Read>(
    reader: &mut R,
    remaining: &mut u64,
    length: usize,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    let length_u64 =
        u64::try_from(length).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "length"))?;
    if *remaining < length_u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "entry underflow"));
    }
    buffer.clear();
    buffer.resize(length, 0);
    reader.read_exact(buffer)?;
    *remaining -= length_u64;
    Ok(())
}

pub(crate) fn skip_field<R: Read>(
    reader: &mut R,
    wire_type: u8,
    mut remaining: Option<&mut u64>,
) -> io::Result<()> {
    match wire_type {
        0 => skip_varint(reader, remaining.as_deref_mut())?,
        1 => skip_exact(reader, 8, remaining.as_deref_mut())?,
        2 => {
            let length = match remaining.as_deref_mut() {
                Some(remaining) => read_counted_u64(reader, remaining)?,
                None => read_varint(reader)?,
            };
            let length = usize::try_from(length)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "length too large"))?;
            skip_exact(reader, length, remaining.as_deref_mut())?;
        }
        5 => skip_exact(reader, 4, remaining)?,
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported wire type"));
        }
    }
    Ok(())
}

fn read_varint_from_first<R: Read>(reader: &mut R, first: u8) -> io::Result<u64> {
    let mut result = u64::from(first & 0x7f);
    let mut byte = first;
    let mut shift = 7u32;
    while byte & 0x80 != 0 {
        if shift >= 64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint overflow"));
        }
        reader.read_exact(std::slice::from_mut(&mut byte))?;
        result |= u64::from(byte & 0x7f) << shift;
        shift += 7;
    }
    Ok(result)
}

fn skip_varint<R: Read>(reader: &mut R, mut remaining: Option<&mut u64>) -> io::Result<()> {
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
