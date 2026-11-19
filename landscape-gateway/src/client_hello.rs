//! Bounded ClientHello inspection with byte-for-byte replay to TLS or passthrough.
use std::{
    io::{self, Cursor, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

pub(crate) const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
pub(crate) const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Read complete TLS records until the first handshake message is complete.
/// TCP and TLS record boundaries are independent of handshake boundaries.
/// Keep all wire bytes, including any bytes following ClientHello in its record.
pub(crate) async fn read_client_hello<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(Vec<u8>, Option<String>)> {
    let mut wire = Vec::new();
    let mut handshake = Vec::new();
    loop {
        if wire.len() + 5 > MAX_CLIENT_HELLO_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello exceeds 64 KiB inspection limit",
            ));
        }
        let mut header = [0; 5];
        reader.read_exact(&mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22 || header[1] != 3 || length == 0 || length > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ClientHello TLS record",
            ));
        }
        if wire.len() + header.len() + length > MAX_CLIENT_HELLO_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello exceeds 64 KiB inspection limit",
            ));
        }
        wire.extend_from_slice(&header);
        let start = wire.len();
        wire.resize(start + length, 0);
        reader.read_exact(&mut wire[start..]).await?;
        handshake.extend_from_slice(&wire[start..]);
        if handshake[0] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected ClientHello handshake",
            ));
        }
        if handshake.len() >= 4 {
            let length = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if length + 4 > MAX_CLIENT_HELLO_BYTES - 5 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ClientHello handshake exceeds inspection limit",
                ));
            }
            if handshake.len() >= length + 4 {
                let sni = crate::sni_proxy::parse_sni_from_handshake(&handshake[..length + 4]);
                return Ok((wire, sni));
            }
        }
    }
}

/// The inspected prefix is consumed exactly once before reading the socket.
/// Socket metadata and vectored writes still come from the original TCP stream.
pub(crate) type ReplayTcpStream = ReplayStream<TcpStream>;

pub(crate) struct ReplayStream<S> {
    inner: S,
    prefix: Cursor<Vec<u8>>,
}
impl<S> ReplayStream<S> {
    pub(crate) fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self { inner, prefix: Cursor::new(prefix) }
    }
}
impl ReplayTcpStream {
    pub(crate) fn into_split(self) -> (ReplayStream<OwnedReadHalf>, OwnedWriteHalf) {
        let (read, write) = self.inner.into_split();
        (ReplayStream { inner: read, prefix: self.prefix }, write)
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let position = self.prefix.position() as usize;
        if position < self.prefix.get_ref().len() {
            let end = (position + buf.remaining()).min(self.prefix.get_ref().len());
            buf.put_slice(&self.prefix.get_ref()[position..end]);
            if end == self.prefix.get_ref().len() {
                self.prefix = Cursor::new(Vec::new());
            } else {
                self.prefix.set_position(end as u64);
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bytes)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl std::os::fd::AsRawFd for ReplayTcpStream {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_raw_fd()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn fragmented_client_hello_preserves_sni_and_wire_bytes() {
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut tls =
            rustls::ClientConnection::new(Arc::new(client), "gateway.example".try_into().unwrap())
                .unwrap();
        let mut wire = Vec::new();
        tls.write_tls(&mut wire).unwrap();
        let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let mut fragmented = Vec::new();
        for payload in wire[5..5 + record_len].chunks(31) {
            fragmented.extend_from_slice(&wire[..3]);
            fragmented.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            fragmented.extend_from_slice(payload);
        }
        fragmented.extend_from_slice(&wire[5 + record_len..]);
        let (mut writer, mut reader) = tokio::io::duplex(32);
        let expected = fragmented.clone();
        let send = tokio::spawn(async move { writer.write_all(&fragmented).await.unwrap() });
        let (prefix, sni) = read_client_hello(&mut reader).await.unwrap();
        assert_eq!(sni.as_deref(), Some("gateway.example"));
        let mut bytes = Vec::new();
        ReplayStream::new(reader, prefix).read_to_end(&mut bytes).await.unwrap();
        send.await.unwrap();
        assert_eq!(bytes, expected);
    }
}
