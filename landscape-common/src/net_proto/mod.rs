pub mod error;
pub mod icmpv6;
pub mod options;
pub mod ppp;
pub mod pppoe;
pub mod udp;
pub use udp::dhcp;

/// 定义通用数据包 Option 序列化 trait
pub trait EthFrameOption {
    /// 编码为字节数组
    fn encode(&self) -> Vec<u8>;

    /// 解码成对应的类型
    fn decode(data: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

/// 统一的网络协议解析接口
pub trait NetProtoCodec: Sized {
    /// 从原始字节流中解析出消息 (适配 Decoder)
    /// 返回 Ok(Some(Self)) 表示解析成功，Ok(None) 表示长度不足
    fn decode(src: &mut bytes::BytesMut) -> Result<Option<Self>, error::NetProtoError>;

    /// 将消息编码到字节流中 (适配 Encoder)
    fn encode(&self, dst: &mut bytes::BytesMut) -> Result<(), error::NetProtoError>;
}

pub struct LandscapeCodec<T>(pub std::marker::PhantomData<T>);

impl<T> Default for LandscapeCodec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LandscapeCodec<T> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<T: NetProtoCodec> tokio_util::codec::Decoder for LandscapeCodec<T> {
    type Item = T;
    type Error = error::NetProtoError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<T>, Self::Error> {
        T::decode(src)
    }
}

impl<T: NetProtoCodec> tokio_util::codec::Encoder<T> for LandscapeCodec<T> {
    type Error = error::NetProtoError;

    fn encode(&mut self, item: T, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        item.encode(dst)
    }
}
