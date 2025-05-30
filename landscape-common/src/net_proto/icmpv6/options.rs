use std::net::Ipv6Addr;

use crate::define_options;
use serde::{Deserialize, Serialize};

// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
define_options!(IcmpV6Option, u8, u8, {
    {1,   SourceLinkLayerAddress, "Source Link-layer Address", Vec<u8>},
    {2,   TargetLinkLayerAddress, "Target Link-layer Address", Vec<u8>},
    {3,   PrefixInformation, "Prefix Information", PrefixInformation},
    {4,   RedirectedHeader, "Redirected Header", Vec<u8>},
    {5,   MTU, "MTU", u32},
    {6,   NBMAShortcutLimit, "NBMA Shortcut Limit Option", Vec<u8>},
    {7,   AdvertisementInterval, "Advertisement Interval Option - ms \n\n https://www.rfc-editor.org/rfc/rfc6275.html#section-7.3", u32},
    {8,   HomeAgentInformation, "Home Agent Information Option", Vec<u8>},
    {9,   SourceAddressList, "Source Address List", Vec<u8>},
    {10,  TargetAddressList, "Target Address List", Vec<u8>},
    {11,  CGAOption, "CGA option", Vec<u8>},
    {12,  RSASignature, "RSA Signature option", Vec<u8>},
    {13,  Timestamp, "Timestamp option", Vec<u8>},
    {14,  Nonce, "Nonce option", Vec<u8>},
    {15,  TrustAnchor, "Trust Anchor option", Vec<u8>},
    {16,  Certificate, "Certificate option", Vec<u8>},
    {17,  IPAddressPrefix, "IP Address/Prefix Option", Vec<u8>},
    {18,  NewRouterPrefixInformation, "New Router Prefix Information Option", Vec<u8>},
    {19,  LinkLayerAddress, "Link-layer Address Option", Vec<u8>},
    {20,  NeighborAdvertisementAcknowledgment, "Neighbor Advertisement Acknowledgment Option", Vec<u8>},
    {21,  PvDIDRouterAdvertisement, "PvD ID Router Advertisement Option", Vec<u8>},
    {23,  MAP, "MAP Option", Vec<u8>},
    {24,  RouteInformation, "Route Information Option", RouteInformation},
    {25,  RecursiveDNSServer, "Recursive DNS Server Option", (u32, Ipv6Addr)},
    {26,  RAFlagsExtension, "RA Flags Extension Option", Vec<u8>},
    {27,  HandoverKeyRequest, "Handover Key Request Option", Vec<u8>},
    {28,  HandoverKeyReply, "Handover Key Reply Option", Vec<u8>},
    {29,  HandoverAssistInformation, "Handover Assist Information Option", Vec<u8>},
    {30,  MobileNodeIdentifier, "Mobile Node Identifier Option", Vec<u8>},
    {31,  DNSSearchList, "DNS Search List Option", Vec<u8>},
    {32,  ProxySignature, "Proxy Signature (PS)", Vec<u8>},
    {33,  AddressRegistration, "Address Registration Option", Vec<u8>},
    {34,  LowPANContext, "6LoWPAN Context Option", Vec<u8>},
    {35,  AuthoritativeBorderRouter, "Authoritative Border Router Option", Vec<u8>},
    {36,  LowPANCapabilityIndication, "6LoWPAN Capability Indication Option (6CIO)", Vec<u8>},
    {37,  DHCPCaptivePortal, "DHCP Captive-Portal", Vec<u8>},
    {38,  PREF64, "PREF64 option", Vec<u8>},
    {39,  CryptoIDParameters, "Crypto-ID Parameters Option (CIPO)", Vec<u8>},
    {40,  NDPSignature, "NDP Signature Option (NDPSO)", Vec<u8>},
    {41,  ResourceDirectoryAddress, "Resource Directory Address Option", Vec<u8>},
    {42,  ConsistentUptime, "Consistent Uptime Option", Vec<u8>},
    {138, CARDRequest, "CARD Request option", Vec<u8>},
    {139, CARDReply, "CARD Reply option", Vec<u8>},
    {144, EncryptedDNS, "Encrypted DNS Option", Vec<u8>},
    {253, RFC3692Experiment1, "RFC3692-style Experiment 1", Vec<u8>},
    {254, RFC3692Experiment2, "RFC3692-style Experiment 2", Vec<u8>},
});

impl dhcproto::Decodable for IcmpV6Options {
    fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
        let mut opts = Vec::new();
        while let Ok(opt) = IcmpV6Option::decode(decoder) {
            opts.push(opt);
        }
        // sorts by OptionCode
        opts.sort_unstable();
        Ok(IcmpV6Options(opts))
    }
}

impl dhcproto::Encodable for IcmpV6Options {
    fn encode(&self, e: &mut dhcproto::Encoder<'_>) -> dhcproto::v6::EncodeResult<()> {
        self.0.iter().try_for_each(|opt| opt.encode(e))
    }
}

impl dhcproto::Decodable for IcmpV6Option {
    fn decode(decoder: &mut dhcproto::Decoder<'_>) -> dhcproto::error::DecodeResult<Self> {
        let code = decoder.read_u8()?.into();
        let len = decoder.read_u8()? as usize;

        let result = match code {
            IcmpV6OptionCode::SourceLinkLayerAddress => {
                IcmpV6Option::SourceAddressList(decoder.read_slice(len)?.to_vec())
            }
            code => IcmpV6Option::UnknownOption(code.into(), decoder.read_slice(len)?.to_vec()),
        };
        Ok(result)
    }
}

impl dhcproto::Encodable for IcmpV6Option {
    fn encode(&self, e: &mut dhcproto::Encoder<'_>) -> dhcproto::v6::EncodeResult<()> {
        let code: IcmpV6OptionCode = self.into();
        e.write_u8(code.into())?;
        match self {
            IcmpV6Option::SourceAddressList(data) | IcmpV6Option::SourceLinkLayerAddress(data) => {
                let len = ((data.len() as u8) + 2) / 8;
                e.write_u8(len)?;
                e.write_slice(data)?;
            }
            IcmpV6Option::TargetLinkLayerAddress(_items) => todo!(),
            IcmpV6Option::PrefixInformation(items) => {
                let mut buf = Vec::new();
                let mut item_enc = dhcproto::Encoder::new(&mut buf);
                items.encode(&mut item_enc)?;
                let len = ((buf.len() as u8) + 2) / 8;
                e.write_u8(len)?;
                e.write_slice(&buf)?;
            }
            IcmpV6Option::RedirectedHeader(_items) => todo!(),
            IcmpV6Option::MTU(mtu) => {
                e.write_u8(1)?;
                e.write_u16(0)?;
                e.write_u32(*mtu)?;
            }
            IcmpV6Option::NBMAShortcutLimit(_items) => todo!(),
            IcmpV6Option::AdvertisementInterval(interval) => {
                e.write_u8(1)?;
                e.write_u16(0)?;
                e.write_u32(*interval)?;
            }
            IcmpV6Option::HomeAgentInformation(_items) => todo!(),
            IcmpV6Option::TargetAddressList(_items) => todo!(),
            IcmpV6Option::CGAOption(_items) => todo!(),
            IcmpV6Option::RSASignature(_items) => todo!(),
            IcmpV6Option::Timestamp(_items) => todo!(),
            IcmpV6Option::Nonce(_items) => todo!(),
            IcmpV6Option::TrustAnchor(_items) => todo!(),
            IcmpV6Option::Certificate(_items) => todo!(),
            IcmpV6Option::IPAddressPrefix(_items) => todo!(),
            IcmpV6Option::NewRouterPrefixInformation(_items) => todo!(),
            IcmpV6Option::LinkLayerAddress(_items) => todo!(),
            IcmpV6Option::NeighborAdvertisementAcknowledgment(_items) => todo!(),
            IcmpV6Option::PvDIDRouterAdvertisement(_items) => todo!(),
            IcmpV6Option::MAP(_items) => todo!(),
            IcmpV6Option::RouteInformation(items) => {
                let mut buf = Vec::new();
                let mut item_enc = dhcproto::Encoder::new(&mut buf);
                items.encode(&mut item_enc)?;
                let len = ((buf.len() as u8) + 2) / 8;
                e.write_u8(len)?;
                e.write_slice(&buf)?;
            }
            IcmpV6Option::RecursiveDNSServer((lifetime, ip)) => {
                e.write_u8(3)?;
                e.write_u16(0)?;
                e.write_u32(*lifetime)?;
                e.write_slice(&ip.octets())?;
            }
            IcmpV6Option::RAFlagsExtension(_items) => todo!(),
            IcmpV6Option::HandoverKeyRequest(_items) => todo!(),
            IcmpV6Option::HandoverKeyReply(_items) => todo!(),
            IcmpV6Option::HandoverAssistInformation(_items) => todo!(),
            IcmpV6Option::MobileNodeIdentifier(_items) => todo!(),
            IcmpV6Option::DNSSearchList(_items) => todo!(),
            IcmpV6Option::ProxySignature(_items) => todo!(),
            IcmpV6Option::AddressRegistration(_items) => todo!(),
            IcmpV6Option::LowPANContext(_items) => todo!(),
            IcmpV6Option::AuthoritativeBorderRouter(_items) => todo!(),
            IcmpV6Option::LowPANCapabilityIndication(_items) => todo!(),
            IcmpV6Option::DHCPCaptivePortal(_items) => todo!(),
            IcmpV6Option::PREF64(_items) => todo!(),
            IcmpV6Option::CryptoIDParameters(_items) => todo!(),
            IcmpV6Option::NDPSignature(_items) => todo!(),
            IcmpV6Option::ResourceDirectoryAddress(_items) => todo!(),
            IcmpV6Option::ConsistentUptime(_items) => todo!(),
            IcmpV6Option::CARDRequest(_items) => todo!(),
            IcmpV6Option::CARDReply(_items) => todo!(),
            IcmpV6Option::EncryptedDNS(_items) => todo!(),
            IcmpV6Option::RFC3692Experiment1(_items) => todo!(),
            IcmpV6Option::RFC3692Experiment2(_items) => todo!(),
            IcmpV6Option::UnknownOption(_, data) => {
                e.write_u8(data.len() as u8)?;
                e.write_slice(data)?;
            }
        }
        Ok(())
    }
}

/// https://www.rfc-editor.org/rfc/rfc4861.html#section-4.6.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixInformation {
    /// 前缀长度（有效前导位数，范围 0 ~ 128）
    pub prefix_length: u8,
    /// 标志字段：最高位为 L（on-link 标志），次高位为 A（autonomous 标志），其余6位保留，发送时应置 0，接收时忽略。
    pub flags: u8,
    /// 有效生存期（单位：秒），0xffffffff 表示无限期
    pub valid_lifetime: u32,
    /// 首选生存期（单位：秒），0xffffffff 表示无限期；注意其值不能超过 valid_lifetime
    pub preferred_lifetime: u32,
    /// 保留字段，发送时置 0，接收时忽略
    pub reserved2: u32,
    /// IPv6 前缀地址，后面(不在 prefix_length 指定范围内)的位必须置 0
    pub prefix: Ipv6Addr,
}

impl PrefixInformation {
    pub fn new(
        prefix_length: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Addr,
    ) -> Self {
        PrefixInformation {
            prefix_length,
            flags: 0xc0,
            valid_lifetime,
            preferred_lifetime,
            reserved2: 0,
            prefix,
        }
    }
}

impl dhcproto::Encodable for PrefixInformation {
    fn encode(&self, e: &mut dhcproto::Encoder<'_>) -> dhcproto::v6::EncodeResult<()> {
        e.write_u8(self.prefix_length)?;
        e.write_u8(self.flags)?;
        e.write_u32(self.valid_lifetime)?;
        e.write_u32(self.preferred_lifetime)?;
        e.write_u32(self.reserved2)?;
        e.write_slice(&self.prefix.octets())?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInformation {
    /// 前缀中有效位数，范围 0～128
    pub prefix_length: u8,
    /// 8 位字段，其中：
    /// - 高 3 位：保留，发送方置零，接收方忽略
    /// - 中间 2 位：路由偏好（prf），为 2 位有符号整数（取值范围：-2 ~ 1）
    /// - 低 3 位：保留，发送方置零，接收方忽略
    pub flags: u8,
    /// 路由生存时间（秒），0xffffffff 表示无限期
    pub route_lifetime: u32,
    /// 前缀字段，实际有效长度由 `length` 决定（可能为 0、8 或 16 字节）
    pub prefix: Ipv6Addr,
}

impl RouteInformation {
    pub fn new(prefix_length: u8, prefix: Ipv6Addr) -> Self {
        RouteInformation {
            prefix_length,
            flags: 0,
            route_lifetime: 1800,
            prefix,
        }
    }
}

impl dhcproto::Encodable for RouteInformation {
    fn encode(&self, e: &mut dhcproto::Encoder<'_>) -> dhcproto::v6::EncodeResult<()> {
        e.write_u8(self.prefix_length)?;
        e.write_u8(self.flags)?;
        e.write_u32(self.route_lifetime)?;
        e.write_slice(&self.prefix.octets())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::net_proto::EthFrameOption;

    use super::*;

    /// 这部分是额外用户定义的, 不需要宏中实现
    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
    pub struct Test;

    /// 这部分是额外用户定义的, 不需要宏中实现
    impl EthFrameOption for Test {
        fn encode(&self) -> Vec<u8> {
            todo!()
        }

        fn decode(_data: &[u8]) -> Option<Self>
        where
            Self: Sized,
        {
            todo!()
        }
    }

    define_options!(AOption, u8,u8,{
        {1,   A1, "描述 A1", Test },
        {2,   A2, "描述 A1", Test },
    });

    define_options!(BOption, u16,u16,{
        {1,   B1, "描述 B1", Test },
        {2,   B2, "描述 B1", Test },
    });

    // pub enum AOptionCode {
    //     /// 描述 A1
    //     A1,
    //     /// 描述 A2
    //     A2,
    //     Unknown(u8),
    // }

    // pub enum AOption {
    //     /// 描述 A1
    //     A1(Test),
    //     /// 描述 A2
    //     A2(Test),
    // }

    // impl From<u8> for AOptionCode {
    //     fn from(value: u8) -> Self {
    //         match value {
    //             1 => AOptionCode::A1,
    //             2 => AOptionCode::A2,
    //             value => AOptionCode::Unknown(value),
    //         }
    //     }
    // }

    // impl From<AOptionCode> for u8 {
    //     fn from(value: AOptionCode) -> Self {
    //         match value {
    //             AOptionCode::A1 => 1,
    //             AOptionCode::A2 => 2,
    //             AOptionCode::Unknown(n) => n,
    //         }
    //     }
    // }
    // });

    // 首先创建一些测试数据
    fn create_test_data() -> Vec<AOption> {
        vec![
            AOption::A1(Test::default()),
            AOption::A2(Test::default()),
            AOption::A1(Test::default()), // 重复的选项，用于测试多个相同代码的选项
        ]
    }

    #[test]
    fn test_option_code_conversion() {
        // 测试从 u8 到 AOptionCode 的转换
        assert!(matches!(AOptionCode::from(1u8), AOptionCode::A1));
        assert!(matches!(AOptionCode::from(2u8), AOptionCode::A2));
        assert!(matches!(AOptionCode::from(255u8), AOptionCode::Unknown(255)));

        // 测试从 AOptionCode 到 u8 的转换
        assert_eq!(u8::from(AOptionCode::A1), 1);
        assert_eq!(u8::from(AOptionCode::A2), 2);
        assert_eq!(u8::from(AOptionCode::Unknown(255)), 255);
    }

    #[test]
    fn test_option_ordering() {
        let a1 = AOption::A1(Test::default());
        let a2 = AOption::A2(Test::default());

        // 测试选项比较
        assert!(a1 < a2);
        assert!(a2 > a1);
        assert_eq!(a1, AOption::A1(Test::default()));
    }

    #[test]
    fn test_options_new() {
        let options = AOptions::new();
        assert!(options.0.is_empty());
    }

    #[test]
    fn test_options_insert() {
        let mut options = AOptions::new();

        // 插入选项
        options.insert(AOption::A1(Test::default()));
        assert_eq!(options.0.len(), 1);

        // 插入另一个选项
        options.insert(AOption::A2(Test::default()));
        assert_eq!(options.0.len(), 2);

        // 验证排序
        assert!(matches!(options.0[0], AOption::A1(_)));
        assert!(matches!(options.0[1], AOption::A2(_)));
    }

    #[test]
    fn test_options_get() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));

        // 测试获取选项
        let a1 = options.get(AOptionCode::A1);
        assert!(a1.is_some());
        assert!(matches!(a1.unwrap(), AOption::A1(_)));

        let a2 = options.get(AOptionCode::A2);
        assert!(a2.is_some());
        assert!(matches!(a2.unwrap(), AOption::A2(_)));

        // 测试获取不存在的选项
        let unknown = options.get(AOptionCode::Unknown(3));
        assert!(unknown.is_none());
    }

    #[test]
    fn test_options_get_all() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));
        options.insert(AOption::A1(Test::default())); // 添加重复的A1

        // 测试获取所有匹配的选项
        let all_a1 = options.get_all(AOptionCode::A1);
        assert!(all_a1.is_some());
        assert_eq!(all_a1.unwrap().len(), 2);

        let all_a2 = options.get_all(AOptionCode::A2);
        assert!(all_a2.is_some());
        assert_eq!(all_a2.unwrap().len(), 1);
    }

    #[test]
    fn test_options_remove() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));
        options.insert(AOption::A1(Test::default())); // 添加重复的A1

        // 测试删除单个选项
        let removed = options.remove(AOptionCode::A1);
        assert!(removed.is_some());
        assert!(matches!(removed.unwrap(), AOption::A1(_)));

        // 验证仍然有一个A1和一个A2
        assert_eq!(options.0.len(), 2);

        // 获取并检查剩余的选项
        let all_a1 = options.get_all(AOptionCode::A1);
        assert!(all_a1.is_some());
        assert_eq!(all_a1.unwrap().len(), 1);
    }

    #[test]
    fn test_options_remove_all() {
        let mut options = AOptions::new();
        options.insert(AOption::A1(Test::default()));
        options.insert(AOption::A2(Test::default()));
        options.insert(AOption::A1(Test::default())); // 添加重复的A1

        // 测试删除所有匹配的选项
        let removed = options.remove_all(AOptionCode::A1);
        assert!(removed.is_some());
        let removed_vec: Vec<_> = removed.unwrap().collect();
        assert_eq!(removed_vec.len(), 2);

        // 验证只剩下A2
        assert_eq!(options.0.len(), 1);
        assert!(matches!(options.0[0], AOption::A2(_)));
    }

    #[test]
    fn test_options_iter() {
        let options = create_test_data().into_iter().collect::<AOptions>();

        // 测试迭代器
        let items: Vec<_> = options.iter().collect();
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn test_options_from_iterator() {
        let data = create_test_data();
        let options = data.into_iter().collect::<AOptions>();

        // 验证排序和收集
        assert_eq!(options.0.len(), 3);
        assert!(matches!(options.0[0], AOption::A1(_)));
        assert!(matches!(options.0[1], AOption::A1(_)));
        assert!(matches!(options.0[2], AOption::A2(_)));
    }

    #[test]
    fn test_options_into_iterator() {
        let options = create_test_data().into_iter().collect::<AOptions>();

        // 测试将选项集合转换为迭代器
        let items: Vec<_> = options.into_iter().collect();
        assert_eq!(items.len(), 3);
    }
}
